package recovery

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
)

// Automatic repairs (ADR-0069, Part R). The server watches for the
// conditions below, notes since when each holds, and starts a repair once it
// has held for its time. An attempt is one escalation: the first step, then
// the next if the target is still broken after the wait. The limits count
// attempts, not steps.

// Timing and limits.
const (
	// SeenForMesh and SeenForPatching are how long the condition must have
	// held, as the server has seen it, before an attempt starts.
	SeenForMesh     = 10 * time.Minute
	SeenForPatching = 30 * time.Minute
	// AutoWaitMesh and AutoWaitPatching are how long the target gets to
	// come back after a step, before the next step is tried (and after the
	// last).
	AutoWaitMesh     = 20 * time.Minute
	AutoWaitPatching = 30 * time.Minute
	// AttemptEvery is the shortest time between two attempts on one target
	// of one device, and PerDay how many a rolling day allows.
	AttemptEvery = 6 * time.Hour
	PerDay       = 3
	// Settle is how long EasyRMM's connection to MeshCentral must have been
	// open before conditions about MeshAgent are judged.
	Settle = 15 * time.Minute
	// SilentAfter is how long the EasyPatch agent must not have checked in
	// to count as silent. The engine's default check-in interval is a
	// minute, and twice that is below what a poll every 5 minutes can tell,
	// so it is twice the poll. An organization that sets a longer interval
	// is not read: the condition's own 30 minutes stand for it.
	SilentAfter = 10 * time.Minute
)

// lockEvaluate keeps two servers on one database from judging at once.
const lockEvaluate = 7302265818153

// conditionSQL says, per target, which devices are in the condition now: $1
// is now. An EasyRMM agent that checks in is a precondition of both, since
// it is the one that repairs; nothing is judged for a device that is
// leaving.
var conditionSQL = map[string]string{
	// The EasyRMM agent checks in, supervises MeshAgent here (it reported
	// its state), and MeshCentral has a group for the device's site but does
	// not see MeshAgent connected.
	agentproto.TargetMeshAgent: `SELECT d.id FROM devices d
		WHERE d.agent_public_key IS NOT NULL AND d.agent_last_seen_at > $1::timestamptz - interval '3 minutes'
		  AND d.meshagent_state IS NOT NULL AND NOT d.remote_online AND $2::int >= 0
		  AND EXISTS (SELECT 1 FROM mesh_sites ms WHERE ms.site_id = d.site_id)
		  AND NOT ` + devices.LeavingSQL,
	// The EasyRMM agent checks in, the device is patched and its EasyPatch
	// agent is linked, and the engine has not heard from the agent for
	// SilentAfter.
	agentproto.TargetEasyPatchAgent: `SELECT d.id FROM devices d
		JOIN easypatch_organizations lo ON lo.organization_id = d.organization_id
		JOIN easypatch_devices e ON e.device_id = d.id AND e.state = 'linked'
		WHERE d.agent_public_key IS NOT NULL AND d.agent_last_seen_at > $1::timestamptz - interval '3 minutes'
		  AND e.agent_seen_at IS NOT NULL AND e.agent_seen_at < $1::timestamptz - make_interval(secs => $2::int)
		  AND NOT ` + devices.LeavingSQL,
}

// Evaluate notes the conditions that call for a repair and starts the
// repairs that are due. A target's conditions are not judged, and their
// clocks forgotten, while EasyRMM cannot see what it judges them by:
// MeshCentral for MeshAgent (its connection open for Settle), the patching
// engine for the EasyPatch agent (answering for patching's EngineSettle).
// It never starts a repair on a device that is leaving, in an organization
// that turned automatic repairs off, or beyond the limits.
func (s *Service) Evaluate(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, int64(lockEvaluate)).Scan(&locked); err != nil || !locked {
			return err
		}
		now := s.now().UTC()
		// Nothing about a device that is leaving stays open.
		if _, err := tx.Exec(ctx, `UPDATE alerts a SET status = 'resolved', resolved_at = $1, resolution = 'not_covered'
			WHERE a.kind = 'repair_failed' AND a.status <> 'resolved'
			  AND EXISTS (SELECT 1 FROM devices d WHERE d.id = a.device_id AND `+devices.LeavingSQL+`)`, now); err != nil {
			return err
		}
		meshOK := false
		if s.remote && s.link != nil {
			connected, since := s.link()
			meshOK = connected && !since.IsZero() && now.Sub(since) >= Settle
		}
		patchOK := s.patch != nil && s.patch.AgentsSettled(now)
		for _, t := range []struct {
			target  string
			judged  bool
			seenFor time.Duration
		}{
			{agentproto.TargetMeshAgent, meshOK, SeenForMesh},
			{agentproto.TargetEasyPatchAgent, patchOK, SeenForPatching},
		} {
			if err := s.evaluateTarget(ctx, tx, now, t.target, t.judged, t.seenFor); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Service) evaluateTarget(ctx context.Context, tx pgx.Tx, now time.Time, target string, judged bool, seenFor time.Duration) error {
	if !judged {
		_, err := tx.Exec(ctx, `DELETE FROM agent_conditions WHERE target = $1`, target)
		return err
	}
	silent := int(SilentAfter.Seconds())
	cond := conditionSQL[target]
	if _, err := tx.Exec(ctx, `INSERT INTO agent_conditions (device_id, target, since)
		SELECT c.id, $3::text, $1::timestamptz FROM (`+cond+`) c ON CONFLICT DO NOTHING`, now, silent, target); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM agent_conditions k WHERE k.target = $3::text AND k.device_id NOT IN (SELECT c.id FROM (`+cond+`) c)`,
		now, silent, target); err != nil {
		return err
	}
	// The Repair failed alert goes when its target is back.
	if _, err := tx.Exec(ctx, `UPDATE alerts a SET status = 'resolved', resolved_at = $1::timestamptz, resolution = 'cleared'
		WHERE a.kind = 'repair_failed' AND a.subject = $2::text AND a.status <> 'resolved'
		  AND NOT EXISTS (SELECT 1 FROM agent_conditions k WHERE k.device_id = a.device_id AND k.target = a.subject)
		  AND NOT EXISTS (SELECT 1 FROM agent_repairs r WHERE r.device_id = a.device_id AND r.target = a.subject AND r.state = 'running')`,
		now, target); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT k.device_id, d.name, d.organization_id, d.site_id
		FROM agent_conditions k JOIN devices d ON d.id = k.device_id JOIN organizations o ON o.id = d.organization_id
		WHERE k.target = $2::text AND k.since <= $1::timestamptz - make_interval(secs => $3::int) AND o.auto_repair
		  AND NOT EXISTS (SELECT 1 FROM agent_repairs r WHERE r.device_id = k.device_id AND r.target = k.target AND r.state = 'running')
		  AND NOT EXISTS (SELECT 1 FROM agent_repairs r WHERE r.device_id = k.device_id AND r.target = k.target AND r.trigger = 'automatic'
			AND r.started_at > $1::timestamptz - make_interval(secs => $4::int))
		  AND (SELECT count(*) FROM agent_repairs r WHERE r.device_id = k.device_id AND r.target = k.target AND r.trigger = 'automatic'
			AND r.started_at > $1::timestamptz - interval '24 hours') < $5::int
		ORDER BY k.since, k.device_id LIMIT 200`,
		now, target, int(seenFor.Seconds()), int(AttemptEvery.Seconds()), PerDay)
	if err != nil {
		return err
	}
	type due struct {
		id, org, site uuid.UUID
		name          string
	}
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.name, &d.org, &d.site); err != nil {
			rows.Close()
			return err
		}
		list = append(list, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, d := range list {
		r, err := s.insert(ctx, tx, d.id, target, TriggerAutomatic, nil)
		if errors.Is(err, errRunning) {
			continue
		}
		if err != nil {
			return err
		}
		if err := s.audit.Write(ctx, tx, audit.Event{
			Actor: audit.SystemActor("recovery"), Action: "device.repair_auto", Outcome: audit.Success,
			OrganizationID: d.org, SiteID: d.site, DeviceID: d.id, TargetType: "device", TargetID: d.id.String(),
			Details: map[string]any{"device": d.name, "target": target, "repair": r.ID.String()},
		}); err != nil {
			return err
		}
	}
	return nil
}
