package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// The daily check (ADR-0054, The job): on every Windows device where
// EasyRMM's values are in place, one ordinary signed check job a day, at a
// time of day taken from the device's ID, so that an owner who arrives
// later is seen. It is never apply or undo.

const (
	// dailyCheckWindow is how long after its time a device's check may
	// still be created: a day missed while jobs were held or the server
	// was down is not caught up.
	dailyCheckWindow = time.Hour
	// dailyCheckExpiry is how long a check waits for its device.
	dailyCheckExpiry = 24 * time.Hour
	// DailyCheckRetention is how long a daily check job and its runs are
	// kept; the last result per device and module stays in device_hardening.
	DailyCheckRetention = 7 * 24 * time.Hour
)

// dailyOffset is a device's time of day (UTC) for its check.
func dailyOffset(device uuid.UUID) time.Duration {
	sum := sha256.Sum256(device[:])
	return time.Duration(binary.BigEndian.Uint64(sum[:8])%86400) * time.Second
}

// dailyBatch is the batch of an organization's checks on a day.
func dailyBatch(org uuid.UUID, day time.Time) uuid.UUID {
	return uuid.NewSHA1(org, []byte(day.UTC().Format("2006-01-02")))
}

// QueueDailyChecks creates the checks that are due now.
func (s *Service) QueueDailyChecks(ctx context.Context) (int, error) {
	now := s.now().UTC()
	day := now.Truncate(24 * time.Hour)
	since := now.Sub(day)
	type cand struct {
		device, org, site uuid.UUID
		modules           []string
	}
	var made []cand
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		// Windows devices with an agent and a record of EasyRMM's changes,
		// and none queued or running that changes the computer or checks it.
		rows, err := tx.Query(ctx, `SELECT d.id, d.organization_id, d.site_id, array_agg(h.module ORDER BY h.module)
			FROM devices d JOIN device_hardening h ON h.device_id = d.id AND h.detail->>'recorded' = 'true'
			WHERE d.platform = 'windows' AND d.agent_public_key IS NOT NULL
			  AND NOT EXISTS (SELECT 1 FROM job_runs r JOIN jobs j ON j.id = r.job_id
			      WHERE r.device_id = d.id AND j.kind = 'hardening'
			        AND r.status IN ('queued', 'sent', 'running')
			        AND (j.batch_id IS NOT NULL OR j.hardening->>'mode' IN ('apply', 'undo', 'confirm')))
			GROUP BY d.id`)
		if err != nil {
			return err
		}
		var all []cand
		for rows.Next() {
			var c cand
			if err := rows.Scan(&c.device, &c.org, &c.site, &c.modules); err != nil {
				rows.Close()
				return err
			}
			all = append(all, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, c := range all {
			off := dailyOffset(c.device)
			if since < off || since >= off+dailyCheckWindow || !devscope.Allowed(c.org) {
				continue
			}
			batch := dailyBatch(c.org, day)
			var done bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM job_runs r JOIN jobs j ON j.id = r.job_id
				WHERE r.device_id = $1 AND j.batch_id = $2)`, c.device, batch).Scan(&done); err != nil {
				return err
			}
			if done {
				continue
			}
			if err := s.insertDailyCheck(ctx, tx, c.device, c.org, c.site, batch, c.modules, now); err != nil {
				return err
			}
			made = append(made, cand{device: c.device, org: c.org})
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for _, c := range made {
		s.hub.notify(c.device)
	}
	return len(made), nil
}

func (s *Service) insertDailyCheck(ctx context.Context, tx pgx.Tx, device, org, site, batch uuid.UUID, modules []string, now time.Time) error {
	h := &Hardening{Platform: HardeningWindows, Mode: HardeningCheck, Modules: modules}
	f := apperr.Fields{}
	h.validate(f)
	if err := f.Err(); err != nil {
		return err
	}
	body := windowsHardeningScript
	sum := sha256.Sum256([]byte(body))
	expires := now.Add(dailyCheckExpiry)
	jobID := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO jobs (id, script_id, script_name, shell, body, body_sha256, args, timeout_seconds,
			expires_at, created_by, created_by_label, created_at, kind, software, hardening, pwsh_fallback, requires, params, params_sha256, batch_id)
		VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, NULL, 'EasyRMM daily check', $9, $10, NULL, $11, false, $12, NULL, NULL, $13)`,
		jobID, h.windowsLabel(), agentproto.ShellPowerShell, body, sum[:], h.windowsArgs(), h.timeout(), expires, now,
		KindHardening, h, agentproto.ShellRequires(agentproto.ShellPowerShell), batch); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO job_runs (job_id, organization_id, site_id, device_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, jobID, org, site, device, expires, now); err != nil {
		return err
	}
	// One audit row per organization per daily batch, not one per run.
	var audited bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_log WHERE action = 'device.hardening_daily_check'
		AND organization_id = $1 AND details->>'batch' = $2)`, org, batch.String()).Scan(&audited); err != nil {
		return err
	}
	if audited {
		return nil
	}
	return s.audit.Write(ctx, tx, audit.Event{
		Actor: audit.SystemActor("hardening-daily-check"), Action: "device.hardening_daily_check", Outcome: audit.Success,
		OrganizationID: org, TargetType: "job", TargetID: jobID.String(),
		Details: map[string]any{"batch": batch.String(), "sha256": hex.EncodeToString(sum[:]), "platform": HardeningWindows, "mode": HardeningCheck},
	})
}

// cancelDailyChecks cancels the checks of the devices that an undo is made
// for and that have not started: an undo comes first. The run is canceled
// with no user, and the audit has the system as its actor.
func (s *Service) cancelDailyChecks(ctx context.Context, devices []uuid.UUID) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE job_runs r SET status = 'canceled', finished_at = now(), error = 'Replaced by an undo.'
			FROM jobs j WHERE j.id = r.job_id AND j.kind = 'hardening' AND j.batch_id IS NOT NULL AND r.device_id = ANY ($1)
			  AND r.status IN ('queued', 'sent')
			RETURNING r.id, r.device_id, r.organization_id, r.site_id`, devices)
		if err != nil {
			return err
		}
		type run struct{ id, device, org, site uuid.UUID }
		var all []run
		for rows.Next() {
			var r run
			if err := rows.Scan(&r.id, &r.device, &r.org, &r.site); err != nil {
				rows.Close()
				return err
			}
			all = append(all, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range all {
			if err := s.audit.Write(ctx, tx, audit.Event{
				Actor: audit.SystemActor("hardening-daily-check"), Action: "job.cancel", Outcome: audit.Success,
				OrganizationID: r.org, SiteID: r.site, DeviceID: r.device, TargetType: "job_run", TargetID: r.id.String(),
				Details: map[string]any{"reason": "replaced by an undo"},
			}); err != nil {
				return err
			}
		}
		return nil
	})
}
