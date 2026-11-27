package monitoring

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/devices"
)

// Remote access alerts (ADR-0069, "Default alerts"). Remote access down
// opens when the EasyRMM agent checks in but MeshAgent has not been
// connected for the policy's minutes, and resolves when MeshCentral sees it
// connected. EasyRMM agent silent opens when MeshCentral sees MeshAgent
// connected but the EasyRMM agent has not checked in for the policy's
// minutes, and resolves when it checks in. Neither opens for a device that
// is leaving, and nothing is judged while EasyRMM cannot see MeshCentral or
// for RemoteSettle after it can again.

// remoteFacts is what one policy sees on one device it covers.
type remoteFacts struct {
	policyID, deviceID uuid.UUID
	kind               string
	minutes            int
	alertID            *uuid.UUID
	remoteOnline       bool
	wrongGroup         bool
	hasGroup           bool
	leaving            bool
	agentSeen          *time.Time // the agent's last check-in, or its enrollment
	agentOnline        bool       // the agent has not missed three of its intervals
	changedAt          *time.Time // MeshCentral's view last changed, or the enrollment
	state              []byte
}

// remoteAction is decideRemote's answer: what to do with the pair, the
// alert's detail and its value (minutes of the condition).
type remoteAction struct {
	act    action
	detail string
	value  float64
	// gone: the alert is resolved because the device is no longer covered,
	// not because its condition cleared.
	gone bool
}

// decideRemote turns facts into what to do. judge says whether conditions
// are judged now (see RemoteSettle). floor is the earliest moment a device
// counts as seen after the server began serving agents, as for offline
// policies.
func decideRemote(f remoteFacts, now, floor time.Time, judge bool) remoteAction {
	if f.leaving {
		if f.alertID != nil {
			return remoteAction{act: actResolve, gone: true}
		}
		return remoteAction{}
	}
	// agent_silent resolves on the agent's own heartbeat, not on
	// MeshCentral's view, so it must not wait for RemoteSettle.
	if f.kind == KindAgentSilent && f.agentOnline && f.alertID != nil {
		return remoteAction{act: actResolve, detail: "The EasyRMM agent checks in again."}
	}
	if !judge {
		return remoteAction{}
	}
	limit := time.Duration(f.minutes) * time.Minute
	agentOnline := f.agentOnline
	switch f.kind {
	case KindRemoteDown:
		if f.remoteOnline {
			if f.alertID != nil {
				return remoteAction{act: actResolve, detail: "MeshCentral sees MeshAgent connected."}
			}
			return remoteAction{}
		}
		if f.changedAt == nil {
			return remoteAction{}
		}
		held := now.Sub(*f.changedAt)
		_, why := devices.RemoteReason(false, agentOnline, f.wrongGroup, f.state)
		detail := fmt.Sprintf("%s Not connected for %d minutes.", why, int(held.Minutes()))
		value := math.Floor(held.Minutes())
		switch {
		case f.alertID != nil:
			return remoteAction{act: actUpdate, detail: detail, value: value}
		case agentOnline && f.hasGroup && held >= limit:
			return remoteAction{act: actOpen, detail: detail, value: value}
		}
	case KindAgentSilent:
		if f.agentSeen == nil {
			return remoteAction{}
		}
		if agentOnline {
			if f.alertID != nil {
				return remoteAction{act: actResolve, detail: "The EasyRMM agent checks in again."}
			}
			return remoteAction{}
		}
		silent := now.Sub(*f.agentSeen)
		detail := fmt.Sprintf("The EasyRMM agent last checked in %d minutes ago; MeshCentral sees MeshAgent connected.", int(silent.Minutes()))
		value := math.Floor(silent.Minutes())
		switch {
		case f.alertID != nil:
			return remoteAction{act: actUpdate, detail: detail, value: value}
		case f.remoteOnline && silent >= limit && now.Sub(floor) >= limit:
			return remoteAction{act: actOpen, detail: detail, value: value}
		}
	}
	return remoteAction{}
}

// loadRemoteFacts reads, for every enabled remote access policy and the
// enrolled devices it covers, what the decision needs; pairs whose condition
// plainly does not hold and that have no alert are left out.
func loadRemoteFacts(ctx context.Context, tx pgx.Tx, now time.Time) ([]remoteFacts, error) {
	rows, err := tx.Query(ctx, `SELECT * FROM (
			SELECT p.id AS policy_id, d.id AS device_id, p.kind, p.minutes, a.id AS alert_id,
				d.remote_online, d.mesh_wrong_group,
				EXISTS (SELECT 1 FROM mesh_sites ms WHERE ms.site_id = d.site_id) AS has_group,
				`+devices.LeavingSQL+` AS leaving,
				coalesce(d.agent_last_seen_at, d.enrolled_at) AS agent_seen,
				coalesce(d.agent_online_until > $1::timestamptz, false) AS agent_online,
				coalesce(d.remote_changed_at, d.enrolled_at) AS changed_at,
				d.meshagent_state
			FROM alert_policies p
			JOIN devices d ON d.agent_public_key IS NOT NULL
				AND (p.organization_id IS NULL OR (p.organization_id = d.organization_id AND (p.site_id IS NULL OR p.site_id = d.site_id)))
			LEFT JOIN alerts a ON a.policy_id = p.id AND a.device_id = d.id AND a.status <> 'resolved'
			LEFT JOIN alert_suppressions sup ON sup.device_id = d.id AND sup.kind = p.kind AND sup.subject = ''
			WHERE p.enabled AND p.kind IN ('remote_down', 'agent_silent')
			  AND sup.id IS NULL
		) f
		WHERE alert_id IS NOT NULL
		   OR (kind = 'remote_down' AND NOT remote_online AND has_group AND NOT leaving)
		   OR (kind = 'agent_silent' AND remote_online AND NOT leaving
			AND agent_seen <= $1::timestamptz - make_interval(mins => minutes))`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []remoteFacts
	for rows.Next() {
		var f remoteFacts
		if err := rows.Scan(&f.policyID, &f.deviceID, &f.kind, &f.minutes, &f.alertID, &f.remoteOnline, &f.wrongGroup, &f.hasGroup,
			&f.leaving, &f.agentSeen, &f.agentOnline, &f.changedAt, &f.state); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// evaluateRemote opens, updates and resolves the remote access alerts at
// now, returning how many it opened and resolved.
func (s *Service) evaluateRemote(ctx context.Context, tx pgx.Tx, now, floor time.Time) (opened, resolved int, err error) {
	if s.mesh == nil {
		// No remote access: there is nothing for these policies to watch.
		tag, err := tx.Exec(ctx, `UPDATE alerts SET status = 'resolved', resolved_at = $1, resolution = 'not_covered'
			WHERE kind IN ('remote_down', 'agent_silent') AND status <> 'resolved'`, now)
		return 0, int(tag.RowsAffected()), err
	}
	connected, since := s.mesh()
	judge := connected && !since.IsZero() && now.Sub(since) >= RemoteSettle
	list, err := loadRemoteFacts(ctx, tx, now)
	if err != nil {
		return 0, 0, err
	}
	type row struct {
		ids, devices []uuid.UUID
		detail       []string
		values       []float64
	}
	var opens, updates, resolves, gone row
	for i := range list {
		f := &list[i]
		r := decideRemote(*f, now, floor, judge)
		switch r.act {
		case actOpen:
			opens.ids = append(opens.ids, f.policyID)
			opens.devices = append(opens.devices, f.deviceID)
			opens.detail = append(opens.detail, r.detail)
			opens.values = append(opens.values, r.value)
		case actUpdate, actResolve:
			c := &updates
			switch {
			case r.gone:
				c = &gone
			case r.act == actResolve:
				c = &resolves
			}
			c.ids = append(c.ids, *f.alertID)
			c.detail = append(c.detail, r.detail)
			c.values = append(c.values, r.value)
		}
	}
	if len(opens.ids) > 0 {
		tag, err := tx.Exec(ctx, `INSERT INTO alerts (policy_id, device_id, name, kind, threshold, minutes, severity, detail, value, last_value, opened_at)
			SELECT p.id, x.device_id, p.name, p.kind, NULL, p.minutes, p.severity, x.detail, x.value, x.value, $5
			FROM unnest($1::uuid[], $2::uuid[], $3::text[], $4::float8[]) AS x(policy_id, device_id, detail, value)
			JOIN alert_policies p ON p.id = x.policy_id
			ON CONFLICT (policy_id, device_id, subject) WHERE status <> 'resolved' DO NOTHING`,
			opens.ids, opens.devices, opens.detail, opens.values, now)
		if err != nil {
			return 0, 0, err
		}
		opened = int(tag.RowsAffected())
	}
	if len(updates.ids) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE alerts a SET last_value = x.value, detail = left(x.detail, 500)
			FROM unnest($1::uuid[], $2::float8[], $3::text[]) AS x(id, value, detail)
			WHERE a.id = x.id AND a.status <> 'resolved' AND (a.last_value <> x.value OR a.detail <> left(x.detail, 500))`,
			updates.ids, updates.values, updates.detail); err != nil {
			return 0, 0, err
		}
	}
	if len(resolves.ids) > 0 {
		tag, err := tx.Exec(ctx, `UPDATE alerts a SET status = 'resolved', resolved_at = $3, resolution = 'cleared', detail = left(x.detail, 500)
			FROM unnest($1::uuid[], $2::text[]) AS x(id, detail)
			WHERE a.id = x.id AND a.status <> 'resolved'`,
			resolves.ids, resolves.detail, now)
		if err != nil {
			return 0, 0, err
		}
		resolved += int(tag.RowsAffected())
	}
	if len(gone.ids) > 0 {
		tag, err := tx.Exec(ctx, `UPDATE alerts SET status = 'resolved', resolved_at = $2, resolution = 'not_covered'
			WHERE id = ANY ($1) AND status <> 'resolved'`, gone.ids, now)
		if err != nil {
			return 0, 0, err
		}
		resolved += int(tag.RowsAffected())
	}
	return opened, resolved, nil
}
