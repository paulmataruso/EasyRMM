package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// The connectivity guard (ADR-0054, W2; ADR-0078, the access guard). An
// apply that changed something asked the script to set a timer on the
// computer. Here the server queues the confirm job that ends it: the job
// is delivered only if the agent is reachable, so a change that cuts the
// agent off is undone by the computer itself, with no help from the agent.

// armedSettings are the setting IDs an apply changed.
func (r *hardeningResult) armedSettings() []string {
	var ids []string
	for _, m := range r.Modules {
		for _, st := range m.Settings {
			if st.Outcome == "applied" {
				ids = append(ids, st.ID)
			}
		}
	}
	return ids
}

// queueGuardConfirm records a guard and queues its confirm job, in the
// transaction that records the apply's result.
func (s *Service) queueGuardConfirm(ctx context.Context, tx pgx.Tx, device, applyJob uuid.UUID, at time.Time, ids []string) error {
	var org, site uuid.UUID
	var name string
	if err := tx.QueryRow(ctx, `SELECT organization_id, site_id, name FROM devices WHERE id = $1`, device).Scan(&org, &site, &name); err != nil {
		return err
	}
	// A new, automatic behavior: outside the development scope no confirm
	// is queued, and the computer's timer undoes the change. That is the
	// safe side.
	if !devscope.Allowed(org) {
		s.log.Warn("jobs: no confirmation queued for a hardening guard outside the development scope", "device", device)
		return nil
	}
	confirm := &Hardening{Platform: HardeningWindows, Mode: HardeningConfirm, Modules: []string{}}
	body := windowsHardeningScript
	sum := sha256.Sum256([]byte(body))
	now := s.now()
	expires := now.Add(GuardConfirmWithin)
	jobID := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO jobs (id, script_id, script_name, shell, body, body_sha256, args, timeout_seconds,
			expires_at, created_by, created_by_label, created_at, kind, software, hardening, pwsh_fallback, requires, params, params_sha256)
		VALUES ($1, NULL, $2, $3, $4, $5, $6, 300, $7, NULL, 'EasyRMM hardening guard', $8, $9, NULL, $10, false,
			$11, NULL, NULL)`,
		jobID, confirm.windowsLabel(), agentproto.ShellPowerShell, body, sum[:], confirm.windowsArgs(), expires, now,
		KindHardening, confirm, agentproto.ShellRequires(agentproto.ShellPowerShell)); err != nil {
		return err
	}
	var runID uuid.UUID
	if err := tx.QueryRow(ctx, `INSERT INTO job_runs (job_id, organization_id, site_id, device_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, jobID, org, site, device, expires, now).Scan(&runID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO hardening_guards (apply_job_id, device_id, confirm_job_id, settings, armed_at, rollback_at, state)
		VALUES ($1, $2, $3, $4, $5, $6, 'armed')`,
		applyJob, device, jobID, ids, at, at.Add(time.Duration(GuardMinutes)*time.Minute)); err != nil {
		return err
	}
	return s.audit.Write(ctx, tx, audit.Event{
		Actor: audit.SystemActor("hardening-guard"), Action: "device.hardening", Outcome: audit.Success,
		OrganizationID: org, SiteID: site, DeviceID: device, TargetType: "job_run", TargetID: runID.String(),
		Details: map[string]any{
			"device": name, "jobId": jobID.String(), "sha256": hex.EncodeToString(sum[:]), "platform": HardeningWindows,
			"mode": HardeningConfirm, "appliedBy": applyJob.String(), "settings": ids, "guardMinutes": GuardMinutes,
		},
	})
}

// confirmGuard records that a confirm job ran: the agent answered, the
// timer on the computer is ended and the change stands.
func (s *Service) confirmGuard(ctx context.Context, tx pgx.Tx, device, confirmJob uuid.UUID) error {
	var applyJob uuid.UUID
	var org, site uuid.UUID
	var ids []string
	err := tx.QueryRow(ctx, `UPDATE hardening_guards g SET state = 'confirmed', decided_at = now()
		FROM devices d WHERE g.confirm_job_id = $1 AND g.device_id = $2 AND g.state = 'armed' AND d.id = g.device_id
		RETURNING g.apply_job_id, d.organization_id, d.site_id, g.settings`, confirmJob, device).Scan(&applyJob, &org, &site, &ids)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.audit.Write(ctx, tx, audit.Event{
		Actor: audit.SystemActor("hardening-guard"), Action: "device.hardening.guard_confirmed", Outcome: audit.Success,
		OrganizationID: org, SiteID: site, DeviceID: device, TargetType: "job", TargetID: applyJob.String(),
		Details: map[string]any{"settings": ids},
	})
}

// timeOutGuards records the guards whose confirmation did not come by the
// time the computer's timer fired: the change is being undone there. The
// next check on the device shows whether it was.
func (s *Service) timeOutGuards(ctx context.Context, tx pgx.Tx) (int64, error) {
	rows, err := tx.Query(ctx, `UPDATE hardening_guards g SET state = 'timed_out', decided_at = now()
		FROM devices d WHERE g.state = 'armed' AND g.rollback_at + make_interval(secs => $1) <= now() AND d.id = g.device_id
		RETURNING g.apply_job_id, g.device_id, d.organization_id, d.site_id, g.settings`, guardSlack.Seconds())
	if err != nil {
		return 0, err
	}
	type timedOut struct {
		job, device, org, site uuid.UUID
		ids                    []string
	}
	var all []timedOut
	for rows.Next() {
		var t timedOut
		if err := rows.Scan(&t.job, &t.device, &t.org, &t.site, &t.ids); err != nil {
			rows.Close()
			return 0, err
		}
		all = append(all, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, t := range all {
		if err := s.audit.Write(ctx, tx, audit.Event{
			Actor: audit.SystemActor("hardening-guard"), Action: "device.hardening.guard_timed_out", Outcome: audit.Failure,
			OrganizationID: t.org, SiteID: t.site, DeviceID: t.device, TargetType: "job", TargetID: t.job.String(),
			Details: map[string]any{"settings": t.ids, "reason": "the agent did not confirm in time; the computer undoes the change"},
		}); err != nil {
			return 0, err
		}
	}
	return int64(len(all)), nil
}
