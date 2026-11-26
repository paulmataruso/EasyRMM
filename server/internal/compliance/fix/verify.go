package fix

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
)

// Outcome is what the job reported for an item's setting, kept with the
// item (section 6: "the job result (before and after values, change time) is
// kept with the item").
type Outcome struct {
	Act       string `json:"act"`
	Result    string `json:"result"`
	Before    string `json:"before,omitempty"`
	After     string `json:"after,omitempty"`
	ChangedAt string `json:"changedAt,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// pending is an item whose job runs or whose result waits to be read.
type pending struct {
	id, org, dev, job uuid.UUID
	control, setting  string
	state             string
	version           int
	tier              string
	status            string
	// What the job reported for the setting, when it did (hardening_setting_results).
	reported                                     bool
	modOutcome, modReason, outcome, state2, note string
	before, value, changedAt                     string
}

// AdvanceOpen reads the jobs of the items that wait for one, in every
// organization, and the re-scans of the items that were applied.
func (s *Service) AdvanceOpen(ctx context.Context) error {
	var orgs []uuid.UUID
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT organization_id FROM compliance_fix_items WHERE state IN ('applying', 'undoing', 'applied')`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o uuid.UUID
			if err := rows.Scan(&o); err != nil {
				return err
			}
			orgs = append(orgs, o)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, o := range orgs {
		if err := s.advanceOrg(ctx, o); err != nil {
			return err
		}
	}
	return nil
}

// advanceOrg reads what finished: a job that applied or undid a setting, then
// the single-control re-scan that follows, then a guard that undid a change
// because the agent did not report.
func (s *Service) advanceOrg(ctx context.Context, org uuid.UUID) error {
	var todo []pending
	var scans []uuid.UUID
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT i.id, i.organization_id, i.device_id, coalesce(i.apply_job_id, i.undo_job_id), i.control_id, i.control_version, i.tier, i.state,
				coalesce(c.apply_ref->'settings'->>0, ''), coalesce(r.status, ''), sr.job_id IS NOT NULL,
				coalesce(sr.module_outcome, ''), coalesce(sr.module_reason, ''), coalesce(sr.outcome, ''), coalesce(sr.state, ''), coalesce(sr.note, ''),
				coalesce(sr.before_value, ''), coalesce(sr.value, ''), coalesce(sr.changed_at, '')
			FROM compliance_fix_items i
			JOIN compliance_controls c ON c.id = i.control_id AND c.version = i.control_version
			LEFT JOIN jobs j ON j.id = CASE i.state WHEN 'undoing' THEN i.undo_job_id ELSE i.apply_job_id END
			LEFT JOIN job_runs r ON r.job_id = j.id AND r.device_id = i.device_id
			LEFT JOIN hardening_setting_results sr ON sr.job_id = j.id AND sr.device_id = i.device_id
				AND sr.setting_id = coalesce(c.apply_ref->'settings'->>0, '')
			WHERE i.organization_id = $1 AND i.state IN ('applying', 'undoing')`, org)
		if err != nil {
			return err
		}
		for rows.Next() {
			var p pending
			var job *uuid.UUID
			if err := rows.Scan(&p.id, &p.org, &p.dev, &job, &p.control, &p.version, &p.tier, &p.state, &p.setting, &p.status, &p.reported,
				&p.modOutcome, &p.modReason, &p.outcome, &p.state2, &p.note, &p.before, &p.value, &p.changedAt); err != nil {
				rows.Close()
				return err
			}
			if job != nil {
				p.job = *job
			}
			todo = append(todo, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		sr, err := tx.Query(ctx, `SELECT DISTINCT verify_scan_id FROM compliance_fix_items WHERE organization_id = $1 AND state = 'applied' AND verify_scan_id IS NOT NULL`, org)
		if err != nil {
			return err
		}
		defer sr.Close()
		for sr.Next() {
			var id uuid.UUID
			if err := sr.Scan(&id); err != nil {
				return err
			}
			scans = append(scans, id)
		}
		return sr.Err()
	})
	if err != nil {
		return err
	}
	// A job's items are read together, so one re-scan covers them all.
	verify := map[uuid.UUID][]pending{}
	for _, p := range todo {
		switch p.status {
		case "", "queued", "sent", "running":
			continue
		}
		done, err := s.settle(ctx, p)
		if err != nil {
			return err
		}
		if done != "" {
			verify[p.job] = append(verify[p.job], p)
		}
	}
	for _, group := range verify {
		if err := s.startVerify(ctx, group); err != nil {
			s.log.Warn("compliance: the re-scan after a fix did not start", "organization_id", org, "error", err)
		}
	}
	for _, id := range scans {
		if err := s.eng.Advance(ctx, id); err != nil {
			return err
		}
	}
	return s.guards(ctx, org)
}

// settle records what a finished job did to one item's setting. It returns
// "applied" or "undone" when the change stood and a re-scan should follow.
func (s *Service) settle(ctx context.Context, p pending) (string, error) {
	act := "apply"
	if p.state == StateUndoing {
		act = "undo"
	}
	o := Outcome{Act: act}
	next, reason := "", ""
	switch {
	case p.status != "succeeded":
		next, reason = StateFailed, "The job ended as "+p.status+", so the change was not confirmed."
		if act == "undo" {
			next = StateNotVerified
			reason = "The undo job ended as " + p.status + "."
		}
	case !p.reported:
		next, reason = StateFailed, "The agent's report does not describe this setting."
		if act == "undo" {
			next, reason = StateNotVerified, "The undo's report does not describe this setting."
		}
	case act == "apply" && (p.outcome == "applied" || p.outcome == "unchanged") && p.state2 == "in_place":
		next = StateApplied
		o.Result, o.Before, o.After, o.ChangedAt = p.outcome, p.before, p.value, p.changedAt
	case act == "undo" && p.outcome == "restored":
		next = StateUndone
		o.Result, o.Before, o.After, o.ChangedAt = p.outcome, p.before, p.value, p.changedAt
	default:
		next, reason = StateFailed, "The setting was not as intended after the change."
		if act == "undo" {
			next, reason = StateNotVerified, "The undo did not put the value back."
		}
		o.Result, o.Before, o.After = p.outcome, p.before, p.value
		for _, extra := range []string{p.modReason, p.note} {
			if extra != "" {
				reason += " " + extra
			}
		}
	}
	o.Reason = reason
	oj, _ := json.Marshal(o)
	if len(reason) > 1900 {
		reason = reason[:1900]
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE compliance_fix_items SET state = $2, outcome = $3, fail_reason = $4, updated_at = $5
			WHERE id = $1 AND state = $6`, p.id, next, oj, reason, s.now(), p.state)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return nil
		}
		action := map[string]string{StateApplied: "compliance.fix.applied", StateUndone: "compliance.fix.undone",
			StateFailed: "compliance.fix.failed", StateNotVerified: "compliance.fix.failed"}[next]
		it := &itemRow{Item: Item{ID: p.id, OrgID: p.org, DeviceID: p.dev, ControlID: p.control, Version: p.version, Tier: p.tier}}
		outcome := audit.Success
		if next == StateFailed || next == StateNotVerified {
			outcome = audit.Failure
		}
		return s.audit.Write(ctx, tx, event(access.System("compliance"), action, it, outcome, map[string]any{"jobId": p.job, "act": act, "reason": reason}))
	})
	if err != nil {
		return "", err
	}
	if next == StateApplied || next == StateUndone {
		return next, nil
	}
	return "", nil
}

// startVerify asks the engine for one re-scan of the controls a job changed
// on a computer, and notes it on the items that were applied (an undone
// item has nothing to verify: the next scan makes a new item if the control
// still does not meet).
func (s *Service) startVerify(ctx context.Context, group []pending) error {
	var ids []string
	var applied []uuid.UUID
	for _, p := range group {
		ids = append(ids, p.control)
		if p.state == StateApplying {
			applied = append(applied, p.id)
		}
	}
	scanID, err := s.eng.StartVerify(ctx, group[0].org, group[0].dev, ids)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		return nil
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE compliance_fix_items SET verify_scan_id = $2 WHERE id = ANY ($1)`, applied, scanID)
		return err
	})
}

// finishVerify reads the re-scan of the items that were applied: the item
// is verified when the control now meets, and not verified when the scan
// cannot say or still finds it does not meet. A requirement's status is
// only ever moved by this scan's result, never by the fix itself.
func (s *Service) finishVerify(ctx context.Context, scanID, org uuid.UUID) error {
	type row struct {
		id, dev uuid.UUID
		control string
		version int
		tier    string
	}
	var items []row
	got := map[string]string{} // device|control -> state
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, device_id, control_id, control_version, tier FROM compliance_fix_items
			WHERE verify_scan_id = $1 AND state = 'applied'`, scanID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.dev, &r.control, &r.version, &r.tier); err != nil {
				rows.Close()
				return err
			}
			items = append(items, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		rr, err := tx.Query(ctx, `SELECT device_id, control_id, state FROM compliance_results_history WHERE scan_id = $1`, scanID)
		if err != nil {
			return err
		}
		defer rr.Close()
		for rr.Next() {
			var d uuid.UUID
			var c, st string
			if err := rr.Scan(&d, &c, &st); err != nil {
				return err
			}
			got[d.String()+"|"+c] = st
		}
		return rr.Err()
	})
	if err != nil {
		return err
	}
	for _, r := range items {
		st := got[r.dev.String()+"|"+r.control]
		next, reason := StateVerified, ""
		switch st {
		case "in_place":
		case "":
			next, reason = StateNotVerified, "The re-scan gave no answer for this control."
		case "not_in_place", "partly", "half_applied":
			next, reason = StateNotVerified, "The re-scan found that the control still does not meet."
		default:
			next, reason = StateNotVerified, "The re-scan could not tell whether the control meets."
		}
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE compliance_fix_items SET state = $2, fail_reason = $3, updated_at = $4 WHERE id = $1 AND state = 'applied'`,
				r.id, next, reason, s.now())
			if err != nil || tag.RowsAffected() != 1 {
				return err
			}
			it := &itemRow{Item: Item{ID: r.id, OrgID: org, DeviceID: r.dev, ControlID: r.control, Version: r.version, Tier: r.tier}}
			outcome := audit.Success
			if next != StateVerified {
				outcome = audit.Failure
			}
			return s.audit.Write(ctx, tx, event(access.System("compliance"), "compliance.fix.read_back", it, outcome, map[string]any{"scan": scanID, "result": st}))
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// guards marks failed the items whose change the computer undid by itself
// because the agent did not report back in time (section 6, rule 8).
func (s *Service) guards(ctx context.Context, org uuid.UUID) error {
	if !devscope.Allowed(org) {
		return nil
	}
	type row struct {
		id, dev, job uuid.UUID
		control      string
		version      int
		tier         string
	}
	var hit []row
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT i.id, i.device_id, i.apply_job_id, i.control_id, i.control_version, i.tier FROM compliance_fix_items i
			JOIN hardening_guards g ON g.apply_job_id = i.apply_job_id
			WHERE i.organization_id = $1 AND i.state IN ('applied', 'verified', 'not_verified') AND g.state = 'timed_out'`, org)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.dev, &r.job, &r.control, &r.version, &r.tier); err != nil {
				return err
			}
			hit = append(hit, r)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, r := range hit {
		reason := fmt.Sprintf("The agent did not report back within %d minutes, so the computer undid the change by itself.", jobs.GuardMinutes)
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE compliance_fix_items SET state = 'failed', fail_reason = $2, updated_at = $3
				WHERE id = $1 AND state IN ('applied', 'verified', 'not_verified')`, r.id, reason, s.now())
			if err != nil || tag.RowsAffected() != 1 {
				return err
			}
			it := &itemRow{Item: Item{ID: r.id, OrgID: org, DeviceID: r.dev, ControlID: r.control, Version: r.version, Tier: r.tier}}
			return s.audit.Write(ctx, tx, event(access.System("compliance"), "compliance.fix.failed", it, audit.Failure, map[string]any{"jobId": r.job, "reason": "guard"}))
		})
		if err != nil {
			return err
		}
	}
	return nil
}
