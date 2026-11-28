package schedule

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/notify"
)

// stuckAfter is how long a pending or running occurrence may sit before it
// is picked up again (pending) or called interrupted (running).
const stuckAfter = 10 * time.Minute

// Run claims and runs due tasks until ctx ends.
func (s *Service) Run(ctx context.Context) {
	tick := time.NewTicker(Tick)
	defer tick.Stop()
	for {
		if err := s.Fire(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("schedule: firing due tasks failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Fire claims the occurrences that are due and runs them. Several servers
// may call it at once: an occurrence is claimed under a row lock and the
// unique occurrence key, so it runs on one of them only.
func (s *Service) Fire(ctx context.Context) error {
	ids, err := s.claim(ctx)
	if err != nil {
		return err
	}
	more, err := s.recover(ctx)
	if err != nil {
		return err
	}
	for _, id := range append(ids, more...) {
		if err := s.execute(ctx, id); err != nil && ctx.Err() == nil {
			s.log.Error("schedule: running an occurrence failed", "run", id, "error", err)
		}
	}
	return s.dispatch(ctx)
}

// claim records the due occurrences and moves each task to its next one. A
// task whose time passed while the server was down, or that is more than
// Grace late, has missed: with the skip rule only a skipped record is
// kept; with run as soon as possible one run stands for every missed
// occurrence, so a long outage never makes a storm.
func (s *Service) claim(ctx context.Context) ([]uuid.UUID, error) {
	var run []uuid.UUID
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		now := s.now()
		rows, err := tx.Query(ctx, taskSelect+` WHERE a.state = 'active' AND a.next_run_at <= $1
			ORDER BY a.next_run_at FOR UPDATE OF a SKIP LOCKED LIMIT 100`, now)
		if err != nil {
			return err
		}
		var due []*Task
		for rows.Next() {
			t, err := scanTask(rows)
			if err != nil {
				rows.Close()
				return err
			}
			due = append(due, t)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		sys := audit.SystemActor("scheduler")
		for _, t := range due {
			if !devscope.Allowed(t.OrganizationID) {
				continue
			}
			last, n := t.Schedule.LastDue(t.loc(), *t.NextRunAt, now)
			missed := n > 1 || now.Sub(last) > Grace
			state, detail := RunPending, ""
			switch {
			case missed && t.MissedRunRule == RuleSkip:
				state, detail = RunSkipped, "The server was not running at this time; the task skips what it missed."
			case missed:
				detail = "Run late: the server was not running at this time."
			}
			if missed && n > 1 {
				detail += fmt.Sprintf(" %d occurrences fell due.", n)
			}
			key := last.UTC().Format(time.RFC3339)
			var runID uuid.UUID
			err := tx.QueryRow(ctx, `INSERT INTO automation_runs (automation_id, organization_id, site_id, occurrence_key, scheduled_for, state, detail, completed_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $6 = 'skipped' THEN $8::timestamptz END)
				ON CONFLICT (automation_id, occurrence_key) DO NOTHING RETURNING id`,
				t.ID, t.OrganizationID, t.SiteID, key, last, state, detail, now).Scan(&runID)
			created := err == nil
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			newState, next := StateActive, (*time.Time)(nil)
			if nx, ok := t.Schedule.Next(t.loc(), last); ok {
				next = &nx
			} else {
				newState = StateCompleted
			}
			if _, err := tx.Exec(ctx, `UPDATE automations SET next_run_at = $2, state = $3, last_run_at = $4 WHERE id = $1`,
				t.ID, next, newState, last); err != nil {
				return err
			}
			if !created {
				continue
			}
			d := details(t)
			d["occurrence"], d["detail"] = key, detail
			action := "automation.run_started"
			if state == RunSkipped {
				action = "automation.run_skipped"
			} else {
				run = append(run, runID)
			}
			if err := s.auditTx(ctx, tx, sys, action, t, audit.Success, d); err != nil {
				return err
			}
		}
		return nil
	})
	return run, err
}

// recover returns pending occurrences a crashed server left, and fails
// running ones that never made a job.
func (s *Service) recover(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		cutoff := s.now().Add(-stuckAfter)
		if _, err := tx.Exec(ctx, `UPDATE automation_runs SET state = 'failed', completed_at = $2,
			detail = 'The server stopped while this run was starting.' WHERE state = 'running' AND started_at < $1
			AND NOT EXISTS (SELECT 1 FROM automation_run_batches b WHERE b.run_id = automation_runs.id AND b.state IN ('pending', 'running'))`, cutoff, s.now()); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM automation_runs WHERE state = 'pending' AND created_at < $1 LIMIT 100`, s.now().Add(-time.Minute))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}

// finish closes a run.
func (s *Service) finish(ctx context.Context, id uuid.UUID, t *Task, key string, state, detail string, jobIDs []uuid.UUID) error {
	if jobIDs == nil {
		jobIDs = []uuid.UUID{}
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE automation_runs SET state = $2, detail = left(detail || $3, 2000), completed_at = $4, job_ids = $5 WHERE id = $1`,
			id, state, detail, s.now(), jobIDs); err != nil {
			return err
		}
		outcome, action := audit.Success, "automation.run_finished"
		switch state {
		case RunFailed:
			outcome, action = audit.Failure, "automation.run_failed"
		case RunSkipped:
			action = "automation.run_skipped"
		}
		d := details(t)
		d["occurrence"], d["detail"], d["jobs"] = key, detail, len(jobIDs)
		return s.auditTx(ctx, tx, audit.SystemActor("scheduler"), action, t, outcome, d)
	})
}

// execute makes the jobs of one claimed occurrence, as the task's owner
// with everything checked again: the owner's account and permissions, the
// script's hash, and the devices the owner can reach now.
func (s *Service) execute(ctx context.Context, runID uuid.UUID) error {
	var taskID uuid.UUID
	var key string
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE automation_runs SET state = 'running', started_at = $2
			WHERE id = $1 AND state = 'pending' RETURNING automation_id, occurrence_key`, runID, s.now()).Scan(&taskID, &key)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // another server has it
	}
	if err != nil {
		return err
	}
	var t *Task
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		t, err = scanTask(tx.QueryRow(ctx, taskSelect+` WHERE a.id = $1`, taskID))
		return err
	}); err != nil {
		return err
	}
	if !devscope.Allowed(t.OrganizationID) {
		return s.finish(ctx, runID, t, key, RunSkipped, " Not started: the development scope does not reach this organization.", nil)
	}
	ids, state, msg, batches := s.launch(ctx, t, runID)
	if batches > 0 && state == RunSucceeded {
		// The later starts of a staggered run are still to come: the run
		// stays open until the last of them has been made.
		return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE automation_runs SET detail = left(detail || $2, 2000), job_ids = job_ids || $3 WHERE id = $1`, runID, msg, ids)
			return err
		})
	}
	return s.finish(ctx, runID, t, key, state, msg, ids)
}

// gate says why a task held to a window may not start now: the empty string
// when it may.
func (s *Service) gate(ctx context.Context, t *Task) (reason string, w notify.TaskWindow, err error) {
	if t.WindowID == nil {
		return "", w, nil
	}
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		w, err = notify.LoadTaskWindow(ctx, tx, *t.WindowID, s.now())
		return err
	})
	switch {
	case err != nil:
		return "", w, err
	case !w.Enabled || !notify.AllowsTasks(w.Purpose):
		return " Not started: the maintenance window is switched off or no longer allows tasks.", w, nil
	case !w.Open:
		return " Not started: the maintenance window is not open.", w, nil
	}
	return "", w, nil
}

// prepare checks, as the task's owner, everything a run depends on: the
// owner's account and permissions and the script's hash. A non-empty bad
// says why the run fails.
func (s *Service) prepare(ctx context.Context, t *Task) (c access.Caller, sc *jobs.Script, bad string) {
	var status, email string
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, email FROM users WHERE id = $1`, t.OwnerID).Scan(&status, &email)
	}); err != nil || status != "active" {
		return c, nil, "The task's owner no longer has an active account."
	}
	p, err := s.principals.LoadPrincipal(ctx, t.OwnerID)
	if err != nil {
		return c, nil, fmt.Sprintf("The owner's permissions could not be read: %v", err)
	}
	c = access.User(p, s.scopeOf(p), audit.Actor{Type: audit.ActorUser, ID: t.OwnerID, Label: email + " (scheduled task " + t.Name + ")"})
	if !c.Can(t.perm(), t.resource()) {
		return c, nil, "The owner may no longer " + t.permVerb() + " here."
	}
	if t.StepKind != StepScript {
		return c, nil, ""
	}
	sc, err = s.scripts.GetScript(ctx, c, *t.ScriptID)
	switch {
	case errors.Is(err, apperr.ErrNotFound):
		return c, nil, "The script no longer exists, or the owner can no longer read it."
	case err != nil:
		return c, nil, fmt.Sprintf("The script could not be read: %v", err)
	case sc.SHA256 != t.ScriptSHA256:
		return c, nil, fmt.Sprintf("The script has changed since the task was saved (pinned %.12s, now %.12s). Review it and save the task again.", t.ScriptSHA256, sc.SHA256)
	}
	return c, sc, ""
}

// device is a target of a run.
type device struct {
	id, site uuid.UUID
	platform string
	online   bool
}

// resolve lists the devices a run reaches now, in site and ID order. Held
// to a window, a task reaches that window's site only. only, when not
// empty, narrows to those devices (a later batch). With OnlyIfOnline the
// offline ones are left out and counted.
func (s *Service) resolve(ctx context.Context, c access.Caller, t *Task, sc *jobs.Script, w notify.TaskWindow, only []uuid.UUID) (devs []device, offline int, err error) {
	platforms := t.platforms(sc)
	if only == nil {
		only = []uuid.UUID{}
	}
	site := t.SiteID
	if t.WindowID != nil {
		site = &w.SiteID
	}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, site_id, platform, coalesce(agent_online_until > now(), false) FROM devices
			WHERE organization_id = $1 AND ($2::uuid IS NULL OR site_id = $2) AND platform = ANY($3) AND agent_public_key IS NOT NULL
			  AND (cardinality($4::uuid[]) = 0 OR id = ANY($4)) AND (cardinality($5::uuid[]) = 0 OR id = ANY($5))
			ORDER BY site_id, id`, t.OrganizationID, site, platforms, t.Targets.DeviceIDs, only)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d device
			var st *uuid.UUID
			if err := rows.Scan(&d.id, &st, &d.platform, &d.online); err != nil {
				return err
			}
			if st != nil {
				d.site = *st
			}
			if t.OnlyIfOnline && !d.online {
				offline++
				continue
			}
			devs = append(devs, d)
		}
		return rows.Err()
	})
	return devs, offline, err
}

// makeJobs makes the jobs of the task's step for the devices, in batches of
// at most the bound on a job, and for a maintenance step one set per
// platform (its script differs).
func (s *Service) makeJobs(ctx context.Context, c access.Caller, t *Task, devs []device) (jobIDs []uuid.UUID, err error) {
	platforms := []string{""}
	if t.StepKind != StepScript && t.StepKind != StepSoftware {
		platforms = []string{"linux", "windows"}
	}
	for _, p := range platforms {
		var ids []uuid.UUID
		for _, d := range devs {
			if p == "" || d.platform == p {
				ids = append(ids, d.id)
			}
		}
		for len(ids) > 0 {
			n := min(jobs.MaxDevices, len(ids))
			j, err := s.createJob(ctx, c, t, p, ids[:n])
			if err != nil {
				return jobIDs, err
			}
			jobIDs = append(jobIDs, j.ID)
			ids = ids[n:]
		}
	}
	return jobIDs, nil
}

// createJob makes one job of the task's step.
func (s *Service) createJob(ctx context.Context, c access.Caller, t *Task, platform string, devs []uuid.UUID) (*jobs.Job, error) {
	switch t.StepKind {
	case StepScript:
		return s.scripts.CreateJob(ctx, c, jobs.JobInput{ScriptID: *t.ScriptID, DeviceIDs: devs, Args: t.ScriptArgs, WaitHours: t.WaitHours})
	case StepSoftware:
		return s.scripts.CreateSoftwareJob(ctx, c, jobs.SoftwareInput{DeviceIDs: devs, Software: *t.Step.Software, WaitHours: t.WaitHours})
	}
	return s.scripts.CreateMaintenanceJob(ctx, c, jobs.MaintenanceInput{DeviceIDs: devs, Platform: platform,
		Maintenance: t.Step.maintenance(t.StepKind), WaitHours: t.WaitHours})
}

// launch starts one occurrence: the jobs of the devices whose turn it is
// now, and the batches of the rest when the task staggers. batches counts
// those.
func (s *Service) launch(ctx context.Context, t *Task, runID uuid.UUID) (jobIDs []uuid.UUID, state, msg string, batches int) {
	fail := func(format string, a ...any) ([]uuid.UUID, string, string, int) {
		return jobIDs, RunFailed, " " + fmt.Sprintf(format, a...), 0
	}
	reason, w, err := s.gate(ctx, t)
	if err != nil {
		return fail("The maintenance window could not be read: %v", err)
	}
	if reason != "" {
		return nil, RunSkipped, reason, 0
	}
	c, sc, bad := s.prepare(ctx, t)
	if bad != "" {
		return fail("%s", bad)
	}
	devs, offline, err := s.resolve(ctx, c, t, sc, w, nil)
	if err != nil {
		return fail("The targets could not be resolved: %v", err)
	}
	note := ""
	if offline > 0 {
		note = fmt.Sprintf(" %d offline device(s) left out.", offline)
	}
	if len(devs) == 0 {
		return nil, RunSucceeded, " No device matched the targets; no job was made." + note, 0
	}
	span := time.Duration(t.StaggerMinutes) * time.Minute
	if t.WindowID != nil {
		span = min(span, w.Until.Sub(s.now())-time.Minute)
	}
	now, later := Plan(devs, span), []slot(nil)
	var first []uuid.UUID
	for _, sl := range now {
		if sl.offset == 0 {
			first = append(first, sl.devices...)
		} else {
			later = append(later, sl)
		}
	}
	byID := make(map[uuid.UUID]device, len(devs))
	for _, d := range devs {
		byID[d.id] = d
	}
	firstDevs := make([]device, 0, len(first))
	for _, id := range first {
		firstDevs = append(firstDevs, byID[id])
	}
	if len(later) > 0 {
		if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			for _, sl := range later {
				for rest := sl.devices; len(rest) > 0; {
					n := min(jobs.MaxDevices, len(rest))
					if _, err := tx.Exec(ctx, `INSERT INTO automation_run_batches (run_id, automation_id, organization_id, site_id, due_at, device_ids)
						VALUES ($1, $2, $3, $4, $5, $6)`, runID, t.ID, t.OrganizationID, t.SiteID, s.now().Add(sl.offset), rest[:n]); err != nil {
						return err
					}
					batches++
					rest = rest[n:]
				}
			}
			return nil
		}); err != nil {
			return fail("The staggered starts could not be planned: %v", err)
		}
	}
	jobIDs, err = s.makeJobs(ctx, c, t, firstDevs)
	if err != nil {
		if batches > 0 {
			// The planned starts still run; this run keeps what it made.
			return jobIDs, RunSucceeded, fmt.Sprintf(" A job could not be made for the first devices: %v. %d later start(s) planned.", err, batches), batches
		}
		return fail("A job could not be made: %v", err)
	}
	if batches > 0 {
		return jobIDs, RunSucceeded, fmt.Sprintf(" Made %d job(s) now; %d later start(s) over %d minute(s).%s", len(jobIDs), batches, int(span/time.Minute), note), batches
	}
	return jobIDs, RunSucceeded, fmt.Sprintf(" Made %d job(s).%s", len(jobIDs), note), 0
}
