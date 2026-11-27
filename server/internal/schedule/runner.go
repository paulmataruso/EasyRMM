package schedule

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
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
	return nil
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
			detail = 'The server stopped while this run was starting.' WHERE state = 'running' AND started_at < $1`, cutoff, s.now()); err != nil {
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
		if state == RunFailed {
			outcome, action = audit.Failure, "automation.run_failed"
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
	ids, state, msg := s.launch(ctx, t)
	return s.finish(ctx, runID, t, key, state, msg, ids)
}

func (s *Service) launch(ctx context.Context, t *Task) (jobIDs []uuid.UUID, state, msg string) {
	fail := func(format string, a ...any) ([]uuid.UUID, string, string) {
		return jobIDs, RunFailed, " " + fmt.Sprintf(format, a...)
	}
	var status, email string
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, email FROM users WHERE id = $1`, t.OwnerID).Scan(&status, &email)
	}); err != nil || status != "active" {
		return fail("The task's owner no longer has an active account.")
	}
	p, err := s.principals.LoadPrincipal(ctx, t.OwnerID)
	if err != nil {
		return fail("The owner's permissions could not be read: %v", err)
	}
	c := access.User(p, s.scopeOf(p), audit.Actor{Type: audit.ActorUser, ID: t.OwnerID, Label: email + " (scheduled task " + t.Name + ")"})
	if !c.Can(rbac.PermScriptRun, t.resource()) {
		return fail("The owner may no longer run scripts here.")
	}
	sc, err := s.scripts.GetScript(ctx, c, t.ScriptID)
	switch {
	case errors.Is(err, apperr.ErrNotFound):
		return fail("The script no longer exists, or the owner can no longer read it.")
	case err != nil:
		return fail("The script could not be read: %v", err)
	case sc.SHA256 != t.ScriptSHA256:
		return fail("The script has changed since the task was saved (pinned %.12s, now %.12s). Review it and save the task again.", t.ScriptSHA256, sc.SHA256)
	}
	var devs []uuid.UUID
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM devices
			WHERE organization_id = $1 AND ($2::uuid IS NULL OR site_id = $2) AND platform = ANY($3) AND agent_public_key IS NOT NULL
			  AND (cardinality($4::uuid[]) = 0 OR id = ANY($4))
			ORDER BY id`, t.OrganizationID, t.SiteID, agentproto.ShellPlatforms(sc.Shell), t.Targets.DeviceIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			devs = append(devs, id)
		}
		return rows.Err()
	})
	if err != nil {
		return fail("The targets could not be resolved: %v", err)
	}
	if len(devs) == 0 {
		return nil, RunSucceeded, " No device matched the targets; no job was made."
	}
	for len(devs) > 0 {
		n := min(jobs.MaxDevices, len(devs))
		j, err := s.scripts.CreateJob(ctx, c, jobInput(t, devs[:n]))
		if err != nil {
			return fail("A job could not be made: %v", err)
		}
		jobIDs = append(jobIDs, j.ID)
		devs = devs[n:]
	}
	return jobIDs, RunSucceeded, fmt.Sprintf(" Made %d job(s).", len(jobIDs))
}

func jobInput(t *Task, devs []uuid.UUID) jobs.JobInput {
	return jobs.JobInput{ScriptID: t.ScriptID, DeviceIDs: devs, Args: t.ScriptArgs, WaitHours: t.WaitHours}
}
