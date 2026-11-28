package schedule

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// Pacing (feature 11 slice 2): a task with a stagger starts the devices of
// each site one after another over that long, so that the devices of a
// site never restart at once. The first of every site starts at once; the
// rest wait as batches, which the scheduler runs when they fall due.

// slot is the devices of one site that start offset after the run began.
type slot struct {
	site    uuid.UUID
	offset  time.Duration
	devices []uuid.UUID
}

// Spread is the start offsets of n devices spread evenly over span, in
// whole minutes, the first at zero.
func Spread(n int, span time.Duration) []time.Duration {
	out := make([]time.Duration, n)
	if n < 2 || span < time.Minute {
		return out
	}
	for i := range out {
		out[i] = (span * time.Duration(i) / time.Duration(n)).Truncate(time.Minute)
	}
	return out
}

// Plan spreads each site's devices (listed site by site) over span. Devices
// of one site with the same offset share a slot.
func Plan(devs []device, span time.Duration) []slot {
	var out []slot
	for lo := 0; lo < len(devs); {
		hi := lo
		for hi < len(devs) && devs[hi].site == devs[lo].site {
			hi++
		}
		offs := Spread(hi-lo, span)
		for i, d := range devs[lo:hi] {
			if n := len(out); n > 0 && out[n-1].site == d.site && out[n-1].offset == offs[i] {
				out[n-1].devices = append(out[n-1].devices, d.id)
				continue
			}
			out = append(out, slot{site: d.site, offset: offs[i], devices: []uuid.UUID{d.id}})
		}
		lo = hi
	}
	return out
}

// dispatch runs the batches that have fallen due.
func (s *Service) dispatch(ctx context.Context) error {
	var due []uuid.UUID
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE automation_run_batches SET state = 'running' WHERE id IN (
			SELECT id FROM automation_run_batches WHERE state = 'pending' AND due_at <= $1
			ORDER BY due_at FOR UPDATE SKIP LOCKED LIMIT 100) RETURNING id`, s.now())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			due = append(due, id)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, id := range due {
		if err := s.runBatch(ctx, id); err != nil && ctx.Err() == nil {
			s.log.Error("schedule: running a batch failed", "batch", id, "error", err)
		}
	}
	return s.settleStale(ctx)
}

// settleStale fails batches a crashed server left running and closes the
// runs that have nothing left to wait for.
func (s *Service) settleStale(ctx context.Context) error {
	var runs []uuid.UUID
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE automation_run_batches SET state = 'failed', detail = 'The server stopped while this batch was starting.'
			WHERE state = 'running' AND due_at < $1 RETURNING run_id`, s.now().Add(-stuckAfter))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			runs = append(runs, id)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, id := range runs {
		if err := s.settle(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// runBatch makes the job of one batch, with the same checks as the run
// itself, made again now: the window, the owner, the script, and which of
// the devices are still there and online.
func (s *Service) runBatch(ctx context.Context, id uuid.UUID) error {
	var runID, taskID uuid.UUID
	var devs []uuid.UUID
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT run_id, automation_id, device_ids FROM automation_run_batches WHERE id = $1`, id).Scan(&runID, &taskID, &devs)
	}); err != nil {
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
	state, detail, jobIDs := s.batchJob(ctx, t, devs)
	if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var first *uuid.UUID
		if len(jobIDs) > 0 {
			first = &jobIDs[0]
		}
		if _, err := tx.Exec(ctx, `UPDATE automation_run_batches SET state = $2, detail = $3, job_id = $4 WHERE id = $1`, id, state, detail, first); err != nil {
			return err
		}
		if len(jobIDs) == 0 {
			return nil
		}
		_, err := tx.Exec(ctx, `UPDATE automation_runs SET job_ids = job_ids || $2::uuid[] WHERE id = $1`, runID, jobIDs)
		return err
	}); err != nil {
		return err
	}
	return s.settle(ctx, runID)
}

func (s *Service) batchJob(ctx context.Context, t *Task, devs []uuid.UUID) (state, detail string, jobIDs []uuid.UUID) {
	if !devscope.Allowed(t.OrganizationID) {
		return "skipped", "The development scope does not reach this organization.", nil
	}
	if t.State == StateCanceled {
		return "skipped", "The task was ended.", nil
	}
	reason, w, err := s.gate(ctx, t)
	if err != nil {
		return "failed", fmt.Sprintf("The maintenance window could not be read: %v", err), nil
	}
	if reason != "" {
		return "skipped", reason, nil
	}
	c, sc, bad := s.prepare(ctx, t)
	if bad != "" {
		return "failed", bad, nil
	}
	live, offline, err := s.resolve(ctx, c, t, sc, w, devs)
	if err != nil {
		return "failed", fmt.Sprintf("The targets could not be resolved: %v", err), nil
	}
	note := ""
	if offline > 0 {
		note = fmt.Sprintf(" %d offline device(s) left out.", offline)
	}
	if len(live) == 0 {
		return "skipped", "No device is left to start." + note, nil
	}
	ids, err := s.makeJobs(ctx, c, t, live)
	if err != nil {
		return "failed", fmt.Sprintf("A job could not be made: %v", err), ids
	}
	return "done", fmt.Sprintf("Made %d job(s) for %d device(s).%s", len(ids), len(live), note), ids
}

// settle closes a staggered run once none of its batches is waiting.
func (s *Service) settle(ctx context.Context, runID uuid.UUID) error {
	var t *Task
	var key string
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var taskID uuid.UUID
		var state string
		if err := tx.QueryRow(ctx, `SELECT automation_id, occurrence_key, state FROM automation_runs WHERE id = $1 FOR UPDATE`, runID).Scan(&taskID, &key, &state); err != nil {
			return err
		}
		if state != RunRunning {
			return nil
		}
		var waiting, failed, skipped, done int
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state IN ('pending', 'running')), count(*) FILTER (WHERE state = 'failed'),
			count(*) FILTER (WHERE state = 'skipped'), count(*) FILTER (WHERE state = 'done') FROM automation_run_batches WHERE run_id = $1`, runID).
			Scan(&waiting, &failed, &skipped, &done); err != nil {
			return err
		}
		if waiting > 0 {
			return nil
		}
		var jobIDs []uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT job_ids FROM automation_runs WHERE id = $1`, runID).Scan(&jobIDs); err != nil {
			return err
		}
		var err error
		if t, err = scanTask(tx.QueryRow(ctx, taskSelect+` WHERE a.id = $1`, taskID)); err != nil {
			return err
		}
		state, outcome, action := RunSucceeded, audit.Success, "automation.run_finished"
		if failed > 0 {
			state, outcome, action = RunFailed, audit.Failure, "automation.run_failed"
		}
		detail := fmt.Sprintf(" Later starts: %d made, %d skipped, %d failed.", done, skipped, failed)
		if _, err := tx.Exec(ctx, `UPDATE automation_runs SET state = $2, detail = left(detail || $3, 2000), completed_at = $4 WHERE id = $1`,
			runID, state, detail, s.now()); err != nil {
			return err
		}
		d := details(t)
		d["occurrence"], d["detail"], d["jobs"] = key, detail, len(jobIDs)
		return s.auditTx(ctx, tx, audit.SystemActor("scheduler"), action, t, outcome, d)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}
