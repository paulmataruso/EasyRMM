package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Poll answers an agent's long poll: the device's due runs and the running
// runs to stop. Without work it waits up to agentproto.PollWait for some to
// arrive on this instance, and returns early when ctx ends or the service
// closes.
func (s *Service) Poll(ctx context.Context, device uuid.UUID) (*agentproto.PollResponse, error) {
	timer := time.NewTimer(s.pollWait)
	defer timer.Stop()
	for {
		// Subscribe before looking, so work queued in between still wakes us.
		wake := s.hub.subscribe(device)
		resp, err := s.claim(ctx, device)
		if err != nil || len(resp.Jobs) > 0 || len(resp.Cancel) > 0 {
			s.hub.unsubscribe(device, wake)
			return resp, err
		}
		select {
		case <-wake:
			s.hub.unsubscribe(device, wake)
		case <-timer.C:
			s.hub.unsubscribe(device, wake)
			return resp, nil
		case <-ctx.Done():
			s.hub.unsubscribe(device, wake)
			return nil, ctx.Err()
		case <-s.hub.done:
			s.hub.unsubscribe(device, wake)
			return resp, nil
		}
	}
}

// claim marks the device's due runs delivered and signs them, and collects
// cancellations to send.
func (s *Service) claim(ctx context.Context, device uuid.UUID) (*agentproto.PollResponse, error) {
	resp := &agentproto.PollResponse{Jobs: []agentproto.SignedJob{}, Cancel: []string{}}
	now := s.now().UTC()
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `WITH due AS (
				SELECT id FROM job_runs
				WHERE device_id = $1 AND expires_at > now() AND cancel_requested_at IS NULL
				  AND (status = 'queued' OR (status = 'sent' AND sent_at < now() - make_interval(secs => $2)))
				ORDER BY created_at, id LIMIT $3
				FOR UPDATE SKIP LOCKED
			)
			UPDATE job_runs r SET status = 'sent', sent_at = now(), deliveries = r.deliveries + 1
			FROM due, jobs j
			WHERE r.id = due.id AND j.id = r.job_id
			RETURNING r.id, r.job_id, r.expires_at, j.shell, j.body, j.args, j.timeout_seconds`,
			device, RedeliverAfter.Seconds(), agentproto.MaxPollJobs)
		if err != nil {
			return err
		}
		var payloads []agentproto.JobPayload
		for rows.Next() {
			var (
				p              agentproto.JobPayload
				runID, jobID   uuid.UUID
				expires        time.Time
				args           []string
				timeoutSeconds int
			)
			if err := rows.Scan(&runID, &jobID, &expires, &p.Shell, &p.Script, &args, &timeoutSeconds); err != nil {
				rows.Close()
				return err
			}
			if args == nil {
				args = []string{}
			}
			p.V, p.RunID, p.JobID, p.DeviceID = agentproto.JobPayloadVersion, runID.String(), jobID.String(), device.String()
			p.Args, p.TimeoutSeconds, p.IssuedAt, p.ExpiresAt = args, timeoutSeconds, now, expires.UTC()
			payloads = append(payloads, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, p := range payloads {
			signed, err := agentproto.SignJob(s.key, p)
			if err != nil {
				return err
			}
			resp.Jobs = append(resp.Jobs, signed)
		}
		rows, err = tx.Query(ctx, `UPDATE job_runs SET cancel_sent_at = now()
			WHERE device_id = $1 AND status = 'running' AND cancel_requested_at IS NOT NULL
			  AND (cancel_sent_at IS NULL OR cancel_sent_at < now() - make_interval(secs => $2))
			RETURNING id`, device, CancelResend.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			resp.Cancel = append(resp.Cancel, id.String())
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("jobs: claiming runs: %w", err)
	}
	return resp, nil
}

// Start lets the agent run a delivered run, unless it was canceled, has
// expired or has ended. Asking again for a running run is allowed: the
// agent records a run as started before it executes anything, so a repeat
// means the first answer was lost, not that the script ran.
func (s *Service) Start(ctx context.Context, device, run uuid.UUID) (*agentproto.StartResponse, error) {
	out := &agentproto.StartResponse{}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var (
			status   string
			expires  time.Time
			canceled bool
			timeout  int
		)
		err := tx.QueryRow(ctx, `SELECT r.status, r.expires_at, r.cancel_requested_at IS NOT NULL, j.timeout_seconds
			FROM job_runs r JOIN jobs j ON j.id = r.job_id
			WHERE r.id = $1 AND r.device_id = $2 FOR UPDATE OF r`, run, device).Scan(&status, &expires, &canceled, &timeout)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRunNotFound
		}
		if err != nil {
			return err
		}
		switch status {
		case StatusQueued, StatusSent:
			if canceled {
				return nil
			}
			if !s.now().Before(expires) {
				_, err = tx.Exec(ctx, `UPDATE job_runs SET status = 'expired', finished_at = now(),
					error = 'The device did not start the job before it expired.' WHERE id = $1`, run)
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE job_runs SET status = 'running', started_at = now(),
				deadline_at = now() + make_interval(secs => $2) WHERE id = $1`, run, float64(timeout)+DeadlineGrace.Seconds())
			out.Proceed = err == nil
			return err
		case StatusRunning:
			if !canceled {
				out.Proceed = true
				return nil
			}
			// Canceled while the agent had not started it after all.
			_, err = tx.Exec(ctx, `UPDATE job_runs SET status = 'canceled', finished_at = now(),
				error = 'Canceled before it started.' WHERE id = $1`, run)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Result records how a run ended. The first result wins; a repeat (the
// agent did not see the first answer) is acknowledged and ignored. A late
// result replaces "lost".
func (s *Service) Result(ctx context.Context, device, run uuid.UUID, in agentproto.ResultRequest) error {
	switch in.Status {
	case StatusSucceeded, StatusFailed, StatusTimedOut, StatusCanceled:
	default:
		return fmt.Errorf("%w: unknown status %q", ErrBadResult, in.Status)
	}
	if in.Status == StatusSucceeded && (in.ExitCode == nil || *in.ExitCode != 0) {
		return fmt.Errorf("%w: a successful run exits with 0", ErrBadResult)
	}
	stdout, cutOut := cleanOutput(in.Stdout)
	stderr, cutErr := cleanOutput(in.Stderr)
	msg := truncateRunes(cleanText(in.Error, true), agentproto.MaxJobError)
	var started *time.Time
	if !in.StartedAt.IsZero() {
		t := in.StartedAt
		started = &t
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE job_runs SET status = $3, exit_code = $4, stdout = $5, stderr = $6,
				stdout_truncated = $7, stderr_truncated = $8, error = $9,
				started_at = coalesce(started_at, $10), finished_at = now()
			WHERE id = $1 AND device_id = $2 AND status IN ('sent', 'running', 'lost')`,
			run, device, in.Status, in.ExitCode, stdout, stderr, in.StdoutTruncated || cutOut, in.StderrTruncated || cutErr, msg, started)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM job_runs WHERE id = $1 AND device_id = $2)`, run, device).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrRunNotFound
		}
		return nil
	})
}
