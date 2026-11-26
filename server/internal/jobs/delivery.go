package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
//
// accepts is the poll's own list of job capabilities (ADR-0064): a run
// whose job requires one the list lacks stays queued. A list, even an empty
// one, is kept on the device with the build that sent it, when it changed;
// nil (a poll without one) leaves what the device keeps.
func (s *Service) Poll(ctx context.Context, device uuid.UUID, accepts []string) (*agentproto.PollResponse, error) {
	accepts = cleanAccepts(accepts)
	if accepts != nil {
		if err := s.keepAccepts(ctx, device, accepts); err != nil {
			return nil, err
		}
	}
	timer := time.NewTimer(s.pollWait)
	defer timer.Stop()
	for {
		// Subscribe before looking, so work queued in between still wakes us.
		wake := s.hub.subscribe(device)
		resp, err := s.claim(ctx, device, accepts)
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

// cleanAccepts keeps the well-formed names of a poll's list, sorted and
// without repeats, at most agentproto.MaxAccepts; nil stays nil.
func cleanAccepts(in []string) []string {
	if in == nil {
		return nil
	}
	out := []string{}
	for _, a := range in {
		if acceptName(a) && !slices.Contains(out, a) && len(out) < agentproto.MaxAccepts {
			out = append(out, a)
		}
	}
	slices.Sort(out)
	return out
}

// acceptName reports whether a is a capability name: lower-case letters,
// digits, '.', '_' and '-', at most agentproto.MaxAcceptLen.
func acceptName(a string) bool {
	if a == "" || len(a) > agentproto.MaxAcceptLen {
		return false
	}
	for _, r := range a {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// KeepAccepts stores the list a heartbeat carries, as a poll's is kept; a
// heartbeat without one leaves what the device keeps.
func (s *Service) KeepAccepts(ctx context.Context, device uuid.UUID, accepts []string) error {
	if accepts = cleanAccepts(accepts); accepts == nil {
		return nil
	}
	return s.keepAccepts(ctx, device, accepts)
}

// keepAccepts stores a poll's list on its device with the build the device
// runs now, writing only when either changed.
func (s *Service) keepAccepts(ctx context.Context, device uuid.UUID, accepts []string) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET agent_accepts = $2, agent_accepts_build = coalesce(agent_sha256, agent_version)
			WHERE id = $1 AND (agent_accepts IS DISTINCT FROM $2
			  OR agent_accepts_build IS DISTINCT FROM coalesce(agent_sha256, agent_version))`, device, accepts)
		if err != nil {
			return fmt.Errorf("jobs: keeping what the agent accepts: %w", err)
		}
		return nil
	})
}

// oneEventlogAtATime holds an event log query back while another one of the
// device is running, or was delivered and has not yet been given up on: the
// claim delivers one to a device only while none is running there, so that at
// most one of the quick lane's two slots holds an event log query and registry
// reads are not starved by searches (ADR-0068, Settings per kind). $2 is the
// time after which a delivered run is sent again.
const oneEventlogAtATime = `(j.kind <> 'eventlog_query' OR NOT EXISTS (
	SELECT 1 FROM job_runs r2 JOIN jobs j2 ON j2.id = r2.job_id
	WHERE r2.device_id = r.device_id AND r2.id <> r.id AND j2.kind = 'eventlog_query'
	  AND (r2.status = 'running' OR (r2.status = 'sent' AND r2.sent_at >= now() - make_interval(secs => $2)))
))`

// oneChangeAtATime holds a hardening apply or undo back while another
// hardening or software run of the device is sent, running or queued
// before it, and holds those back while an apply or undo is (ADR-0054, One
// change at a time on a device). A confirm job, which ends a hardening
// guard, waits for nothing, and an apply or undo waits for one: the change
// before it is not yet shown to be safe. r and j are the run and job of
// the candidate.
const oneChangeAtATime = `NOT EXISTS (
	SELECT 1 FROM job_runs r2 JOIN jobs j2 ON j2.id = r2.job_id
	WHERE r2.device_id = r.device_id AND r2.id <> r.id
	  AND j.hardening->>'mode' IS DISTINCT FROM 'confirm'
	  AND j2.kind IN ('hardening', 'software')
	  AND (
	    -- the candidate changes the computer: every other run of these kinds is ahead of it or in its way
	    (j.kind = 'hardening' AND j.hardening->>'mode' IN ('apply', 'undo')
	     AND (r2.status IN ('sent', 'running')
	          OR (r2.status = 'queued' AND r2.expires_at > now() AND r2.cancel_requested_at IS NULL
	              AND (j2.hardening->>'mode' = 'confirm' OR (r2.created_at, r2.id) < (r.created_at, r.id)))))
	    OR
	    -- the candidate only reads or installs: an apply or undo that is active or earlier is ahead of it
	    (j.kind IN ('hardening', 'software') AND NOT (j.kind = 'hardening' AND j.hardening->>'mode' IN ('apply', 'undo'))
	     AND j2.kind = 'hardening' AND j2.hardening->>'mode' IN ('apply', 'undo')
	     AND (r2.status IN ('sent', 'running')
	          OR (r2.status = 'queued' AND r2.expires_at > now() AND r2.cancel_requested_at IS NULL
	              AND (r2.created_at, r2.id) < (r.created_at, r.id))))
	  )
)`

// claim marks the device's due runs delivered and signs them, and collects
// cancellations to send. A run whose job requires a capability the poll's
// list lacks is left queued.
func (s *Service) claim(ctx context.Context, device uuid.UUID, accepts []string) (*agentproto.PollResponse, error) {
	resp := &agentproto.PollResponse{Jobs: []agentproto.SignedJob{}, Cancel: []string{}}
	now := s.now().UTC()
	if accepts == nil {
		accepts = []string{}
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		// A run delivered MaxDeliveries times without starting fails, so a run
		// whose answer the agent cannot take never holds a device's runs back
		// for good (ADR-0067).
		if _, err := tx.Exec(ctx, `UPDATE job_runs SET status = 'failed', finished_at = now(),
				error = 'The agent did not take it after '||$3::text||' deliveries.'
			WHERE device_id = $1 AND status = 'sent' AND deliveries >= $3 AND sent_at < now() - make_interval(secs => $2)`,
			device, RedeliverAfter.Seconds(), agentproto.MaxDeliveries); err != nil {
			return err
		}
		// Due runs, quick ones first, then oldest first.
		rows, err := tx.Query(ctx, `SELECT r.id, r.status = 'sent',
				coalesce(nullif(j.signed_bytes, 0), octet_length(j.body) * 2 + 4096), j.kind = 'eventlog_query'
			FROM job_runs r JOIN jobs j ON j.id = r.job_id
			WHERE r.device_id = $1 AND r.expires_at > now() AND r.cancel_requested_at IS NULL
			  AND (r.status = 'queued' OR (r.status = 'sent' AND r.sent_at < now() - make_interval(secs => $2)))
			  AND j.requires <@ $4::text[]
			  AND `+oneChangeAtATime+`
			  AND `+oneEventlogAtATime+`
			ORDER BY (j.lane IS NOT NULL) DESC, r.created_at, r.id LIMIT $3
			FOR UPDATE OF r SKIP LOCKED`,
			device, RedeliverAfter.Seconds(), agentproto.MaxPollJobs, accepts)
		if err != nil {
			return err
		}
		type candidate struct {
			id       uuid.UUID
			resent   bool
			size     int
			eventlog bool
		}
		var cands []candidate
		for rows.Next() {
			var c candidate
			if err := rows.Scan(&c.id, &c.resent, &c.size, &c.eventlog); err != nil {
				rows.Close()
				return err
			}
			cands = append(cands, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		// An answer holds up to 8 runs and 6 MiB of signed jobs, and at
		// least one run, which always fits. A run being sent again goes in
		// an answer of its own, never with others.
		var chosen []uuid.UUID
		total := 0
		eventlogChosen := false
		for i, c := range cands {
			if i == 0 && c.resent {
				chosen = append(chosen, c.id)
				break
			}
			if c.resent {
				continue
			}
			if len(chosen) > 0 && total+c.size > agentproto.MaxAnswerBytes {
				break
			}
			if c.eventlog && eventlogChosen {
				continue // one event log query runs on a device at a time (ADR-0068)
			}
			eventlogChosen = eventlogChosen || c.eventlog
			chosen = append(chosen, c.id)
			total += c.size
		}
		order := make(map[uuid.UUID]int, len(chosen))
		for i, id := range chosen {
			order[id] = i
		}
		rows, err = tx.Query(ctx, `UPDATE job_runs r SET status = 'sent', sent_at = now(), deliveries = r.deliveries + 1,
				ran_agent_sha256 = (SELECT d.agent_sha256 FROM devices d WHERE d.id = r.device_id)
			FROM jobs j
			WHERE r.id = ANY($1) AND j.id = r.job_id
			RETURNING r.id, r.job_id, r.expires_at, j.shell, j.body, j.timeout_seconds, j.pwsh_fallback, j.params, j.winmod,
				j.executor, j.builtin, j.lane`, chosen)
		if err != nil {
			return err
		}
		var (
			payloads []agentproto.JobPayload
			runIDs   []uuid.UUID
			// winmods holds each payload's winmod record, nil for other kinds.
			winmods []json.RawMessage
		)
		for rows.Next() {
			var (
				p              agentproto.JobPayload
				runID, jobID   uuid.UUID
				expires        time.Time
				timeoutSeconds int
				wm             json.RawMessage
				builtin, lane  *string
			)
			if err := rows.Scan(&runID, &jobID, &expires, &p.Shell, &p.Script, &timeoutSeconds, &p.PwshFallback, &p.Params, &wm,
				&p.Executor, &builtin, &lane); err != nil {
				rows.Close()
				return err
			}
			p.V, p.RunID, p.JobID, p.DeviceID = agentproto.JobPayloadVersion, runID.String(), jobID.String(), device.String()
			p.TimeoutSeconds, p.IssuedAt, p.ExpiresAt = timeoutSeconds, now, expires.UTC()
			if p.Executor == ExecBuiltin {
				p.Builtin, p.Lane = deref(builtin), deref(lane)
			} else {
				p.Executor = ""
			}
			payloads, runIDs, winmods = append(payloads, p), append(runIDs, runID), append(winmods, wm)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		// UPDATE ... RETURNING does not keep the order the runs were chosen in.
		idx := make([]int, len(payloads))
		for i := range idx {
			idx[i] = i
		}
		slices.SortFunc(idx, func(a, b int) int { return order[runIDs[a]] - order[runIDs[b]] })
		payloads, runIDs, winmods = permute(payloads, idx), permute(runIDs, idx), permute(winmods, idx)
		inputs, err := deliveryInputs(ctx, tx, device, runIDs)
		if err != nil {
			return err
		}
		for i := range payloads {
			if payloads[i].Executor == ExecBuiltin {
				in, ok := inputs[payloads[i].RunID]
				if !ok {
					// The input was removed with its results: nothing to run.
					if err := refuseDelivery(ctx, tx, uuid.MustParse(payloads[i].RunID), StatusFailed, "The job's input is no longer kept, so it was not sent."); err != nil {
						return err
					}
					payloads[i].RunID = ""
					continue
				}
				payloads[i].Input = in
			}
		}
		keep := make([]int, 0, len(payloads))
		for i, p := range payloads {
			if p.RunID != "" {
				keep = append(keep, i)
			}
		}
		payloads, runIDs, winmods = permute(payloads, keep), permute(runIDs, keep), permute(winmods, keep)
		args, err := deliveryArgs(ctx, tx, device, runIDs)
		if err != nil {
			return err
		}
		for i, p := range payloads {
			p.Args = args[p.RunID]
			if len(winmods) > i && len(winmods[i]) > 0 {
				// A winmod job's script is checked against its pin and its
				// secrets are placed in the params, for this delivery only.
				jobID, _ := uuid.Parse(p.JobID)
				switch err := s.winmodDeliver(ctx, tx, jobID, &p, winmods[i]); {
				case err == nil:
				case errors.Is(err, errSecretGone):
					if err := refuseDelivery(ctx, tx, uuid.MustParse(p.RunID), StatusExpired,
						"The request's secret was already delivered or has expired. Ask for the action again."); err != nil {
						return err
					}
					continue
				case errors.Is(err, errWinmodPin):
					s.log.Error("jobs: a winmod script does not match its pinned hash; the run was not sent", "run", p.RunID)
					if err := refuseDelivery(ctx, tx, uuid.MustParse(p.RunID), StatusFailed, "The script does not match the hash the job pinned, so it was not sent."); err != nil {
						return err
					}
					continue
				default:
					return err
				}
			}
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

// deref is the text a nullable column holds, or "".
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// permute returns list in the order idx gives.
func permute[T any](list []T, idx []int) []T {
	out := make([]T, len(idx))
	for i, j := range idx {
		out[i] = list[j]
	}
	return out
}

// deliveryInputs reads the inputs of the structured runs just delivered, by
// run, compacted: the bytes the payload carries and the signature covers.
// Like the arguments, they are read through a function that answers only
// under the system scope.
func deliveryInputs(ctx context.Context, tx pgx.Tx, device uuid.UUID, runs []uuid.UUID) (map[string][]byte, error) {
	out := map[string][]byte{}
	if len(runs) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT run_id, run_input FROM easyrmm_job_delivery_inputs($1, $2)`, device, runs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var in []byte
		if err := rows.Scan(&id, &in); err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		if err := json.Compact(&buf, in); err != nil {
			return nil, err
		}
		out[id.String()] = buf.Bytes()
	}
	return out, rows.Err()
}

// deliveryArgs reads the arguments of the runs just delivered, by run.
// The server's database role cannot select them; a function that answers
// only under the system scope reads them (ADR-0063). Every run must have
// its arguments, or the job would run without them.
func deliveryArgs(ctx context.Context, tx pgx.Tx, device uuid.UUID, runs []uuid.UUID) (map[string][]string, error) {
	out := make(map[string][]string, len(runs))
	if len(runs) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT run_id, run_args FROM easyrmm_job_delivery_args($1, $2)`, device, runs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var args []string
		if err := rows.Scan(&id, &args); err != nil {
			return nil, err
		}
		if args == nil {
			args = []string{}
		}
		out[id.String()] = args
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) != len(runs) {
		return nil, fmt.Errorf("jobs: arguments found for %d of %d runs", len(out), len(runs))
	}
	return out, nil
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
// result replaces "lost". Output is stored with the time it arrived, from
// which its retention counts, and never on a run whose output was removed:
// there the status and exit code are recorded without it (ADR-0063).
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
	p := cleanProgram(in.Interpreter)
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var job uuid.UUID
		var ran time.Time
		err := tx.QueryRow(ctx, `UPDATE job_runs SET status = $3, exit_code = $4,
				stdout = CASE WHEN output_removed_at IS NULL THEN $5 ELSE '' END,
				stderr = CASE WHEN output_removed_at IS NULL THEN $6 ELSE '' END,
				stdout_truncated = output_removed_at IS NULL AND $7, stderr_truncated = output_removed_at IS NULL AND $8,
				output_stored_at = CASE WHEN output_removed_at IS NULL AND ($5 <> '' OR $6 <> '') THEN now() END,
				error = $9, started_at = coalesce(started_at, $10), finished_at = now(),
				program_edition = $11, program_version = $12, program_arch = $13, program_path = $14, program_fallback = $15
			WHERE id = $1 AND device_id = $2 AND status IN ('sent', 'running', 'lost')
			RETURNING job_id, coalesce(started_at, finished_at)`,
			run, device, in.Status, in.ExitCode, stdout, stderr, in.StdoutTruncated || cutOut, in.StderrTruncated || cutErr, msg, started,
			p.edition, p.version, p.arch, p.path, p.fallback).
			Scan(&job, &ran)
		if err == nil {
			// A structured run's result is checked against its input and
			// kept as lines (ADR-0067).
			if handled, herr := s.recordRegistryResult(ctx, tx, device, run, in); handled || herr != nil {
				return herr
			}
			// A winmod run's result is kept typed, not as text (ADR-0073).
			if handled, herr := s.recordWinmod(ctx, tx, device, run, in.Status, stdout); handled || herr != nil {
				return herr
			}
		}
		switch {
		case err == nil && in.Status == StatusSucceeded:
			// A hardening run's result is kept per module (ADR-0051).
			return s.recordHardening(ctx, tx, device, run, job, ran, stdout)
		case err == nil:
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return err
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
	if err == nil {
		// A run that ended may release work held behind it (one change at a
		// time on a device) or queue the confirmation of a hardening guard.
		s.hub.notify(device)
	}
	return err
}

// program is a result's interpreter as a run keeps it: NULL columns for
// what was not reported or is not one of the known values.
type program struct {
	edition, version, arch, path *string
	fallback                     bool
}

// cleanProgram bounds what an agent says it started. Without a path there
// is no program; an unknown edition or architecture is dropped, and only
// Windows PowerShell can be a fallback.
func cleanProgram(in *agentproto.Interpreter) program {
	var p program
	if in == nil {
		return p
	}
	path := truncateRunes(cleanText(in.Path, false), agentproto.MaxInterpreterPath)
	if path == "" {
		return p
	}
	p.path = &path
	if in.Edition == agentproto.EditionDesktop || in.Edition == agentproto.EditionCore {
		p.edition = &in.Edition
	}
	if v := truncateRunes(cleanText(in.Version, false), agentproto.MaxInterpreterVersion); v != "" {
		p.version = &v
	}
	switch in.Arch {
	case agentproto.ArchX64, agentproto.ArchARM64, agentproto.ArchX86:
		p.arch = &in.Arch
	}
	p.fallback = in.Fallback && in.Edition == agentproto.EditionDesktop
	return p
}
