package jobs

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
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// What a run printed and a job's argument values can hold secrets. The
// server's database role cannot select them: they are read through
// database functions that check job.view_sensitive and append the audit
// record in the same transaction (ADR-0063, migration 00028).

// Output is what a run printed, as kept.
type Output struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdoutTruncated"`
	StderrTruncated bool   `json:"stderrTruncated"`
}

// Arguments are a job's argument values.
type Arguments struct {
	Args []string `json:"args"`
}

// emptyOutput is the change that removes a run's output, by retention or
// at once.
const emptyOutput = `stdout = '', stderr = '', stdout_truncated = false, stderr_truncated = false,
	output_stored_at = NULL, output_removed_at = now()`

// scopeOf is where the caller holds perm, for the database functions that
// check it themselves.
func scopeOf(c access.Caller, perm rbac.Permission) rbac.Scope {
	if c.IsSystem() {
		return rbac.Scope{All: true}
	}
	return c.Principal.Scope(perm)
}

// readCall runs one of the read functions for the caller. They take the
// same arguments after the run or job: the caller's job.view and
// job.view_sensitive scopes, and who reads, as the audit record has it.
// A refusal is recorded too, so the transaction commits whatever the
// result; the caller turns the result into an answer.
func (s *Service) readCall(ctx context.Context, c access.Caller, sql string, id uuid.UUID, dst ...any) error {
	view, read := scopeOf(c, rbac.PermJobView), scopeOf(c, rbac.PermJobViewSensitive)
	st := s.audit.Stamp(c.Actor)
	return s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, sql, id, view.All, view.Orgs, view.Sites, read.All, read.Orgs, read.Sites,
			st.At, st.ActorType, st.ActorID, st.ActorLabel, st.SourceIP, st.UserAgent).Scan(dst...)
	})
}

// readResult turns what a read function found into an error, or nil when
// there is something to return.
func readResult(result string) error {
	switch result {
	case "ok", "empty":
		return nil
	case "not_found":
		return apperr.NotFound()
	case "forbidden":
		return apperr.Forbidden()
	case "run_open":
		return apperr.Conflict("run_open", "The run has not finished: its output arrives when it ends.")
	case "output_removed":
		return apperr.Conflict("output_removed", "This run's output was removed.")
	}
	return fmt.Errorf("jobs: a read answered %q", result)
}

// ReadOutput returns what a finished run printed to a caller who holds
// job.view_sensitive at its site, and records the read as
// job_run.output_view. A run that printed nothing answers empty and is not
// recorded. A caller who sees the run but may not read its output is
// refused and recorded as denied, within the bound migration 00028 sets.
func (s *Service) ReadOutput(ctx context.Context, c access.Caller, id uuid.UUID) (*Output, error) {
	var result string
	var stdout, stderr *string
	var outCut, errCut *bool
	if err := s.readCall(ctx, c, `SELECT result, out_text, err_text, out_cut, err_cut
		FROM easyrmm_job_run_output($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::inet, $13)`,
		id, &result, &stdout, &stderr, &outCut, &errCut); err != nil {
		return nil, err
	}
	if err := readResult(result); err != nil {
		return nil, err
	}
	return &Output{Stdout: *stdout, Stderr: *stderr, StdoutTruncated: *outCut, StderrTruncated: *errCut}, nil
}

// ReadArguments returns a job's argument values to a caller who holds
// job.view_sensitive at the site of one of its runs they can see, and
// records the read as job.arguments_view once for each organization of
// those runs. A job without arguments answers an empty list and is not
// recorded. A refusal is recorded as ReadOutput's is.
func (s *Service) ReadArguments(ctx context.Context, c access.Caller, id uuid.UUID) (*Arguments, error) {
	var result string
	var args []string
	if err := s.readCall(ctx, c, `SELECT result, job_args
		FROM easyrmm_job_arguments($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::inet, $13)`,
		id, &result, &args); err != nil {
		return nil, err
	}
	if err := readResult(result); err != nil {
		return nil, err
	}
	return &Arguments{Args: args}, nil
}

// canRemoveOutput says whether the caller may remove output at a site: it
// takes reading it and managing jobs there.
func canRemoveOutput(c access.Caller, at rbac.Resource) bool {
	return c.Can(rbac.PermJobViewSensitive, at) && c.Can(rbac.PermJobManage, at)
}

// RemoveOutput empties a finished run's output at once, for a caller who
// may read it and manage jobs at its site, records it as
// job_run.output_remove, and returns the run.
func (s *Service) RemoveOutput(ctx context.Context, c access.Caller, id uuid.UUID) (*Run, error) {
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var (
			kind               string
			outBytes, errBytes int
			removed            *time.Time
		)
		r, err := scanRun(tx.QueryRow(ctx, `SELECT `+runColumns+`, j.kind, r.stdout_bytes, r.stderr_bytes, r.output_removed_at`+
			runFrom+` WHERE r.id = $1 FOR UPDATE OF r`, id), &kind, &outBytes, &errBytes, &removed)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		at := rbac.Site(r.OrganizationID, r.SiteID)
		switch {
		case !c.Can(rbac.PermJobView, at):
			return apperr.NotFound()
		case !canRemoveOutput(c, at):
			return apperr.Forbidden()
		case r.open():
			return apperr.Conflict("run_open", "The run has not finished: its output arrives when it ends.")
		case removed != nil:
			return apperr.Conflict("output_removed", "This run's output was removed.")
		case outBytes+errBytes == 0:
			return apperr.Conflict("no_output", "This run printed nothing, so there is no output to remove.")
		}
		if _, err := tx.Exec(ctx, `UPDATE job_runs SET `+emptyOutput+` WHERE id = $1`, id); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "job_run.output_remove", Outcome: audit.Success,
			OrganizationID: r.OrganizationID, SiteID: r.SiteID, DeviceID: r.DeviceID, TargetType: "job_run", TargetID: id.String(),
			Details: map[string]any{"device": r.DeviceName, "jobId": r.JobID.String(), "script": r.ScriptName, "kind": kind,
				"stdoutBytes": outBytes, "stderrBytes": errBytes},
		})
	})
	if err != nil {
		return nil, err
	}
	return s.GetRun(ctx, c, id)
}
