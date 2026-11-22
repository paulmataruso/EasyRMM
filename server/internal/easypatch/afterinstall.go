package easypatch

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Restarts after an install (ADR-0030, amended 2026-11-22). The patching
// engine cannot restart a computer when an install ends, and asking it for
// the install and the restart together is not safe: the restart could run
// first. So EasyRMM keeps the choice (easypatch_install_restarts) and, every
// minute, reads each install job it waits for: when the job has completed,
// it asks the engine to restart the device, once; when the install waits
// for a restart to go on, it asks for that restart first. A failed,
// canceled or expired install never restarts its device.
//
// Asking the engine for a restart is claimed in the database first, so that
// one of EasyRMM's servers asks, and a claim a stopped server left behind is
// settled from the engine's own jobs before anything is asked again: a
// restart of EasyRMM's server neither loses a restart nor asks for one twice.

const (
	conditionAlways  = "Always"
	conditionPending = "OnlyIfPending"
	// claimStale is how long a claim may be in flight: longer than any call
	// to the engine takes.
	claimStale = 2 * time.Minute
	// claimSlack allows for the engine's clock when its jobs are looked up.
	claimSlack = time.Minute
	// restartWaitLimit is how long EasyRMM waits for an install to end: the
	// engine expires an install still waiting for a restart after 30 days.
	restartWaitLimit = 40 * 24 * time.Hour
	// restartSweepBatch is the most installs one pass reads.
	restartSweepBatch = 500
	// lookupParallel is how many devices are read from the engine at once.
	lookupParallel = 8
)

// What became of a restart after an install.
const (
	afterWaiting = "waiting"
	afterDone    = "done"
	afterSkipped = "skipped"
	afterFailed  = "failed"
)

// AfterInstall restarts each device once its install has finished: only if
// the updates need it (OnlyIfPending) or always, and how the people signed in
// are treated, as for any restart.
type AfterInstall struct {
	Condition           string `json:"condition"`
	Mode                string `json:"mode"`
	CountdownMinutes    *int   `json:"countdownMinutes"`
	DeadlineMinutes     *int   `json:"deadlineMinutes"`
	ExpiresAfterMinutes *int   `json:"expiresAfterMinutes"`
}

// options checks the choice as any restart's, Countdown by default.
func (a AfterInstall) options(now time.Time) (RestartOptions, error) {
	if a.Condition != conditionPending && a.Condition != conditionAlways {
		return RestartOptions{}, apperr.Invalid("restart", "Choose to restart only if the updates need it, or when done.")
	}
	o := RestartOptions{Mode: a.Mode, Condition: a.Condition, CountdownMinutes: a.CountdownMinutes, DeadlineMinutes: a.DeadlineMinutes,
		ExpiresAfterMinutes: a.ExpiresAfterMinutes}
	err := o.normalize(now)
	return o, err
}

// afterText says when a device restarts after its install, for the audit
// trail.
func afterText(condition string) string {
	if condition == conditionAlways {
		return "when done"
	}
	return "if the updates need it"
}

// RestartAfterView is an install's restart afterwards, as its job shows it.
type RestartAfterView struct {
	Condition           string `json:"condition"`
	Mode                string `json:"mode"`
	CountdownMinutes    *int   `json:"countdownMinutes"`
	DeadlineMinutes     *int   `json:"deadlineMinutes"`
	ExpiresAfterMinutes *int   `json:"expiresAfterMinutes"`
	// State is waiting (for the install to end), done (the restart was asked
	// for: RestartJobID), skipped or failed, as Message says.
	State   string `json:"state"`
	Message string `json:"message"`
	// RestartJobID is the restart asked for once the install ended;
	// MidwayJobID, one asked for while it waited for a restart to go on.
	RestartJobID *uuid.UUID `json:"restartJobId"`
	MidwayJobID  *uuid.UUID `json:"midwayJobId"`
	// Server says the device was ticked by name as a server to restart.
	Server      bool      `json:"server"`
	RequestedBy string    `json:"requestedBy"`
	RequestedAt time.Time `json:"requestedAt"`
}

// keepRestarts keeps the restart choice of each install the engine started,
// and returns how many devices will restart.
func (s *Service) keepRestarts(ctx context.Context, c access.Caller, devices []deviceRow, results []ActionItem, o RestartOptions,
	confirmServers []uuid.UUID) (int, error) {
	byID := map[uuid.UUID]deviceRow{}
	for _, d := range devices {
		byID[d.id] = d
	}
	var by *uuid.UUID
	if c.Actor.Type == audit.ActorUser && c.Actor.ID != uuid.Nil {
		id := c.Actor.ID
		by = &id
	}
	n := 0
	err := s.db.InTx(context.WithoutCancel(ctx), database.System, func(tx pgx.Tx) error {
		for _, it := range results {
			d, ok := byID[it.DeviceID]
			if !it.OK || it.JobID == nil || !ok || d.endpointID == nil || d.easyPatchOrg == nil {
				continue
			}
			tag, err := tx.Exec(ctx, `INSERT INTO easypatch_install_restarts (install_job_id, device_id, endpoint_id, easypatch_org_id, condition,
					mode, countdown_minutes, deadline_minutes, expires_after_minutes, server_confirmed, requested_by, requested_label, requested_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) ON CONFLICT (install_job_id) DO NOTHING`,
				*it.JobID, d.id, *d.endpointID, *d.easyPatchOrg, o.Condition, o.Mode, o.CountdownMinutes, o.DeadlineMinutes,
				o.ExpiresAfterMinutes, slices.Contains(confirmServers, d.id), by, cut(c.Actor.Label, 255), s.now())
			if err != nil {
				return err
			}
			n += int(tag.RowsAffected())
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// restartRow is an install EasyRMM restarts the device of afterwards.
type restartRow struct {
	job, device, endpoint, epOrg uuid.UUID
	opts                         RestartOptions
	server                       bool
	by                           *uuid.UUID
	label                        string
	requestedAt                  time.Time
	midway                       *uuid.UUID
	claimedAt                    *time.Time
	claimedFor                   *string
}

// caller is who asked for the install, as the engine is told.
func (r restartRow) caller() access.Caller {
	a := audit.SystemActor(r.label)
	if r.by != nil {
		a = audit.Actor{Type: audit.ActorUser, ID: *r.by, Label: r.label}
	}
	return access.Caller{Scope: database.System, Actor: a}
}

// SweepRestarts restarts the devices whose install has finished, as the
// installs asked, and returns how many restarts it asked for.
func (s *Service) SweepRestarts(ctx context.Context) (int, error) {
	r, cl, err := s.conn(ctx)
	if err != nil || r == nil {
		return 0, err
	}
	now := s.now()
	var rows []restartRow
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		list, err := tx.Query(ctx, `SELECT install_job_id, device_id, endpoint_id, easypatch_org_id, condition, mode, countdown_minutes,
				deadline_minutes, expires_after_minutes, server_confirmed, requested_by, requested_label, requested_at, midway_job_id,
				claimed_at, claimed_for
			FROM easypatch_install_restarts WHERE state = 'waiting' ORDER BY checked_at NULLS FIRST, requested_at LIMIT $1`, restartSweepBatch)
		if err != nil {
			return err
		}
		for list.Next() {
			var x restartRow
			if err := list.Scan(&x.job, &x.device, &x.endpoint, &x.epOrg, &x.opts.Condition, &x.opts.Mode, &x.opts.CountdownMinutes,
				&x.opts.DeadlineMinutes, &x.opts.ExpiresAfterMinutes, &x.server, &x.by, &x.label, &x.requestedAt, &x.midway,
				&x.claimedAt, &x.claimedFor); err != nil {
				return err
			}
			rows = append(rows, x)
		}
		return list.Err()
	})
	if err != nil {
		return 0, err
	}
	asked := 0
	var errs []error
	for _, x := range rows {
		ok, err := s.afterInstall(ctx, cl, x, now)
		if ok {
			asked++
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if asked > 0 {
		s.fleet.clear()
	}
	return asked, errors.Join(errs...)
}

// afterInstall moves one install's restart on, and says whether it asked
// the engine for a restart.
func (s *Service) afterInstall(ctx context.Context, cl *Client, x restartRow, now time.Time) (bool, error) {
	if x.claimedAt != nil {
		if now.Sub(*x.claimedAt) < claimStale {
			return false, nil
		}
		done, err := s.settleClaim(ctx, cl, x)
		if done || err != nil {
			return false, err
		}
		x.claimedAt, x.claimedFor = nil, nil
	}
	if now.Sub(x.requestedAt) > restartWaitLimit {
		return false, s.finishRestart(ctx, x.job, afterSkipped, "The install did not end within 40 days, so the device was not restarted.", nil)
	}
	d, err := s.restartDevice(ctx, x)
	if err != nil || d == nil {
		return false, err
	}
	rctx := s.as(ctx, x.caller(), RoleReadOnly, x.epOrg)
	j, err := cl.Job(rctx, x.job)
	switch {
	case IsStatus(err, http.StatusNotFound):
		return false, s.finishRestart(ctx, x.job, afterSkipped, "The patching engine no longer has the install, so the device was not restarted.", nil)
	case err != nil:
		s.noteError(err)
		return false, s.touchRestart(ctx, x.job)
	}
	switch j.Summary.Status {
	case "Completed":
		return s.askRestart(ctx, cl, x, *d, "final", j.Summary.RebootRequired)
	case "WaitingForReboot":
		if x.midway == nil {
			return s.askRestart(ctx, cl, x, *d, "midway", true)
		}
	case "Failed":
		return false, s.finishRestart(ctx, x.job, afterSkipped, "The install failed, so the device was not restarted.", nil)
	case statusCanceled:
		return false, s.finishRestart(ctx, x.job, afterSkipped, "The install was canceled, so the device was not restarted.", nil)
	case "Expired":
		return false, s.finishRestart(ctx, x.job, afterSkipped, "The install expired before it ran, so the device was not restarted.", nil)
	}
	return false, s.touchRestart(ctx, x.job)
}

// restartDevice reads the device an install restarts, or ends the restart
// when patching stopped on it or its agent changed (nil).
func (s *Service) restartDevice(ctx context.Context, x restartRow) (*deviceRow, error) {
	var d deviceRow
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		d, err = scanDevice(tx.QueryRow(ctx, deviceSelect+` WHERE d.id = $1`, x.device))
		return err
	})
	if err != nil {
		return nil, err
	}
	switch {
	case d.stopped != nil || d.removal != nil:
		return nil, s.finishRestart(ctx, x.job, afterSkipped, "Patching was stopped on the device, so it was not restarted.", nil)
	case d.state != LinkLinked || d.endpointID == nil || *d.endpointID != x.endpoint:
		return nil, s.finishRestart(ctx, x.job, afterSkipped, "The device's EasyPatch agent changed since the install, so it was not restarted.", nil)
	}
	return &d, nil
}

// askRestart asks the engine to restart the device: midway, while the
// install waits for a restart to go on (only if one is pending), or final,
// once it has finished, as the install asked. needed says the install
// reported that its updates need a restart.
func (s *Service) askRestart(ctx context.Context, cl *Client, x restartRow, d deviceRow, kind string, needed bool) (bool, error) {
	actx := s.as(ctx, x.caller(), RoleAdmin, x.epOrg)
	e, err := cl.Endpoint(actx, x.endpoint)
	switch {
	case IsStatus(err, http.StatusNotFound):
		return false, s.finishRestart(ctx, x.job, afterSkipped, "The patching engine no longer lists the device's endpoint, so it was not restarted.", nil)
	case err != nil:
		s.noteError(err)
		return false, s.touchRestart(ctx, x.job)
	case !slices.Contains(e.AgentCapabilities, AgentCanRestart):
		return false, s.finishRestart(ctx, x.job, afterSkipped, "Its EasyPatch agent cannot restart the computer, so it was not restarted.", nil)
	case (e.OsProductType == "Server" || e.OsProductType == "DomainController") && !x.server:
		msg := "A server that was not ticked by name: it installed, and was not restarted."
		if kind == "midway" {
			msg = "A server that was not ticked by name: it was not restarted, and its install waits for a restart."
		}
		return false, s.finishRestart(ctx, x.job, afterSkipped, msg, nil)
	case x.opts.Condition == conditionPending && !needed && !e.Summary.RebootPending:
		return false, s.finishRestart(ctx, x.job, afterSkipped, "The updates did not need a restart, so the device was not restarted.", nil)
	}
	claimed, err := s.claimRestart(ctx, x.job, kind)
	if err != nil || !claimed {
		return false, err
	}
	o := x.opts
	if kind == "midway" {
		o.Condition = conditionPending
	}
	br, err := cl.BulkRestart(actx, []uuid.UUID{x.endpoint}, o, x.label)
	var ee *Error
	switch {
	case errors.As(err, &ee) && ee.Status >= 400 && ee.Status < 500:
		// The engine refused it: nothing was started.
		return false, s.finishRestart(ctx, x.job, afterFailed, cut("The patching engine refused the restart: "+message(epError(err)), 1000), nil)
	case err != nil:
		// It may have reached the engine: the claim stays, and is settled
		// from the engine's jobs once it is stale.
		s.noteError(err)
		return false, err
	}
	var item *BulkItem
	for i := range br.Results {
		if br.Results[i].EndpointID == x.endpoint {
			item = &br.Results[i]
		}
	}
	switch {
	case item == nil:
		return false, s.finishRestart(ctx, x.job, afterFailed, unansweredMessage, nil)
	case item.Success && item.JobID != nil, item.ErrorCode == "duplicate_job" && item.JobID != nil:
		return true, s.adoptRestart(ctx, x, d, kind, *item.JobID)
	}
	return false, s.finishRestart(ctx, x.job, afterFailed, cut("The patching engine refused the restart: "+item.Message, 1000), nil)
}

// settleClaim settles a claim a server left behind: the restart it asked
// for, when the engine has one for the device since that no other install
// asked for, or none, when it does not, so that it is asked for again. It
// says whether the restart was found.
func (s *Service) settleClaim(ctx context.Context, cl *Client, x restartRow) (bool, error) {
	since := x.claimedAt.Add(-claimSlack)
	endpoint := x.endpoint
	p, err := cl.Jobs(s.as(ctx, x.caller(), RoleReadOnly, x.epOrg),
		JobFilter{OrganizationID: x.epOrg, EndpointID: &endpoint, Type: "Restart", From: &since}, 1)
	if err != nil {
		s.noteError(err)
		return false, epError(err)
	}
	for _, j := range p.Items {
		// A restart already asked for after an install is that install's.
		var known bool
		err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM easypatch_install_restarts WHERE restart_job_id = $1 OR midway_job_id = $1)`,
				j.ID).Scan(&known)
		})
		if err != nil {
			return false, err
		}
		if known {
			continue
		}
		d, err := s.restartDevice(ctx, x)
		if err != nil || d == nil {
			return true, err
		}
		return true, s.adoptRestart(ctx, x, *d, *x.claimedFor, j.ID)
	}
	return false, s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE easypatch_install_restarts SET claimed_at = NULL, claimed_for = NULL
			WHERE install_job_id = $1 AND claimed_at = $2`, x.job, *x.claimedAt)
		return err
	})
}

// claimRestart claims asking for a restart, and says whether this server
// has it.
func (s *Service) claimRestart(ctx context.Context, job uuid.UUID, kind string) (bool, error) {
	claimed := false
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE easypatch_install_restarts SET claimed_at = $2, claimed_for = $3, checked_at = $2
			WHERE install_job_id = $1 AND state = 'waiting' AND claimed_at IS NULL`, job, s.now(), kind)
		claimed = tag.RowsAffected() == 1
		return err
	})
	return claimed, err
}

// adoptRestart records the restart the engine started, and audits it.
func (s *Service) adoptRestart(ctx context.Context, x restartRow, d deviceRow, kind string, restart uuid.UUID) error {
	ctx = context.WithoutCancel(ctx)
	if kind == "midway" {
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE easypatch_install_restarts SET midway_job_id = $2, claimed_at = NULL, claimed_for = NULL,
					checked_at = $3, message = 'Restarted while the install waited for a restart; the install goes on after it.'
				WHERE install_job_id = $1 AND state = 'waiting'`, x.job, restart, s.now())
			return err
		})
		if err != nil {
			return err
		}
	} else if err := s.finishRestart(ctx, x.job, afterDone, "Restart asked for once the install finished.", &restart); err != nil {
		return err
	}
	when := afterText(x.opts.Condition)
	if kind == "midway" {
		when = "while the install waited for a restart"
	}
	return s.record(ctx, []audit.Event{{Actor: audit.SystemActor("patching"), Action: "patch.restart", OrganizationID: d.organizationID,
		SiteID: d.siteID, DeviceID: d.id, TargetType: "device", TargetID: d.id.String(), Outcome: audit.Success,
		Details: map[string]any{"device": d.name, "endpointId": x.endpoint.String(), "jobId": restart.String(), "afterInstall": x.job.String(),
			"when": when, "mode": restartModeText(x.opts), "requestedBy": x.label}}})
}

// finishRestart ends an install's restart: done (restart is the job),
// skipped or failed.
func (s *Service) finishRestart(ctx context.Context, job uuid.UUID, state, msg string, restart *uuid.UUID) error {
	return s.db.InTx(context.WithoutCancel(ctx), database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE easypatch_install_restarts SET state = $2, message = $3, restart_job_id = coalesce($4, restart_job_id),
				claimed_at = NULL, claimed_for = NULL, checked_at = $5, finished_at = $5
			WHERE install_job_id = $1 AND state = 'waiting'`, job, state, cut(msg, 1000), restart, s.now())
		return err
	})
}

// touchRestart notes that an install was read and is still going.
func (s *Service) touchRestart(ctx context.Context, job uuid.UUID) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE easypatch_install_restarts SET checked_at = $2 WHERE install_job_id = $1`, job, s.now())
		return err
	})
}

// restartAfter reads an install job's restart afterwards, and, for a
// restart EasyRMM asked for after an install, that install, as the caller
// sees them.
func (s *Service) restartAfter(ctx context.Context, c access.Caller, job uuid.UUID) (*RestartAfterView, *uuid.UUID, error) {
	var view *RestartAfterView
	var install *uuid.UUID
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var v RestartAfterView
		var by *string
		err := tx.QueryRow(ctx, `SELECT r.condition, r.mode, r.countdown_minutes, r.deadline_minutes, r.expires_after_minutes, r.state,
				r.message, r.restart_job_id, r.midway_job_id, r.server_confirmed, u.email, r.requested_label, r.requested_at
			FROM easypatch_install_restarts r LEFT JOIN users u ON u.id = r.requested_by WHERE r.install_job_id = $1`, job).
			Scan(&v.Condition, &v.Mode, &v.CountdownMinutes, &v.DeadlineMinutes, &v.ExpiresAfterMinutes, &v.State, &v.Message,
				&v.RestartJobID, &v.MidwayJobID, &v.Server, &by, &v.RequestedBy, &v.RequestedAt)
		switch {
		case err == nil:
			if by != nil {
				v.RequestedBy = *by
			}
			view = &v
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		err = tx.QueryRow(ctx, `SELECT install_job_id FROM easypatch_install_restarts WHERE restart_job_id = $1 OR midway_job_id = $1
			LIMIT 1`, job).Scan(&install)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return view, install, err
}

// forEach runs fn for 0…n-1, lookupParallel at a time.
func forEach(n int, fn func(i int)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, lookupParallel)
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			fn(i)
		}()
	}
	wg.Wait()
}
