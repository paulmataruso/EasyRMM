package easypatch

import (
	"context"
	"errors"
	"fmt"
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
// minute, reads each install job it waits for: when the device's install
// jobs have all completed, it asks the engine to restart the device, once;
// when one waits for a restart to go on, it asks for that restart first. A
// failed, canceled or expired install never restarts its device; one the
// engine timed out is waited for, as the agent's late result can still
// complete it.
//
// Asking the engine for a restart is claimed in the database first, on the
// state the server read, so that one of EasyRMM's servers asks, and a claim
// a stopped server left behind is settled from the engine's own jobs before
// anything is asked again: a restart of EasyRMM's server neither loses a
// restart nor asks for one twice.

const (
	conditionAlways  = "Always"
	conditionPending = "OnlyIfPending"
	// claimStale is how long a claim may be in flight: longer than any call
	// to the engine takes.
	claimStale = 2 * time.Minute
	// claimSlack allows for the engine's clock when its jobs are looked up.
	claimSlack = time.Minute
	// restartWaitLimit is how long EasyRMM waits for an install to end, from
	// when it was to start: the engine expires an install still waiting for
	// a restart after 30 days (WaitingForRebootExpiryDays).
	restartWaitLimit = 40 * 24 * time.Hour
	// restartSweepBatch is the most installs one pass reads.
	restartSweepBatch = 500
	// lookupParallel is how many devices are read from the engine at once.
	lookupParallel = 8
	// maxMidway is how many restarts EasyRMM asks for while an install waits
	// for one to go on: one each time it waits again.
	maxMidway = 3
	// scheduledMargin is how soon a restart the device already has queued
	// must start to count as one right after the install.
	scheduledMargin = 5 * time.Minute
	// restartPassLimit bounds one pass of the sweep, and restartFailures is
	// how many failures of the engine in a row end it early.
	restartPassLimit = 45 * time.Second
	restartFailures  = 3
	// restartRetention is how long a finished restart is kept: as long as
	// the engine keeps a finished job by default (RetentionJobsDays, 180).
	restartRetention = 180 * 24 * time.Hour
	// sendLimit bounds what is sent to the engine on a request's behalf
	// and saved of it, once the request no longer bounds it.
	sendLimit = 2 * time.Minute
)

// What became of a restart after an install.
const (
	afterWaiting = "waiting"
	afterDone    = "done"
	afterSkipped = "skipped"
	afterFailed  = "failed"
)

// midwayMessage is what an install's restart says after a restart asked for
// while it waited for one.
const midwayMessage = "Restarted while the install waited for a restart; the install goes on after it."

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
	// MidwayJobID, the last of the MidwayCount asked for while it waited for
	// a restart to go on.
	RestartJobID *uuid.UUID `json:"restartJobId"`
	MidwayJobID  *uuid.UUID `json:"midwayJobId"`
	MidwayCount  int        `json:"midwayCount"`
	// InstallJobs counts the device's install jobs: more than one when its
	// updates were split, the restart waiting for them all.
	InstallJobs int `json:"installJobs"`
	// Server says the device was ticked by name as a server to restart.
	Server      bool      `json:"server"`
	RequestedBy string    `json:"requestedBy"`
	RequestedAt time.Time `json:"requestedAt"`
}

// detached is ctx for what must finish once started on a request's behalf,
// whatever becomes of the request: sending a batch to the engine and saving
// what it started.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), sendLimit)
}

// restartKeeper keeps the restart choice of each install, batch by batch, as
// soon as the engine has started it, so that no install it started is left
// without its restart.
type restartKeeper struct {
	s           *Service
	c           access.Caller
	o           RestartOptions
	confirm     []uuid.UUID
	scheduledAt *time.Time

	mu sync.Mutex
	n  int
}

// count is how many devices will restart.
func (k *restartKeeper) count() *int {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	n := k.n
	return &n
}

// keep saves the choice for each install of items the engine started; ctx
// is detached from the request. Nothing to keep without a choice.
func (k *restartKeeper) keep(ctx context.Context, devices []deviceRow, items []ActionItem) error {
	if k == nil {
		return nil
	}
	byID := map[uuid.UUID]deviceRow{}
	for _, d := range devices {
		byID[d.id] = d
	}
	var by *uuid.UUID
	if k.c.Actor.Type == audit.ActorUser && k.c.Actor.ID != uuid.Nil {
		id := k.c.Actor.ID
		by = &id
	}
	n := 0
	err := k.s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, it := range items {
			d, ok := byID[it.DeviceID]
			if !it.OK || it.JobID == nil || !ok || d.endpointID == nil || d.easyPatchOrg == nil {
				continue
			}
			jobs := it.JobIDs
			if len(jobs) == 0 {
				jobs = []uuid.UUID{*it.JobID}
			}
			tag, err := tx.Exec(ctx, `INSERT INTO easypatch_install_restarts (install_job_id, install_job_ids, device_id, endpoint_id,
					easypatch_org_id, condition, mode, countdown_minutes, deadline_minutes, expires_after_minutes, server_confirmed, requested_by,
					by_user, requested_label, requested_at, scheduled_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) ON CONFLICT (install_job_id) DO NOTHING`,
				*it.JobID, jobs, d.id, *d.endpointID, *d.easyPatchOrg, k.o.Condition, k.o.Mode, k.o.CountdownMinutes, k.o.DeadlineMinutes,
				k.o.ExpiresAfterMinutes, slices.Contains(k.confirm, d.id), by, by != nil, cut(k.c.Actor.Label, 255), k.s.now(), k.scheduledAt)
			if err != nil {
				return err
			}
			n += int(tag.RowsAffected())
		}
		return nil
	})
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.n += n
	k.mu.Unlock()
	return nil
}

// restartRow is an install EasyRMM restarts the device of afterwards.
type restartRow struct {
	job, device, endpoint, epOrg uuid.UUID
	// jobs are the device's install jobs, job among them.
	jobs        []uuid.UUID
	opts        RestartOptions
	server      bool
	by          *uuid.UUID
	byUser      bool
	label       string
	requestedAt time.Time
	scheduledAt *time.Time
	midway      *uuid.UUID
	midwayCount int
	claimedAt   *time.Time
	claimedFor  *string
}

// caller is who asked for the install, as the engine is told.
func (r restartRow) caller() access.Caller {
	a := audit.SystemActor(r.label)
	if r.by != nil {
		a = audit.Actor{Type: audit.ActorUser, ID: *r.by, Label: r.label}
	}
	return access.Caller{Scope: database.System, Actor: a}
}

// engineFailure is the engine failing to answer while an install's restart
// was moved on: enough of them in a row end a pass early.
type engineFailure struct{ err error }

func (e engineFailure) Error() string { return "the patching engine: " + e.err.Error() }
func (e engineFailure) Unwrap() error { return e.err }

// RunRestarts moves restarts after installs on every minute, until ctx
// ends. Each of EasyRMM's servers runs it, beside the patching loop rather
// than in it; the claims make one of them ask for each restart.
func (s *Service) RunRestarts(ctx context.Context) {
	t := time.NewTicker(s.restartEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.SweepRestarts(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("easypatch: restarts after installs", "err", err)
			}
		}
	}
}

// SweepRestarts restarts the devices whose install has finished, as the
// installs asked, and returns how many restarts it asked for. A pass takes
// at most restartPass, and ends early when the engine fails restartFailures
// times in a row: the next pass goes on.
func (s *Service) SweepRestarts(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, s.restartPass)
	defer cancel()
	r, cl, err := s.conn(ctx)
	if err != nil || r == nil {
		return 0, err
	}
	now := s.now()
	rows, err := s.waitingRestarts(ctx, now)
	if err != nil {
		return 0, err
	}
	asked, failures := 0, 0
	var errs []error
	for i, x := range rows {
		if ctx.Err() != nil {
			errs = append(errs, fmt.Errorf("the pass ran out of time with %d installs left for the next", len(rows)-i))
			break
		}
		ok, err := s.afterInstall(ctx, cl, x, now)
		if ok {
			asked++
		}
		if err == nil {
			failures = 0
			continue
		}
		errs = append(errs, err)
		if errors.As(err, new(engineFailure)) {
			if failures++; failures >= restartFailures {
				errs = append(errs, fmt.Errorf("the patching engine failed %d times in a row; %d installs left for the next pass",
					failures, len(rows)-i-1))
				break
			}
		} else {
			failures = 0
		}
	}
	if asked > 0 {
		s.fleet.clear()
	}
	return asked, errors.Join(errs...)
}

// waitingRestarts prunes the restarts finished more than restartRetention
// ago, and reads the installs still waited for, those read longest ago
// first.
func (s *Service) waitingRestarts(ctx context.Context, now time.Time) ([]restartRow, error) {
	var rows []restartRow
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM easypatch_install_restarts WHERE finished_at < $1`, now.Add(-restartRetention)); err != nil {
			return err
		}
		list, err := tx.Query(ctx, `SELECT install_job_id, install_job_ids, device_id, endpoint_id, easypatch_org_id, condition, mode,
				countdown_minutes, deadline_minutes, expires_after_minutes, server_confirmed, requested_by, by_user, requested_label, requested_at,
				scheduled_at, midway_job_id, midway_count, claimed_at, claimed_for
			FROM easypatch_install_restarts WHERE state = 'waiting' ORDER BY checked_at NULLS FIRST, requested_at LIMIT $1`, restartSweepBatch)
		if err != nil {
			return err
		}
		for list.Next() {
			var x restartRow
			if err := list.Scan(&x.job, &x.jobs, &x.device, &x.endpoint, &x.epOrg, &x.opts.Condition, &x.opts.Mode, &x.opts.CountdownMinutes,
				&x.opts.DeadlineMinutes, &x.opts.ExpiresAfterMinutes, &x.server, &x.by, &x.byUser, &x.label, &x.requestedAt, &x.scheduledAt,
				&x.midway, &x.midwayCount, &x.claimedAt, &x.claimedFor); err != nil {
				return err
			}
			rows = append(rows, x)
		}
		return list.Err()
	})
	return rows, err
}

// engineFailed notes that the engine failed while an install's restart was
// moved on: the install is read again at the next pass.
func (s *Service) engineFailed(ctx context.Context, x restartRow, err error) error {
	s.noteError(err)
	return errors.Join(engineFailure{err}, s.touchRestart(ctx, x, ""))
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
	start := x.requestedAt
	if x.scheduledAt != nil && x.scheduledAt.After(start) {
		start = *x.scheduledAt
	}
	if now.Sub(start) > restartWaitLimit {
		return false, s.finishRestart(ctx, x.job, afterSkipped, "The install did not end within 40 days of when it was to start, so the device was not restarted.", nil)
	}
	if x.byUser && x.by == nil {
		return false, s.finishRestart(ctx, x.job, afterSkipped, "The person who asked for the install was deleted, so the device was not restarted on their behalf.", nil)
	}
	d, err := s.restartDevice(ctx, x)
	if err != nil || d == nil {
		return false, err
	}
	rctx := s.as(ctx, x.caller(), RoleReadOnly, x.epOrg)
	jobs := make([]JobDetail, 0, len(x.jobs))
	for _, id := range x.jobs {
		j, err := cl.Job(rctx, id)
		switch {
		case IsStatus(err, http.StatusNotFound):
			return false, s.finishRestart(ctx, x.job, afterSkipped, "The patching engine no longer has the install, so the device was not restarted.", nil)
		case err != nil:
			return false, s.engineFailed(ctx, x, err)
		}
		jobs = append(jobs, j)
	}
	return s.moveOn(ctx, cl, x, *d, jobs, now)
}

// moveOn moves an install's restart on from its jobs as the engine has them.
func (s *Service) moveOn(ctx context.Context, cl *Client, x restartRow, d deviceRow, jobs []JobDetail, now time.Time) (bool, error) {
	var parked, ended *JobDetail
	going, timedOut, needed := false, false, false
	for i := range jobs {
		j := &jobs[i]
		needed = needed || j.Summary.RebootRequired
		switch st := j.Summary.Status; {
		case st == "Completed":
		case st == "WaitingForReboot":
			if parked == nil {
				parked = j
			}
		case st == "Failed" && j.Summary.TimedOut:
			// The engine fails a job whose agent stopped reporting, and the
			// agent's late result replaces that (MaintenanceTasks.cs, step
			// 3; JobTransitions.AgentMayTransition): it may yet complete.
			timedOut = true
		case st == "Failed" || st == statusCanceled || st == "Expired":
			if ended == nil {
				ended = j
			}
		default:
			going = true
		}
	}
	switch {
	case parked != nil:
		return s.midway(ctx, cl, x, d, *parked)
	case timedOut:
		start := x.requestedAt
		if x.scheduledAt != nil && x.scheduledAt.After(start) {
			start = *x.scheduledAt
		}
		return false, s.touchRestart(ctx, x, fmt.Sprintf("The patching engine timed out the install when its agent stopped reporting. "+
			"The agent's late result can still complete it, so EasyRMM waits for it until %s.", whenText(start.Add(restartWaitLimit))))
	case going:
		return false, s.touchRestart(ctx, x, "")
	case ended != nil:
		return false, s.finishRestart(ctx, x.job, afterSkipped, endedText(ended.Summary.Status, len(jobs)), nil)
	}
	return s.askRestart(ctx, cl, x, d, "final", needed, now)
}

// endedText says why an install that did not complete restarts nothing.
func endedText(status string, jobs int) string {
	what := map[string]string{statusCanceled: "was canceled", "Expired": "expired before it ran"}[status]
	if what == "" {
		what = "failed"
	}
	if jobs > 1 {
		return fmt.Sprintf("One of the install's %d jobs %s, so the device was not restarted.", jobs, what)
	}
	return "The install " + what + ", so the device was not restarted."
}

// whenText writes a time for a message.
func whenText(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// active says a job is still to run or running: the statuses the engine's
// duplicate guard covers (JobTransitions.DedupeStatuses).
func active(status string) bool {
	return slices.Contains([]string{"Queued", "Delivered", "Acknowledged", "Running", "WaitingForReboot"}, status)
}

// midway asks for a restart while an install waits for one to go on: once,
// and again each time it waits again after one, up to maxMidway.
func (s *Service) midway(ctx context.Context, cl *Client, x restartRow, d deviceRow, parked JobDetail) (bool, error) {
	if x.midway != nil {
		prev, err := cl.Job(s.as(ctx, x.caller(), RoleReadOnly, x.epOrg), *x.midway)
		reportedSince := parked.LastProgress != nil && prev.Summary.CompletedAt != nil && parked.LastProgress.After(*prev.Summary.CompletedAt)
		switch {
		case IsStatus(err, http.StatusNotFound):
		case err != nil:
			return false, s.engineFailed(ctx, x, err)
		case active(prev.Summary.Status):
			return false, s.touchRestart(ctx, x, midwayMessage)
		case prev.Summary.Status == "Completed" && !reportedSince:
			// The device restarted, and the install has not reported since:
			// it goes on at its agent's next report.
			return false, s.touchRestart(ctx, x, midwayMessage)
		}
	}
	if x.midwayCount >= maxMidway {
		return false, s.touchRestart(ctx, x, fmt.Sprintf("The install waits for a restart again. EasyRMM asked for %d while it waited, "+
			"and asks for no more: restart the device to let the install go on.", maxMidway))
	}
	return s.askRestart(ctx, cl, x, d, "midway", true, s.now())
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
func (s *Service) askRestart(ctx context.Context, cl *Client, x restartRow, d deviceRow, kind string, needed bool, now time.Time) (bool, error) {
	actx := s.as(ctx, x.caller(), RoleAdmin, x.epOrg)
	e, err := cl.Endpoint(actx, x.endpoint)
	switch {
	case IsStatus(err, http.StatusNotFound):
		return false, s.finishRestart(ctx, x.job, afterSkipped, "The patching engine no longer lists the device's endpoint, so it was not restarted.", nil)
	case err != nil:
		return false, s.engineFailed(ctx, x, err)
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
	claim, err := s.claimRestart(ctx, x, kind)
	if err != nil || claim == nil {
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
		return false, engineFailure{err}
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
	case item.Success && item.JobID != nil:
		return true, s.adoptRestart(ctx, x, d, kind, *item.JobID)
	case item.ErrorCode == "duplicate_job" && item.JobID != nil:
		return s.alreadyRestarting(ctx, cl, x, d, kind, *item.JobID, *claim, now)
	}
	return false, s.finishRestart(ctx, x.job, afterFailed, cut("The patching engine refused the restart: "+item.Message, 1000), nil)
}

// alreadyRestarting settles a restart the engine refused as a duplicate: the
// device already has one queued or running, whenever it is to start (the
// engine's duplicate guard keys every restart of an endpoint alike,
// JobService.CreateAsync). One that starts now, or within scheduledMargin,
// is this install's restart. One scheduled for later is someone else's
// choice: EasyRMM neither cancels it nor counts it as a restart right after
// the install, and says so; the install finishes when it runs.
func (s *Service) alreadyRestarting(ctx context.Context, cl *Client, x restartRow, d deviceRow, kind string, existing uuid.UUID,
	claim time.Time, now time.Time) (bool, error) {
	j, err := cl.Job(s.as(ctx, x.caller(), RoleReadOnly, x.epOrg), existing)
	switch {
	case IsStatus(err, http.StatusNotFound):
		// Gone meanwhile: asked for again at the next pass.
		return false, s.unclaim(ctx, x, claim, "")
	case err != nil:
		s.noteError(err)
		return false, errors.Join(engineFailure{err}, s.unclaim(ctx, x, claim, ""))
	case j.NotBefore == nil || !j.NotBefore.After(now.Add(scheduledMargin)):
		return true, s.adoptRestart(ctx, x, d, kind, existing)
	}
	at := whenText(*j.NotBefore)
	if kind == "midway" {
		return false, s.unclaim(ctx, x, claim, "The install waits for a restart, and one is already scheduled for "+at+
			", so EasyRMM did not ask for another: the install goes on after it.")
	}
	msg := "A restart was already scheduled for " + at + ", so EasyRMM did not ask for another: the device restarts then, which finishes the install."
	if err := s.finishRestart(ctx, x.job, afterSkipped, msg, &existing); err != nil {
		return false, err
	}
	return false, s.record(ctx, []audit.Event{{Actor: audit.SystemActor("patching"), Action: "patch.restart", OrganizationID: d.organizationID,
		SiteID: d.siteID, DeviceID: d.id, TargetType: "device", TargetID: d.id.String(), Outcome: audit.Failure,
		Details: map[string]any{"device": d.name, "endpointId": x.endpoint.String(), "afterInstall": x.job.String(), "when": afterText(x.opts.Condition),
			"reason": msg, "scheduledRestart": existing.String(), "scheduledAt": j.NotBefore.UTC().Format(time.RFC3339), "requestedBy": x.label}}})
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
		return false, engineFailure{epError(err)}
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
	return false, s.unclaim(ctx, x, *x.claimedAt, "")
}

// claimRestart claims asking for a restart, and returns the claim when this
// server has it. Only one server wins: the claim holds only while the
// install's restart is as this server read it (no claim, no final restart,
// as many midway restarts).
func (s *Service) claimRestart(ctx context.Context, x restartRow, kind string) (*time.Time, error) {
	now := s.now()
	var claimed bool
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE easypatch_install_restarts SET claimed_at = $2, claimed_for = $3, checked_at = $2
			WHERE install_job_id = $1 AND state = 'waiting' AND claimed_at IS NULL AND restart_job_id IS NULL AND midway_count = $4`,
			x.job, now, kind, x.midwayCount)
		claimed = tag.RowsAffected() == 1
		return err
	})
	if err != nil || !claimed {
		return nil, err
	}
	return &now, nil
}

// unclaim drops this server's claim, nothing having been asked of the
// engine, and says why when msg is set.
func (s *Service) unclaim(ctx context.Context, x restartRow, claim time.Time, msg string) error {
	return s.db.InTx(context.WithoutCancel(ctx), database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE easypatch_install_restarts SET claimed_at = NULL, claimed_for = NULL,
				message = CASE WHEN $3 = '' THEN message ELSE $3 END, checked_at = $4
			WHERE install_job_id = $1 AND claimed_at = $2`, x.job, claim, msg, s.now())
		return err
	})
}

// adoptRestart records the restart the engine started, and audits it.
func (s *Service) adoptRestart(ctx context.Context, x restartRow, d deviceRow, kind string, restart uuid.UUID) error {
	ctx = context.WithoutCancel(ctx)
	if kind == "midway" {
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE easypatch_install_restarts SET midway_job_id = $2, midway_count = midway_count + 1, claimed_at = NULL,
					claimed_for = NULL, checked_at = $3, message = $4
				WHERE install_job_id = $1 AND state = 'waiting'`, x.job, restart, s.now(), midwayMessage)
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

// touchRestart notes that an install was read and is still going, and what
// it waits for: msg, or what the restarts asked for while it waited say.
func (s *Service) touchRestart(ctx context.Context, x restartRow, msg string) error {
	if msg == "" && x.midwayCount > 0 {
		msg = midwayMessage
	}
	return s.db.InTx(context.WithoutCancel(ctx), database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE easypatch_install_restarts SET checked_at = $2, message = $3 WHERE install_job_id = $1 AND state = 'waiting'`,
			x.job, s.now(), cut(msg, 1000))
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
				r.message, r.restart_job_id, r.midway_job_id, r.midway_count, cardinality(r.install_job_ids), r.server_confirmed, u.email,
				r.requested_label, r.requested_at
			FROM easypatch_install_restarts r LEFT JOIN users u ON u.id = r.requested_by WHERE r.install_job_ids @> ARRAY[$1::uuid]`, job).
			Scan(&v.Condition, &v.Mode, &v.CountdownMinutes, &v.DeadlineMinutes, &v.ExpiresAfterMinutes, &v.State, &v.Message,
				&v.RestartJobID, &v.MidwayJobID, &v.MidwayCount, &v.InstallJobs, &v.Server, &by, &v.RequestedBy, &v.RequestedAt)
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
