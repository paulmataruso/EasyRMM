// Package jobs runs the scripts the server sends (ADR-0017): it polls for
// signed jobs, checks them against the pinned server key, asks before
// starting each run, executes it, and reports the result, keeping a journal
// so that nothing runs twice and nothing that ran goes unreported.
package jobs

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Client is the part of the server client the worker uses.
type Client interface {
	// Poll sends the capabilities this build accepts (Accepts) and the
	// server keys it trusts (ADR-0057).
	Poll(ctx context.Context, accepts []string, keys []agentproto.TrustedKey) (*agentproto.PollResponse, error)
	Start(ctx context.Context, runID string) (*agentproto.StartResponse, error)
	Result(ctx context.Context, runID string, r agentproto.ResultRequest) error
}

// Worker polls for jobs and runs them.
type Worker struct {
	Client   Client
	DeviceID string
	// Dir holds the journal and the runs' working directories.
	Dir string
	Log *slog.Logger
	// Concurrency is how many scripts run at once (4), beside QuickSlots
	// for quick runs.
	Concurrency int
	// Retry timing, shortened by tests.
	MinRetry time.Duration // 5 s
	MaxRetry time.Duration // 5 min
	// Execute runs one job; tests replace it.
	Execute func(ctx context.Context, p agentproto.JobPayload, workRoot string) agentproto.ResultRequest
	// Live, when set, says the WebSocket channel is up (ADR-0059): the server
	// then pushes jobs, and the worker holds no long poll. It makes one
	// ordinary poll when PollNow is called. Changed signals that Live may
	// have changed, so a connection that ends sends the worker back to long
	// polls at once.
	Live    func() bool
	Changed <-chan struct{}

	// Finished, when set, is called after each run ends: a script may have
	// changed what the inventory shows (ADR-0028).
	Finished func()

	// Keys returns the server keys the agent trusts (ADR-0057), nil while
	// none is pinned: the worker then does not ask for jobs. Dropped returns
	// the keys a cut-over took away, to recognise a job signed with one; and
	// Report the keys a poll reports. All three are optional: SetKey gives a
	// worker one fixed key.
	Keys    func() agentproto.Keys
	Dropped func() agentproto.Keys
	Report  func() []agentproto.TrustedKey
	// Record is told of each job accepted (the instruction log); nil records
	// nothing.
	Record agentproto.InstructionRecorder

	fixed   atomic.Pointer[agentproto.Keys]
	keySet  chan struct{}
	dropMu  sync.Mutex
	dropped map[string]int
	once    sync.Once
	// paused holds new jobs back while the agent updates (ADR-0027).
	paused  atomic.Bool
	resumed chan struct{}
	// pollNow asks for one ordinary poll while the channel is live.
	pollNow chan struct{}

	mu      sync.Mutex
	active  map[string]*active
	pending map[string]agentproto.ResultRequest
	done    map[string]time.Time
	slots   chan struct{}
	// quick holds the slots kept for quick runs (ADR-0067): a registry read
	// never waits behind an install or a hardening run.
	quick chan struct{}
	wg    sync.WaitGroup
}

// active is a run the worker has accepted and not yet finished.
type active struct {
	cancel context.CancelCauseFunc
}

// QuickSlots is how many quick runs (JobPayload.Lane) may run beside the
// agent's other slots.
const QuickSlots = 2

func (w *Worker) init() {
	w.once.Do(func() {
		if w.Concurrency <= 0 {
			w.Concurrency = 4
		}
		if w.MinRetry == 0 {
			w.MinRetry = 5 * time.Second
		}
		if w.MaxRetry == 0 {
			w.MaxRetry = 5 * time.Minute
		}
		if w.Execute == nil {
			w.Execute = Execute
		}
		w.keySet = make(chan struct{}, 1)
		w.resumed = make(chan struct{}, 1)
		w.pollNow = make(chan struct{}, 1)
		w.active = map[string]*active{}
		w.pending = map[string]agentproto.ResultRequest{}
		w.done = map[string]time.Time{}
		w.slots = make(chan struct{}, w.Concurrency)
		w.quick = make(chan struct{}, QuickSlots)
	})
}

func (w *Worker) journal() journal { return journal{dir: filepath.Join(w.Dir, "journal")} }
func (w *Worker) workRoot() string { return filepath.Join(w.Dir, "work") }

// ClearWork deletes the runs' working directories, with whatever a stopped
// agent, or a script's own processes, left in them. RemoveAll deletes a
// link or junction found there, never what it points to.
func (w *Worker) ClearWork() error { return os.RemoveAll(w.workRoot()) }

// SetKey fixes the job-signing key of a worker that has no Keys function.
// Until a key is known the worker does not ask for jobs.
func (w *Worker) SetKey(encoded string) error {
	k, err := agentproto.DecodeKey(encoded)
	if err != nil {
		return err
	}
	w.fixed.Store(&agentproto.Keys{k})
	w.KeysChanged()
	return nil
}

// KeysChanged tells the worker that the keys the agent trusts may have
// changed: one that waited for a key asks for jobs now.
func (w *Worker) KeysChanged() {
	w.init()
	select {
	case w.keySet <- struct{}{}:
	default:
	}
}

// keys is the server keys the agent trusts now.
func (w *Worker) keys() agentproto.Keys {
	if w.Keys != nil {
		return w.Keys()
	}
	if f := w.fixed.Load(); f != nil {
		return *f
	}
	return nil
}

// DroppedAfter is how many deliveries of a run signed with a key the agent
// dropped are left alone: the next is reported failed (ADR-0057).
const DroppedAfter = 3

// droppedDelivery counts one more delivery of a run signed with a dropped key
// and returns the count. The map is bounded: a flood of run IDs cannot grow it.
func (w *Worker) droppedDelivery(runID string) int {
	w.dropMu.Lock()
	defer w.dropMu.Unlock()
	if w.dropped == nil || len(w.dropped) >= 256 {
		w.dropped = map[string]int{}
	}
	w.dropped[runID]++
	return w.dropped[runID]
}

// Pause stops the worker from asking for jobs and from starting delivered
// ones, which the server delivers again later; scripts already running
// go on. The agent pauses before it updates itself.
func (w *Worker) Pause() {
	w.init()
	w.paused.Store(true)
}

// Resume undoes Pause.
func (w *Worker) Resume() {
	w.init()
	w.paused.Store(false)
	select {
	case w.resumed <- struct{}{}:
	default:
	}
}

// Busy reports whether any job is being run or waits to start.
func (w *Worker) Busy() bool {
	w.init()
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.active) > 0
}

// Run polls for jobs until ctx ends, then waits for running scripts to
// stop and records their results for the next start.
func (w *Worker) Run(ctx context.Context) error {
	w.init()
	w.recover()
	failures := 0
	for ctx.Err() == nil {
		if len(w.keys()) == 0 {
			select {
			case <-ctx.Done():
			case <-w.keySet:
			}
			continue
		}
		if w.paused.Load() {
			select {
			case <-ctx.Done():
			case <-w.resumed:
			}
			continue
		}
		w.flush(ctx)
		if w.Live != nil && w.Live() && !w.waitLive(ctx) {
			continue
		}
		var report []agentproto.TrustedKey
		if w.Report != nil {
			report = w.Report()
		}
		resp, err := w.Client.Poll(ctx, Accepts(), report)
		switch {
		case err == nil:
			failures = 0
			for _, j := range resp.Jobs {
				w.accept(ctx, j)
			}
			for _, id := range resp.Cancel {
				w.cancel(ctx, id)
			}
		case ctx.Err() == nil:
			failures++
			wait := w.MinRetry << min(failures-1, 10)
			if client.Code(err) == "device_unknown" {
				wait = w.MaxRetry
			}
			w.Log.Warn("asking the server for jobs failed", "error", err, "attempt", failures)
			sleep(ctx, jitter(min(wait, w.MaxRetry)))
		}
	}
	w.wg.Wait()
	return nil
}

// recover settles what the journal recorded before a restart: runs that
// were started cannot be resumed and are reported as failed, finished runs
// are reported, and runs that never started are left for redelivery.
func (w *Worker) recover() {
	j := w.journal()
	recs, errs := j.load()
	for _, err := range errs {
		w.Log.Error("reading the job journal failed", "error", err)
	}
	for _, r := range recs {
		switch r.State {
		case stateStarted:
			res := agentproto.ResultRequest{Status: agentproto.RunFailed, Error: "The agent restarted while the script ran.", FinishedAt: time.Now().UTC()}
			r.State, r.Result = stateFinished, &res
			if err := j.put(r); err != nil {
				w.Log.Error("recording an interrupted run failed", "error", err, "run_id", r.RunID)
			}
			w.pending[r.RunID] = res
		case stateFinished:
			if r.Result != nil {
				w.pending[r.RunID] = *r.Result
				continue
			}
			_ = j.remove(r.RunID)
		default:
			_ = j.remove(r.RunID)
		}
	}
}

// accept checks a delivered job and starts working on it, unless it is a
// repeat of one already accepted.
func (w *Worker) accept(ctx context.Context, sj agentproto.SignedJob) {
	keys := w.keys()
	p, err := agentproto.VerifyJob(keys, sj, w.DeviceID, time.Now())
	if _, idErr := uuid.Parse(p.RunID); idErr != nil {
		w.Log.Error("refused a job without a valid run id", "error", err)
		return
	}
	if w.known(p.RunID) {
		return
	}
	if errors.Is(err, agentproto.ErrJobSignature) && w.Dropped != nil && p.DeviceID == w.DeviceID {
		if dropped := w.Dropped(); len(dropped) > 0 {
			if _, derr := agentproto.VerifyJob(dropped, sj, w.DeviceID, time.Now()); derr == nil {
				// Signed with a key the agent dropped at a cut-over: the
				// server signed it before it saw the agent's new report. It
				// is left alone, so that the redelivery, signed with the
				// newer key, runs; the third such delivery is reported
				// failed, so that a run never waits silently.
				if n := w.droppedDelivery(p.RunID); n < DroppedAfter {
					w.Log.Warn("left a job signed with a key this agent no longer trusts for its redelivery", "run_id", p.RunID, "delivery", n)
					return
				}
				w.Log.Error("refused a job signed with a key this agent no longer trusts", "run_id", p.RunID, "job_id", p.JobID)
				w.finish(ctx, record{RunID: p.RunID, JobID: p.JobID}, agentproto.ResultRequest{
					Status: agentproto.RunFailed, Error: "Signed with a key this agent no longer trusts. It was not run.", FinishedAt: time.Now().UTC(),
				})
				return
			}
		}
	}
	if err != nil {
		w.Log.Error("refused a job", "error", err, "run_id", p.RunID, "job_id", p.JobID)
		if errors.Is(err, agentproto.ErrJobExpired) || p.DeviceID != w.DeviceID {
			return // the server expires it; another device's run is not ours to report
		}
		msg := strings.TrimPrefix(err.Error(), "agentproto: ")
		w.finish(ctx, record{RunID: p.RunID, JobID: p.JobID}, agentproto.ResultRequest{
			Status: agentproto.RunFailed, Error: capitalize(msg) + ". It was not run.", FinishedAt: time.Now().UTC(),
		})
		return
	}
	if w.paused.Load() {
		return // delivered again once the agent has updated
	}
	rec := record{RunID: p.RunID, JobID: p.JobID, State: stateReceived, ExpiresAt: p.ExpiresAt}
	if err := w.journal().put(rec); err != nil {
		w.Log.Error("recording a job failed; it will be delivered again", "error", err, "run_id", p.RunID)
		return
	}
	if w.Record != nil {
		w.Record(agentproto.InstructionJob, p.RunID, keys.SignerOf(func(k ed25519.PublicKey) bool {
			_, err := agentproto.VerifyJob(k, sj, w.DeviceID, time.Now())
			return err == nil
		}))
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	w.mu.Lock()
	w.active[p.RunID] = &active{cancel: cancel}
	w.mu.Unlock()
	w.wg.Add(1)
	go w.run(runCtx, rec, p)
}

// known reports whether a run is already being handled or was just
// finished.
func (w *Worker) known(runID string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for id, at := range w.done {
		if time.Since(at) > time.Hour {
			delete(w.done, id)
		}
	}
	_, a := w.active[runID]
	_, p := w.pending[runID]
	_, d := w.done[runID]
	return a || p || d
}

// run waits for a free slot, asks the server to start, runs the script and
// reports how it ended.
func (w *Worker) run(ctx context.Context, rec record, p agentproto.JobPayload) {
	defer w.wg.Done()
	defer func() {
		w.mu.Lock()
		if a := w.active[rec.RunID]; a != nil {
			a.cancel(nil)
			delete(w.active, rec.RunID)
		}
		w.mu.Unlock()
	}()
	j := w.journal()
	// A quick run takes one of the slots kept for it, or an ordinary one
	// if that comes free first.
	release, ok := w.acquire(ctx, p.Lane == agentproto.LaneQuick)
	if !ok {
		_ = j.remove(rec.RunID) // the server delivers it again
		return
	}
	defer release()

	if !w.start(ctx, rec) {
		_ = j.remove(rec.RunID)
		w.markDone(rec.RunID)
		return
	}
	rec.State = stateStarted
	if err := j.put(rec); err != nil {
		// Without the record a restart could run it again; do not run it.
		w.Log.Error("recording a started job failed", "error", err, "run_id", rec.RunID)
		w.finish(ctx, rec, agentproto.ResultRequest{Status: agentproto.RunFailed,
			Error: "The agent could not record the job before running it: " + err.Error(), FinishedAt: time.Now().UTC()})
		return
	}
	w.Log.Info("running a job", "run_id", rec.RunID, "job_id", rec.JobID, "shell", p.Shell)
	res := w.Execute(ctx, p, w.workRoot())
	w.Log.Info("job finished", "run_id", rec.RunID, "status", res.Status)
	w.finish(ctx, rec, res)
}

// acquire waits for a slot. A quick run is first offered the slots kept for
// quick runs, and then either kind.
func (w *Worker) acquire(ctx context.Context, quick bool) (func(), bool) {
	if quick {
		select {
		case w.quick <- struct{}{}:
			return func() { <-w.quick }, true
		default:
		}
		select {
		case w.quick <- struct{}{}:
			return func() { <-w.quick }, true
		case w.slots <- struct{}{}:
			return func() { <-w.slots }, true
		case <-ctx.Done():
			return nil, false
		}
	}
	select {
	case w.slots <- struct{}{}:
		return func() { <-w.slots }, true
	case <-ctx.Done():
		return nil, false
	}
}

// start asks the server whether the run may start, retrying until it
// answers or the run expires.
func (w *Worker) start(ctx context.Context, rec record) bool {
	for attempt := 0; ; attempt++ {
		resp, err := w.Client.Start(ctx, rec.RunID)
		if err == nil {
			return resp.Proceed
		}
		if client.Code(err) == "run_not_found" || ctx.Err() != nil || !time.Now().Before(rec.ExpiresAt) {
			return false
		}
		w.Log.Warn("asking to start a job failed", "error", err, "run_id", rec.RunID)
		sleep(ctx, jitter(min(w.MinRetry<<min(attempt, 10), w.MaxRetry)))
	}
}

// finish records a result and reports it; a result the server did not
// receive is reported again later.
func (w *Worker) finish(ctx context.Context, rec record, res agentproto.ResultRequest) {
	rec.State, rec.Result = stateFinished, &res
	if err := w.journal().put(rec); err != nil {
		w.Log.Error("recording a job result failed", "error", err, "run_id", rec.RunID)
	}
	if w.Finished != nil {
		w.Finished()
	}
	w.mu.Lock()
	w.pending[rec.RunID] = res
	w.mu.Unlock()
	// Report even while the agent stops: the script has already run.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	w.report(rctx, rec.RunID, res)
}

// report sends a result, forgetting it once the server has it (or can
// never take it).
func (w *Worker) report(ctx context.Context, runID string, res agentproto.ResultRequest) {
	err := w.Client.Result(ctx, runID, res)
	switch code := client.Code(err); {
	case err == nil:
	case code == "run_not_found" || code == "result_invalid":
		w.Log.Error("the server refused a job result; dropping it", "error", err, "run_id", runID)
	default:
		w.Log.Warn("reporting a job result failed; will retry", "error", err, "run_id", runID)
		return
	}
	if err := w.journal().remove(runID); err != nil {
		w.Log.Warn("removing a reported job from the journal failed", "error", err, "run_id", runID)
	}
	w.mu.Lock()
	delete(w.pending, runID)
	w.mu.Unlock()
	w.markDone(runID)
}

// flush reports results that could not be reported before.
func (w *Worker) flush(ctx context.Context) {
	w.mu.Lock()
	pending := make(map[string]agentproto.ResultRequest, len(w.pending))
	for id, res := range w.pending {
		if _, running := w.active[id]; !running {
			pending[id] = res
		}
	}
	w.mu.Unlock()
	for id, res := range pending {
		if ctx.Err() != nil {
			return
		}
		w.report(ctx, id, res)
	}
}

// cancel stops a running run. A run the agent does not know is reported as
// canceled, so the server stops waiting for it.
func (w *Worker) cancel(ctx context.Context, runID string) {
	if _, err := uuid.Parse(runID); err != nil {
		return
	}
	w.mu.Lock()
	a := w.active[runID]
	_, pending := w.pending[runID]
	w.mu.Unlock()
	switch {
	case a != nil:
		w.Log.Info("stopping a job on request", "run_id", runID)
		a.cancel(errCanceled)
	case pending:
		// Finished already; its result is on its way.
	default:
		w.finish(ctx, record{RunID: runID}, agentproto.ResultRequest{
			Status: agentproto.RunCanceled, Error: "The agent was not running this job when asked to stop it.", FinishedAt: time.Now().UTC(),
		})
	}
}

func (w *Worker) markDone(runID string) {
	w.mu.Lock()
	w.done[runID] = time.Now()
	w.mu.Unlock()
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// jitter spreads d by ±10%.
func jitter(d time.Duration) time.Duration {
	spread := int64(d) / 5
	if spread <= 0 {
		return d
	}
	return d - time.Duration(spread/2) + time.Duration(rand.Int64N(spread)) //nolint:gosec // timing jitter, not security
}

// PollNow asks for one ordinary poll while the channel is live: a jobs wake,
// or a heartbeat answer that says jobs wait (ADR-0059). Without a live
// channel the worker is polling anyway.
func (w *Worker) PollNow() {
	w.init()
	select {
	case w.pollNow <- struct{}{}:
	default:
	}
}

// Deliver takes jobs and cancellations the server pushed over the channel,
// as it would take a poll's answer. The journal dedupes a run delivered by
// both. ctx is the agent's own, not the connection's.
func (w *Worker) Deliver(ctx context.Context, resp *agentproto.PollResponse) {
	w.init()
	if resp == nil || len(w.keys()) == 0 {
		return // the poll delivers them again
	}
	for _, j := range resp.Jobs {
		w.accept(ctx, j)
	}
	for _, id := range resp.Cancel {
		w.cancel(ctx, id)
	}
}

// waitLive waits while the channel is live and reports whether to poll now:
// true for a PollNow, false when ctx ended or the state may have changed.
func (w *Worker) waitLive(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-w.pollNow:
		return true
	case <-w.Changed:
		return false
	case <-time.After(time.Minute):
		return false
	}
}
