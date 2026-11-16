//go:build unix

// The scripts here are sh scripts.

package jobs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

const device = "33333333-3333-4333-8333-333333333333"

// fakeServer plays the job API: it hands out queued polls, answers starts
// and records results.
type fakeServer struct {
	mu        sync.Mutex
	polls     chan *agentproto.PollResponse
	proceed   map[string]bool
	starts    map[string]int
	results   map[string]agentproto.ResultRequest
	failNext  int // results to fail before accepting
	resultErr error
	gotResult chan string
}

func newFakeServer() *fakeServer {
	return &fakeServer{
		polls: make(chan *agentproto.PollResponse, 16), proceed: map[string]bool{}, starts: map[string]int{},
		results: map[string]agentproto.ResultRequest{}, gotResult: make(chan string, 16),
	}
}

func (f *fakeServer) Poll(ctx context.Context) (*agentproto.PollResponse, error) {
	select {
	case p := <-f.polls:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeServer) Start(_ context.Context, run string) (*agentproto.StartResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts[run]++
	p, ok := f.proceed[run]
	return &agentproto.StartResponse{Proceed: !ok || p}, nil
}

func (f *fakeServer) Result(_ context.Context, run string, r agentproto.ResultRequest) error {
	f.mu.Lock()
	if f.failNext > 0 {
		f.failNext--
		f.mu.Unlock()
		return errors.New("connection refused")
	}
	if f.resultErr != nil {
		err := f.resultErr
		f.mu.Unlock()
		return err
	}
	f.results[run] = r
	f.mu.Unlock()
	f.gotResult <- run
	return nil
}

func (f *fakeServer) result(t *testing.T) (string, agentproto.ResultRequest) {
	t.Helper()
	select {
	case run := <-f.gotResult:
		f.mu.Lock()
		defer f.mu.Unlock()
		return run, f.results[run]
	case <-time.After(10 * time.Second):
		t.Fatal("no result reported")
		return "", agentproto.ResultRequest{}
	}
}

type harness struct {
	t      *testing.T
	srv    *fakeServer
	w      *Worker
	priv   ed25519.PrivateKey
	cancel context.CancelFunc
	done   chan struct{}
}

func newHarness(t *testing.T, dir string, exec func(context.Context, agentproto.JobPayload, string) agentproto.ResultRequest) *harness {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return newHarnessWithKey(t, dir, pub, priv, exec)
}

func newHarnessWithKey(t *testing.T, dir string, pub ed25519.PublicKey, priv ed25519.PrivateKey, exec func(context.Context, agentproto.JobPayload, string) agentproto.ResultRequest) *harness {
	h := &harness{t: t, srv: newFakeServer(), priv: priv, done: make(chan struct{})}
	h.w = &Worker{
		Client: h.srv, DeviceID: device, Dir: dir, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		MinRetry: 10 * time.Millisecond, MaxRetry: 50 * time.Millisecond, Execute: exec,
	}
	if err := h.w.SetKey(agentproto.EncodeKey(pub)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		_ = h.w.Run(ctx)
		close(h.done)
	}()
	t.Cleanup(h.stop)
	return h
}

func (h *harness) stop() {
	h.cancel()
	<-h.done
}

func (h *harness) job(run, script string) agentproto.SignedJob {
	sj, err := agentproto.SignJob(h.priv, agentproto.JobPayload{
		V: 1, RunID: run, JobID: "44444444-4444-4444-8444-444444444444", DeviceID: device, Shell: "sh", Script: script,
		Args: []string{}, TimeoutSeconds: 30, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return sj
}

func echoExec(_ context.Context, p agentproto.JobPayload, _ string) agentproto.ResultRequest {
	code := 0
	return agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: &code, Stdout: p.Script}
}

const (
	run1 = "55555555-5555-4555-8555-555555555551"
	run2 = "55555555-5555-4555-8555-555555555552"
	run3 = "55555555-5555-4555-8555-555555555553"
)

func TestWorkerRunsEachJobOnce(t *testing.T) {
	var mu sync.Mutex
	ran := map[string]int{}
	h := newHarness(t, t.TempDir(), func(ctx context.Context, p agentproto.JobPayload, root string) agentproto.ResultRequest {
		mu.Lock()
		ran[p.RunID]++
		mu.Unlock()
		return echoExec(ctx, p, root)
	})
	j := h.job(run1, "echo one")
	// Delivered twice (redelivery), run once.
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{j, j}}
	run, res := h.srv.result(t)
	if run != run1 || res.Status != agentproto.RunSucceeded || res.Stdout != "echo one" {
		t.Fatalf("%s %+v", run, res)
	}
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{j}}
	// A run the server says not to start is dropped.
	h.srv.mu.Lock()
	h.srv.proceed[run2] = false
	h.srv.mu.Unlock()
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.job(run2, "echo two")}}
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.job(run3, "echo three")}}
	if run, _ := h.srv.result(t); run != run3 {
		t.Fatalf("expected run3, got %s", run)
	}
	h.stop()
	mu.Lock()
	defer mu.Unlock()
	if ran[run1] != 1 || ran[run2] != 0 || ran[run3] != 1 {
		t.Errorf("runs %v", ran)
	}
	h.srv.mu.Lock()
	defer h.srv.mu.Unlock()
	if h.srv.starts[run2] != 1 {
		t.Errorf("starts %v", h.srv.starts)
	}
	// Nothing is left in the journal once results are reported.
	if entries, _ := os.ReadDir(filepath.Join(h.w.Dir, "journal")); len(entries) != 0 {
		t.Errorf("journal not empty: %d entries", len(entries))
	}
}

func TestWorkerSaysWhenARunEnds(t *testing.T) {
	ended := make(chan struct{}, 4)
	h := newHarness(t, t.TempDir(), echoExec)
	h.w.Finished = func() { ended <- struct{}{} }
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.job(run1, "apt-get install -y jq")}}
	if run, _ := h.srv.result(t); run != run1 {
		t.Fatalf("result for %s", run)
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("Finished was not called")
	}
}

func TestWorkerRefusesJobsItCannotTrust(t *testing.T) {
	h := newHarness(t, t.TempDir(), func(context.Context, agentproto.JobPayload, string) agentproto.ResultRequest {
		t.Error("an untrusted job ran")
		return agentproto.ResultRequest{}
	})
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := agentproto.SignJob(other, agentproto.JobPayload{
		V: 1, RunID: run1, JobID: "44444444-4444-4444-8444-444444444444", DeviceID: device, Shell: "sh", Script: "id",
		TimeoutSeconds: 5, ExpiresAt: time.Now().Add(time.Hour),
	})
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{forged}}
	run, res := h.srv.result(t)
	if run != run1 || res.Status != agentproto.RunFailed || !strings.Contains(res.Error, "signature does not verify") || !strings.HasSuffix(res.Error, "It was not run.") {
		t.Errorf("%s %+v", run, res)
	}
	// Another device's job and an expired job are not reported.
	otherDevice, _ := agentproto.SignJob(h.priv, agentproto.JobPayload{
		V: 1, RunID: run2, JobID: "j", DeviceID: "someone-else", Shell: "sh", Script: "id", TimeoutSeconds: 5, ExpiresAt: time.Now().Add(time.Hour),
	})
	expired, _ := agentproto.SignJob(h.priv, agentproto.JobPayload{
		V: 1, RunID: run3, JobID: "j", DeviceID: device, Shell: "sh", Script: "id", TimeoutSeconds: 5, ExpiresAt: time.Now().Add(-time.Minute),
	})
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{otherDevice, expired, {Payload: "junk"}}}
	select {
	case run := <-h.srv.gotResult:
		t.Errorf("reported %s", run)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestWorkerWaitsForTheKey(t *testing.T) {
	srv := newFakeServer()
	w := &Worker{Client: srv, DeviceID: device, Dir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Execute: echoExec}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = w.Run(ctx)
		close(done)
	}()
	srv.polls <- &agentproto.PollResponse{}
	time.Sleep(100 * time.Millisecond)
	if len(srv.polls) != 1 {
		t.Error("polled without a pinned key")
	}
	if err := w.SetKey("not a key"); err == nil {
		t.Error("accepted a bad key")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := w.SetKey(agentproto.EncodeKey(pub)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(srv.polls) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(srv.polls) != 0 {
		t.Error("did not poll once the key was set")
	}
	cancel()
	<-done
}

func TestWorkerStopsRunsOnRequest(t *testing.T) {
	started := make(chan struct{})
	h := newHarness(t, t.TempDir(), func(ctx context.Context, _ agentproto.JobPayload, _ string) agentproto.ResultRequest {
		close(started)
		<-ctx.Done()
		if errors.Is(context.Cause(ctx), errCanceled) {
			return agentproto.ResultRequest{Status: agentproto.RunCanceled, Error: "Stopped on request."}
		}
		return agentproto.ResultRequest{Status: agentproto.RunFailed}
	})
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.job(run1, "sleep 100")}}
	<-started
	h.srv.polls <- &agentproto.PollResponse{Cancel: []string{run1}}
	if run, res := h.srv.result(t); run != run1 || res.Status != agentproto.RunCanceled {
		t.Errorf("%s %+v", run, res)
	}
	// A run the agent does not know is reported as canceled.
	h.srv.polls <- &agentproto.PollResponse{Cancel: []string{run2, "not-a-uuid"}}
	if run, res := h.srv.result(t); run != run2 || res.Status != agentproto.RunCanceled || !strings.Contains(res.Error, "not running") {
		t.Errorf("%s %+v", run, res)
	}
}

func TestWorkerReportsAgainAndRecoversAfterARestart(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Results the server does not take are kept and sent with a later poll.
	h := newHarnessWithKey(t, dir, pub, priv, echoExec)
	h.srv.mu.Lock()
	h.srv.failNext = 1
	h.srv.mu.Unlock()
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.job(run1, "echo kept")}}
	time.Sleep(100 * time.Millisecond)
	h.srv.polls <- &agentproto.PollResponse{}
	if run, res := h.srv.result(t); run != run1 || res.Stdout != "echo kept" {
		t.Errorf("%s %+v", run, res)
	}
	h.stop()

	// A journal left by an agent that stopped mid-run, and one with an
	// unreported result.
	j := journal{dir: filepath.Join(dir, "journal")}
	finished := agentproto.ResultRequest{Status: agentproto.RunSucceeded, Stdout: "earlier"}
	for _, r := range []record{
		{RunID: run1, JobID: "j", State: stateStarted},
		{RunID: run2, JobID: "j", State: stateFinished, Result: &finished},
		{RunID: run3, JobID: "j", State: stateReceived},
	} {
		if err := j.put(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(j.dir, "66666666-6666-4666-8666-666666666666.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	h = newHarnessWithKey(t, dir, pub, priv, echoExec)
	h.srv.polls <- &agentproto.PollResponse{}
	got := map[string]agentproto.ResultRequest{}
	for range 2 {
		run, res := h.srv.result(t)
		got[run] = res
	}
	if got[run1].Status != agentproto.RunFailed || got[run1].Error != "The agent restarted while the script ran." {
		t.Errorf("interrupted run %+v", got[run1])
	}
	if got[run2].Stdout != "earlier" {
		t.Errorf("unreported result %+v", got[run2])
	}
	// The received-only run is left for redelivery: it runs when it comes again.
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.job(run3, "echo again")}}
	if run, res := h.srv.result(t); run != run3 || res.Stdout != "echo again" {
		t.Errorf("%s %+v", run, res)
	}
}

func TestWorkerDropsResultsTheServerRefuses(t *testing.T) {
	h := newHarness(t, t.TempDir(), echoExec)
	h.srv.mu.Lock()
	h.srv.resultErr = &client.Error{Status: 404, Code: "run_not_found"}
	h.srv.mu.Unlock()
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.job(run1, "echo x")}}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.w.mu.Lock()
		n := len(h.w.pending) + len(h.w.active)
		_, done := h.w.done[run1]
		h.w.mu.Unlock()
		if n == 0 && done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("refused result kept")
}

func TestJournalRefusesStrangeRunIDs(t *testing.T) {
	j := journal{dir: t.TempDir()}
	if err := j.put(record{RunID: "../../etc/passwd"}); err == nil {
		t.Error("accepted a path as a run id")
	}
	if err := j.remove("../x"); err == nil {
		t.Error("removed by path")
	}
	if recs, errs := (journal{dir: filepath.Join(j.dir, "missing")}).load(); recs != nil || errs != nil {
		t.Error("a missing journal is empty")
	}
}

func TestWorkerPausesForUpdates(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	ran := map[string]int{}
	h := newHarness(t, t.TempDir(), func(ctx context.Context, p agentproto.JobPayload, root string) agentproto.ResultRequest {
		mu.Lock()
		ran[p.RunID]++
		mu.Unlock()
		if p.RunID == run1 {
			<-release
		}
		return echoExec(ctx, p, root)
	})
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting until %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if h.w.Busy() {
		t.Fatal("busy without jobs")
	}
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.job(run1, "long")}}
	waitFor("the job runs", h.w.Busy)

	// Paused, the running job finishes; a delivered one does not start.
	h.w.Pause()
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.job(run2, "two")}}
	close(release)
	if run, _ := h.srv.result(t); run != run1 {
		t.Fatalf("result of %s", run)
	}
	waitFor("the worker is idle", func() bool { return !h.w.Busy() })
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if ran[run2] != 0 {
		t.Error("started a job while paused")
	}
	mu.Unlock()

	// Resumed, the job delivered again runs.
	h.w.Resume()
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.job(run2, "two")}}
	if run, _ := h.srv.result(t); run != run2 {
		t.Fatalf("result of %s", run)
	}
	mu.Lock()
	defer mu.Unlock()
	if ran[run2] != 1 {
		t.Errorf("runs %v", ran)
	}
}
