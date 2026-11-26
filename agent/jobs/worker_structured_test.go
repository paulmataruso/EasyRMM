//go:build unix

package jobs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func (h *harness) quickJob(run string) agentproto.SignedJob {
	sj, err := agentproto.SignJob(h.priv, agentproto.JobPayload{
		RunID: run, JobID: "44444444-4444-4444-8444-444444444444", DeviceID: device, Executor: agentproto.ExecutorBuiltin,
		Builtin: "registry", Lane: agentproto.LaneQuick, Input: []byte(`{"v":1}`), TimeoutSeconds: 60,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return sj
}

// TestQuickRunsTakeTheReservedSlotsWhileFourLongRunsHoldTheOthers: a
// registry read never waits behind an install or a hardening run.
func TestQuickRunsTakeTheReservedSlotsWhileFourLongRunsHoldTheOthers(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	started := map[string]bool{}
	h := newHarness(t, t.TempDir(), func(_ context.Context, p agentproto.JobPayload, _ string) agentproto.ResultRequest {
		mu.Lock()
		started[p.RunID] = true
		mu.Unlock()
		if p.Lane != agentproto.LaneQuick {
			<-release
		}
		code := 0
		return agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: &code}
	})
	defer close(release)
	longs := []string{
		"66666666-6666-4666-8666-666666666661", "66666666-6666-4666-8666-666666666662", "66666666-6666-4666-8666-666666666663",
		"66666666-6666-4666-8666-666666666664", "66666666-6666-4666-8666-666666666665",
	}
	var jobs []agentproto.SignedJob
	for _, r := range longs {
		jobs = append(jobs, h.job(r, "sleep"))
	}
	h.srv.polls <- &agentproto.PollResponse{Jobs: jobs}
	wait := func(cond func() bool, what string) {
		t.Helper()
		for i := 0; i < 500; i++ {
			mu.Lock()
			ok := cond()
			mu.Unlock()
			if ok {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal(what)
	}
	wait(func() bool { return len(started) == 4 }, "four long runs did not start")
	// The fifth waits for a slot; two quick runs do not.
	q1, q2 := "77777777-7777-4777-8777-777777777771", "77777777-7777-4777-8777-777777777772"
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.quickJob(q1), h.quickJob(q2)}}
	for range 2 {
		run, res := h.srv.result(t)
		if (run != q1 && run != q2) || res.Status != agentproto.RunSucceeded {
			t.Fatalf("%s %+v", run, res)
		}
	}
	mu.Lock()
	n := 0
	for _, r := range longs {
		if started[r] {
			n++
		}
	}
	mu.Unlock()
	if n != 4 {
		t.Errorf("%d long runs started, want 4", n)
	}
}

// TestJournalKeepsTheResultAcrossARestart, and the release before drops it.
func TestJournalKeepsTheResultAcrossARestart(t *testing.T) {
	dir := t.TempDir()
	j := journal{dir: filepath.Join(dir, "journal")}
	res := agentproto.ResultRequest{Status: agentproto.RunSucceeded, Result: "e30K", ResultCut: true, AgentVersion: "1.5.0"}
	if err := j.put(record{RunID: run1, JobID: "j", State: stateFinished, Result: &res}); err != nil {
		t.Fatal(err)
	}
	recs, errs := j.load()
	if len(errs) != 0 || len(recs) != 1 || recs[0].Result == nil || recs[0].Result.Result != "e30K" || !recs[0].Result.ResultCut || recs[0].Result.AgentVersion != "1.5.0" {
		t.Fatalf("%+v %v", recs, errs)
	}
	// The release before decodes the journal with plain json.Unmarshal into a
	// result without these fields: it reads the run and drops the result.
	type oldResult struct {
		Status string `json:"status"`
		Stdout string `json:"stdout"`
	}
	type oldRecord struct {
		RunID  string     `json:"runId"`
		State  string     `json:"state"`
		Result *oldResult `json:"result,omitempty"`
	}
	b, err := os.ReadFile(filepath.Join(j.dir, run1+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var old oldRecord
	if err := json.Unmarshal(b, &old); err != nil || old.Result == nil || old.Result.Status != agentproto.RunSucceeded {
		t.Errorf("the release before reads %+v: %v", old, err)
	}
}
