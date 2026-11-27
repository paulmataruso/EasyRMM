//go:build unix

package jobs

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type recorder struct {
	mu   sync.Mutex
	list []string
}

func (r *recorder) record(kind, id, signer string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.list = append(r.list, kind+" "+id+" "+signer)
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.list...)
}

// An agent that trusts the new key and has dropped the old one: a job the
// server signed with the old key before it saw the agent's report is left
// alone twice and reported failed the third time (ADR-0057). A job signed with
// a key the agent never trusted fails at once. A job with a trusted key is
// run, and logged with the key that signed it.
func TestWorkerAndDroppedKeys(t *testing.T) {
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	rec := &recorder{}
	h := newHarnessWithKey(t, t.TempDir(), newPub, newPriv, echoExec)
	h.w.Dropped = func() agentproto.Keys { return agentproto.Keys{oldPub} }
	h.w.Record = rec.record
	_ = oldPriv
	signed := func(key ed25519.PrivateKey, run string) agentproto.SignedJob {
		h.priv = key
		return h.job(run, "echo "+run[len(run)-1:])
	}

	// Dropped key: two deliveries are ignored, no result, nothing journaled or logged.
	old := signed(oldPriv, run1)
	for i := 0; i < DroppedAfter-1; i++ {
		h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{old}}
	}
	// A job signed with the trusted key goes through meanwhile.
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{signed(newPriv, run2)}}
	if run, res := h.srv.result(t); run != run2 || res.Status != agentproto.RunSucceeded {
		t.Fatalf("%s %+v", run, res)
	}
	h.srv.mu.Lock()
	_, early := h.srv.results[run1]
	h.srv.mu.Unlock()
	if early {
		t.Fatal("a job signed with a dropped key was reported at the first deliveries")
	}
	// The third delivery is reported failed.
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{old}}
	run, res := h.srv.result(t)
	if run != run1 || res.Status != agentproto.RunFailed || !strings.Contains(res.Error, "no longer trusts") {
		t.Fatalf("third delivery: %s %+v", run, res)
	}
	// A key the agent never trusted: failed at once.
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{signed(strangerPriv, run3)}}
	run, res = h.srv.result(t)
	if run != run3 || res.Status != agentproto.RunFailed || strings.Contains(res.Error, "no longer trusts") {
		t.Fatalf("a stranger: %s %+v", run, res)
	}
	h.stop()
	// Only the job that was accepted is in the log, with its signer.
	got := rec.all()
	want := agentproto.InstructionJob + " " + run2 + " " + agentproto.Fingerprint(newPub)
	if len(got) != 1 || got[0] != want {
		t.Errorf("log %q, want %q", got, want)
	}
}

// The worker reads the keys it trusts when it checks a job, so a hand-over
// takes effect without a restart, and its poll reports them.
func TestWorkerReadsTheKeysItTrustsNow(t *testing.T) {
	aPub, aPriv, _ := ed25519.GenerateKey(rand.Reader)
	bPub, bPriv, _ := ed25519.GenerateKey(rand.Reader)
	var mu sync.Mutex
	keys := agentproto.Keys{aPub}
	h := newHarnessWithKey(t, t.TempDir(), aPub, aPriv, echoExec)
	h.w.Keys = func() agentproto.Keys { mu.Lock(); defer mu.Unlock(); return keys }
	h.w.Report = func() []agentproto.TrustedKey { return []agentproto.TrustedKey{{Key: agentproto.EncodeKey(aPub), Generation: 1}} }
	h.priv = bPriv
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.job(run1, "echo b")}}
	if _, res := h.srv.result(t); res.Status != agentproto.RunFailed {
		t.Fatalf("a key not yet trusted ran a job: %+v", res)
	}
	mu.Lock()
	keys = agentproto.Keys{aPub, bPub}
	mu.Unlock()
	h.srv.polls <- &agentproto.PollResponse{Jobs: []agentproto.SignedJob{h.job(run2, "echo b")}}
	if run, res := h.srv.result(t); run != run2 || res.Status != agentproto.RunSucceeded {
		t.Fatalf("after the hand-over: %s %+v", run, res)
	}
	h.stop()
}

func TestDroppedDeliveriesAreBounded(t *testing.T) {
	w := &Worker{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for i := 0; i < 1000; i++ {
		w.droppedDelivery(time.Duration(i).String())
	}
	w.dropMu.Lock()
	n := len(w.dropped)
	w.dropMu.Unlock()
	if n > 256 {
		t.Errorf("%d runs counted", n)
	}
}
