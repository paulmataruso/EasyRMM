package move

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type sent struct {
	address string
	report  agentproto.MoveReport
}

type rig struct {
	t     *testing.T
	store state.Store
	cfg   *state.Config
	m     *Mover
	sent  []sent
	check []string
	fail  map[string]error
}

func newRig(t *testing.T) *rig {
	t.Helper()
	s, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := state.NewKey()
	cfg := &state.Config{Server: "https://old.example.com", DeviceID: "d1", EnrolledAt: time.Unix(1_800_000_000, 0).UTC(), MeshAgentMode: "child"}
	if err := s.Save(cfg, key); err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, store: s, cfg: cfg, fail: map[string]error{}}
	r.m = &Mover{
		Config: cfg, Store: s,
		Check: func(_ context.Context, a string) error {
			r.check = append(r.check, a)
			return r.fail[a]
		},
		Report: func(_ context.Context, a string, rep agentproto.MoveReport) error {
			r.sent = append(r.sent, sent{a, rep})
			return nil
		},
		Now: func() time.Time { return time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC) },
	}
	return r
}

func (r *rig) server() string {
	r.t.Helper()
	c, _, err := r.store.Load()
	if err != nil {
		r.t.Fatal(err)
	}
	return c.Server
}

func TestMoveChecksThenSwitchesAndReportsAtTheNewAddress(t *testing.T) {
	r := newRig(t)
	if err := r.m.Move(context.Background(), agentproto.MoveSetServer, "https://NEW.example.com/"); err != nil {
		t.Fatal(err)
	}
	if len(r.check) != 1 || r.check[0] != "https://new.example.com" {
		t.Errorf("checked %v", r.check)
	}
	if got := r.server(); got != "https://new.example.com" {
		t.Errorf("agent.json names %q", got)
	}
	if r.cfg.Server != "https://new.example.com" {
		t.Errorf("the running configuration names %q: a later save of it would undo the move", r.cfg.Server)
	}
	if p, ok := r.store.LoadAddresses().Previous(); !ok || p.Server != "https://old.example.com" || !p.At.Equal(r.m.Now()) {
		t.Errorf("previous: %+v", p)
	}
	if len(r.sent) != 1 || r.sent[0].address != "https://new.example.com" || !r.sent[0].report.Moved ||
		r.sent[0].report.From != "https://old.example.com" || r.sent[0].report.To != "https://new.example.com" || r.sent[0].report.Kind != agentproto.MoveSetServer {
		t.Errorf("reports: %+v", r.sent)
	}
}

func TestAFailedCheckLeavesTheAgentWhereItWasAndIsReportedThere(t *testing.T) {
	r := newRig(t)
	r.fail["https://new.example.com"] = agentproto.ErrAddressSignature
	err := r.m.Move(context.Background(), agentproto.MoveInstall, "https://new.example.com")
	if !errors.Is(err, agentproto.ErrAddressSignature) {
		t.Fatalf("error: %v", err)
	}
	if r.server() != "https://old.example.com" || len(r.store.LoadAddresses().Moved) != 0 {
		t.Error("a failed check changed the agent")
	}
	if len(r.sent) != 1 || r.sent[0].address != "https://old.example.com" || r.sent[0].report.Moved || r.sent[0].report.Error == "" || r.sent[0].report.Kind != agentproto.MoveInstall {
		t.Errorf("reports: %+v", r.sent)
	}
}

func TestMoveRefusesWhatIsNotAnHTTPSOriginOrWhereItIs(t *testing.T) {
	r := newRig(t)
	for _, to := range []string{"http://new.example.com", "http://127.0.0.1", "new.example.com", "https://new.example.com/x", ""} {
		if err := r.m.Move(context.Background(), agentproto.MoveSetServer, to); err == nil {
			t.Errorf("%q accepted", to)
		}
	}
	if err := r.m.Move(context.Background(), agentproto.MoveSetServer, "https://OLD.example.com/"); !errors.Is(err, ErrSame) {
		t.Errorf("the same address: %v", err)
	}
	if len(r.check) != 0 || len(r.sent) != 0 {
		t.Errorf("checked %v, reported %v", r.check, r.sent)
	}
}

func TestMoveWaitsForRunningWorkAndStopsWithItsContext(t *testing.T) {
	r := newRig(t)
	var busy atomic.Int32
	busy.Store(3)
	r.m.Busy = func() bool { return busy.Add(-1) >= 0 }
	r.m.Poll = time.Millisecond
	if err := r.m.Move(context.Background(), agentproto.MoveSetServer, "https://new.example.com"); err != nil {
		t.Fatal(err)
	}
	if busy.Load() >= 0 {
		t.Error("did not wait for the work to end")
	}

	r = newRig(t)
	r.m.Busy = func() bool { return true }
	r.m.Poll = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := r.m.Move(ctx, agentproto.MoveSetServer, "https://new.example.com"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("busy forever: %v", err)
	}
	if r.server() != "https://old.example.com" {
		t.Error("switched while work was running")
	}
}

func TestMoveFailsWhenTheAddressCannotBeSavedAndSaysSo(t *testing.T) {
	r := newRig(t)
	if err := os.Chmod(r.store.Dir(), 0o500); err != nil {
		t.Skip("cannot make the folder read-only here")
	}
	t.Cleanup(func() { _ = os.Chmod(r.store.Dir(), 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	if err := r.m.Move(context.Background(), agentproto.MoveSetServer, "https://new.example.com"); err == nil {
		t.Fatal("moved with nowhere to write")
	}
	if r.cfg.Server != "https://old.example.com" {
		t.Error("the running configuration changed without the file")
	}
	if len(r.sent) != 1 || r.sent[0].address != "https://old.example.com" || r.sent[0].report.Moved {
		t.Errorf("reports: %+v", r.sent)
	}
}

func TestFallbackGoesBackOnlyToTheAddressItMovedFromAndOnlyIfItConfirms(t *testing.T) {
	r := newRig(t)
	// Nowhere to go back to.
	if r.m.Fallback(context.Background()) || len(r.check) != 0 {
		t.Fatal("fell back with no previous address")
	}
	if err := r.m.Move(context.Background(), agentproto.MoveSetServer, "https://new.example.com"); err != nil {
		t.Fatal(err)
	}
	r.check, r.sent = nil, nil

	// The old address does not confirm (down, or held by someone else).
	r.fail["https://old.example.com"] = errors.New("connection refused")
	if r.m.Fallback(context.Background()) {
		t.Fatal("fell back to an address that did not confirm")
	}
	if r.server() != "https://new.example.com" {
		t.Error("a failed fallback changed the agent")
	}
	if len(r.sent) != 1 || r.sent[0].report.Kind != agentproto.MoveFallback || r.sent[0].report.Moved {
		t.Errorf("failure report: %+v", r.sent)
	}

	// It confirms: the agent goes back, and the address it left is the one it falls back to next.
	delete(r.fail, "https://old.example.com")
	r.sent = nil
	if !r.m.Fallback(context.Background()) {
		t.Fatal("did not fall back")
	}
	if r.server() != "https://old.example.com" {
		t.Errorf("agent.json names %q", r.server())
	}
	if p, _ := r.store.LoadAddresses().Previous(); p.Server != "https://new.example.com" {
		t.Errorf("previous: %+v", p)
	}
	if len(r.sent) != 1 || r.sent[0].address != "https://old.example.com" || !r.sent[0].report.Moved || r.sent[0].report.Kind != agentproto.MoveFallback {
		t.Errorf("reports: %+v", r.sent)
	}
}

func TestReportsAreBoundedAndOptional(t *testing.T) {
	r := newRig(t)
	r.m.Report = nil
	if err := r.m.Move(context.Background(), agentproto.MoveSetServer, "https://new.example.com"); err != nil {
		t.Fatal(err)
	}

	r = newRig(t)
	long := ""
	for range agentproto.MaxMoveError * 2 {
		long += "é"
	}
	r.fail["https://new.example.com"] = errors.New(long)
	_ = r.m.Move(context.Background(), agentproto.MoveSetServer, "https://new.example.com")
	if n := len([]rune(r.sent[0].report.Error)); n != agentproto.MaxMoveError {
		t.Errorf("the error report has %d runes", n)
	}

	// A report that cannot be made changes nothing about the move.
	r = newRig(t)
	r.m.Report = func(context.Context, string, agentproto.MoveReport) error { return errors.New("404") }
	if err := r.m.Move(context.Background(), agentproto.MoveSetServer, "https://new.example.com"); err != nil || r.server() != "https://new.example.com" {
		t.Errorf("a refused report undid the move: %v %s", err, r.server())
	}
}
