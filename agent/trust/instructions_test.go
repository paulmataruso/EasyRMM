package trust

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func newLog(t *testing.T) (*InstructionLog, state.Store) {
	t.Helper()
	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	return &InstructionLog{Store: store, Now: func() time.Time { return now }}, store
}

var fp = strings.Repeat("ab", 16)

func TestInstructionLogIsWrittenAndSentOnlyWhenTheServerListsIt(t *testing.T) {
	l, store := newLog(t)
	l.Record(agentproto.InstructionJob, "run-1", fp)
	l.Record(agentproto.InstructionUpdate, "attempt-1", fp)
	// Not listed: nothing is sent, nothing is dropped.
	if r := l.Report(false); r != nil {
		t.Fatalf("sent to a server that does not list it: %+v", r)
	}
	r := l.Report(true)
	if r == nil || r.Acked != 0 || len(r.Entries) != 2 || r.Entries[0].Seq != 1 || r.Entries[1].Kind != agentproto.InstructionUpdate || !r.Entries[0].Valid() {
		t.Fatalf("report %+v", r)
	}
	// Written to disk: a restart reads it back.
	again := &InstructionLog{Store: store}
	if got := again.Report(true); len(got.Entries) != 2 {
		t.Fatalf("after a restart: %+v", got)
	}
	// An instruction the server repeats while it is open is one entry; the
	// same run signed by another key is another.
	l.Record(agentproto.InstructionJob, "run-1", fp)
	l.Record(agentproto.InstructionJob, "run-1", strings.Repeat("cd", 16))
	if got := l.Report(true); len(got.Entries) != 3 {
		t.Fatalf("dedupe: %+v", got)
	}
	// Dropped once acknowledged; the sequence goes on.
	l.Acknowledged(2)
	got := l.Report(true)
	if got.Acked != 2 || len(got.Entries) != 1 || got.Entries[0].Seq != 3 {
		t.Fatalf("after an acknowledgment: %+v", got)
	}
	// A lower or an impossible acknowledgment changes nothing.
	l.Acknowledged(1)
	l.Acknowledged(99)
	if g := l.Report(true); g.Acked != 2 || len(g.Entries) != 1 {
		t.Fatalf("a bad acknowledgment: %+v", g)
	}
	l.Record(agentproto.InstructionJob, "run-2", fp)
	if g := l.Report(true); g.Entries[len(g.Entries)-1].Seq != 4 {
		t.Fatalf("sequence: %+v", g)
	}
	// status shows the latest, acknowledged ones included.
	if latest := l.Latest(10); len(latest) != 4 {
		t.Errorf("latest %d", len(latest))
	}
}

func TestInstructionLogIsBounded(t *testing.T) {
	l, _ := newLog(t)
	for i := 0; i < agentproto.MaxInstructionLog+50; i++ {
		l.Record(agentproto.InstructionJob, "r"+strings.Repeat("x", 3)+string(rune('A'+i%26))+time.Duration(i).String(), fp)
	}
	l.mu.Lock()
	n := len(l.log.Entries)
	first := l.log.Entries[0].Seq
	l.mu.Unlock()
	if n != agentproto.MaxInstructionLog || first != 51 {
		t.Fatalf("kept %d from %d", n, first)
	}
	// One heartbeat carries at most a batch, oldest first.
	if r := l.Report(true); len(r.Entries) != agentproto.MaxInstructionBatch || r.Entries[0].Seq != 51 {
		t.Fatalf("batch %d from %d", len(r.Entries), r.Entries[0].Seq)
	}
	l.Record(agentproto.InstructionJob, strings.Repeat("i", 400), fp)
	for _, e := range l.Latest(1) {
		if len(e.ID) > 200 {
			t.Error("an unbounded ID")
		}
	}
}

func TestInstructionLogIsClearedByANewEnrollment(t *testing.T) {
	l, store := newLog(t)
	l.Record(agentproto.InstructionJob, "run-1", fp)
	l.Acknowledged(1)
	l.Record(agentproto.InstructionJob, "run-2", fp)
	if err := store.SaveKeyLog(state.KeyLog{Handled: []string{"s"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearKeyState(); err != nil {
		t.Fatal(err)
	}
	fresh := &InstructionLog{Store: store}
	if r := fresh.Report(true); r.Acked != 0 || len(r.Entries) != 0 {
		t.Fatalf("not cleared: %+v", r)
	}
	fresh.Record(agentproto.InstructionJob, "run-3", fp)
	if r := fresh.Report(true); r.Entries[0].Seq != 1 {
		t.Errorf("the sequence did not start again: %+v", r)
	}
	if kl := store.LoadKeyLog(); len(kl.Handled) != 0 {
		t.Error("the statement log stayed")
	}
	// Saving an enrollment clears both too.
	fresh.Record(agentproto.InstructionJob, "run-4", fp)
	if err := store.Approved(&state.Config{Server: "https://s", DeviceID: "d"}); err != nil {
		t.Fatal(err)
	}
	if r := (&InstructionLog{Store: store}).Report(true); len(r.Entries) != 0 {
		t.Errorf("Approved kept the log: %+v", r)
	}
}

func TestNilAndUnopenedLogsDoNothing(t *testing.T) {
	var l *InstructionLog
	l.Record("job", "x", fp)
	l.Acknowledged(1)
	if l.Report(true) != nil {
		t.Error("a nil log reported")
	}
	(&InstructionLog{}).Record("job", "x", fp)
	// A store that cannot write is logged, never fatal.
	bad := &InstructionLog{Store: failingInstr{}}
	bad.Record("job", "x", fp)
}

type failingInstr struct{}

func (failingInstr) LoadInstructionLog() state.InstructionLog { return state.InstructionLog{} }
func (failingInstr) SaveInstructionLog(state.InstructionLog) error {
	return errors.New("read-only")
}
