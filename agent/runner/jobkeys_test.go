package runner

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type fakeKeys struct {
	mu        sync.Mutex
	report    []agentproto.TrustedKey
	refusal   *agentproto.KeyRefusal
	answered  [][2]*agentproto.SignedKeyStatement
	levels    []int
	onAnswer  func()
	cleared   int
	callOrder *[]string
}

func (*fakeKeys) Caps() []string { return []string{agentproto.CapJobKeys} }
func (f *fakeKeys) Report() []agentproto.TrustedKey {
	return f.report
}
func (f *fakeKeys) Refusal() *agentproto.KeyRefusal { return f.refusal }
func (f *fakeKeys) Answered(level int, h, c *agentproto.SignedKeyStatement) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.levels = append(f.levels, level)
	f.answered = append(f.answered, [2]*agentproto.SignedKeyStatement{h, c})
	if f.callOrder != nil {
		*f.callOrder = append(*f.callOrder, "statements")
	}
	if f.onAnswer != nil {
		f.onAnswer()
	}
}

type fakeInstr struct {
	featureSeen []bool
	acks        []uint64
}

func (f *fakeInstr) Report(listed bool) *agentproto.InstructionLogReport {
	f.featureSeen = append(f.featureSeen, listed)
	if !listed {
		return nil
	}
	return &agentproto.InstructionLogReport{Acked: 3, Entries: []agentproto.LoggedInstruction{{Seq: 4}}}
}
func (f *fakeInstr) Acknowledged(ack uint64) { f.acks = append(f.acks, ack) }

// The report is sent by ADR-0009's rule: never in a process's first
// heartbeat, never after an answer of level 1, and from an answer of level 2
// on. The authorities go with it. The instruction log goes only when the last
// answer listed the feature, and is acknowledged from the answer.
func TestKeyReportFollowsTheProtocolRule(t *testing.T) {
	s := &server{}
	r := newRunner(t, s, nil)
	fk := &fakeKeys{report: []agentproto.TrustedKey{{Key: "k", Generation: 1}}, refusal: &agentproto.KeyRefusal{Statement: "handover", ID: "x", Reason: "r"}}
	fi := &fakeInstr{}
	r.JobKeys, r.Instructions, r.Authorities = fk, fi, []string{"abc"}
	ctx := context.Background()

	// The first heartbeat of the process: no answer seen yet.
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	first := s.heartbeats[0]
	if first.JobKeys != nil || first.Authorities != nil || first.KeyRefused != nil || first.InstructionLog != nil || slices.Contains(first.Caps, agentproto.CapJobKeys) {
		t.Fatalf("the first heartbeat carried the report: %+v", first)
	}
	// An answer of level 1 (no level at all): still none.
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if h := s.heartbeats[1]; h.JobKeys != nil || h.Authorities != nil {
		t.Fatalf("after a level 1 answer: %+v", h)
	}
	// A server of level 3 that lists the log and acknowledges 3.
	s.protocol = 3
	s.extra = `,"features":["instruction-log"],"instructionAck":3`
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	h := s.heartbeats[3]
	if len(h.JobKeys) != 1 || h.JobKeys[0].Generation != 1 || len(h.Authorities) != 1 || h.KeyRefused == nil || !slices.Contains(h.Caps, agentproto.CapJobKeys) {
		t.Fatalf("after a level 3 answer: %+v", h)
	}
	if h.InstructionLog == nil || h.InstructionLog.Acked != 3 || len(h.InstructionLog.Entries) != 1 {
		t.Fatalf("the log: %+v", h.InstructionLog)
	}
	// The one before it (the first after the answer that listed the feature
	// came in the same beat) did not carry the log yet.
	if s.heartbeats[2].InstructionLog != nil {
		t.Errorf("the log was sent before the feature was listed: %+v", s.heartbeats[2].InstructionLog)
	}
	if !slices.Equal(fi.acks, []uint64{3, 3}) {
		t.Errorf("acks %v", fi.acks)
	}
	// A server that stops listing the feature gets no log.
	s.extra = ``
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if last := s.heartbeats[len(s.heartbeats)-1]; last.InstructionLog != nil {
		t.Errorf("sent to a server that does not list it: %+v", last.InstructionLog)
	}
}

// The statements are handled before anything else in the answer: here, before
// the update instruction is looked at, and with the server's level.
func TestStatementsAreHandledBeforeTheInstructions(t *testing.T) {
	s := &server{protocol: 2}
	r := newRunner(t, s, nil)
	var order []string
	fk := &fakeKeys{callOrder: &order}
	r.JobKeys = fk
	u := &orderedUpdater{order: &order}
	r.Update = u
	s.update = `{"payload":"x","signature":"y"}`
	s.extra = `,"keyHandover":{"payload":"h","signature":"s"},"keyCutover":{"payload":"c","signature":"s"}`
	ctx := context.Background()
	if _, err := r.beat(ctx); err != nil && err != ErrRestart {
		t.Fatal(err)
	}
	if len(fk.answered) != 1 || fk.answered[0][0] == nil || fk.answered[0][1] == nil {
		t.Fatalf("statements %v", fk.answered)
	}
	if len(order) < 2 || order[0] != "statements" || !slices.Contains(order, "apply") {
		t.Fatalf("order %v", order)
	}
	if fk.levels[0] != 2 {
		t.Errorf("level %v", fk.levels)
	}
}

// orderedUpdater notes when Apply runs.
type orderedUpdater struct {
	order *[]string
}

func (*orderedUpdater) Report() *agentproto.UpdateReport { return nil }
func (*orderedUpdater) Reached()                         {}
func (*orderedUpdater) Unreached() bool                  { return false }
func (u *orderedUpdater) Apply(context.Context, *agentproto.SignedUpdate) bool {
	*u.order = append(*u.order, "apply")
	return false
}

// MeshAgent's downloads are logged as accepted instructions, named by the
// nonce of the request they answered, and signed by the key that verified.
func TestMeshDownloadsAreLogged(t *testing.T) {
	s := &server{available: true}
	m := &mesh{}
	r := newRunner(t, s, m)
	var mu sync.Mutex
	var got []string
	r.Record = func(kind, id, signer string) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, kind+"|"+signer)
		if id == "" {
			t.Error("a download without a nonce")
		}
	}
	if _, err := r.beat(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[0][:8] != "download" || len(got[0]) != len("download|")+32 {
		t.Fatalf("logged %v", got)
	}
}
