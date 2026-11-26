package runner

import (
	"context"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type fakeEscrow struct {
	answers []*agentproto.SignedEscrowKey
	starts  int
}

func (*fakeEscrow) Caps() []string { return []string{agentproto.CapEscrow} }
func (f *fakeEscrow) Answered(s *agentproto.SignedEscrowKey) {
	f.answers = append(f.answers, s)
}
func (f *fakeEscrow) Start(context.Context) { f.starts++ }

// The heartbeat announces the capability only to a server of level 2 or
// higher, hands the answer's escrow key to the escrow agent and starts it.
func TestHeartbeatCarriesTheEscrowCapabilityAndKey(t *testing.T) {
	s := &server{protocol: 3, escrow: `{"payload":"p","signature":"s"}`}
	r := newRunner(t, s, nil)
	e := &fakeEscrow{}
	r.Escrow = e
	ctx := context.Background()

	// The first heartbeat does not know the server's level yet: no capability.
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if len(s.heartbeats[0].Caps) != 0 {
		t.Fatalf("a level-1 request carried caps: %v", s.heartbeats[0].Caps)
	}
	if len(e.answers) != 1 || e.answers[0] == nil || e.answers[0].Payload != "p" || e.starts != 1 {
		t.Fatalf("answers %+v, starts %d", e.answers, e.starts)
	}
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.heartbeats[1].Caps; len(got) != 1 || got[0] != agentproto.CapEscrow {
		t.Fatalf("caps = %v", got)
	}
	// A server that sends no key tells the escrow agent so.
	s.escrow = ""
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if e.answers[2] != nil {
		t.Fatal("an absent key was passed on")
	}
}
