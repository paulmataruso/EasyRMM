package runner

import (
	"context"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type fakeTrust struct {
	report  *agentproto.TrustReport
	levels  []int
	answers []*agentproto.SignedTrust
	// reachedAtAnswer is the update's Reached count when each instruction
	// was handed over.
	u               *updater
	reachedAtAnswer []int
}

func (*fakeTrust) Caps() []string                    { return []string{agentproto.CapTrust} }
func (f *fakeTrust) Report() *agentproto.TrustReport { return f.report }
func (f *fakeTrust) Answered(_ context.Context, level int, s *agentproto.SignedTrust) {
	f.levels = append(f.levels, level)
	f.answers = append(f.answers, s)
	if f.u != nil {
		f.reachedAtAnswer = append(f.reachedAtAnswer, f.u.reached)
	}
}

// The capability and the report go only to a server of level 2 or higher; the
// answer's instruction goes to the trust agent with the level (ADR-0009).
func TestHeartbeatCarriesTheTrustCapabilityAndReport(t *testing.T) {
	s := &server{protocol: 3, trust: `{"payload":"p","signature":"s"}`}
	r := newRunner(t, s, nil)
	f := &fakeTrust{report: &agentproto.TrustReport{ID: "t1"}}
	r.Trust = f
	ctx := context.Background()

	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if len(s.heartbeats[0].Caps) != 0 || s.heartbeats[0].Trust != nil {
		t.Fatalf("a request to a server of unknown level carried %v, %+v", s.heartbeats[0].Caps, s.heartbeats[0].Trust)
	}
	if len(f.answers) != 1 || f.answers[0] == nil || f.answers[0].Payload != "p" || f.levels[0] != 3 {
		t.Fatalf("answers %+v, levels %v", f.answers, f.levels)
	}
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.heartbeats[1].Caps; len(got) != 1 || got[0] != agentproto.CapTrust {
		t.Fatalf("caps = %v", got)
	}
	if got := s.heartbeats[1].Trust; got == nil || got.ID != "t1" {
		t.Fatalf("report = %+v", got)
	}
	s.trust = ""
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if f.answers[2] != nil {
		t.Fatal("an absent instruction was passed on")
	}
}

// A server of level 1 gets neither: the agent behaves as it did before.
func TestNoTrustFieldsToALevelOneServer(t *testing.T) {
	s := &server{protocol: 1}
	r := newRunner(t, s, nil)
	r.Trust = &fakeTrust{report: &agentproto.TrustReport{ID: "t1"}}
	for range 2 {
		if _, err := r.beat(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for i, h := range s.heartbeats {
		if len(h.Caps) != 0 || h.Trust != nil {
			t.Errorf("heartbeat %d carried %v, %+v", i, h.Caps, h.Trust)
		}
	}
}

// A trust instruction is handled only after the heartbeat confirmed the
// running build, so a probation rollback cannot lose what it changed.
func TestTrustIsHandledAfterTheUpdateIsConfirmed(t *testing.T) {
	s := &server{protocol: 3, trust: `{"payload":"p","signature":"s"}`}
	r := newRunner(t, s, nil)
	u := &updater{}
	r.Update = u
	f := &fakeTrust{u: u}
	r.Trust = f
	if _, err := r.beat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.reachedAtAnswer) != 1 || f.reachedAtAnswer[0] != 1 {
		t.Errorf("the instruction was handled before the build was confirmed: %v", f.reachedAtAnswer)
	}
}
