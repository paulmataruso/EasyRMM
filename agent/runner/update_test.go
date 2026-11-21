package runner

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// updater records what the loop tells it.
type updater struct {
	report             *agentproto.UpdateReport
	reached, unreached int
	undo, restart      bool
	applied            []*agentproto.SignedUpdate
}

func (u *updater) Report() *agentproto.UpdateReport { return u.report }
func (u *updater) Reached()                         { u.reached++ }
func (u *updater) Unreached() bool                  { u.unreached++; return u.undo }
func (u *updater) Apply(_ context.Context, su *agentproto.SignedUpdate) bool {
	u.applied = append(u.applied, su)
	return su != nil && u.restart
}

func TestBeatUpdates(t *testing.T) {
	s := &server{}
	r := newRunner(t, s, nil)
	u := &updater{report: &agentproto.UpdateReport{ID: "a1", Error: "boom"}}
	r.Update = u
	ctx := context.Background()

	// A failure is reported with the heartbeat; an answer without an
	// instruction still reaches Apply, as nil.
	if _, err := r.beat(ctx); err != nil {
		t.Fatal("restart without an update")
	}
	if got := s.heartbeats[0].Update; got == nil || got.ID != "a1" || got.Error != "boom" {
		t.Errorf("reported %+v", got)
	}
	if u.reached != 1 || len(u.applied) != 1 || u.applied[0] != nil {
		t.Errorf("reached %d, applied %v", u.reached, u.applied)
	}

	// An instruction is handed over; a build in place restarts the agent.
	s.update = `{"payload":"cA==","signature":"cw=="}`
	u.report, u.restart = nil, true
	if _, err := r.beat(ctx); !errors.Is(err, ErrRestart) {
		t.Fatal("no restart after the update")
	}
	if got := u.applied[1]; got == nil || got.Payload != "cA==" || got.Signature != "cw==" {
		t.Errorf("applied %+v", got)
	}
	if s.heartbeats[1].Update != nil {
		t.Errorf("reported %+v", s.heartbeats[1].Update)
	}
	if err := r.Run(ctx); !errors.Is(err, ErrRestart) {
		t.Errorf("Run = %v", err)
	}

	// A failed heartbeat may undo a new build on probation.
	s.status, s.code = http.StatusBadGateway, "x"
	if _, err := r.beat(ctx); err != nil || u.unreached != 1 {
		t.Errorf("err %v, unreached %d", err, u.unreached)
	}
	u.undo = true
	if _, err := r.beat(ctx); !errors.Is(err, ErrRestart) {
		t.Error("no restart after undoing the update")
	}
}

// easyPatch records what the loop tells the EasyPatch installer.
type easyPatch struct {
	status  *agentproto.EasyPatchInstallStatus
	started []*agentproto.SignedEasyPatchInstall
}

func (e *easyPatch) Status() *agentproto.EasyPatchInstallStatus { return e.status }
func (e *easyPatch) Start(_ context.Context, s *agentproto.SignedEasyPatchInstall) {
	e.started = append(e.started, s)
}

func TestBeatEasyPatch(t *testing.T) {
	s := &server{}
	r := newRunner(t, s, nil)
	ep := &easyPatch{status: &agentproto.EasyPatchInstallStatus{Busy: "b1", Last: &agentproto.EasyPatchInstallReport{ID: "a0", OK: true}}}
	r.EasyPatch = ep
	ctx := context.Background()
	// The status goes with every heartbeat; an answer without an
	// instruction still reaches Start, as nil.
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.heartbeats[0].EasyPatch; got == nil || got.Busy != "b1" || got.Last == nil || got.Last.ID != "a0" || !got.Last.OK {
		t.Errorf("reported %+v", got)
	}
	if len(ep.started) != 1 || ep.started[0] != nil {
		t.Errorf("started %v", ep.started)
	}
	s.easyPatch = `{"payload":"cA==","signature":"cw=="}`
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ep.started[1]; got == nil || got.Payload != "cA==" || got.Signature != "cw==" {
		t.Errorf("started %+v", got)
	}
	// Without an installer the heartbeat says nothing about EasyPatch.
	r.EasyPatch = nil
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.heartbeats[2].EasyPatch; got != nil {
		t.Errorf("reported %+v without an installer", got)
	}
}
