package runner

import (
	"context"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type fakeDef struct {
	reconciles int
	next       agentproto.DefenderReport
}

func (f *fakeDef) Reconcile(context.Context) *agentproto.DefenderReport {
	f.reconciles++
	r := f.next
	return &r
}
func (*fakeDef) TakeEvents() []agentproto.DefenderEvent   { return nil }
func (*fakeDef) RestoreEvents([]agentproto.DefenderEvent) {}

type fakeInstalled struct{ due []*agentproto.InstalledFiles }

func (f *fakeInstalled) Due(context.Context) *agentproto.InstalledFiles {
	if len(f.due) == 0 {
		return nil
	}
	x := f.due[0]
	f.due = f.due[1:]
	return x
}

func TestNothingRunsUntilTheServerAllows(t *testing.T) {
	d := &fakeDef{next: agentproto.DefenderReport{State: agentproto.DefenderEffective}}
	i := &fakeInstalled{due: []*agentproto.InstalledFiles{{AgentVersion: "v1"}}}
	r := &Runner{Defender: d, Installed: i}
	var req agentproto.HeartbeatRequest
	r.defendRequest(context.Background(), &req)
	if d.reconciles != 0 || req.Defender != nil || req.InstalledFiles != nil || len(i.due) != 1 {
		t.Fatal("the agent acted on Defender before the server allowed it")
	}
	r.defendAnswered(&agentproto.DefenderPolicy{Enabled: false})
	r.defendRequest(context.Background(), &req)
	if d.reconciles != 0 || req.Defender != nil || req.InstalledFiles != nil {
		t.Fatal("the agent acted where the server said no")
	}
	r.defendAnswered(nil) // an older server
	r.defendRequest(context.Background(), &req)
	if d.reconciles != 0 {
		t.Fatal("an older server's silence means no")
	}
}

func TestReportIsSentOnceThenOnlyOnChangeAndInstalledHashesRideAlong(t *testing.T) {
	d := &fakeDef{next: agentproto.DefenderReport{State: agentproto.DefenderEffective, Events: []agentproto.DefenderEvent{{Kind: "add", Path: "x"}}}}
	i := &fakeInstalled{due: []*agentproto.InstalledFiles{{AgentVersion: "v1"}, {AgentVersion: "v2"}}}
	r := &Runner{Defender: d, Installed: i}
	ctx := context.Background()
	r.defendAnswered(&agentproto.DefenderPolicy{Enabled: true})

	var a agentproto.HeartbeatRequest
	r.defendRequest(ctx, &a)
	if a.Defender == nil || len(a.Defender.Events) != 1 || a.InstalledFiles == nil || a.InstalledFiles.AgentVersion != "v1" {
		t.Fatalf("first request: %+v", a)
	}
	// The heartbeat did not get through: the same report, with its events, again.
	var b agentproto.HeartbeatRequest
	r.defendRequest(ctx, &b)
	if b.Defender == nil || len(b.Defender.Events) != 1 || b.InstalledFiles == nil || b.InstalledFiles.AgentVersion != "v2" {
		t.Fatalf("after a failure: %+v", b)
	}
	// It got through: nothing is sent again, and no new reconcile yet.
	r.defendAnswered(&agentproto.DefenderPolicy{Enabled: true})
	var c agentproto.HeartbeatRequest
	r.defendRequest(ctx, &c)
	if c.Defender != nil || c.InstalledFiles != nil || d.reconciles != 1 {
		t.Fatalf("a settled state is not sent again: %+v (%d reconciles)", c, d.reconciles)
	}
	// An hour later the state is looked at again, and a change is sent.
	r.defend.last = r.defend.last.Add(-defenderEvery)
	d.next = agentproto.DefenderReport{State: agentproto.DefenderNotLocked, Reason: "a folder"}
	var e agentproto.HeartbeatRequest
	r.defendRequest(ctx, &e)
	if e.Defender == nil || e.Defender.State != agentproto.DefenderNotLocked || d.reconciles != 2 {
		t.Fatalf("a changed state is sent: %+v", e)
	}
	// The same state again is not.
	r.defendAnswered(&agentproto.DefenderPolicy{Enabled: true})
	r.defend.last = r.defend.last.Add(-defenderEvery)
	var f agentproto.HeartbeatRequest
	d.next.Events = nil
	r.defendRequest(ctx, &f)
	if f.Defender != nil {
		t.Fatal("an unchanged state was sent again")
	}
}
