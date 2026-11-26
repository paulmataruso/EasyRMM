//go:build integration

package agentchannel_test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agentchannel"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

var fastTiming = agentchannel.Timing{Tick: 150 * time.Millisecond, Sweep: time.Hour, ContradictFor: 300 * time.Millisecond}

func wake() agentproto.ChannelMessage {
	return agentproto.ChannelMessage{Type: agentproto.TypeWake, What: agentproto.WakeCheckin, Reason: "settings"}
}

// A connection is trusted only once a signed heartbeat names it. The
// upgrade here was held back and replayed by someone on the path: it opens
// first, and the real agent's own use of the same request is refused.
func TestReplayedUpgradeNeverConfirms(t *testing.T) {
	f := newFixture(t, fixtureOpts{timing: fastTiming})
	d := f.device(f.orgA)
	run := f.queueRun(d)

	// The request was signed two minutes ago and kept back.
	held := d.header(time.Now().Add(-2 * time.Minute))
	attacker, err := f.dialWith(d, held, []string{agentproto.ChannelSubprotocol})
	if err != nil {
		t.Fatalf("the replayed upgrade: %v", err)
	}
	if attacker.hello.Nonce == "" {
		t.Error("hello does not repeat the request's nonce")
	}
	if r, ok := func() (*refusal, bool) {
		_, err := f.dialWith(d, held, []string{agentproto.ChannelSubprotocol})
		r := asRefusal(err)
		return r, r != nil
	}(); !ok || r.Status != 401 || r.Code != "replayed" {
		t.Fatalf("the real agent's use of the same request: %+v", r)
	}

	// Nothing reaches a pending connection: no push, no claim, nothing sent.
	if f.hub.Push(d.id, wake()) {
		t.Error("Push reached a pending connection")
	}
	f.hub.Kick(d.id)
	f.hub.Sweep()
	attacker.quiet(500 * time.Millisecond)
	if n := f.claimCount(d.id); n != 0 || f.runStatus(run) != "queued" {
		t.Fatalf("claims for a pending connection: %d, run %s", n, f.runStatus(run))
	}

	// The real agent connects with a fresh request: pending too, and the
	// replayed one, older, is closed.
	real := f.dial(d)
	if m, _ := attacker.ends(2 * time.Second); m == nil || m.Reason != agentproto.ClosingReplaced {
		t.Errorf("the replayed connection was not told it was replaced: %+v", m)
	}
	f.hub.Sweep()
	real.quiet(300 * time.Millisecond)
	if f.claimCount(d.id) != 0 || f.runStatus(run) != "queued" {
		t.Fatal("a pending connection claimed")
	}

	// Its heartbeat names it: now it is live, claims, and takes pushes.
	out := f.confirm(real)
	if len(out.Features) != 1 || out.Features[0] != agentproto.FeatureChannel || out.Instance != "test-instance" {
		t.Errorf("heartbeat answer: features %v, instance %q", out.Features, out.Instance)
	}
	m, err := real.nextNot(3 * time.Second)
	if err != nil || m.Type != agentproto.TypeJobs || len(m.Jobs.Jobs) != 1 {
		t.Fatalf("after confirmation: %+v %v", m, err)
	}
	if f.runStatus(run) != "sent" {
		t.Errorf("run is %s", f.runStatus(run))
	}
	if !f.hub.Push(d.id, wake()) {
		t.Fatal("Push to the confirmed connection failed")
	}
	if m, err := real.nextNot(2 * time.Second); err != nil || m.Type != agentproto.TypeWake || m.What != "checkin" {
		t.Errorf("wake: %+v %v", m, err)
	}
	if !f.hub.Live(d.id) {
		t.Error("not live")
	}
}

// A pending connection never replaces a confirmed one, and a heartbeat that
// names the real connection closes the pending one at once.
func TestPendingNeverReplacesConfirmed(t *testing.T) {
	f := newFixture(t, fixtureOpts{timing: fastTiming})
	d := f.device(f.orgA)
	real := f.dial(d)
	f.confirm(real)

	// A replayed request signed over a minute ago, used after the real
	// connection was confirmed.
	stale, err := f.dialWith(d, d.header(time.Now().Add(-3*time.Minute)), []string{agentproto.ChannelSubprotocol})
	if err != nil {
		t.Fatal(err)
	}
	if !f.hub.Push(d.id, wake()) {
		t.Fatal("the confirmed connection stopped taking pushes")
	}
	if m, err := real.nextNot(2 * time.Second); err != nil || m.Type != agentproto.TypeWake {
		t.Fatalf("the real connection: %+v %v", m, err)
	}
	stale.quiet(300 * time.Millisecond) // the pending one got no wake

	// The real agent's next heartbeat names its own connection: the pending
	// one, signed for over 60 seconds before, is contradicted and closed.
	f.confirm(real)
	if m, _ := stale.ends(2 * time.Second); m == nil || m.Reason != agentproto.ClosingReplaced {
		t.Errorf("the pending connection: %+v", m)
	}
	if !f.hub.Push(d.id, wake()) {
		t.Error("the real connection was lost")
	}
}

// A confirmed connection that a heartbeat contradicts (it names another
// connection) is sent nothing, and then told it was replaced.
func TestContradictedConnection(t *testing.T) {
	f := newFixture(t, fixtureOpts{timing: fastTiming})
	d := f.device(f.orgA)
	c, err := f.dialWith(d, d.header(time.Now().Add(-2*time.Minute)), []string{agentproto.ChannelSubprotocol})
	if err != nil {
		t.Fatal(err)
	}
	f.confirm(c)
	// A heartbeat signed before the latest one confirms and contradicts
	// nothing.
	f.heartbeat(d, &agentproto.ChannelReport{ConnID: "someone-else"}, time.Now().Add(-time.Minute))
	if !f.hub.Push(d.id, wake()) {
		t.Fatal("an out-of-order heartbeat contradicted the connection")
	}
	// One that names another connection does.
	f.heartbeat(d, &agentproto.ChannelReport{ConnID: "someone-else"}, time.Now().Add(time.Second))
	if f.hub.Push(d.id, wake()) {
		t.Error("a contradicted connection took a push")
	}
	time.Sleep(350 * time.Millisecond)
	f.hub.Sweep()
	if m, _ := c.ends(2 * time.Second); m == nil || m.Reason != agentproto.ClosingReplaced {
		t.Errorf("closing: %+v", m)
	}
}

// A heartbeat without a report neither confirms nor contradicts.
func TestHeartbeatWithoutReport(t *testing.T) {
	f := newFixture(t, fixtureOpts{timing: fastTiming})
	d := f.device(f.orgA)
	c, err := f.dialWith(d, d.header(time.Now().Add(-2*time.Minute)), []string{agentproto.ChannelSubprotocol})
	if err != nil {
		t.Fatal(err)
	}
	f.heartbeat(d, nil, time.Now())
	if f.hub.Live(d.id) || f.hub.Push(d.id, wake()) {
		t.Fatal("a heartbeat without a report confirmed the connection")
	}
	f.confirm(c)
	f.heartbeat(d, nil, time.Now().Add(time.Second))
	if !f.hub.Push(d.id, wake()) {
		t.Fatal("a heartbeat without a report contradicted the connection")
	}
}

// A connection no heartbeat confirms in time is closed by the sweep.
func TestUnconfirmedConnectionClosed(t *testing.T) {
	tm := fastTiming
	tm.ConfirmWithin = 200 * time.Millisecond
	f := newFixture(t, fixtureOpts{timing: tm})
	c := f.dial(f.device(f.orgA))
	time.Sleep(300 * time.Millisecond)
	f.hub.Sweep()
	if m, _ := c.ends(2 * time.Second); m == nil || m.Reason != agentproto.ClosingRefresh {
		t.Errorf("closing: %+v", m)
	}
}

func TestUpgradeRefusals(t *testing.T) {
	f := newFixture(t, fixtureOpts{timing: fastTiming})
	d := f.device(f.orgA)
	if _, err := f.dialWith(d, d.header(time.Now()), nil); asRefusal(err) == nil || asRefusal(err).Status != 400 {
		t.Errorf("no subprotocol: %v", err)
	}
	if _, err := f.dialWith(d, d.header(time.Now()), []string{"easyrmm-agent.v9"}); asRefusal(err) == nil || asRefusal(err).Status != 400 {
		t.Errorf("another subprotocol: %v", err)
	}
	other := f.device(f.orgA)
	if _, err := f.dialWith(d, d.forged(other), []string{agentproto.ChannelSubprotocol}); asRefusal(err) == nil || asRefusal(err).Status != 401 {
		t.Errorf("another device's signature: %v", err)
	}
	if _, err := f.dialWith(d, "", []string{agentproto.ChannelSubprotocol}); asRefusal(err) == nil || asRefusal(err).Status != 401 {
		t.Errorf("no signature: %v", err)
	}
}

func TestPerDeviceAndServerLimits(t *testing.T) {
	t.Run("device upgrades", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{timing: fastTiming})
		d := f.device(f.orgA)
		for range agentproto.ChannelUpgradeBurst {
			f.dial(d)
		}
		if r := f.dialRefused(d); r.Status != 429 {
			t.Errorf("the seventh upgrade: %+v", r)
		}
	})
	t.Run("connections", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{timing: fastTiming, maxConns: 2})
		a, b, c := f.device(f.orgA), f.device(f.orgA), f.device(f.orgA)
		f.dial(a)
		f.dial(b)
		r := f.dialRefused(c)
		if r.Status != 503 || r.Code != "channel_full" || r.RetryAfter == "" {
			t.Errorf("over the maximum: %+v", r)
		}
	})
	t.Run("a slot is given back", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{timing: fastTiming, maxConns: 1})
		a, b := f.device(f.orgA), f.device(f.orgA)
		c := f.dial(a)
		_ = c.ws.Close(websocket.StatusNormalClosure, "")
		eventually(t, "the slot is free", func() bool { return f.hub.Connections() == 0 })
		f.dial(b)
	})
	t.Run("upgrades a second", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{timing: fastTiming, perSec: 1})
		f.dial(f.device(f.orgA))
		r := f.dialRefused(f.device(f.orgA))
		if r.Status != 503 || r.Code != "channel_busy" || r.RetryAfter == "" {
			t.Errorf("over the rate: %+v", r)
		}
	})
	t.Run("descriptors", func(t *testing.T) {
		low := true
		f := newFixture(t, fixtureOpts{timing: fastTiming, fds: func() (uint64, uint64, bool) {
			if low {
				return 99_000, 100_000, true // 1,000 left of 100,000: under a quarter
			}
			return 1_000, 100_000, true
		}})
		d := f.device(f.orgA)
		if r := f.dialRefused(d); r.Status != 503 || r.Code != "channel_full" {
			t.Errorf("few descriptors: %+v", r)
		}
		low = false
		time.Sleep(5100 * time.Millisecond) // the reading is five seconds old
		f.dial(d)
	})
	t.Run("unverified upgrades spend no budget", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{timing: fastTiming, perSec: 1})
		d, e := f.device(f.orgA), f.device(f.orgA)
		for range 5 {
			_, _ = f.dialWith(d, d.forged(e), []string{agentproto.ChannelSubprotocol})
		}
		f.dial(d)
	})
}

func TestInboundFrameCaps(t *testing.T) {
	f := newFixture(t, fixtureOpts{timing: fastTiming})
	confirmed := func() (*client, *device) {
		d := f.device(f.orgA)
		c := f.dial(d)
		f.confirm(c)
		return c, d
	}

	t.Run("a signed logs.batch is stored and acked", func(t *testing.T) {
		c, d := confirmed()
		if err := c.sendBatch(3); err != nil {
			t.Fatal(err)
		}
		m, err := c.nextNot(3 * time.Second)
		if err != nil || m.Type != agentproto.TypeLogsAck || m.Ack == nil || m.Ack.Seq != 3 {
			t.Fatalf("ack: %+v %v", m, err)
		}
		if f.logCount(d.id) != 3 {
			t.Errorf("stored %d", f.logCount(d.id))
		}
	})
	t.Run("a pending connection's batch is not stored", func(t *testing.T) {
		d := f.device(f.orgA)
		c := f.dial(d)
		if err := c.sendBatch(2); err != nil {
			t.Fatal(err)
		}
		c.quiet(300 * time.Millisecond)
		if f.logCount(d.id) != 0 {
			t.Error("a pending connection stored logs")
		}
	})
	t.Run("more than one a second", func(t *testing.T) {
		c, _ := confirmed()
		for range agentproto.ChannelAgentFrameBurst + 2 {
			_ = c.sendBatch(1)
		}
		if _, st := c.ends(3 * time.Second); st != websocket.StatusPolicyViolation {
			t.Errorf("status %v", st)
		}
	})
	t.Run("over 64 KiB", func(t *testing.T) {
		c, _ := confirmed()
		_ = c.sendRaw(websocket.MessageText, bytes.Repeat([]byte("x"), agentproto.MaxChannelAgentFrame+1))
		if _, st := c.ends(3 * time.Second); st != websocket.StatusMessageTooBig {
			t.Errorf("status %v", st)
		}
	})
	t.Run("forged", func(t *testing.T) {
		c, d := confirmed()
		other := f.device(f.orgA)
		frame, _ := agentproto.SignChannelAgentFrame(other.key, agentproto.ChannelAgentFrame{Type: agentproto.TypeLogsBatch, ConnID: c.connID, Seq: 1, Batch: &agentproto.LogBatch{}})
		_ = c.sendRaw(websocket.MessageText, frame)
		if _, st := c.ends(3 * time.Second); st != websocket.StatusPolicyViolation {
			t.Errorf("status %v", st)
		}
		if f.logCount(d.id) != 0 {
			t.Error("stored")
		}
	})
	t.Run("another connection, a repeat and a gap", func(t *testing.T) {
		for name, mod := range map[string]func(*agentproto.ChannelAgentFrame, *client){
			"connection": func(fr *agentproto.ChannelAgentFrame, _ *client) { fr.ConnID = "other" },
			"gap":        func(fr *agentproto.ChannelAgentFrame, _ *client) { fr.Seq = 2 },
			"zero":       func(fr *agentproto.ChannelAgentFrame, _ *client) { fr.Seq = 0 },
		} {
			c, _ := confirmed()
			fr := agentproto.ChannelAgentFrame{Type: agentproto.TypeLogsBatch, ConnID: c.connID, Seq: 1, Batch: &agentproto.LogBatch{}}
			mod(&fr, c)
			frame, _ := agentproto.SignChannelAgentFrame(c.d.key, fr)
			_ = c.sendRaw(websocket.MessageText, frame)
			if _, st := c.ends(3 * time.Second); st != websocket.StatusPolicyViolation {
				t.Errorf("%s: status %v", name, st)
			}
		}
	})
	t.Run("a repeat", func(t *testing.T) {
		c, _ := confirmed()
		_ = c.sendBatch(1)
		c.sendSeq-- // the same seq again
		_ = c.sendBatch(1)
		if _, st := c.ends(3 * time.Second); st != websocket.StatusPolicyViolation {
			t.Errorf("status %v", st)
		}
	})
	t.Run("any other type, and binary", func(t *testing.T) {
		c, _ := confirmed()
		frame, _ := agentproto.SignChannelAgentFrame(c.d.key, agentproto.ChannelAgentFrame{Type: agentproto.TypeWake, ConnID: c.connID, Seq: 1})
		_ = c.sendRaw(websocket.MessageText, frame)
		if _, st := c.ends(3 * time.Second); st != websocket.StatusPolicyViolation {
			t.Errorf("type: status %v", st)
		}
		c, _ = confirmed()
		_ = c.sendRaw(websocket.MessageBinary, []byte("x"))
		if _, st := c.ends(3 * time.Second); st != websocket.StatusPolicyViolation {
			t.Errorf("binary: status %v", st)
		}
	})
}

func TestOversizeJobsGoByJobsWaiting(t *testing.T) {
	f := newFixture(t, fixtureOpts{timing: fastTiming,
		claim: func(_ context.Context, _ *fixture, _ uuid.UUID, max int) (*agentproto.PollResponse, error) {
			if max >= agentproto.MaxChannelBigFrame {
				t.Errorf("the claim was given %d bytes, the cap", max)
			}
			// A claim that ignored its budget.
			return &agentproto.PollResponse{Jobs: []agentproto.SignedJob{{Payload: strings.Repeat("a", agentproto.MaxChannelBigFrame), Signature: "x"}}}, nil
		}})
	d := f.device(f.orgA)
	c := f.dial(d)
	if out := f.confirm(c); out.JobsWaiting {
		t.Error("jobsWaiting before anything was too big")
	}
	eventually(t, "the claim ran", func() bool { return f.claimCount(d.id) > 0 })
	c.quiet(300 * time.Millisecond) // no jobs frame
	if !f.heartbeat(d, nil, time.Now()).JobsWaiting {
		t.Fatal("no jobsWaiting")
	}
	if f.heartbeat(d, nil, time.Now()).JobsWaiting {
		t.Error("jobsWaiting is not taken once")
	}
	// A pushed jobs frame over the cap is refused the same way.
	big := agentproto.ChannelMessage{Type: agentproto.TypeJobs, Jobs: &agentproto.PollResponse{Jobs: []agentproto.SignedJob{{Payload: strings.Repeat("a", agentproto.MaxChannelBigFrame)}}}}
	if f.hub.Push(d.id, big) {
		t.Error("an oversize jobs frame was pushed")
	}
	// Other types have their own caps: 16 KiB for a wake or logs.
	l := agentproto.ChannelMessage{Type: agentproto.TypeLogs, Logs: &agentproto.LogInstructions{}}
	if !f.hub.Push(d.id, l) {
		t.Error("a small logs push failed")
	}
	if f.hub.Push(d.id, agentproto.ChannelMessage{Type: agentproto.TypeWake, Reason: strings.Repeat("r", 20<<10)}) {
		t.Error("a wake over 16 KiB was pushed")
	}
	// Only the types the hub pushes go this way.
	if f.hub.Push(d.id, agentproto.ChannelMessage{Type: agentproto.TypeClosing}) || f.hub.Push(d.id, agentproto.ChannelMessage{Type: agentproto.TypeHello}) {
		t.Error("a type that is not a push was pushed")
	}
}

func TestKeepalivesAndIdle(t *testing.T) {
	tm := fastTiming
	tm.Idle = 600 * time.Millisecond
	f := newFixture(t, fixtureOpts{timing: tm})
	t.Run("ticks", func(t *testing.T) {
		c := f.dial(f.device(f.orgA))
		for range 3 {
			if m := c.next(2 * time.Second); m.Type != agentproto.TypeTick {
				t.Fatalf("got %q", m.Type)
			}
		}
	})
	t.Run("silence is closed, pings keep it", func(t *testing.T) {
		quiet := f.dial(f.device(f.orgA))
		pinged := f.dial(f.device(f.orgA))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			for ctx.Err() == nil {
				pctx, c2 := context.WithTimeout(ctx, time.Second)
				_ = pinged.ws.Ping(pctx)
				c2()
				time.Sleep(100 * time.Millisecond)
			}
		}()
		quiet.ends(5 * time.Second)
		time.Sleep(900 * time.Millisecond)
		if f.hub.Connections() != 1 {
			t.Errorf("connections: %d", f.hub.Connections())
		}
	})
}

func TestHoldShutdownAndRemoval(t *testing.T) {
	var held atomic.Bool
	tm := fastTiming
	tm.HeldCheck = 50 * time.Millisecond
	f := newFixture(t, fixtureOpts{timing: tm, held: held.Load})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.hub.Run(ctx); close(done) }()

	a := f.device(f.orgA)
	ca := f.dial(a)
	held.Store(true)
	if m, _ := ca.ends(3 * time.Second); m == nil || m.Reason != agentproto.ClosingRestart {
		t.Errorf("hold: %+v", m)
	}
	if r := f.dialRefused(f.device(f.orgA)); r.Status != 503 || r.Code != "held" {
		t.Errorf("an upgrade during the hold: %+v", r)
	}
	held.Store(false)
	time.Sleep(150 * time.Millisecond)

	// Removal closes the connection at once.
	b := f.device(f.orgA)
	cb := f.dial(b)
	if err := f.svc.ForceRemove(context.Background(), access.System("test"), b.id); err != nil {
		t.Fatal(err)
	}
	if m, _ := cb.ends(3 * time.Second); m == nil || m.Reason != agentproto.ClosingRemoved {
		t.Errorf("removal: %+v", m)
	}

	// Stopping the server says restart and waits for the connections.
	c := f.dial(f.device(f.orgA))
	cancel()
	if m, _ := c.ends(3 * time.Second); m == nil || m.Reason != agentproto.ClosingRestart {
		t.Errorf("shutdown: %+v", m)
	}
	<-done
}

// An organization outside the dev scope neither connects nor receives a
// push, and the scope's own organization is unaffected.
func TestDevScope(t *testing.T) {
	f := newFixture(t, fixtureOpts{timing: fastTiming})
	a, b := f.device(f.orgA), f.device(f.orgB)
	ca := f.dial(a)
	f.confirm(ca)
	cb := f.dial(b)
	f.confirm(cb)
	if !f.hub.Push(b.id, wake()) {
		t.Fatal("no scope: the push failed")
	}
	runB := f.queueRun(b)
	_, _ = cb.nextNot(time.Second)

	restore := devscope.Set(f.orgA)
	t.Cleanup(restore)
	// B: the upgrade is 404, features are not listed, pushes are dropped,
	// the sweep spends nothing and closes it; heartbeat still works.
	if r := f.dialRefused(f.device(f.orgB)); r.Status != 404 {
		t.Errorf("an outside upgrade: %+v", r)
	}
	if out := f.heartbeat(b, nil, time.Now()); len(out.Features) != 0 || out.Instance != "" {
		t.Errorf("an outside organization is offered the channel: %+v", out)
	}
	if f.hub.Push(b.id, wake()) {
		t.Error("an outside device took a push")
	}
	before := f.claimCount(b.id)
	f.hub.Kick(b.id)
	f.hub.Sweep()
	if m, _ := cb.ends(3 * time.Second); m == nil || m.Reason != agentproto.ClosingRefresh {
		t.Errorf("the outside connection: %+v", m)
	}
	if f.claimCount(b.id) != before || f.runStatus(runB) == "" {
		t.Error("a claim ran for an outside device")
	}
	// A is in scope.
	if out := f.heartbeat(a, nil, time.Now()); len(out.Features) != 1 {
		t.Errorf("an inside organization: %+v", out)
	}
	if !f.hub.Push(a.id, wake()) {
		t.Error("an inside push failed")
	}
	if m, err := ca.nextNot(2 * time.Second); err != nil || m.Type != agentproto.TypeWake {
		t.Errorf("%+v %v", m, err)
	}
	f.dial(f.device(f.orgA))

	// Clearing the scope restores it.
	restore()
	f.dial(f.device(f.orgB))
	if out := f.heartbeat(b, nil, time.Now()); len(out.Features) != 1 {
		t.Errorf("after clearing: %+v", out)
	}
}

// With the switch off nothing changes: the route is as absent as before the
// channel existed, and heartbeat answers say nothing of it.
func TestSwitchOff(t *testing.T) {
	f := newFixture(t, fixtureOpts{off: true})
	d := f.device(f.orgA)
	ghost := func(path string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, f.srv.URL+path, nil)
		h, _ := agentproto.Sign(d.key, d.id.String(), http.MethodGet, path, nil, time.Now())
		req.Header.Set("Authorization", h)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var b bytes.Buffer
		_, _ = b.ReadFrom(resp.Body)
		return resp.StatusCode, b.String()
	}
	code, body := ghost(agentproto.PathChannel)
	wantCode, wantBody := ghost("/api/agent/v1/nothing-here")
	if code != 404 || code != wantCode || body != wantBody {
		t.Errorf("the channel route: %d %q, an unknown one: %d %q", code, body, wantCode, wantBody)
	}
	out := f.heartbeat(d, &agentproto.ChannelReport{ConnID: "x"}, time.Now())
	if out.Features != nil || out.Instance != "" || out.JobsWaiting {
		t.Errorf("heartbeat answer: %+v", out)
	}
	if f.hub.Push(d.id, wake()) || f.hub.Live(d.id) || f.hub.Enabled() {
		t.Error("an off hub does something")
	}
	f.hub.Sweep()
	f.hub.Close(d.id, "x")
	f.hub.Run(context.Background()) // returns at once
}
