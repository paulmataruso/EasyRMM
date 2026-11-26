package channel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

const dev = "device-1"

// fake is a server end built on agentproto alone: it accepts the upgrade,
// sends hello, and then whatever script says.
type fake struct {
	t     *testing.T
	srv   *httptest.Server
	job   ed25519.PrivateKey
	pub   ed25519.PublicKey
	dials atomic.Int32
	// refuse, if set, answers the upgrade with this status.
	refuse func(w http.ResponseWriter) bool
	// script runs after the hello; the frames it sends are numbered from 2.
	script func(s *session)
	// helloNonce, if set, replaces the upgrade's nonce in the hello.
	helloNonce string
	instance   string
	done       chan struct{}
}

type session struct {
	f      *fake
	ws     *websocket.Conn
	ctx    context.Context
	connID string
	seq    uint64
}

func newFake(t *testing.T) *fake {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fake{t: t, job: priv, pub: pub, instance: "inst-1", done: make(chan struct{})}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(func() { close(f.done); f.srv.Close() })
	return f
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	f.dials.Add(1)
	if f.refuse != nil && f.refuse(w) {
		return
	}
	a, err := agentproto.Parse(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{agentproto.ChannelSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer func() { _ = ws.CloseNow() }()
	s := &session{f: f, ws: ws, ctx: r.Context(), connID: "conn-" + a.Nonce[:6]}
	nonce := a.Nonce
	if f.helloNonce != "" {
		nonce = f.helloNonce
	}
	s.send(agentproto.ChannelMessage{Type: agentproto.TypeHello, Nonce: nonce, Features: []string{agentproto.FeatureChannel}, Instance: f.instance})
	// Count the agent's pings: reading is what answers them.
	go func() {
		for {
			if _, _, err := ws.Read(context.Background()); err != nil {
				return
			}
		}
	}()
	if f.script != nil {
		f.script(s)
	}
	select {
	case <-f.done:
	case <-r.Context().Done():
	case <-time.After(30 * time.Second):
	}
}

func (s *session) msg(m agentproto.ChannelMessage) agentproto.ChannelMessage {
	s.seq++
	m.V, m.DeviceID, m.ConnID, m.Seq, m.SentAt = 1, dev, s.connID, s.seq, time.Now()
	return m
}

func (s *session) send(m agentproto.ChannelMessage) {
	s.raw(s.f.job, s.msg(m))
}

func (s *session) raw(key ed25519.PrivateKey, m agentproto.ChannelMessage) {
	b, err := agentproto.SignChannelMessage(key, m)
	if err != nil {
		s.f.t.Error(err)
		return
	}
	_ = s.ws.Write(s.ctx, websocket.MessageText, b)
}

type rig struct {
	*fake
	ch *Channel
	c  *client.Client
}

func newRig(t *testing.T, f *fake, tm Timing, off bool) *rig {
	t.Helper()
	c, err := client.New(client.Options{Server: f.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c.SetIdentity(dev, key)
	ch := New(Config{Dialer: c, DeviceID: dev, Key: func() ed25519.PublicKey { return f.pub }, Off: off, Timing: tm,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { ch.Run(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	return &rig{fake: f, ch: ch, c: c}
}

var fast = Timing{Hello: time.Second, Idle: 2 * time.Second, Ping: 100 * time.Millisecond, FirstWait: 20 * time.Millisecond,
	MinRetry: 20 * time.Millisecond, MaxRetry: 100 * time.Millisecond, SleepCheck: time.Hour, Dial: 2 * time.Second}

func listed(instance string) *agentproto.HeartbeatResponse {
	return &agentproto.HeartbeatResponse{Features: []string{agentproto.FeatureChannel}, Instance: instance}
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out: %s", what)
}

func (r *rig) never(what string, bad func() bool) {
	r.t.Helper()
	for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if bad() {
			r.t.Fatalf("%s", what)
		}
	}
}

func (r *rig) gotWake(d time.Duration) (Wake, bool) {
	select {
	case w := <-r.ch.Wakes():
		return w, true
	case <-time.After(d):
		return Wake{}, false
	}
}

func TestConnectsOnlyAfterAReportedHeartbeatListsChannel(t *testing.T) {
	f := newFake(t)
	r := newRig(t, f, fast, false)
	r.never("connected before any answer", func() bool { return f.dials.Load() > 0 })

	r.ch.Answered(&agentproto.HeartbeatResponse{}, true)
	r.never("connected to a server that lists nothing", func() bool { return f.dials.Load() > 0 })

	// Listed, but the heartbeat did not carry the agent's capability: no
	// connection yet, and the next check-in is brought forward.
	r.ch.Answered(listed("inst-1"), false)
	if w, ok := r.gotWake(time.Second); !ok || w.What != agentproto.WakeCheckin {
		t.Fatalf("no early check-in: %+v %v", w, ok)
	}
	r.never("connected on an answer to a heartbeat without the capability", func() bool { return f.dials.Load() > 0 })

	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "the channel is live", r.ch.Live)
	rep := r.ch.Report()
	if rep == nil || rep.ConnID == "" || rep.Since == 0 {
		t.Fatalf("the report: %+v", rep)
	}
	if w, ok := r.gotWake(time.Second); !ok || w.Reason != "connected" {
		t.Fatalf("no check-in after the hello: %+v", w)
	}
}

func TestOffSwitchNeverConnects(t *testing.T) {
	f := newFake(t)
	r := newRig(t, f, fast, true)
	r.ch.Answered(listed("inst-1"), true)
	r.never("an agent that is off connected", func() bool { return f.dials.Load() > 0 })
	if r.ch.Live() || r.ch.Report() != nil {
		t.Fatal("live while off")
	}
}

func TestWakeReachesTheRunner(t *testing.T) {
	f := newFake(t)
	f.script = func(s *session) {
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeTick})
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeWake, What: agentproto.WakeJobs, Reason: "job"})
	}
	r := newRig(t, f, fast, false)
	r.ch.Answered(listed("inst-1"), true)
	r.gotWake(time.Second) // the check-in after the hello
	if w, ok := r.gotWake(time.Second); !ok || w.What != agentproto.WakeJobs || w.Reason != "job" {
		t.Fatalf("wake: %+v %v", w, ok)
	}
	eventually(t, "still live after ticks and a wake", r.ch.Live)
}

// Every frame that does not verify, in each way it can fail, ends the
// connection and delivers nothing.
func TestRefusesForgedReplayedAndMisboundFrames(t *testing.T) {
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	w := func() agentproto.ChannelMessage {
		return agentproto.ChannelMessage{Type: agentproto.TypeWake, What: agentproto.WakeCheckin, Reason: "job"}
	}
	cases := map[string]func(s *session){
		"signed with another key": func(s *session) { s.raw(other, s.msg(w())) },
		"another device": func(s *session) {
			m := s.msg(w())
			m.DeviceID = "device-2"
			s.raw(s.f.job, m)
		},
		"another connection": func(s *session) {
			m := s.msg(w())
			m.ConnID = "conn-other"
			s.raw(s.f.job, m)
		},
		"a gap in the sequence": func(s *session) {
			s.seq += 3
			s.send(w())
		},
		"a payload that was changed": func(s *session) {
			b, _ := agentproto.SignChannelMessage(s.f.job, s.msg(w()))
			var e agentproto.ChannelEnvelope
			_ = json.Unmarshal(b, &e)
			e.Payload = e.Payload[:len(e.Payload)-4] + "AAAA"
			b, _ = json.Marshal(e)
			_ = s.ws.Write(s.ctx, websocket.MessageText, b)
		},
		"an oversized frame": func(s *session) {
			m := s.msg(w())
			m.Reason = string(make([]byte, agentproto.MaxChannelFrame))
			s.raw(s.f.job, m)
		},
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.script = script
			r := newRig(t, f, fast, false)
			r.ch.Answered(listed("inst-1"), true)
			// The connection ends; the agent connects again, so the dial count grows.
			eventually(t, "the frame was refused", func() bool { return f.dials.Load() >= 2 })
			for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); {
				w, ok := r.gotWake(50 * time.Millisecond)
				if ok && w.Reason == "job" {
					t.Fatalf("a refused frame woke the runner: %+v", w)
				}
			}
		})
	}
}

// The replayed copy breaks the sequence: the wake is delivered once and the
// connection ends.
func TestReplayedWakeIsDeliveredOnce(t *testing.T) {
	f := newFake(t)
	var once sync.Once
	f.script = func(s *session) {
		once.Do(func() {
			m := s.msg(agentproto.ChannelMessage{Type: agentproto.TypeWake, What: agentproto.WakeCheckin, Reason: "job"})
			s.raw(s.f.job, m)
			s.raw(s.f.job, m)
		})
	}
	r := newRig(t, f, fast, false)
	r.ch.Answered(listed("inst-1"), true)
	n := 0
	for end := time.Now().Add(400 * time.Millisecond); time.Now().Before(end); {
		if w, ok := r.gotWake(50 * time.Millisecond); ok && w.Reason == "job" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("delivered %d times", n)
	}
}

func TestHelloMustRepeatTheUpgradesNonce(t *testing.T) {
	f := newFake(t)
	f.helloNonce = "someone else's"
	r := newRig(t, f, fast, false)
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "tried again", func() bool { return f.dials.Load() >= 2 })
	if r.ch.Live() {
		t.Fatal("live on a hello that is not for this connection")
	}
}

func TestNoHelloMeansNoConnection(t *testing.T) {
	f := newFake(t)
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.dials.Add(1)
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{agentproto.ChannelSubprotocol}})
		if err != nil {
			return
		}
		defer func() { _ = ws.CloseNow() }()
		<-r.Context().Done()
	})
	tm := fast
	tm.Hello = 100 * time.Millisecond
	r := newRig(t, f, tm, false)
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "gave up and tried again", func() bool { return f.dials.Load() >= 2 })
	if r.ch.Live() {
		t.Fatal("live without a hello")
	}
}

func TestSilenceEndsTheConnection(t *testing.T) {
	f := newFake(t)
	tm := fast
	tm.Idle = 150 * time.Millisecond
	r := newRig(t, f, tm, false)
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "live", r.ch.Live)
	eventually(t, "dropped for silence and tried again", func() bool { return f.dials.Load() >= 2 })
}

func Test404IsNotSupportedUntilAnotherAnswerListsChannel(t *testing.T) {
	f := newFake(t)
	f.refuse = func(w http.ResponseWriter) bool { http.NotFound(w, nil); return true }
	r := newRig(t, f, fast, false)
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "one attempt", func() bool { return f.dials.Load() == 1 })
	r.never("tried again after a 404", func() bool { return f.dials.Load() > 1 })
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "tried again after a heartbeat listed it", func() bool { return f.dials.Load() == 2 })
}

func TestRetryAfterIsHonoured(t *testing.T) {
	f := newFake(t)
	f.refuse = func(w http.ResponseWriter) bool {
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"channel_busy"}}`))
		return true
	}
	r := newRig(t, f, fast, false)
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "one attempt", func() bool { return f.dials.Load() == 1 })
	r.never("ignored the server's Retry-After", func() bool { return f.dials.Load() > 1 })
}

func TestUnknownRefusalBacksOffAndRetries(t *testing.T) {
	f := newFake(t)
	f.refuse = func(w http.ResponseWriter) bool { w.WriteHeader(http.StatusBadGateway); return true }
	r := newRig(t, f, fast, false)
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "retried", func() bool { return f.dials.Load() >= 3 })
}

func TestUnlistedMessageClosesTheConnection(t *testing.T) {
	f := newFake(t)
	f.script = func(s *session) { s.send(agentproto.ChannelMessage{Type: "future.thing"}) }
	r := newRig(t, f, fast, false)
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "counted", func() bool {
		r.ch.mu.Lock()
		defer r.ch.mu.Unlock()
		return r.ch.unlisted["inst-1"] == 1
	})
	eventually(t, "closed", func() bool { return !r.ch.Live() })
}

func TestUnlistedStopAndRecovery(t *testing.T) {
	c := New(Config{Key: func() ed25519.PublicKey { return nil }})
	for range stopAfter {
		c.unlistedMessage("inst-1", agentproto.ChannelMessage{Type: "x"})
	}
	c.Answered(listed("inst-1"), true)
	if c.ready() {
		t.Fatal("still connecting after three unlisted messages from one instance")
	}
	c.Answered(listed("inst-2"), true)
	if !c.ready() {
		t.Fatal("did not resume when another instance answered")
	}
}

func TestClosingRemovedHoldsUntilAHeartbeatSaysMore(t *testing.T) {
	f := newFake(t)
	f.script = func(s *session) {
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeClosing, Reason: agentproto.ClosingRemoved})
	}
	r := newRig(t, f, fast, false)
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "one connection", func() bool { return f.dials.Load() == 1 })
	r.never("reconnected after removed", func() bool { return f.dials.Load() > 1 })
	// The heartbeat carries the uninstall: still no connection.
	r.ch.Answered(&agentproto.HeartbeatResponse{Features: []string{agentproto.FeatureChannel}, Uninstall: &agentproto.SignedUninstall{}}, true)
	r.never("connected while the device is being removed", func() bool { return f.dials.Load() > 1 })
	// The removal was canceled.
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "reconnected", func() bool { return f.dials.Load() >= 2 })
}

func TestClosingRestartReconnectsWithinTheWindow(t *testing.T) {
	f := newFake(t)
	f.script = func(s *session) {
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeClosing, Reason: agentproto.ClosingRestart, ReconnectWithin: 1})
	}
	r := newRig(t, f, fast, false)
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "connected again", func() bool { return f.dials.Load() >= 2 })
}

func TestAnswerWithoutChannelEndsTheConnection(t *testing.T) {
	f := newFake(t)
	r := newRig(t, f, fast, false)
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "live", r.ch.Live)
	r.ch.Answered(&agentproto.HeartbeatResponse{}, true)
	eventually(t, "down", func() bool { return !r.ch.Live() })
	r.never("reconnected to a server that stopped listing the channel", func() bool { return f.dials.Load() > 1 })
}

func TestClosingReplacedAndUnknownReason(t *testing.T) {
	c := New(Config{})
	if d, ok := c.closing(agentproto.ChannelMessage{Reason: agentproto.ClosingReplaced}); !ok || d > 5*time.Minute {
		t.Fatalf("replaced: %v %v", d, ok)
	}
	if d, ok := c.closing(agentproto.ChannelMessage{Reason: agentproto.ClosingRefresh}); !ok || d > 5*time.Minute {
		t.Fatalf("refresh: %v %v", d, ok)
	}
	if _, ok := c.closing(agentproto.ChannelMessage{Reason: "later"}); ok {
		t.Fatal("an unlisted reason was taken")
	}
}

func TestFailureBackoffGrowsAndIsCapped(t *testing.T) {
	c := New(Config{Timing: Timing{FirstWait: time.Second, MinRetry: 5 * time.Second, MaxRetry: 20 * time.Second}})
	if d := c.failure(); d > time.Second {
		t.Fatalf("first wait %v", d)
	}
	for range 20 {
		if d := c.failure(); d > 20*time.Second {
			t.Fatalf("wait %v over the cap", d)
		}
	}
}

func TestSleepIsNoticed(t *testing.T) {
	f := newFake(t)
	tm := fast
	tm.SleepCheck = 10 * time.Millisecond
	tm.SleepJump = -time.Hour // any tick counts as a jump
	r := newRig(t, f, tm, false)
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "closed for a slept clock and connected at once", func() bool { return f.dials.Load() >= 2 })
}

func TestNoKeyNoTrust(t *testing.T) {
	f := newFake(t)
	r := newRig(t, f, fast, false)
	r.ch.cfg.Key = func() ed25519.PublicKey { return nil }
	r.ch.Answered(listed("inst-1"), true)
	eventually(t, "tried", func() bool { return f.dials.Load() >= 1 })
	r.never("trusted a frame with no pinned key", r.ch.Live)
}
