package channel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// got records what the handlers were given.
type got struct {
	mu       sync.Mutex
	jobs     []*agentproto.PollResponse
	logs     []*agentproto.LogInstructions
	repairs  []*agentproto.SignedRepair
	settings []agentproto.ChannelSettings
	pollNow  atomic.Int32
}

func (g *got) handlers() Handlers {
	return Handlers{
		Jobs: func(_ context.Context, p *agentproto.PollResponse) {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.jobs = append(g.jobs, p)
		},
		Logs: func(l *agentproto.LogInstructions) {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.logs = append(g.logs, l)
		},
		Repair: func(_ context.Context, r *agentproto.SignedRepair) {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.repairs = append(g.repairs, r)
		},
		Settings: func(_ context.Context, s agentproto.ChannelSettings) {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.settings = append(g.settings, s)
		},
		PollNow: func() { g.pollNow.Add(1) },
	}
}

func (g *got) counts() (jobs, logs, repairs, settings int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.jobs), len(g.logs), len(g.repairs), len(g.settings)
}

// newPushRig is newRig with handlers and a device key for log batches.
func newPushRig(t *testing.T, f *fake, h Handlers) (*Channel, ed25519.PublicKey) {
	t.Helper()
	c, err := client.New(client.Options{Server: f.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c.SetIdentity(dev, key)
	ch := New(Config{Dialer: c, DeviceID: dev, Key: func() ed25519.PublicKey { return f.pub }, Timing: fast, Device: key, Handlers: h,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { ch.Run(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	return ch, pub
}

func TestPushedInstructionsReachTheirHandlers(t *testing.T) {
	f := newFake(t)
	f.script = func(s *session) {
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeJobs, Jobs: &agentproto.PollResponse{
			Jobs: []agentproto.SignedJob{{Payload: "p", Signature: "s"}}, Cancel: []string{"run-9"}}})
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeLogs, Logs: &agentproto.LogInstructions{FollowUntil: 7}})
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeRepair, Repair: &agentproto.SignedRepair{Payload: "r", Signature: "s"}})
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeSettings, Settings: &agentproto.ChannelSettings{HeartbeatSeconds: 90}})
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeLogs}) // none: ends the instructions
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeWake, What: agentproto.WakeJobs, Reason: "job"})
	}
	g := &got{}
	ch, _ := newPushRig(t, f, g.handlers())
	ch.Answered(listed("inst-1"), true)
	eventually(t, "every handler was called", func() bool {
		j, l, r, s := g.counts()
		return j == 1 && l == 2 && r == 1 && s == 1 && g.pollNow.Load() == 1
	})
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.jobs[0].Jobs) != 1 || g.jobs[0].Cancel[0] != "run-9" || g.logs[0].FollowUntil != 7 || g.logs[1] != nil ||
		g.repairs[0].Payload != "r" || g.settings[0].HeartbeatSeconds != 90 {
		t.Fatalf("the handlers were given %+v %+v %+v %+v", g.jobs, g.logs, g.repairs, g.settings)
	}
	if !ch.Live() {
		t.Fatal("verified pushes ended the connection")
	}
}

// A jobs wake with no PollNow handler is a check-in, as before.
func TestJobsWakeWithoutAHandlerIsACheckin(t *testing.T) {
	f := newFake(t)
	f.script = func(s *session) {
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeWake, What: agentproto.WakeJobs, Reason: "job"})
	}
	ch, _ := newPushRig(t, f, Handlers{})
	ch.Answered(listed("inst-1"), true)
	eventually(t, "the wake reached the runner", func() bool {
		select {
		case w := <-ch.Wakes():
			return w.Reason == "job"
		default:
			return false
		}
	})
}

// A pushed frame that was forged, or replayed, delivers nothing more and
// ends the connection.
func TestForgedAndReplayedPushesAreRefused(t *testing.T) {
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	jobs := func() agentproto.ChannelMessage {
		return agentproto.ChannelMessage{Type: agentproto.TypeJobs, Jobs: &agentproto.PollResponse{Cancel: []string{"run-1"}}}
	}
	for name, script := range map[string]func(s *session){
		"forged":   func(s *session) { s.raw(other, s.msg(jobs())) },
		"replayed": func(s *session) { m := s.msg(jobs()); s.raw(s.f.job, m); s.raw(s.f.job, m) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			var once sync.Once
			f.script = func(s *session) { once.Do(func() { script(s) }) }
			g := &got{}
			ch, _ := newPushRig(t, f, g.handlers())
			ch.Answered(listed("inst-1"), true)
			eventually(t, "the connection ended and came back", func() bool { return f.dials.Load() >= 2 })
			time.Sleep(200 * time.Millisecond)
			want := 0
			if name == "replayed" {
				want = 1 // the first copy was genuine
			}
			if j, _, _, _ := g.counts(); j != want {
				t.Fatalf("%d deliveries, want %d", j, want)
			}
		})
	}
}

// Without a handler a type is one the agent does not list.
func TestPushWithoutAHandlerIsUnlisted(t *testing.T) {
	f := newFake(t)
	f.script = func(s *session) {
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeRepair, Repair: &agentproto.SignedRepair{}})
	}
	ch, _ := newPushRig(t, f, Handlers{})
	ch.Answered(listed("inst-1"), true)
	eventually(t, "counted as unlisted", func() bool {
		ch.mu.Lock()
		defer ch.mu.Unlock()
		return ch.unlisted["inst-1"] >= 1
	})
}

// A log batch goes as a frame signed with the device key, bound to the
// connection and numbered from 1, and the server's ack answers it.
func TestSendLogsIsSignedAndAcked(t *testing.T) {
	f := newFake(t)
	var pub ed25519.PublicKey
	var mu sync.Mutex
	var seen []agentproto.ChannelAgentFrame
	f.onAgent = func(s *session, data []byte) {
		mu.Lock()
		p := pub
		mu.Unlock()
		fr, err := agentproto.VerifyChannelAgentFrame(p, data)
		if err != nil {
			t.Errorf("the agent's frame does not verify: %v", err)
			return
		}
		mu.Lock()
		seen = append(seen, fr)
		mu.Unlock()
		s.send(agentproto.ChannelMessage{Type: agentproto.TypeLogsAck, Ack: &agentproto.LogAck{Seq: fr.Batch.Records[0].Seq}})
	}
	ch, p := newPushRig(t, f, Handlers{})
	mu.Lock()
	pub = p
	mu.Unlock()
	if _, err := ch.SendLogs(context.Background(), agentproto.LogBatch{}); !errors.Is(err, ErrNotLive) {
		t.Fatalf("before a connection: %v", err)
	}
	ch.Answered(listed("inst-1"), true)
	eventually(t, "live", ch.Live)
	ack, err := ch.SendLogs(context.Background(), agentproto.LogBatch{Records: []agentproto.LogRecord{{Seq: 41, Message: "m"}}})
	if err != nil || ack.Seq != 41 {
		t.Fatalf("ack %+v, %v", ack, err)
	}
	// Too soon after the last: the caller sends it over HTTPS instead.
	if _, err := ch.SendLogs(context.Background(), agentproto.LogBatch{Records: []agentproto.LogRecord{{Seq: 42}}}); !errors.Is(err, ErrNotLive) {
		t.Fatalf("a second frame within the rate: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0].Seq != 1 || seen[0].ConnID == "" || seen[0].Type != agentproto.TypeLogsBatch {
		t.Fatalf("frames the server saw: %+v", seen)
	}
}

// A batch the server does not ack is sent over HTTPS, and the channel is
// left alone for a while.
func TestUnackedLogsFallBack(t *testing.T) {
	f := newFake(t)
	f.script = func(s *session) { // ticks keep the connection from going idle
		for {
			select {
			case <-f.done:
				return
			case <-time.After(100 * time.Millisecond):
				s.send(agentproto.ChannelMessage{Type: agentproto.TypeTick})
			}
		}
	}
	ch, _ := newPushRig(t, f, Handlers{})
	ch.Answered(listed("inst-1"), true)
	eventually(t, "live", ch.Live)
	var fellBack atomic.Int32
	send := ch.LogSender(func() bool { return true }, func(context.Context, agentproto.LogBatch) (agentproto.LogAck, error) {
		fellBack.Add(1)
		return agentproto.LogAck{Seq: 5}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	ack, err := send(ctx, agentproto.LogBatch{Records: []agentproto.LogRecord{{Seq: 5}}})
	if err != nil || ack.Seq != 5 || fellBack.Load() != 1 || time.Since(start) > ackWithin+2*time.Second {
		t.Fatalf("ack %+v, %v, fallbacks %d after %v", ack, err, fellBack.Load(), time.Since(start))
	}
	// Muted: the next batch does not wait.
	start = time.Now()
	if _, err := send(ctx, agentproto.LogBatch{}); err != nil || fellBack.Load() != 2 || time.Since(start) > time.Second {
		t.Fatalf("second batch: %v, %d, %v", err, fellBack.Load(), time.Since(start))
	}
	// Not following: HTTPS always.
	send = ch.LogSender(func() bool { return false }, func(context.Context, agentproto.LogBatch) (agentproto.LogAck, error) {
		fellBack.Add(1)
		return agentproto.LogAck{}, nil
	})
	_, _ = send(ctx, agentproto.LogBatch{})
	if fellBack.Load() != 3 {
		t.Fatal("a batch went over the channel while no one follows")
	}
}

func TestReplayedUpgradeIsReported(t *testing.T) {
	f := newFake(t)
	f.refuse = func(w http.ResponseWriter) bool {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":"replayed","message":"x"}}`)
		return true
	}
	ch, _ := newPushRig(t, f, Handlers{})
	if ch.Report() != nil {
		t.Fatal("a report before anything happened")
	}
	ch.Answered(listed("inst-1"), true)
	eventually(t, "the replay was noted", func() bool { r := ch.Report(); return r != nil && r.LastReplayed != 0 && r.ConnID == "" })
}
