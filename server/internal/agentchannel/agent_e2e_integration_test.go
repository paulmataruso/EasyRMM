//go:build integration

package agentchannel_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/paulmataruso/easyrmm/agent/channel"
	agentclient "github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/runner"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// The real agent (its runner and its channel client) against the real agent
// API and hub, over a real database. A relay stands between them, which
// counts heartbeats and can tamper with what the server sends.

type relayMode int

const (
	relayPass   relayMode = iota
	relayForge            // flips a byte of the signature of the first frame after the hello
	relayReplay           // sends the first frame after the hello twice
)

type relay struct {
	srv        *httptest.Server
	heartbeats atomic.Int32
	upgrades   atomic.Int32
}

func newRelay(t *testing.T, f *fixture, mode relayMode) *relay {
	t.Helper()
	target, _ := url.Parse(f.srv.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	r := &relay{}
	mux := http.NewServeMux()
	mux.HandleFunc(agentproto.PathHeartbeat, func(w http.ResponseWriter, req *http.Request) {
		r.heartbeats.Add(1)
		proxy.ServeHTTP(w, req)
	})
	mux.HandleFunc(agentproto.PathChannel, func(w http.ResponseWriter, req *http.Request) {
		r.upgrades.Add(1)
		up, resp, err := websocket.Dial(req.Context(), f.url(), &websocket.DialOptions{
			HTTPHeader:      http.Header{"Authorization": {req.Header.Get("Authorization")}},
			Subprotocols:    []string{agentproto.ChannelSubprotocol},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			status := http.StatusBadGateway
			if resp != nil && resp.Body != nil {
				status = resp.StatusCode
				_ = resp.Body.Close()
			}
			w.WriteHeader(status)
			return
		}
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		defer func() { _ = up.CloseNow() }()
		up.SetReadLimit(agentproto.MaxChannelBigFrame)
		down, err := websocket.Accept(w, req, &websocket.AcceptOptions{Subprotocols: []string{agentproto.ChannelSubprotocol}, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer func() { _ = down.CloseNow() }()
		ctx := req.Context()
		go func() { // the agent's side: its pings are answered by the library; relay nothing
			for {
				if _, _, err := down.Read(ctx); err != nil {
					_ = up.CloseNow()
					return
				}
			}
		}()
		for n := 0; ; n++ {
			typ, data, err := up.Read(ctx)
			if err != nil {
				return
			}
			if n == 1 { // the frame after the hello
				switch mode {
				case relayForge:
					data = append([]byte(nil), data...)
					for i := range data {
						if string(data[i:min(i+13, len(data))]) == `"signature":"` {
							data[i+13] ^= 1 // changes a base64 letter
							break
						}
					}
				case relayReplay:
					_ = down.Write(ctx, typ, data)
				case relayPass:
				}
			}
			if down.Write(ctx, typ, data) != nil {
				return
			}
		}
	})
	mux.Handle("/", proxy)
	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

// agent is a running agent: a runner and its channel.
type agent struct {
	r  *runner.Runner
	ch *channel.Channel
}

type agentOpts struct {
	every time.Duration
	key   ed25519.PublicKey // what the agent trusts; the server's job key by default
	off   bool
}

func startAgent(t *testing.T, f *fixture, d *device, serverURL string, o agentOpts) *agent {
	t.Helper()
	c, err := agentclient.New(agentclient.Options{Server: serverURL, Version: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	c.SetIdentity(d.id.String(), d.key)
	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := mkdir(store.Dir()); err != nil {
		t.Fatal(err)
	}
	pub := o.key
	if pub == nil {
		pub = f.jobPub
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ch := channel.New(channel.Config{Dialer: c, DeviceID: d.id.String(), Key: func() ed25519.PublicKey { return pub }, Off: o.off, Log: log,
		Timing: channel.Timing{FirstWait: 50 * time.Millisecond, MinRetry: 50 * time.Millisecond, MaxRetry: 200 * time.Millisecond}})
	r := &runner.Runner{
		Client: c, Store: store, DeviceID: d.id.String(), Log: log, Channel: ch,
		Facts: func() agentproto.Facts {
			return agentproto.Facts{Hostname: "h", Platform: "linux", Arch: "amd64", AgentVersion: "1"}
		},
		Key:     func() ed25519.PublicKey { return pub },
		Every:   o.every,
		MinWake: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { ch.Run(ctx) })
	wg.Go(func() { _ = r.Run(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	return &agent{r: r, ch: ch}
}

func within(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out after %v: %s", d, what)
}

// A pushed wake makes the agent heartbeat at once, though its own timer is
// an hour away: the connection is confirmed by the agent's own signed
// heartbeats, and only then does the hub push.
func TestAgentWakeLeadsToAnImmediateHeartbeat(t *testing.T) {
	f := newFixture(t, fixtureOpts{timing: fastTiming})
	d := f.device(f.orgA)
	rl := newRelay(t, f, relayPass)
	a := startAgent(t, f, d, rl.srv.URL, agentOpts{every: time.Hour})

	within(t, 10*time.Second, "the agent's channel is live and confirmed by its heartbeat", func() bool {
		return a.ch.Live() && f.hub.Live(d.id)
	})
	// The first heartbeat of the process could not carry the capability; the
	// agent checked in again at once, then connected, then confirmed.
	if rl.upgrades.Load() != 1 {
		t.Fatalf("upgrades: %d", rl.upgrades.Load())
	}
	time.Sleep(300 * time.Millisecond)
	before := rl.heartbeats.Load()

	start := time.Now()
	if !f.hub.Push(d.id, wake()) {
		t.Fatal("the hub did not push to the confirmed connection")
	}
	within(t, 3*time.Second, "a heartbeat after the wake", func() bool { return rl.heartbeats.Load() > before })
	t.Logf("wake to heartbeat: %v", time.Since(start))
}

// With the channel off on the server, down, or refused, the agent's
// heartbeats go on.
func TestHeartbeatsContinueWhenTheChannelIsDown(t *testing.T) {
	t.Run("server switch off", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{off: true})
		d := f.device(f.orgA)
		rl := newRelay(t, f, relayPass)
		a := startAgent(t, f, d, rl.srv.URL, agentOpts{every: 100 * time.Millisecond})
		within(t, 5*time.Second, "heartbeats", func() bool { return rl.heartbeats.Load() >= 5 })
		if a.ch.Live() || rl.upgrades.Load() != 0 {
			t.Fatal("the agent connected to a server that does not list the channel")
		}
	})
	t.Run("agent switch off", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{timing: fastTiming})
		d := f.device(f.orgA)
		rl := newRelay(t, f, relayPass)
		a := startAgent(t, f, d, rl.srv.URL, agentOpts{every: 100 * time.Millisecond, off: true})
		within(t, 5*time.Second, "heartbeats", func() bool { return rl.heartbeats.Load() >= 5 })
		if a.ch.Live() || rl.upgrades.Load() != 0 {
			t.Fatal("an agent that is off connected")
		}
	})
	t.Run("connection closed by the server", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{timing: fastTiming})
		d := f.device(f.orgA)
		rl := newRelay(t, f, relayPass)
		a := startAgent(t, f, d, rl.srv.URL, agentOpts{every: 100 * time.Millisecond})
		within(t, 10*time.Second, "live", func() bool { return a.ch.Live() && f.hub.Live(d.id) })
		f.hub.Close(d.id, agentproto.ClosingRestart)
		within(t, 5*time.Second, "the agent saw the closing", func() bool { return !a.ch.Live() })
		before := rl.heartbeats.Load()
		within(t, 5*time.Second, "heartbeats while the channel is down", func() bool { return rl.heartbeats.Load() >= before+3 })
	})
}

// A frame that was forged or replayed on the way ends the connection and
// never confirms it; the agent keeps its heartbeats.
func TestAgentRefusesForgedAndReplayedFrames(t *testing.T) {
	for name, mode := range map[string]relayMode{"forged": relayForge, "replayed": relayReplay} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, fixtureOpts{timing: fastTiming})
			d := f.device(f.orgA)
			rl := newRelay(t, f, mode)
			a := startAgent(t, f, d, rl.srv.URL, agentOpts{every: 100 * time.Millisecond})
			// Every connection is tampered with at its first tick, so each ends
			// there and the agent tries again.
			within(t, 10*time.Second, "the agent refused the connection and tried again", func() bool { return rl.upgrades.Load() >= 2 })
			before := rl.heartbeats.Load()
			within(t, 5*time.Second, "heartbeats go on", func() bool { return rl.heartbeats.Load() >= before+3 })
			_ = a
		})
	}
	t.Run("a hello signed with a key the agent does not trust", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{timing: fastTiming})
		d := f.device(f.orgA)
		rl := newRelay(t, f, relayPass)
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		a := startAgent(t, f, d, rl.srv.URL, agentOpts{every: 100 * time.Millisecond, key: other})
		within(t, 10*time.Second, "tried", func() bool { return rl.upgrades.Load() >= 1 })
		time.Sleep(300 * time.Millisecond)
		if a.ch.Live() || f.hub.Live(d.id) {
			t.Fatal("a connection the agent could not verify became live")
		}
	})
}

func mkdir(p string) error { return os.MkdirAll(p, 0o700) }
