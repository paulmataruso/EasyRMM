// Package channel is the agent's end of the WebSocket channel (ADR-0059).
//
// The server's heartbeat answer lists the "channel" feature; only then does
// the agent connect. Every frame the server sends is checked (the job
// key's signature, the device, the connection id, the sequence), the agent
// confirms the connection through its next signed heartbeat (Report), and a
// verified wake makes the runner check in at once. The channel only ever
// shortens the wait: the heartbeat keeps its own timer, so a channel that is
// off, down, refused or hostile leaves the device working as it did.
package channel

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Dialer opens the connection; *client.Client is one.
type Dialer interface {
	DialChannel(ctx context.Context) (conn *websocket.Conn, nonce string, err error)
}

var _ Dialer = (*client.Client)(nil)

// Wake is a verified wake from the server.
type Wake struct {
	What   string
	Reason string
}

// Timing is the channel's clocks, shortened by tests.
type Timing struct {
	Hello      time.Duration // the hello after the 101 (10 s)
	Idle       time.Duration // silence from the server before the agent closes (75 s)
	Ping       time.Duration // the agent's WebSocket ping (30 s)
	FirstWait  time.Duration // the random wait after a first failure (30 s)
	MinRetry   time.Duration // backoff's first step (5 s)
	MaxRetry   time.Duration // backoff's ceiling (5 min)
	SleepCheck time.Duration // how often the clocks are compared (5 s)
	SleepJump  time.Duration // how far the wall clock outruns the monotonic one (30 s)
	Dial       time.Duration // the upgrade's own limit (30 s)
}

func (t *Timing) defaults() {
	set := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	set(&t.Hello, agentproto.ChannelHelloWithin)
	set(&t.Idle, agentproto.ChannelIdle)
	set(&t.Ping, agentproto.ChannelTickEvery)
	set(&t.FirstWait, 30*time.Second)
	set(&t.MinRetry, 5*time.Second)
	set(&t.MaxRetry, 5*time.Minute)
	set(&t.SleepCheck, 5*time.Second)
	set(&t.SleepJump, 30*time.Second)
	set(&t.Dial, 30*time.Second)
}

// maxRetryAfter caps the server's Retry-After, which is not signed.
const maxRetryAfter = 30 * time.Minute

// stopAfter is how many verified messages the agent did not list it takes
// from one server instance before it stops connecting.
const stopAfter = 3

// Config makes a Channel.
type Config struct {
	Dialer   Dialer
	DeviceID string
	// Key returns the pinned job-signing key, nil while none is pinned.
	Key func() ed25519.PublicKey
	Log *slog.Logger
	// Off is the agent-side switch: an agent that is off never connects,
	// whatever the server lists.
	Off    bool
	Timing Timing
}

// Channel is one agent's channel.
type Channel struct {
	cfg   Config
	wakes chan Wake
	// changed wakes the loop when Answered changed what it waits for.
	changed chan struct{}

	mu       sync.Mutex
	armed    bool   // the last answer listed channel and nothing since forbids it
	removing bool   // the last answer carried an uninstall
	held     bool   // the server closed as removed; wait for a heartbeat to say more
	stopped  string // the instance whose unlisted messages stopped the agent
	instance string // the instance of the last heartbeat answer
	unlisted map[string]int
	live     *agentproto.ChannelReport
	cancel   context.CancelFunc // ends the current session
	fails    int
}

// New returns a channel that has not connected.
func New(cfg Config) *Channel {
	cfg.Timing.defaults()
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	return &Channel{cfg: cfg, wakes: make(chan Wake, 8), changed: make(chan struct{}, 1), unlisted: map[string]int{}}
}

// Wakes delivers the wakes the server sent. A wake that finds the buffer
// full is dropped: whatever it asked for, one check-in does.
func (c *Channel) Wakes() <-chan Wake { return c.wakes }

// Live says whether a verified connection is up.
func (c *Channel) Live() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.live != nil
}

// Report is what the next heartbeat says of the connection held, nil for
// none: it is what confirms the connection (ADR-0059).
func (c *Channel) Report() *agentproto.ChannelReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.live == nil {
		return nil
	}
	r := *c.live
	return &r
}

// Answered takes each heartbeat answer; reported says that the heartbeat
// carried the agent's channel capability. The agent connects once an answer
// to such a heartbeat lists the channel (the server refuses a device that
// has not reported it), and a later answer that does not list it ends the
// connection. An answer that lists it to a heartbeat that did not carry the
// capability, the first of a process, brings the next check-in forward.
func (c *Channel) Answered(r *agentproto.HeartbeatResponse, reported bool) {
	if r == nil {
		return
	}
	listed := slices.Contains(r.Features, agentproto.FeatureChannel)
	if listed && !reported {
		c.emit(Wake{What: agentproto.WakeCheckin, Reason: "capability"})
		c.mu.Lock()
		c.instance, c.removing = r.Instance, r.Uninstall != nil
		c.mu.Unlock()
		return
	}
	c.mu.Lock()
	c.instance = r.Instance
	c.removing = r.Uninstall != nil
	if r.Uninstall == nil {
		c.held = false
	}
	if c.stopped != "" && r.Instance != c.stopped {
		c.stopped = ""
	}
	c.armed = listed && !c.cfg.Off
	cancel := c.cancel
	drop := !listed && cancel != nil
	c.mu.Unlock()
	if drop {
		cancel()
	}
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

func (c *Channel) ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.armed && !c.removing && !c.held && c.stopped == ""
}

// Run connects, and connects again, until ctx ends.
func (c *Channel) Run(ctx context.Context) {
	for ctx.Err() == nil {
		if !c.ready() {
			select {
			case <-ctx.Done():
				return
			case <-c.changed:
			}
			continue
		}
		delay := c.session(ctx)
		if delay <= 0 {
			continue
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// randUpTo is a random duration in [0, d].
func randUpTo(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d) + 1)) //nolint:gosec // timing jitter, not security
}

// failure counts a connection that ended without a signed closing and
// returns how long to wait: up to FirstWait the first time, then
// exponential backoff with full jitter from MinRetry up to MaxRetry.
func (c *Channel) failure() time.Duration {
	c.mu.Lock()
	c.fails++
	n := c.fails
	c.mu.Unlock()
	if n == 1 {
		return randUpTo(c.cfg.Timing.FirstWait)
	}
	step := c.cfg.Timing.MinRetry
	for i := 2; i < n && step < c.cfg.Timing.MaxRetry; i++ {
		step *= 2
	}
	return randUpTo(min(step, c.cfg.Timing.MaxRetry))
}

func (c *Channel) resetFailures() {
	c.mu.Lock()
	c.fails = 0
	c.mu.Unlock()
}

// session makes one connection and returns how long to wait before the
// next. A wait of 0 means try again at once if still ready.
func (c *Channel) session(parent context.Context) time.Duration {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	c.mu.Lock()
	c.cancel = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.cancel, c.live = nil, nil
		c.mu.Unlock()
	}()

	began := time.Now()
	dctx, dcancel := context.WithTimeout(ctx, c.cfg.Timing.Dial)
	ws, nonce, err := c.cfg.Dialer.DialChannel(dctx)
	dcancel()
	if err != nil {
		return c.refused(ctx, err)
	}
	defer func() { _ = ws.CloseNow() }()
	return c.serve(ctx, ws, nonce, began)
}

// refused decides what a failed upgrade means.
func (c *Channel) refused(ctx context.Context, err error) time.Duration {
	if ctx.Err() != nil {
		return 0
	}
	var e *client.Error
	if errors.As(err, &e) {
		switch {
		case e.Status == 404:
			// Not supported here: nothing until a heartbeat lists channel again.
			c.mu.Lock()
			c.armed = false
			c.mu.Unlock()
			c.cfg.Log.Info("the server has no channel; the agent keeps checking in")
			return 0
		case (e.Status == 429 || e.Status == 503) && isChannelCode(e.Code) && e.RetryAfter > 0:
			c.cfg.Log.Info("the server asked the agent to wait before connecting", "code", e.Code)
			return min(e.RetryAfter, maxRetryAfter)
		case e.Status == 401 && e.Code == "replayed":
			c.cfg.Log.Warn("the channel's upgrade request was used by someone else; the connection is not trusted")
		}
	}
	c.cfg.Log.Info("connecting the channel failed; the agent keeps checking in", "error", err)
	return c.failure()
}

func isChannelCode(code string) bool {
	switch code {
	case "rate_limited", "channel_busy", "channel_full", "held":
		return true
	}
	return false
}

// serve holds one connection: the hello, then every frame, until it ends.
func (c *Channel) serve(ctx context.Context, ws *websocket.Conn, nonce string, began time.Time) time.Duration {
	t := c.cfg.Timing
	hctx, hcancel := context.WithTimeout(ctx, t.Hello)
	_, first, err := ws.Read(hctx)
	hcancel()
	if err != nil {
		c.cfg.Log.Info("no hello from the server's channel", "error", err)
		return c.failure()
	}
	hello, ok := c.verify(first)
	if !ok {
		c.cfg.Log.Warn("the server's first channel frame did not verify; closing")
		return c.failure()
	}
	if hello.Type != agentproto.TypeHello || hello.Seq != 1 || hello.DeviceID != c.cfg.DeviceID ||
		hello.Nonce != nonce || hello.ConnID == "" || !slices.Contains(hello.Features, agentproto.FeatureChannel) {
		c.cfg.Log.Warn("the server's hello is not for this connection; closing")
		return c.failure()
	}
	connID := hello.ConnID
	c.mu.Lock()
	if prev := c.instance; hello.Instance != "" && prev != "" && prev != hello.Instance {
		// A server that restarted is not a failing one.
		c.fails = 0
	}
	c.instance = hello.Instance
	c.live = &agentproto.ChannelReport{ConnID: connID, Since: began.Unix()}
	c.mu.Unlock()
	c.resetFailures()
	c.cfg.Log.Info("the channel is up")
	// Check in at once: the heartbeat names the connection and confirms it.
	c.emit(Wake{What: agentproto.WakeCheckin, Reason: "connected"})

	slept := make(chan struct{})
	gctx, gcancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.ping(gctx, ws) }()
	go func() { defer wg.Done(); c.watchSleep(gctx, ws, slept) }()
	defer wg.Wait()
	defer func() { _ = ws.CloseNow() }()
	defer gcancel()

	seq := uint64(1)
	for {
		rctx, rcancel := context.WithTimeout(ctx, t.Idle)
		_, frame, err := ws.Read(rctx)
		rcancel()
		if err != nil {
			select {
			case <-slept:
				return 0
			default:
			}
			if ctx.Err() != nil {
				return 0
			}
			c.cfg.Log.Info("the channel ended without a closing; the agent keeps checking in", "error", err)
			return c.failure()
		}
		m, ok := c.verify(frame)
		if !ok {
			c.cfg.Log.Warn("a channel frame did not verify; closing the connection")
			return c.failure()
		}
		seq++
		if err := m.Check(c.cfg.DeviceID, connID, seq); err != nil {
			c.cfg.Log.Warn("a channel frame names another device or connection, or breaks the sequence; closing the connection")
			return c.failure()
		}
		if len(frame) > agentproto.MaxChannelFrame && !bigType(m.Type) {
			c.cfg.Log.Warn("a channel frame is larger than its type allows; closing the connection")
			return c.failure()
		}
		switch m.Type {
		case agentproto.TypeTick:
		case agentproto.TypeWake:
			if m.What != agentproto.WakeCheckin && m.What != agentproto.WakeJobs {
				return c.unlistedMessage(hello.Instance, m)
			}
			c.emit(Wake{What: m.What, Reason: m.Reason})
		case agentproto.TypeClosing:
			if d, ok := c.closing(m); ok {
				return d
			}
			return c.unlistedMessage(hello.Instance, m)
		default:
			return c.unlistedMessage(hello.Instance, m)
		}
	}
}

func bigType(t string) bool {
	return t == agentproto.TypeJobs || t == agentproto.TypeRepair || t == agentproto.TypeSettings
}

func (c *Channel) verify(frame []byte) (agentproto.ChannelMessage, bool) {
	key := c.cfg.Key()
	if key == nil {
		return agentproto.ChannelMessage{}, false
	}
	m, err := agentproto.VerifyChannelMessage(key, frame, agentproto.MaxChannelBigFrame)
	return m, err == nil
}

func (c *Channel) emit(w Wake) {
	select {
	case c.wakes <- w:
	default:
	}
}

// closing returns the wait after a signed closing, false for a reason the
// agent does not list.
func (c *Channel) closing(m agentproto.ChannelMessage) (time.Duration, bool) {
	within := time.Duration(m.ReconnectWithin) * time.Second
	c.resetFailures()
	switch m.Reason {
	case agentproto.ClosingRestart:
		if within <= 0 {
			within = time.Minute
		}
	case agentproto.ClosingRefresh:
		if within <= 0 {
			within = 5 * time.Minute
		}
	case agentproto.ClosingReplaced:
		c.cfg.Log.Warn("another connection opened as this device; another computer may be using this identity")
		if within <= 0 || within > 5*time.Minute {
			within = 5 * time.Minute
		}
	case agentproto.ClosingRemoved:
		// Not again until a heartbeat answer says whether the removal stands.
		c.mu.Lock()
		c.held = true
		c.mu.Unlock()
		return 0, true
	default:
		return 0, false
	}
	return randUpTo(within), true
}

// unlistedMessage handles a verified message the agent did not list: a
// server's bug, not the network's. It closes the connection and counts
// nothing as a failure; after three from one instance the agent stops until
// another instance answers.
func (c *Channel) unlistedMessage(instance string, m agentproto.ChannelMessage) time.Duration {
	c.mu.Lock()
	c.unlisted[instance]++
	n := c.unlisted[instance]
	if n >= stopAfter {
		c.stopped = instance
	}
	c.mu.Unlock()
	c.cfg.Log.Warn("the server sent a channel message this agent does not list; closing the connection", "type", m.Type, "count", n)
	if n >= stopAfter {
		c.cfg.Log.Error("the channel is stopped: the server keeps sending messages this agent does not list; the agent keeps checking in")
		return 0
	}
	return randUpTo(time.Minute)
}

// ping sends the agent's WebSocket pings, the only thing it sends.
func (c *Channel) ping(ctx context.Context, ws *websocket.Conn) {
	t := time.NewTicker(c.cfg.Timing.Ping)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, c.cfg.Timing.Idle)
			err := ws.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

// watchSleep notices a computer that slept: the wall clock (monotonic
// reading dropped) moved further than the time that passed on the
// monotonic one. Its connection is probably dead, so it is closed, and
// reconnecting at once costs nothing (ADR-0059).
func (c *Channel) watchSleep(ctx context.Context, ws *websocket.Conn, slept chan<- struct{}) {
	t := time.NewTicker(c.cfg.Timing.SleepCheck)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		if now.Round(0).Sub(last.Round(0))-now.Sub(last) > c.cfg.Timing.SleepJump {
			close(slept)
			_ = ws.CloseNow()
			return
		}
		last = now
	}
}
