// Package agentchannel is the server's end of the agent's WebSocket channel
// (ADR-0059): the upgrade, the registry of connections, the keepalives, the
// limits and what may be sent to whom. It reads no instruction and knows
// nothing of jobs: whatever is pushed, or claimed for a connection, comes
// from the code that decides it.
//
// The rule everything here follows: a connection is trusted only once a
// signed heartbeat of its device has named it. The upgrade's signature does
// not cover the connection, so something on the path that held back one
// upgrade request could open a connection as the device. Until a heartbeat
// names it, a connection is pending and receives hello, tick and closing;
// no push reaches it, no claim runs for it, and nothing is marked sent for
// it.
package agentchannel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// ClaimFunc claims what is waiting for a device and returns it for a jobs
// frame. It marks what it returns as sent, so the hub calls it only for a
// confirmed connection. maxBytes is the most the frame may take; a claim
// that does not fit must be left unclaimed (the heartbeat's jobsWaiting
// then makes the agent poll). It returns nil when nothing waits.
type ClaimFunc func(ctx context.Context, device uuid.UUID, maxBytes int) (*agentproto.PollResponse, error)

// LogBatchFunc stores a batch an agent sent and returns the ack to send
// back, or nil for none.
type LogBatchFunc func(ctx context.Context, device uuid.UUID, b agentproto.LogBatch) (*agentproto.LogAck, error)

// Timing holds the intervals the hub runs on; the zero value of a field
// means the ADR's figure. Tests shorten them.
type Timing struct {
	Tick          time.Duration // the server's keepalive
	Idle          time.Duration // silence after which the hub closes
	Write         time.Duration // a write's limit
	Sweep         time.Duration // the sweep's interval
	ConfirmWithin time.Duration // how long a connection may stay pending
	ContradictFor time.Duration // a contradicted connection's grace
	MaxAge        time.Duration // a connection's life before refresh
	HeldCheck     time.Duration // how often the hold is looked at
	DescriptorTTL time.Duration // how old the descriptor reading may be
}

func (t Timing) filled() Timing {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&t.Tick, agentproto.ChannelTickEvery)
	def(&t.Idle, agentproto.ChannelIdle)
	def(&t.Write, agentproto.ChannelWriteWithin)
	def(&t.Sweep, 30*time.Second)
	def(&t.ConfirmWithin, 2*time.Minute)
	def(&t.ContradictFor, 40*time.Second)
	def(&t.MaxAge, agentproto.ChannelMaxAge)
	def(&t.HeldCheck, time.Second)
	def(&t.DescriptorTTL, 5*time.Second)
	return t
}

// Options configure a Hub.
type Options struct {
	// Enabled is the server-wide switch (EASYRMM_AGENT_CHANNEL). Off, the
	// hub offers nothing and every method does nothing.
	Enabled bool
	// Key signs every frame the server sends: the job key.
	Key ed25519.PrivateKey
	// Instance is the ID this server process drew at its start.
	Instance string
	// MaxConns is the most connections at once; 0 means the default.
	MaxConns int
	// UpgradesPerSecond is the most verified upgrades a second; 0 means the
	// default.
	UpgradesPerSecond int
	Timing            Timing
	// Claim and OnLogBatch are optional.
	Claim      ClaimFunc
	OnLogBatch LogBatchFunc
	// Held says whether the updater holds the server.
	Held func() bool
	// Allowed says whether an organization may be reached by new behavior;
	// devscope.Allowed when nil.
	Allowed func(org uuid.UUID) bool
	// Descriptors reports the open descriptors and the limit, for the
	// gate; the process's own when nil. ok is false where they are not
	// measured.
	Descriptors func() (open, limit uint64, ok bool)
	Log         *slog.Logger
	Now         func() time.Time
}

// Hub is the registry of connections.
type Hub struct {
	opt     Options
	tm      Timing
	log     *slog.Logger
	upgrade *rate.Limiter
	wg      sync.WaitGroup

	mu       sync.Mutex
	devices  map[uuid.UUID]*entry
	total    int // connections, and slots reserved by upgrades in progress
	waiting  map[uuid.UUID]struct{}
	heldSeen bool

	wakeMu  sync.Mutex
	wakeQ   []uuid.UUID
	wakeSet map[uuid.UUID]string

	fd fdGate
}

// entry is a device's connections: at most one confirmed and one pending.
type entry struct {
	confirmed, pending *conn
	lastHeartbeat      time.Time
}

// New returns a Hub.
func New(o Options) *Hub {
	if o.MaxConns <= 0 {
		o.MaxConns = agentproto.ChannelConnectionsMax
	}
	if o.UpgradesPerSecond <= 0 {
		o.UpgradesPerSecond = agentproto.ChannelUpgradesPerSecond
	}
	if o.Allowed == nil {
		o.Allowed = devscope.Allowed
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	h := &Hub{opt: o, tm: o.Timing.filled(), log: o.Log,
		upgrade: rate.NewLimiter(rate.Limit(o.UpgradesPerSecond), o.UpgradesPerSecond),
		devices: map[uuid.UUID]*entry{}, waiting: map[uuid.UUID]struct{}{}}
	h.fd = fdGate{read: o.Descriptors, ttl: h.tm.DescriptorTTL, log: h.log}
	return h
}

// SetHeld tells the hub how to tell that the updater holds the server. Call
// it before Run.
func (h *Hub) SetHeld(f func() bool) { h.opt.Held = f }

// UseClaim sets the claim loop's function and UseLogBatch the one that stores
// a log batch; both are for the code that decides, and are set before Run.
func (h *Hub) UseClaim(f ClaimFunc)       { h.opt.Claim = f }
func (h *Hub) UseLogBatch(f LogBatchFunc) { h.opt.OnLogBatch = f }

// Enabled says whether the channel is on. False for a nil hub.
func (h *Hub) Enabled() bool { return h != nil && h.opt.Enabled }

// Instance is the ID this server process drew at its start.
func (h *Hub) Instance() string { return h.opt.Instance }

// Connections is how many connections are open.
func (h *Hub) Connections() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, e := range h.devices {
		n += len(e.conns())
	}
	return n
}

func (e *entry) conns() []*conn {
	var out []*conn
	if e.confirmed != nil {
		out = append(out, e.confirmed)
	}
	if e.pending != nil {
		out = append(out, e.pending)
	}
	return out
}

// Live says whether the device has a confirmed connection.
func (h *Hub) Live(device uuid.UUID) bool {
	if !h.Enabled() {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.devices[device]
	return e != nil && e.confirmed != nil && e.confirmed.contradictedAt.IsZero()
}

// Heartbeat takes what a verified heartbeat of the device says of its
// connection (ADR-0059, "Presence confirmed by the heartbeat"): signedAt is
// the heartbeat's own signed time. A heartbeat that carries no report, or
// that was signed before the latest one processed, neither confirms nor
// contradicts anything.
func (h *Hub) Heartbeat(device uuid.UUID, rep *agentproto.ChannelReport, signedAt time.Time) {
	if !h.Enabled() {
		return
	}
	h.mu.Lock()
	e := h.devices[device]
	if e == nil || signedAt.Before(e.lastHeartbeat) {
		h.mu.Unlock()
		return
	}
	e.lastHeartbeat = signedAt
	if rep == nil || rep.ConnID == "" { // no connection held: nothing to confirm or contradict
		h.mu.Unlock()
		return
	}
	var (
		promote *conn
		replace *conn
		drop    []*conn
	)
	for _, c := range e.conns() {
		if c.id == rep.ConnID {
			if c == e.pending {
				promote = c
			} else {
				c.contradictedAt = time.Time{}
			}
			continue
		}
		if signedAt.Sub(c.authAt) <= agentproto.ChannelContradictAfter {
			continue // not judged: the heartbeat may predate the upgrade
		}
		if c == e.pending {
			drop = append(drop, c)
		} else if c.contradictedAt.IsZero() {
			c.contradictedAt = h.opt.Now()
		}
	}
	if promote != nil {
		replace = e.confirmed
		e.confirmed, e.pending = promote, nil
		promote.confirmed = true
		promote.contradictedAt = time.Time{}
	}
	for _, c := range drop {
		if e.pending == c {
			e.pending = nil
		}
	}
	h.mu.Unlock()

	for _, c := range drop {
		c.closeWith(agentproto.ClosingReplaced)
	}
	if replace != nil {
		replace.closeWith(agentproto.ClosingReplaced)
	}
	if promote != nil {
		promote.startClaims()
		promote.kickNow()
	}
}

// Push sends m to the device's confirmed connection and says whether it was
// queued. Only wake, jobs, logs, repair and settings go this way; the hub
// fills in the envelope. It is false when the channel is off, the device
// has no confirmed connection (a pending one gets nothing), its
// organization is outside the dev scope, the device is past its rate, the
// frame is over its cap, or the connection's queue is full. A push that
// fails is never an error: the heartbeat and the poll carry it.
func (h *Hub) Push(device uuid.UUID, m agentproto.ChannelMessage) bool {
	if !h.Enabled() {
		return false
	}
	switch m.Type {
	case agentproto.TypeWake, agentproto.TypeJobs, agentproto.TypeLogs, agentproto.TypeRepair, agentproto.TypeSettings:
	default:
		return false
	}
	h.mu.Lock()
	e := h.devices[device]
	var c *conn
	if e != nil {
		c = e.confirmed
	}
	h.mu.Unlock()
	if c == nil || !c.pushable() {
		return false
	}
	if !h.opt.Allowed(c.org) {
		return false
	}
	if m.Type == agentproto.TypeJobs && !fits(m) {
		h.markWaiting(device)
		return false
	}
	if !fits(m) || !c.sendLimit.Allow() {
		return false
	}
	return c.enqueue(m, false)
}

// Kick asks the device's confirmed connection to claim what waits for it:
// when a run is queued or canceled. Nothing happens for a pending one.
func (h *Hub) Kick(device uuid.UUID) {
	if !h.Enabled() {
		return
	}
	h.mu.Lock()
	e := h.devices[device]
	var c *conn
	if e != nil {
		c = e.confirmed
	}
	h.mu.Unlock()
	if c != nil {
		c.kickNow()
	}
}

// TakeJobsWaiting says, once, whether a jobs frame for the device was too
// big to push: the heartbeat answer's jobsWaiting then has the agent make
// an ordinary poll.
func (h *Hub) TakeJobsWaiting(device uuid.UUID) bool {
	if !h.Enabled() {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.waiting[device]
	delete(h.waiting, device)
	return ok
}

func (h *Hub) markWaiting(device uuid.UUID) {
	h.mu.Lock()
	h.waiting[device] = struct{}{}
	h.mu.Unlock()
}

// Close closes the device's connections with a closing message, such as
// removed when the device is deleted.
func (h *Hub) Close(device uuid.UUID, reason string) {
	if !h.Enabled() {
		return
	}
	h.mu.Lock()
	e := h.devices[device]
	var cs []*conn
	if e != nil {
		cs = e.conns()
		delete(h.devices, device)
	}
	delete(h.waiting, device)
	h.mu.Unlock()
	for _, c := range cs {
		c.closeWith(reason)
	}
}

// closeAll closes every connection with reason.
func (h *Hub) closeAll(reason string) {
	h.mu.Lock()
	var cs []*conn
	for _, e := range h.devices {
		cs = append(cs, e.conns()...)
	}
	h.mu.Unlock()
	for _, c := range cs {
		c.closeWith(reason)
	}
}

// Run keeps the hub's periodic work going until ctx ends: the sweep, and
// the hold, which closes every connection with restart when the updater
// takes it. When ctx ends it closes every connection with restart and waits
// for them.
func (h *Hub) Run(ctx context.Context) {
	if !h.Enabled() {
		return
	}
	sweep := time.NewTicker(h.tm.Sweep)
	held := time.NewTicker(h.tm.HeldCheck)
	defer sweep.Stop()
	defer held.Stop()
	wctx, stopWakes := context.WithCancel(ctx)
	defer stopWakes()
	go h.releaseWakes(wctx)
	for {
		select {
		case <-ctx.Done():
			h.closeAll(agentproto.ClosingRestart)
			done := make(chan struct{})
			go func() { h.wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
			return
		case <-sweep.C:
			h.Sweep()
		case <-held.C:
			if h.opt.Held != nil {
				now := h.opt.Held()
				if now && !h.heldSeen {
					h.closeAll(agentproto.ClosingRestart)
				}
				h.heldSeen = now
			}
		}
	}
}

// Sweep does the periodic checks once: connections of organizations outside
// the dev scope are closed (refresh), a pending connection no heartbeat
// confirmed in time is closed, a contradicted one is told it was replaced
// after its grace, an old one is refreshed, and every confirmed connection
// of an organization in scope claims what waits for it, so that
// redeliveries need no wake.
func (h *Hub) Sweep() {
	if !h.Enabled() {
		return
	}
	type act struct {
		c      *conn
		reason string
		kick   bool
	}
	var acts []act
	now := h.opt.Now()
	h.mu.Lock()
	for _, e := range h.devices {
		for _, c := range e.conns() {
			switch {
			case !h.opt.Allowed(c.org):
				acts = append(acts, act{c: c, reason: agentproto.ClosingRefresh})
			case c == e.pending && now.Sub(c.opened) > h.tm.ConfirmWithin:
				acts = append(acts, act{c: c, reason: agentproto.ClosingRefresh})
			case !c.contradictedAt.IsZero() && now.Sub(c.contradictedAt) >= h.tm.ContradictFor:
				acts = append(acts, act{c: c, reason: agentproto.ClosingReplaced})
			case now.Sub(c.opened) > c.maxAge:
				acts = append(acts, act{c: c, reason: agentproto.ClosingRefresh})
			case c == e.confirmed:
				acts = append(acts, act{c: c, kick: true})
			}
		}
	}
	h.mu.Unlock()
	for _, a := range acts {
		if a.kick {
			a.c.kickNow()
		} else {
			a.c.closeWith(a.reason)
		}
	}
}

// remove forgets c.
func (h *Hub) remove(c *conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.devices[c.dev]; e != nil {
		if e.confirmed == c {
			e.confirmed = nil
		}
		if e.pending == c {
			e.pending = nil
		}
		if e.confirmed == nil && e.pending == nil {
			delete(h.devices, c.dev)
			delete(h.waiting, c.dev)
		}
	}
	h.total--
}

// fits says whether m, signed and framed, is within its type's cap.
func fits(m agentproto.ChannelMessage) bool {
	b, err := json.Marshal(m)
	if err != nil {
		return false
	}
	// base64 of the payload, the signature, the envelope and a sequence
	// number the hub adds.
	n := (len(b)+2)/3*4 + 88 + 64
	return n <= capOf(m.Type)
}

func capOf(typ string) int {
	switch typ {
	case agentproto.TypeJobs, agentproto.TypeRepair, agentproto.TypeSettings:
		return agentproto.MaxChannelBigFrame
	}
	return agentproto.MaxChannelFrame
}

// reasons the agent waits before reconnecting, in seconds.
func reconnectWithin(reason string) int {
	switch reason {
	case agentproto.ClosingRestart:
		return 60
	case agentproto.ClosingRefresh, agentproto.ClosingReplaced:
		return 300
	}
	return 0
}

func newConnID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// randBetween returns a random duration in [lo, hi].
func randBetween(lo, hi time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)+1))
	if err != nil {
		return lo
	}
	return lo + time.Duration(n.Int64())
}
