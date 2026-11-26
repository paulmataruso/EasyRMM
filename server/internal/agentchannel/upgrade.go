package agentchannel

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// Peer is the device whose signed upgrade request was verified.
type Peer struct {
	Device uuid.UUID
	Org    uuid.UUID
	// Key is the device's public key, for the frames it sends.
	Key ed25519.PublicKey
	// Nonce is the upgrade request's nonce, which the hello repeats to bind
	// the connection to the request.
	Nonce string
	// SignedAt is the time in the upgrade request's own signature, on the
	// agent's clock.
	SignedAt time.Time
}

// Refusals of an upgrade. Codes are the ones the agent reads (ADR-0059,
// "Reconnecting, with jitter").
func errNotFound() error { return httpapi.ErrNotFound }

func errHeld() error {
	return &httpapi.Error{Status: http.StatusServiceUnavailable, Code: "held",
		Message: "EasyRMM is being upgraded. Try again in a few minutes.", RetryAfter: 60 * time.Second}
}

func errBusy() error {
	return &httpapi.Error{Status: http.StatusServiceUnavailable, Code: "channel_busy",
		Message: "The server is taking many connections at once. Try again shortly.", RetryAfter: randBetween(10*time.Second, 60*time.Second)}
}

func errFull() error {
	return &httpapi.Error{Status: http.StatusServiceUnavailable, Code: "channel_full",
		Message: "The server has as many agent connections open as it takes.", RetryAfter: randBetween(15*time.Minute, 30*time.Minute)}
}

func errSubprotocol() error {
	return httpapi.BadRequest("The agent channel needs the " + agentproto.ChannelSubprotocol + " subprotocol.")
}

// Upgrade serves one upgrade whose signature the caller verified, and
// returns when the connection ends. A refusal is returned as an error
// before anything is written; once the connection is accepted the result is
// nil.
func (h *Hub) Upgrade(w http.ResponseWriter, r *http.Request, p Peer) error {
	if !h.Enabled() {
		return errNotFound()
	}
	// An organization outside the dev scope never opens a channel.
	if !h.opt.Allowed(p.Org) {
		return errNotFound()
	}
	if h.opt.Held != nil && h.opt.Held() {
		return errHeld()
	}
	if !slices.Contains(subprotocols(r), agentproto.ChannelSubprotocol) {
		return errSubprotocol()
	}
	// Verified upgrades only reach here, so refused ones spend no budget.
	if !h.upgrade.Allow() {
		return errBusy()
	}
	if err := h.reserve(); err != nil {
		return err
	}
	// A ping counts as hearing from the agent, though it is no message.
	heard := make(chan struct{}, 1)
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    []string{agentproto.ChannelSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
		OnPingReceived: func(context.Context, []byte) bool {
			select {
			case heard <- struct{}{}:
			default:
			}
			return true
		},
	})
	if err != nil {
		h.release() // Accept has answered the client
		return nil  //nolint:nilerr // nothing is left to write
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	now := h.opt.Now()
	c := &conn{h: h, id: newConnID(), dev: p.Device, org: p.Org, key: p.Key, authAt: p.SignedAt, opened: now,
		ws: ws, ctx: ctx, cancel: cancel,
		out: make(chan item, queueSize), kick: make(chan struct{}, 1), heard: heard,
		sendLimit: rate.NewLimiter(agentproto.ChannelServerFrameRate, agentproto.ChannelServerFrameBurst),
		inLimit:   rate.NewLimiter(agentproto.ChannelAgentFrameRate, agentproto.ChannelAgentFrameBurst),
		maxAge:    h.tm.MaxAge + randBetween(-h.tm.MaxAge/12, h.tm.MaxAge/12),
	}
	// The hello is the first thing queued, before the connection is known
	// to anything else.
	c.out <- item{m: agentproto.ChannelMessage{Type: agentproto.TypeHello, Nonce: p.Nonce,
		Features: []string{agentproto.FeatureChannel}, Instance: h.opt.Instance}}
	h.register(c)
	h.wg.Add(1)
	c.run()
	return nil
}

func subprotocols(r *http.Request) []string {
	var out []string
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, s := range strings.Split(v, ",") {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// register makes c the device's pending connection. A newer pending
// connection replaces an older one; a confirmed one stays until a heartbeat
// names c.
func (h *Hub) register(c *conn) {
	h.mu.Lock()
	e := h.devices[c.dev]
	if e == nil {
		e = &entry{}
		h.devices[c.dev] = e
	}
	old := e.pending
	e.pending = c
	h.mu.Unlock()
	if old != nil {
		old.closeWith(agentproto.ClosingReplaced)
	}
}

// reserve takes a slot for a connection, or refuses with 503
// channel_full: the configured maximum, and on Linux the descriptors left.
func (h *Hub) reserve() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.total >= h.opt.MaxConns || !h.fd.ok() {
		return errFull()
	}
	h.total++
	h.fd.took()
	return nil
}

func (h *Hub) release() {
	h.mu.Lock()
	h.total--
	h.mu.Unlock()
}

// fdGate refuses connections while too few descriptors are left (ADR-0059,
// "Server limits"): fewer than the larger of 4,096 and a quarter of the
// limit. The reading is at most ttl old, and each connection taken since
// counts against it. Where descriptors are not measured it never refuses.
type fdGate struct {
	read func() (open, limit uint64, ok bool)
	ttl  time.Duration
	log  *slog.Logger

	mu     sync.Mutex
	at     time.Time
	free   uint64
	need   uint64
	closed bool
}

func (g *fdGate) ok() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.read == nil {
		g.read = processDescriptors
	}
	if time.Since(g.at) > g.ttl {
		open, limit, measured := g.read()
		g.at = time.Now()
		if !measured || limit == 0 {
			g.free, g.need = 1<<62, 0
		} else {
			g.free = limit - min(open, limit)
			g.need = max(4096, limit/4)
		}
	}
	refuse := g.free < g.need
	switch {
	case refuse && !g.closed:
		g.log.Warn("agent channel: too few descriptors left; refusing connections", "free", g.free, "needed", g.need)
	case !refuse && g.closed:
		g.log.Info("agent channel: descriptors are enough again; accepting connections")
	}
	g.closed = refuse
	return !refuse
}

func (g *fdGate) took() {
	g.mu.Lock()
	if g.free > 0 {
		g.free--
	}
	g.mu.Unlock()
}
