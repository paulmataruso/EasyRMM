package agentchannel

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// queueSize is how many messages may wait for a connection's writer. A
// connection whose queue is full is closed: it is not reading.
const queueSize = 16

type item struct {
	m     agentproto.ChannelMessage
	final bool
}

// conn is one agent connection.
type conn struct {
	h      *Hub
	id     string
	dev    uuid.UUID
	org    uuid.UUID
	key    ed25519.PublicKey
	authAt time.Time // the upgrade request's own signed time
	opened time.Time
	ws     *websocket.Conn
	ctx    context.Context
	cancel context.CancelCauseFunc

	out    chan item
	kick   chan struct{}
	finish sync.Once
	claims sync.Once

	sendLimit *rate.Limiter // pushes, 20 a second, burst 50
	inLimit   *rate.Limiter // agent frames, one a second, burst 3
	maxAge    time.Duration

	// Guarded by h.mu.
	confirmed      bool
	contradictedAt time.Time
	closing        bool

	seq   uint64 // the writer's
	inSeq uint64 // the reader's
	heard chan struct{}
}

// pushable says whether pushes may go to c: it is confirmed, not
// contradicted and not closing.
func (c *conn) pushable() bool {
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	return c.confirmed && c.contradictedAt.IsZero() && !c.closing
}

// enqueue queues m without waiting and says whether it was queued. A full
// queue closes the connection.
func (c *conn) enqueue(m agentproto.ChannelMessage, final bool) bool {
	select {
	case c.out <- item{m, final}:
		return true
	default:
		c.kill(errors.New("the outbound queue is full"))
		return false
	}
}

// closeWith tells the agent why the connection ends and closes it.
func (c *conn) closeWith(reason string) {
	c.h.mu.Lock()
	already := c.closing
	c.closing = true
	c.h.mu.Unlock()
	if already {
		return
	}
	c.enqueue(agentproto.ChannelMessage{Type: agentproto.TypeClosing, Reason: reason, ReconnectWithin: reconnectWithin(reason)}, true)
}

// kill ends the connection without a word.
func (c *conn) kill(cause error) {
	c.finish.Do(func() {
		c.cancel(cause)
		_ = c.ws.CloseNow()
	})
}

// violation closes the connection with 1008, for an agent that broke the
// rules of what it may send.
func (c *conn) violation(why string) {
	c.h.log.Warn("agent channel: closing a connection", "device_id", c.dev, "reason", why)
	c.finish.Do(func() {
		// Closed before the context ends: canceling a write in flight
		// would drop the connection without the close frame.
		_ = c.ws.Close(websocket.StatusPolicyViolation, why)
		c.cancel(errors.New(why))
	})
}

func (c *conn) kickNow() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// startClaims starts the claim loop, once, for a confirmed connection. A
// pending connection never has one.
func (c *conn) startClaims() {
	if c.h.opt.Claim == nil {
		return
	}
	c.claims.Do(func() {
		c.h.wg.Add(1)
		go func() {
			defer c.h.wg.Done()
			c.claimLoop()
		}()
	})
}

func (c *conn) claimLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.kick:
		}
		// Checked at each claim: confirmation, contradiction and the dev
		// scope can change between kicks.
		if !c.pushable() || !c.h.opt.Allowed(c.org) {
			continue
		}
		resp, err := c.h.opt.Claim(c.ctx, c.dev, agentproto.MaxChannelBigFrame-4096)
		if err != nil {
			if c.ctx.Err() == nil {
				c.h.log.Warn("agent channel: claiming failed", "error", err, "device_id", c.dev)
			}
			continue
		}
		if resp == nil || (len(resp.Jobs) == 0 && len(resp.Cancel) == 0) {
			continue
		}
		m := agentproto.ChannelMessage{Type: agentproto.TypeJobs, Jobs: resp}
		if !fits(m) {
			// Over the cap: not sent. What was claimed is delivered by the
			// ordinary poll, which the heartbeat's jobsWaiting asks for.
			c.h.markWaiting(c.dev)
			continue
		}
		c.enqueue(m, false)
	}
}

// run serves the connection until it ends. It owns the reader; the writer
// and the idle watch run beside it.
func (c *conn) run() {
	defer c.h.wg.Done()
	defer c.h.remove(c)
	defer c.kill(nil)
	c.h.wg.Add(1)
	go func() {
		defer c.h.wg.Done()
		c.writer()
	}()
	go c.idleWatch()
	c.reader()
}

func (c *conn) writer() {
	tick := time.NewTimer(randBetween(0, c.h.tm.Tick))
	defer tick.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case it := <-c.out:
			if err := c.write(it.m); err != nil {
				c.kill(err)
				return
			}
			if it.final {
				// The reader keeps running, so the peer's close reply is read.
				c.finish.Do(func() {
					_ = c.ws.Close(websocket.StatusNormalClosure, it.m.Reason)
					c.cancel(nil)
				})
				return
			}
		case <-tick.C:
			tick.Reset(c.h.tm.Tick)
			c.h.mu.Lock()
			muted := !c.contradictedAt.IsZero() || c.closing
			c.h.mu.Unlock()
			if muted {
				continue // a contradicted connection is sent nothing
			}
			if err := c.write(agentproto.ChannelMessage{Type: agentproto.TypeTick}); err != nil {
				c.kill(err)
				return
			}
		}
	}
}

// write signs and sends m with the next sequence number. A frame over its
// cap is dropped without using a number.
func (c *conn) write(m agentproto.ChannelMessage) error {
	m.V = agentproto.ChannelVersion
	m.DeviceID = c.dev.String()
	m.ConnID = c.id
	m.Seq = c.seq + 1
	m.SentAt = c.h.opt.Now().UTC()
	frame, err := agentproto.SignChannelMessage(c.h.opt.Key, m)
	if err != nil {
		return err
	}
	if len(frame) > capOf(m.Type) {
		c.h.log.Warn("agent channel: dropping a frame over its cap", "type", m.Type, "device_id", c.dev)
		return nil
	}
	c.seq++
	ctx, cancel := context.WithTimeout(c.ctx, c.h.tm.Write)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageText, frame)
}

// idleWatch closes the connection after Idle without hearing from the agent:
// a frame or a ping.
func (c *conn) idleWatch() {
	t := time.NewTimer(c.h.tm.Idle)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.heard:
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			t.Reset(c.h.tm.Idle)
		case <-t.C:
			c.h.log.Info("agent channel: closing an idle connection", "device_id", c.dev)
			c.kill(errors.New("idle"))
			return
		}
	}
}

func (c *conn) hear() {
	select {
	case c.heard <- struct{}{}:
	default:
	}
}

// reader reads what the agent sends: pings (answered by the library) and
// signed logs.batch frames, within their size and rate caps. Anything else
// closes the connection.
func (c *conn) reader() {
	c.ws.SetReadLimit(agentproto.MaxChannelAgentFrame)
	for {
		typ, data, err := c.ws.Read(c.ctx)
		if err != nil {
			if websocket.CloseStatus(err) == websocket.StatusMessageTooBig {
				c.h.log.Warn("agent channel: an agent frame over its cap", "device_id", c.dev)
			}
			return
		}
		c.hear()
		if typ != websocket.MessageText {
			c.violation("only text frames are accepted")
			return
		}
		if !c.inLimit.Allow() {
			c.violation("agent frames came too fast")
			return
		}
		f, err := agentproto.VerifyChannelAgentFrame(c.key, data)
		switch {
		case err != nil:
			c.violation("an agent frame did not verify")
			return
		case f.ConnID != c.id || f.Seq != c.inSeq+1:
			c.violation("an agent frame names another connection or breaks the sequence")
			return
		case f.Type != agentproto.TypeLogsBatch || f.Batch == nil:
			c.violation("only logs.batch frames are accepted")
			return
		}
		c.inSeq++
		// A pending connection stores nothing: only a confirmed one is the
		// device's own.
		if c.h.opt.OnLogBatch == nil || !c.pushable() {
			continue
		}
		ack, err := c.h.opt.OnLogBatch(c.ctx, c.dev, *f.Batch)
		if err != nil {
			c.h.log.Warn("agent channel: storing a log batch failed", "error", err, "device_id", c.dev)
			continue
		}
		if ack != nil {
			c.enqueue(agentproto.ChannelMessage{Type: agentproto.TypeLogsAck, Ack: ack}, false)
		}
	}
}
