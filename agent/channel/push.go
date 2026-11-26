package channel

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// push hands a verified instruction to its handler, on its own goroutine. It
// is false when the message is one the agent does not list: a type without a
// handler or without its body.
//
// A "logs" message with no body is valid: it ends the instructions.
func (c *Channel) push(ctx context.Context, m agentproto.ChannelMessage, spawn func(func())) bool {
	h := c.cfg.Handlers
	switch m.Type {
	case agentproto.TypeJobs:
		if h.Jobs == nil || m.Jobs == nil {
			return false
		}
		spawn(func() { h.Jobs(ctx, m.Jobs) })
	case agentproto.TypeLogs:
		if h.Logs == nil {
			return false
		}
		h.Logs(m.Logs) // in order, and quick: a later push must not be applied first
	case agentproto.TypeRepair:
		if h.Repair == nil || m.Repair == nil {
			return false
		}
		spawn(func() { h.Repair(ctx, m.Repair) })
	case agentproto.TypeSettings:
		if h.Settings == nil || m.Settings == nil {
			return false
		}
		spawn(func() { h.Settings(ctx, *m.Settings) })
	case agentproto.TypeLogsAck:
		c.mu.Lock()
		s := c.out
		c.mu.Unlock()
		if s == nil || m.Ack == nil {
			return false
		}
		s.ack(*m.Ack)
	}
	return true
}

// Checkin asks the runner for a heartbeat now, such as when a pushed repair
// is done (the wake's own spacing applies).
func (c *Channel) Checkin(reason string) {
	c.emit(Wake{What: agentproto.WakeCheckin, Reason: reason})
}

// ErrNotLive is what SendLogs returns when the batch should go the usual
// way, over HTTPS: no live connection, no key, a batch too big, too soon
// after the last one, or the server did not answer lately.
var ErrNotLive = errors.New("channel: not live for log batches")

// SendLogs sends a batch as a signed logs.batch frame and waits for the
// server's logs.ack. Any error means the caller sends the batch over HTTPS,
// which stores the same rows (the server dedupes by device and sequence).
func (c *Channel) SendLogs(ctx context.Context, b agentproto.LogBatch) (agentproto.LogAck, error) {
	c.mu.Lock()
	s := c.out
	c.mu.Unlock()
	if s == nil {
		return agentproto.LogAck{}, ErrNotLive
	}
	return s.send(ctx, b)
}

const (
	// sendEvery is the least gap between two frames: the server takes one a
	// second.
	sendEvery = 1100 * time.Millisecond
	ackWithin = 5 * time.Second
	// muteFor is how long the channel is left alone for batches after the
	// server did not ack one (a connection no heartbeat confirmed yet
	// stores nothing).
	muteFor = 2 * time.Minute
)

// sender writes the agent's frames on one connection.
type sender struct {
	ws     *websocket.Conn
	connID string
	key    ed25519.PrivateKey
	acks   chan agentproto.LogAck

	mu    sync.Mutex
	seq   uint64
	last  time.Time
	muted time.Time
}

func newSender(ws *websocket.Conn, connID string, key ed25519.PrivateKey) *sender {
	return &sender{ws: ws, connID: connID, key: key, acks: make(chan agentproto.LogAck, 1)}
}

func (s *sender) ack(a agentproto.LogAck) {
	select {
	case s.acks <- a:
	default:
	}
}

func (s *sender) send(ctx context.Context, b agentproto.LogBatch) (agentproto.LogAck, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Before(s.muted) || now.Sub(s.last) < sendEvery {
		return agentproto.LogAck{}, ErrNotLive
	}
	select { // an ack that came late belongs to an earlier batch
	case <-s.acks:
	default:
	}
	frame, err := agentproto.SignChannelAgentFrame(s.key, agentproto.ChannelAgentFrame{
		Type: agentproto.TypeLogsBatch, ConnID: s.connID, Seq: s.seq + 1, Batch: &b})
	if err != nil || len(frame) > agentproto.MaxChannelAgentFrame {
		return agentproto.LogAck{}, ErrNotLive
	}
	s.seq++
	s.last = now
	wctx, cancel := context.WithTimeout(ctx, ackWithin)
	defer cancel()
	if err := s.ws.Write(wctx, websocket.MessageText, frame); err != nil {
		return agentproto.LogAck{}, err
	}
	select {
	case a := <-s.acks:
		return a, nil
	case <-wctx.Done():
		s.muted = time.Now().Add(muteFor)
		return agentproto.LogAck{}, ErrNotLive
	}
}

// LogSender returns a send function for the log shipper: a batch goes over
// the channel while following says someone watches and the channel can take
// it, and by fallback otherwise. Any failure on the channel sends the same
// batch by fallback (HTTPS), which stores the same rows once: the server
// dedupes by device and sequence.
func (c *Channel) LogSender(following func() bool, fallback func(context.Context, agentproto.LogBatch) (agentproto.LogAck, error)) func(context.Context, agentproto.LogBatch) (agentproto.LogAck, error) {
	return func(ctx context.Context, b agentproto.LogBatch) (agentproto.LogAck, error) {
		if following() {
			if ack, err := c.SendLogs(ctx, b); err == nil {
				return ack, nil
			}
		}
		return fallback(ctx, b)
	}
}
