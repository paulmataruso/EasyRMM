package logship

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/logredact"
)

// SendFunc sends a batch, signed, and returns the server's answer. It
// returns ErrUnsupported for a server that has no endpoint for logs.
type SendFunc func(ctx context.Context, b agentproto.LogBatch) (agentproto.LogAck, error)

// ErrUnsupported is the answer of a server that takes no logs.
var ErrUnsupported = errors.New("logship: the server does not take agent logs")

// Batch limits: a batch of at most MaxLogBatch records and about maxBatchBytes.
const maxBatchBytes = 256 << 10

// Shipper buffers records and sends them. It sends every Every, and every
// FollowEvery while the server says someone watches; it logs at Debug while
// the server says verbose, and the agent ends both by itself when their time
// has passed.
type Shipper struct {
	Buf *Buffer
	// Level is the agent's log level: Info, or Debug while verbose. Make
	// the logger's handler with NewHandler.
	Level *slog.LevelVar
	// Tails are read for new lines before each send.
	Tails []*Tail
	// Log receives the Shipper's own diagnostics.
	Log *slog.Logger
	// Timing and the clock, replaced by tests.
	Every, FollowEvery, Unsupported time.Duration
	Now                             func() time.Time

	mu           sync.Mutex
	verboseUntil time.Time
	followUntil  time.Time
	failures     int
	wake         chan struct{}
}

// New returns a Shipper over buf, logging at Info.
func New(buf *Buffer) *Shipper {
	lv := &slog.LevelVar{}
	lv.Set(slog.LevelInfo)
	s := &Shipper{Buf: buf, Level: lv, wake: make(chan struct{}, 1)}
	// Set here, so that defaults never writes while the Shipper runs.
	s.defaults()
	return s
}

func (s *Shipper) defaults() {
	if s.Every == 0 {
		s.Every = agentproto.LogEvery
	}
	if s.FollowEvery == 0 {
		s.FollowEvery = agentproto.LogFollowEvery
	}
	if s.Unsupported == 0 {
		s.Unsupported = 10 * time.Minute
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Log == nil {
		s.Log = slog.New(slog.DiscardHandler)
	}
}

// add queues a record. A record that cannot be stored is lost: logging
// never fails the agent.
func (s *Shipper) add(r agentproto.LogRecord) {
	_, _ = s.Buf.Append(r)
}

// Record queues a record about another program, which the agent observes
// itself: the message and the attributes are redacted and bounded as the
// agent's own are.
func (s *Shipper) Record(source, level, message string, attrs map[string]string) {
	if s == nil {
		return
	}
	r := agentproto.LogRecord{Time: s.Now().UTC(), Source: source, Level: level, Message: Clip(logredact.Text(message), agentproto.MaxLogMessage)}
	for k, v := range attrs {
		if len(r.Attrs) >= agentproto.MaxLogAttributes {
			break
		}
		if r.Attrs == nil {
			r.Attrs = map[string]string{}
		}
		k = Clip(k, agentproto.MaxLogAttrName)
		r.Attrs[k] = logredact.Attr(k, Clip(v, agentproto.MaxLogAttrValue))
	}
	s.add(r)
}

// Apply takes the server's instructions: nil means none, which is the end
// of verbose mode and of following. Neither lasts longer than the agent's
// own limits, whatever the answer says.
func (s *Shipper) Apply(in *agentproto.LogInstructions) {
	if s == nil {
		return
	}
	s.defaults()
	now := s.Now()
	var verbose, follow time.Time
	if in != nil {
		verbose = clampUntil(in.VerboseUntil, now, agentproto.MaxVerbose)
		follow = clampUntil(in.FollowUntil, now, agentproto.MaxFollow)
	}
	s.mu.Lock()
	wasFollowing := now.Before(s.followUntil)
	s.verboseUntil, s.followUntil = verbose, follow
	s.mu.Unlock()
	s.settle(now)
	if follow.After(now) && !wasFollowing {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

func clampUntil(unix int64, now time.Time, longest time.Duration) time.Time {
	if unix <= 0 {
		return time.Time{}
	}
	t := time.Unix(unix, 0)
	if !t.After(now) {
		return time.Time{}
	}
	return minTime(t, now.Add(longest))
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// settle sets the level for the time now: Debug while verbose.
func (s *Shipper) settle(now time.Time) {
	s.mu.Lock()
	verbose := now.Before(s.verboseUntil)
	s.mu.Unlock()
	want := slog.LevelInfo
	if verbose {
		want = slog.LevelDebug
	}
	if s.Level.Level() != want {
		s.Level.Set(want)
		if verbose {
			s.Log.Info("verbose logging turned on")
		} else {
			s.Log.Info("verbose logging ended")
		}
	}
}

// Following says whether the server has said that someone is watching.
func (s *Shipper) Following() bool {
	if s == nil {
		return false
	}
	s.defaults()
	return s.following(s.Now())
}

func (s *Shipper) following(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Before(s.followUntil)
}

// Run sends until ctx ends, then tries once more to send what is left. A
// nil Shipper does nothing.
func (s *Shipper) Run(ctx context.Context, send SendFunc) {
	if s == nil {
		return
	}
	s.defaults()
	wait := s.Every
	for {
		select {
		case <-ctx.Done():
			flush, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_ = s.Flush(flush, send, 1)
			cancel()
			return
		case <-s.wake:
		case <-time.After(wait):
		}
		wait = s.step(ctx, send)
	}
}

// step does one round and returns the wait until the next.
func (s *Shipper) step(ctx context.Context, send SendFunc) time.Duration {
	now := s.Now()
	s.settle(now)
	for _, t := range s.Tails {
		t.Poll(s.add)
	}
	following := s.following(now)
	// A watched device sends one batch a round, every two seconds; an
	// unwatched one empties what waits, up to 20 batches.
	rounds := 20
	if following {
		rounds = 1
	}
	err := s.Flush(ctx, send, rounds)
	switch {
	case errors.Is(err, ErrUnsupported):
		return s.Unsupported
	case err != nil:
		s.failures++
		return min(s.Every<<min(s.failures, 4), 5*time.Minute)
	}
	s.failures = 0
	if following {
		return s.FollowEvery
	}
	return s.Every
}

// Flush sends up to rounds batches. It returns the first error.
func (s *Shipper) Flush(ctx context.Context, send SendFunc, rounds int) error {
	for range rounds {
		recs, dropped := s.Buf.Next(agentproto.MaxLogBatch, maxBatchBytes)
		if len(recs) == 0 && dropped == 0 {
			return nil
		}
		ack, err := send(ctx, agentproto.LogBatch{Records: recs, Dropped: dropped})
		if err != nil {
			if s.failures == 0 && !errors.Is(err, ErrUnsupported) && ctx.Err() == nil {
				s.Log.Warn("sending logs failed; they are kept and sent later", "error", err)
			}
			return err
		}
		if err := s.Buf.Ack(ack.Seq, dropped); err != nil {
			s.Log.Warn("the log buffer could not be updated", "error", err)
		}
		s.Apply(ack.Logs)
		if len(recs) < agentproto.MaxLogBatch {
			return nil
		}
	}
	return nil
}
