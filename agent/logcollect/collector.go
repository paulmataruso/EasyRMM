package logcollect

import (
	"context"
	"log/slog"
	"time"

	"github.com/paulmataruso/easyrmm/internal/logblock"
	"github.com/paulmataruso/easyrmm/internal/logredact"
)

// Reader reads one place events come from, after a cursor of its own.
type Reader interface {
	// Name identifies the reader in the cursors and the log.
	Name() string
	// Read returns up to limit events after cursor (empty on a first run,
	// when the reader starts at since) and the cursor after them. Each event
	// carries its Source; one reader may produce several sources. A reader
	// returning fewer than limit events has caught up.
	Read(ctx context.Context, cursor string, since time.Time, limit int) (events []logblock.Event, next string, err error)
}

// Collector reads its readers and writes blocks to the spool.
type Collector struct {
	Readers []Reader
	Spool   *Spool
	Log     *slog.Logger
	// Lookback is how far back a reader with no cursor starts; default 24h.
	Lookback time.Duration
	// BatchEvents is the most events read at once and so the most in a
	// block; default 5000. MaxBlocksPerPass bounds one pass so that the
	// collector never works long without looking at its context; default 40.
	BatchEvents      int
	MaxBlocksPerPass int
	Now              func() time.Time
}

func (c *Collector) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Pass reads every reader once, as far as the pass's bounds allow, and
// returns how many blocks it wrote. A reader that fails is logged and the
// others go on; its cursor does not move.
func (c *Collector) Pass(ctx context.Context) int {
	batch := c.BatchEvents
	if batch <= 0 {
		batch = 5000
	}
	budget := c.MaxBlocksPerPass
	if budget <= 0 {
		budget = 40
	}
	lookback := c.Lookback
	if lookback <= 0 {
		lookback = 24 * time.Hour
	}
	cursors := c.Spool.LoadCursors()
	written := 0
	for _, r := range c.Readers {
		for budget > 0 && ctx.Err() == nil {
			cur := cursors[r.Name()]
			evs, next, err := r.Read(ctx, cur, c.now().Add(-lookback), batch)
			if err != nil {
				c.log().Warn("a log reader failed", "reader", r.Name(), "error", err)
				break
			}
			n, err := c.seal(evs)
			if err != nil {
				// Nothing moved: the same events are read again next pass.
				c.log().Warn("writing blocks failed", "reader", r.Name(), "error", err)
				break
			}
			written += n
			budget -= max(n, 1)
			if next != cur {
				cursors[r.Name()] = next
				if err := c.Spool.SaveCursors(cursors); err != nil {
					c.log().Warn("saving the positions failed", "error", err)
					return written
				}
			}
			if len(evs) < batch {
				break
			}
		}
	}
	return written
}

// seal redacts the events, groups them by source and writes one block each.
func (c *Collector) seal(evs []logblock.Event) (int, error) {
	by := map[string][]logblock.Event{}
	var order []string
	for _, e := range evs {
		e = Redact(e)
		if _, ok := by[e.Source]; !ok {
			order = append(order, e.Source)
		}
		by[e.Source] = append(by[e.Source], e)
	}
	n := 0
	for _, src := range order {
		b, err := logblock.Seal(src, logblock.ClassFor(src), by[src])
		if err != nil {
			return n, err
		}
		_, dropped, err := c.Spool.Put(b)
		if err != nil {
			return n, err
		}
		if dropped > 0 {
			c.log().Warn("the spool is full: the oldest blocks were dropped", "dropped", dropped)
		}
		n++
	}
	return n, nil
}

// Run passes every interval until ctx ends.
func (c *Collector) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		c.Pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Redact removes EasyRMM's own tokens and secret-named values from an event,
// before it is written anywhere. Everything else the computer logged is kept
// as it was (ADR-0060, Privacy).
func Redact(e logblock.Event) logblock.Event {
	e.Message = logredact.Text(e.Message)
	e.Fields = redactMap(e.Fields)
	e.Sensitive = redactMap(e.Sensitive)
	return e
}

func redactMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = logredact.Attr(k, v)
	}
	return out
}
