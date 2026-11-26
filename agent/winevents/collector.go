package winevents

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Query says what to read from the log.
type Query struct {
	// After is the bookmark: only records above it. Zero means the first run.
	After int64
	// Since, on the first run, limits the read to the last day.
	Since time.Time
	// Limit is the most events to return.
	Limit int
}

// Result is what a read found: the matching events as rendered XML, in
// record order, and the oldest and newest record ID of the whole channel
// (not only the matching ones), which tell a cleared or wrapped log.
type Result struct {
	Events         []string
	Oldest, Newest int64
}

// Source reads one event channel. It runs one query with the event IDs
// filtered by Windows, and starts no process.
type Source interface {
	Read(ctx context.Context, q Query) (Result, error)
}

// state is the bookmark kept on disk: the highest acknowledged record of the
// current epoch.
type state struct {
	Epoch string `json:"epoch"`
	Acked int64  `json:"acked"`
}

// Collector reads a channel after its bookmark and plans the batches. It is
// used from the heartbeat loop; Next and Acked do not run at the same time.
type Collector struct {
	Source Source
	// File is where the bookmark is kept, written atomically.
	File string
	Now  func() time.Time

	mu    sync.Mutex
	st    state
	known bool
}

// First-run bounds (ADR-0074): the last 24 hours, newest 100 events.
const (
	firstWindow = 24 * time.Hour
	firstKeep   = 100
	readLimit   = 200
)

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *Collector) load() {
	if c.known {
		return
	}
	c.known = true
	b, err := os.ReadFile(c.File)
	if err != nil || json.Unmarshal(b, &c.st) != nil || c.st.Epoch == "" || c.st.Acked < 0 {
		c.st = state{}
	}
}

func (c *Collector) save() error {
	b, err := json.Marshal(c.st)
	if err != nil {
		return err
	}
	tmp := c.File + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.File)
}

// newEpoch names a log incarnation: the time it was first read and some chance.
func newEpoch(t time.Time) string {
	var r [4]byte
	_, _ = rand.Read(r[:])
	return strconv.FormatInt(t.Unix(), 36) + hex.EncodeToString(r[:])
}

// Next reads the events after the bookmark and returns the batch to send, or
// nil when there is nothing. The same events come again until Acked moves the
// bookmark, so a lost response duplicates nothing and loses nothing (the
// server dedups on the record ID).
func (c *Collector) Next(ctx context.Context) (*agentproto.DefenderLogBatch, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Source == nil {
		return nil, errors.New("winevents: no event source")
	}
	c.load()
	q := Query{After: c.st.Acked, Limit: readLimit}
	first := c.st.Epoch == ""
	if first {
		q.Since = c.now().Add(-firstWindow)
		q.Limit = 1000
	}
	res, err := c.Source.Read(ctx, q)
	if err != nil {
		return nil, err
	}
	gap := false
	switch {
	case !first && res.Newest > 0 && res.Newest < c.st.Acked:
		// The log was cleared and numbers again from the start: a new epoch.
		c.st = state{Epoch: newEpoch(c.now())}
		if err := c.save(); err != nil {
			return nil, err
		}
		gap = true
		if res, err = c.Source.Read(ctx, Query{Limit: readLimit}); err != nil {
			return nil, err
		}
	case !first && res.Oldest > c.st.Acked+1:
		// The log wrapped past the bookmark: what was in between is gone.
		gap = true
	}
	var events []agentproto.DefenderLogEvent
	for _, raw := range res.Events {
		e, err := Parse(raw)
		if err != nil {
			continue
		}
		if e.RecordID > c.st.Acked {
			events = append(events, e)
		}
	}
	if first && len(events) > firstKeep {
		events = events[len(events)-firstKeep:]
	}
	if len(events) == 0 && !gap && !first {
		return nil, nil
	}
	epoch := c.st.Epoch
	if first {
		epoch = newEpoch(c.now())
	}
	planned, through := Plan(events)
	b := &agentproto.DefenderLogBatch{Epoch: epoch, Gap: gap, Backfill: first, Through: through, Events: planned}
	if b.Events == nil {
		b.Events = []agentproto.DefenderLogEvent{}
	}
	if first && len(events) == 0 {
		// Nothing in the last day: start from the newest record, so the next
		// read is only what is new.
		b.Through = res.Newest
	}
	return b, nil
}

// Acked moves the bookmark to what the server stored. An acknowledgement of
// another epoch than the one in use (or older than the bookmark) is ignored.
func (c *Collector) Acked(ack *agentproto.DefenderLogAck, sent *agentproto.DefenderLogBatch) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.load()
	if ack == nil || sent == nil {
		return nil
	}
	if c.st.Epoch == "" {
		if ack.Epoch != sent.Epoch {
			return nil
		}
		c.st.Epoch = sent.Epoch
	}
	if ack.Epoch != c.st.Epoch || ack.RecordID <= c.st.Acked {
		return nil
	}
	c.st.Acked = ack.RecordID
	return c.save()
}

// File name of the bookmark in the agent's state folder.
const BookmarkFile = "defender-events.json"

// BookmarkPath is where the bookmark is kept under a state folder.
func BookmarkPath(stateDir string) string { return filepath.Join(stateDir, BookmarkFile) }
