package logstore

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/logblock"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func fsSub() (fs.FS, error) { return fs.Sub(migrationFiles, "migrations") }

func factsJSON(f logblock.Facts) ([]byte, error) { return json.Marshal(f) }

// Limits of a read.
const (
	DefaultLimit = 200
	MaxLimit     = 1000
	// MaxBlocks is the most blocks one read opens; a search that would need
	// more says it stopped (Result.Truncated) and where, so that the console
	// can continue from there.
	MaxBlocks = 400
	// maxSpan is how long a block may span: the collector's lookback. A read
	// looks for blocks that started this long before its range.
	maxSpan = 48 * time.Hour
	// DefaultRange is a read's range when none is given.
	DefaultRange = 24 * time.Hour
)

// Query selects events of one device.
type Query struct {
	// Since and Until bound the events' times; Until zero is now.
	Since, Until time.Time
	// Sources limits to these sources; none is all.
	Sources []string
	// Text limits to events whose message, ID or fields hold it, in any
	// case (and command lines, for a caller who may see them).
	Text  string
	Limit int
}

// Event is an event as the console shows it.
type Event struct {
	Time    time.Time         `json:"time"`
	Source  string            `json:"source"`
	Level   string            `json:"level"`
	ID      string            `json:"id,omitempty"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
	// Sensitive holds command lines and script text: present only for a
	// caller with log.view_sensitive, and then searched too.
	Sensitive map[string]string `json:"sensitive,omitempty"`
}

// Result is a read.
type Result struct {
	// Items are newest first.
	Items []Event `json:"items"`
	// More says there are older events in the range beyond Items; Next is
	// the Until that continues from there.
	More bool       `json:"more"`
	Next *time.Time `json:"next,omitempty"`
	// Truncated says the read stopped at MaxBlocks before covering the range:
	// the events shown are the newest of what it opened.
	Truncated bool `json:"truncated"`
	// CanSeeSensitive says whether Sensitive fields are included.
	CanSeeSensitive bool `json:"canSeeSensitive"`
	// Sources are the sources the device has logs from.
	Sources []string `json:"sources"`
}

// HourFact is a bucket of the timeline.
type HourFact struct {
	Hour   time.Time `json:"hour"`
	Source string    `json:"source"`
	Level  string    `json:"level"`
	Events int64     `json:"events"`
	Bytes  int64     `json:"bytes"`
}

// Timeline is what a device logged by the hour.
type Timeline struct {
	Since   time.Time  `json:"since"`
	Until   time.Time  `json:"until"`
	Buckets []HourFact `json:"buckets"`
}

// Service is the console's side: it checks what the caller may see and reads
// the store.
type Service struct {
	store *Store
	main  *database.DB
}

// NewService reads store for callers checked against the main database.
func NewService(store *Store, main *database.DB) *Service { return &Service{store: store, main: main} }

// Available says whether logs can be read; it is false for a service built
// over no store.
func (s *Service) Available() bool { return s != nil && s.store.Ready() }

// lookup finds the device and checks log.view on it; a caller who may not
// view the device gets not found.
func (s *Service) lookup(ctx context.Context, c access.Caller, id uuid.UUID) (*devices.Device, bool, error) {
	d, err := devices.Lookup(ctx, s.main, c, id)
	if err != nil {
		return nil, false, err
	}
	where := rbac.Site(d.OrganizationID, d.SiteID)
	if err := c.Require(rbac.PermLogView, where); err != nil {
		return nil, false, err
	}
	return d, c.Can(rbac.PermLogViewSensitive, where), nil
}

func (q *Query) normalise(now time.Time) error {
	if q.Until.IsZero() {
		q.Until = now
	}
	if q.Since.IsZero() {
		q.Since = q.Until.Add(-DefaultRange)
	}
	if !q.Since.Before(q.Until) {
		return apperr.Invalid("since", "must be before until")
	}
	if q.Until.Sub(q.Since) > 400*24*time.Hour {
		return apperr.Invalid("since", "the range is longer than a year")
	}
	switch {
	case q.Limit == 0:
		q.Limit = DefaultLimit
	case q.Limit < 0 || q.Limit > MaxLimit:
		return apperr.Invalid("limit", fmt.Sprintf("must be between 1 and %d", MaxLimit))
	}
	if len(q.Text) > 200 {
		return apperr.Invalid("q", "is too long")
	}
	for _, src := range q.Sources {
		if !sourceRE.MatchString(src) {
			return apperr.Invalid("source", "is not a source name")
		}
	}
	return nil
}

// Read returns a device's collected events.
func (s *Service) Read(ctx context.Context, c access.Caller, deviceID uuid.UUID, q Query) (*Result, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	_, sensitive, err := s.lookup(ctx, c, deviceID)
	if err != nil {
		return nil, err
	}
	return s.store.Read(ctx, c.Scope, deviceID, q, sensitive)
}

// Timeline returns what a device logged by the hour.
func (s *Service) Timeline(ctx context.Context, c access.Caller, deviceID uuid.UUID, q Query) (*Timeline, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	if _, _, err := s.lookup(ctx, c, deviceID); err != nil {
		return nil, err
	}
	return s.store.Timeline(ctx, c.Scope, deviceID, q)
}

// Read is Service.Read after the caller was checked; scope is what row-level
// security applies, so a device the scope does not cover has no blocks here
// whatever the id.
func (s *Store) Read(ctx context.Context, scope database.Scope, deviceID uuid.UUID, q Query, sensitive bool) (*Result, error) {
	if err := q.normalise(s.now()); err != nil {
		return nil, err
	}
	type blk struct {
		source, codec string
		start, end    time.Time
		data          []byte
	}
	var blocks []blk
	var sources []string
	truncated := false
	err := s.db.ReadTx(ctx, scope, func(tx pgx.Tx) error {
		args := []any{deviceID, q.Since, q.Until, q.Since.Add(-maxSpan)}
		cond := ""
		if len(q.Sources) > 0 {
			args = append(args, q.Sources)
			cond = " AND source = ANY ($5)"
		}
		rows, err := tx.Query(ctx, `SELECT source, codec, start_time, end_time, compressed_data FROM log_blocks
			WHERE device_id = $1 AND end_time >= $2 AND start_time <= $3 AND start_time >= $4`+cond+`
			ORDER BY end_time DESC LIMIT `+fmt.Sprint(MaxBlocks+1), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b blk
			if err := rows.Scan(&b.source, &b.codec, &b.start, &b.end, &b.data); err != nil {
				return err
			}
			blocks = append(blocks, b)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(blocks) > MaxBlocks {
			truncated, blocks = true, blocks[:MaxBlocks]
		}
		srows, err := tx.Query(ctx, `SELECT DISTINCT source FROM log_hourly_facts WHERE device_id = $1 ORDER BY source`, deviceID)
		if err != nil {
			return err
		}
		defer srows.Close()
		for srows.Next() {
			var src string
			if err := srows.Scan(&src); err != nil {
				return err
			}
			sources = append(sources, src)
		}
		return srows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("logstore: reading blocks: %w", s.unavailable(ctx, err))
	}
	res := &Result{Items: []Event{}, CanSeeSensitive: sensitive, Truncated: truncated, Sources: sources}
	if res.Sources == nil {
		res.Sources = []string{}
	}
	needle := strings.ToLower(q.Text)
	var hits []Event
	for _, b := range blocks {
		// Blocks come newest first by their end: once the limit is met and a
		// block ended before the limit's event, no later block holds a newer
		// one that matters.
		if len(hits) > q.Limit {
			sort.SliceStable(hits, func(i, j int) bool { return hits[i].Time.After(hits[j].Time) })
			if b.end.Before(hits[q.Limit].Time) {
				break
			}
		}
		evs, err := logblock.Open(b.codec, b.data)
		if err != nil {
			s.log.Warn("a stored log block could not be opened", "device_id", deviceID, "source", b.source, "error", err)
			continue
		}
		for _, e := range evs {
			if e.Time.Before(q.Since) || !e.Time.Before(q.Until) {
				continue
			}
			if needle != "" && !matches(e, needle, sensitive) {
				continue
			}
			hits = append(hits, view(e, sensitive))
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Time.After(hits[j].Time) })
	if len(hits) > q.Limit {
		res.More = true
		next := hits[q.Limit-1].Time
		res.Next = &next
		hits = hits[:q.Limit]
	}
	if hits != nil {
		res.Items = hits
	}
	return res, nil
}

func view(e logblock.Event, sensitive bool) Event {
	out := Event{Time: e.Time, Source: e.Source, Level: e.Level, ID: e.ID, Message: e.Message, Fields: e.Fields}
	if out.Level == "" {
		out.Level = "info"
	}
	if sensitive {
		out.Sensitive = e.Sensitive
	}
	return out
}

// matches reports whether an event holds the lower-cased needle. Sensitive
// fields are searched only for a caller who may see them: a search would
// otherwise tell anyone what a command line holds.
func matches(e logblock.Event, needle string, sensitive bool) bool {
	has := func(s string) bool { return strings.Contains(strings.ToLower(s), needle) }
	if has(e.Message) || has(e.ID) {
		return true
	}
	for _, v := range e.Fields {
		if has(v) {
			return true
		}
	}
	if sensitive {
		for _, v := range e.Sensitive {
			if has(v) {
				return true
			}
		}
	}
	return false
}

// Timeline is Service.Timeline after the caller was checked.
func (s *Store) Timeline(ctx context.Context, scope database.Scope, deviceID uuid.UUID, q Query) (*Timeline, error) {
	if err := q.normalise(s.now()); err != nil {
		return nil, err
	}
	t := &Timeline{Since: q.Since, Until: q.Until, Buckets: []HourFact{}}
	err := s.db.ReadTx(ctx, scope, func(tx pgx.Tx) error {
		args := []any{deviceID, q.Since.Truncate(time.Hour), q.Until}
		cond := ""
		if len(q.Sources) > 0 {
			args = append(args, q.Sources)
			cond = " AND source = ANY ($4)"
		}
		rows, err := tx.Query(ctx, `SELECT hour, source, level, events, bytes FROM log_hourly_facts
			WHERE device_id = $1 AND hour >= $2 AND hour < $3`+cond+` ORDER BY hour, source, level`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f HourFact
			if err := rows.Scan(&f.Hour, &f.Source, &f.Level, &f.Events, &f.Bytes); err != nil {
				return err
			}
			t.Buckets = append(t.Buckets, f)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("logstore: reading the timeline: %w", s.unavailable(ctx, err))
	}
	return t, nil
}
