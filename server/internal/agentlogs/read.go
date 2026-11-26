package agentlogs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Record is a stored record as the console shows it.
type Record struct {
	// ID is the cursor: it rises with the order records were stored in.
	ID         int64             `json:"id"`
	Time       time.Time         `json:"time"`
	ReceivedAt time.Time         `json:"receivedAt"`
	Source     string            `json:"source"`
	Level      string            `json:"level"`
	Message    string            `json:"message"`
	Attrs      map[string]string `json:"attrs"`
}

// Query selects records of one device.
type Query struct {
	// After and Before are cursors: records with a greater or a lesser id.
	// With neither, the newest records.
	After, Before int64
	// Sources limits to these sources; none is all.
	Sources []string
	// Level limits to records of at least this level.
	Level string
	// Text limits to records whose message or attributes hold it, in any case.
	Text         string
	Since, Until time.Time
	Limit        int
	// keyset continues a download after the record with this time and id.
	keyset *keyset
}

type keyset struct {
	at time.Time
	id int64
}

// Verbose is a device's verbose mode as the console shows it.
type Verbose struct {
	Until time.Time `json:"until"`
	// Scope is "device" or "group": what the mode was set on.
	Scope   string  `json:"scope"`
	GroupID *string `json:"groupId,omitempty"`
}

// Page is a read of a device's logs.
type Page struct {
	Items []Record `json:"items"`
	// More says there are records beyond Items in the direction asked.
	More bool `json:"more"`
	// Verbose is the device's verbose mode in force, nil when none.
	Verbose *Verbose `json:"verbose"`
	// RetentionDays is how long records are kept.
	RetentionDays int `json:"retentionDays"`
	// Online says the device's agent reported recently.
	Online bool `json:"online"`
}

// MaxPage is the most records a read returns.
const (
	MaxPage     = 1000
	DefaultPage = 200
)

// where builds the conditions of q, from argument number n on.
func (q Query) where(args []any) (string, []any) {
	var w []string
	add := func(cond string, v any) {
		args = append(args, v)
		w = append(w, strings.ReplaceAll(cond, "$$", fmt.Sprintf("$%d", len(args))))
	}
	if q.After > 0 {
		add("id > $$", q.After)
	}
	if q.Before > 0 {
		// Older in the merged order: by time, then by id (the tie-break).
		args = append(args, q.Before)
		w = append(w, fmt.Sprintf("(logged_at, id) < (SELECT b.logged_at, b.id FROM agent_log_records b WHERE b.id = $%d AND b.device_id = $1)", len(args)))
	}
	if q.keyset != nil {
		args = append(args, q.keyset.at, q.keyset.id)
		w = append(w, fmt.Sprintf("(logged_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	if len(q.Sources) > 0 {
		add("source = ANY ($$)", q.Sources)
	}
	if rank, ok := levels[q.Level]; ok && rank > 0 {
		var ls []string
		for l, r := range levels {
			if r >= rank {
				ls = append(ls, l)
			}
		}
		add("level = ANY ($$)", ls)
	}
	if q.Text != "" {
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q.Text)
		add(`(message ILIKE '%' || $$ || '%' OR attrs::text ILIKE '%' || $$ || '%')`, esc)
	}
	if !q.Since.IsZero() {
		add("logged_at >= $$", q.Since)
	}
	if !q.Until.IsZero() {
		add("logged_at <= $$", q.Until)
	}
	if len(w) == 0 {
		return "", args
	}
	return " AND " + strings.Join(w, " AND "), args
}

// Validate checks q's filters.
func (q Query) Validate() error {
	f := apperr.Fields{}
	for _, s := range q.Sources {
		f.Check(sources[s], "source", "must be agent, easypatch or meshagent")
	}
	if q.Level != "" {
		_, ok := levels[q.Level]
		f.Check(ok, "level", "must be debug, info, warn or error")
	}
	f.Check(len(q.Text) <= 200, "q", "must be at most 200 characters")
	return f.Err()
}

func scanRecord(row pgx.Row) (Record, error) {
	var r Record
	var attrs []byte
	if err := row.Scan(&r.ID, &r.Time, &r.ReceivedAt, &r.Source, &r.Level, &r.Message, &attrs); err != nil {
		return r, err
	}
	r.Attrs = map[string]string{}
	return r, json.Unmarshal(attrs, &r.Attrs)
}

const recordColumns = `id, logged_at, received_at, source, level, message, attrs`

// lookup finds the device and checks log.view on it; a caller who may not
// view the device gets not found.
func (s *Service) lookup(ctx context.Context, c access.Caller, id uuid.UUID) (*devices.Device, error) {
	d, err := devices.Lookup(ctx, s.db, c, id)
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermLogView, rbac.Site(d.OrganizationID, d.SiteID)); err != nil {
		return nil, err
	}
	return d, nil
}

// Read returns a device's records. Without a cursor it returns the newest
// q.Limit records; with After, the next ones; with Before, the ones before.
// Either way they come oldest first. With follow, the read tells the
// device's agent that someone is watching, so that it sends every two
// seconds for a little while.
func (s *Service) Read(ctx context.Context, c access.Caller, deviceID uuid.UUID, q Query, follow bool) (*Page, error) {
	d, err := s.lookup(ctx, c, deviceID)
	if err != nil {
		return nil, err
	}
	if err := q.Validate(); err != nil {
		return nil, err
	}
	limit := min(max(q.Limit, 1), MaxPage)
	if q.Limit == 0 {
		limit = DefaultPage
	}
	if follow {
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO agent_log_follow (device_id, until) VALUES ($1, now() + $2::interval)
				ON CONFLICT (device_id) DO UPDATE SET until = excluded.until`, deviceID, FollowFor)
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("agentlogs: marking a follow: %w", err)
		}
	}
	cond, args := q.where([]any{deviceID})
	// The page is the merged view of every source, newest first: by the
	// time a record was logged, ties broken by the order it was stored in
	// (higher id first). The cursors: Before pages to older records in that
	// order; After is for the live tail and means "stored after this id",
	// because a late batch can hold records older than the newest one shown.
	order := "DESC"
	if q.After > 0 {
		order = "ASC"
	}
	page := &Page{Items: []Record{}, RetentionDays: int(s.retention / (24 * time.Hour)), Online: d.Online}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		args = append(args, limit+1)
		rows, err := tx.Query(ctx, `SELECT `+recordColumns+` FROM agent_log_records WHERE device_id = $1`+cond+
			fmt.Sprintf(` ORDER BY %s LIMIT $%d`, orderBy(order), len(args)), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRecord(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Items) > limit {
			page.More, page.Items = true, page.Items[:limit]
		}
		if order == "ASC" {
			SortNewestFirst(page.Items)
		}
		page.Verbose, err = verboseOf(ctx, tx, deviceID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("agentlogs: reading records: %w", err)
	}
	return page, nil
}

func orderBy(dir string) string {
	if dir == "ASC" {
		return "id ASC"
	}
	return "logged_at DESC, id DESC"
}

// SortNewestFirst puts records in the merged order of the Logs tab: newest
// logged time first, a higher id (stored later) first among equal times.
func SortNewestFirst(items []Record) {
	sort.SliceStable(items, func(i, j int) bool {
		if !items[i].Time.Equal(items[j].Time) {
			return items[i].Time.After(items[j].Time)
		}
		return items[i].ID > items[j].ID
	})
}

// Format names a download's format.
type Format string

// The download formats.
const (
	Text  Format = "text"
	JSONL Format = "jsonl"
)

// maxDownload is the most records a download holds: a device's daily cap.
const maxDownload = DailyCap

// Download writes the device's records that match q, in time order, oldest first, up to
// maxDownload of them, as text lines or JSON lines, and records the
// download in the audit log. It returns how many it wrote.
func (s *Service) Download(ctx context.Context, c access.Caller, deviceID uuid.UUID, q Query, format Format, w io.Writer) (int, error) {
	d, err := s.lookup(ctx, c, deviceID)
	if err != nil {
		return 0, err
	}
	if err := q.Validate(); err != nil {
		return 0, err
	}
	if format != Text && format != JSONL {
		return 0, apperr.Invalid("format", "must be text or jsonl")
	}
	q.After, q.Before = 0, 0
	written := 0
	var last *keyset
	for written < maxDownload {
		q.keyset = last
		cond, args := q.where([]any{deviceID})
		args = append(args, min(2000, maxDownload-written))
		var batch []Record
		err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT `+recordColumns+` FROM agent_log_records WHERE device_id = $1`+cond+
				fmt.Sprintf(` ORDER BY logged_at, id LIMIT $%d`, len(args)), args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				r, err := scanRecord(rows)
				if err != nil {
					return err
				}
				batch = append(batch, r)
			}
			return rows.Err()
		})
		if err != nil {
			return written, fmt.Errorf("agentlogs: reading records: %w", err)
		}
		for _, r := range batch {
			if err := writeRecord(w, r, format); err != nil {
				return written, err
			}
			written++
			last = &keyset{at: r.Time, id: r.ID}
		}
		if len(batch) < 2000 {
			break
		}
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.logs_download", Outcome: audit.Success,
			OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"device": d.Hostname, "records": written, "format": string(format)},
		})
	})
	return written, err
}

// writeRecord writes one record as a line.
func writeRecord(w io.Writer, r Record, format Format) error {
	if format == JSONL {
		b, err := json.Marshal(struct {
			Time    time.Time         `json:"time"`
			Source  string            `json:"source"`
			Level   string            `json:"level"`
			Message string            `json:"message"`
			Attrs   map[string]string `json:"attrs,omitempty"`
		}{r.Time, r.Source, r.Level, r.Message, r.Attrs})
		if err != nil {
			return err
		}
		_, err = w.Write(append(b, '\n'))
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %-5s [%s] %s", r.Time.UTC().Format("2006-01-02T15:04:05.000Z"), strings.ToUpper(r.Level), r.Source, oneLine(r.Message))
	keys := make([]string, 0, len(r.Attrs))
	for k := range r.Attrs {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%q", k, r.Attrs[k])
	}
	b.WriteByte('\n')
	_, err := io.WriteString(w, b.String())
	return err
}

// oneLine keeps a record to one line, so that a line of a text download is
// one record.
func oneLine(s string) string {
	return strings.NewReplacer("\r\n", `\n`, "\n", `\n`, "\r", `\r`).Replace(s)
}
