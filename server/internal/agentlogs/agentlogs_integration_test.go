//go:build integration

package agentlogs_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agentlogs"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t    *testing.T
	ctx  context.Context
	db   *database.DB
	svc  *agentlogs.Service
	acme uuid.UUID
	hq   uuid.UUID
	plnt uuid.UUID
	glob uuid.UUID
	dev  uuid.UUID
}

func newFixture(t *testing.T, retentionDays int) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB}
	f.svc = agentlogs.New(inst.DB, audit.New(inst.DB, nil), retentionDays, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.glob = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.plnt = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, f.glob)
	f.dev = f.device(f.acme, f.hq, "pc1")
	return f
}

func (f *fixture) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fixture) device(org, site uuid.UUID, name string) uuid.UUID {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, 'linux', $4, now() - interval '1 day', now()) RETURNING id`, org, site, name, key)
}

func (f *fixture) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

func recs(from, n int64) []agentproto.LogRecord {
	out := make([]agentproto.LogRecord, 0, n)
	for i := from; i < from+n; i++ {
		out = append(out, agentproto.LogRecord{Seq: i, Time: time.Now(), Source: "agent", Level: "info", Message: fmt.Sprintf("record %d", i)})
	}
	return out
}

func (f *fixture) ingest(dev uuid.UUID, b agentproto.LogBatch) agentproto.LogAck {
	f.t.Helper()
	ack, err := f.svc.Ingest(f.ctx, dev, b)
	if err != nil {
		f.t.Fatal(err)
	}
	return ack
}

func TestIngestStoresOnceAndAcknowledges(t *testing.T) {
	f := newFixture(t, 14)
	ack := f.ingest(f.dev, agentproto.LogBatch{Records: recs(10, 5)})
	if ack.Seq != 14 || ack.Logs != nil {
		t.Errorf("ack = %+v", ack)
	}
	// The same batch again, after a lost answer, and an overlapping one.
	f.ingest(f.dev, agentproto.LogBatch{Records: recs(10, 5)})
	f.ingest(f.dev, agentproto.LogBatch{Records: recs(12, 6)})
	if n := f.count(`SELECT count(*) FROM agent_log_records WHERE device_id = $1`, f.dev); n != 8 {
		t.Errorf("%d records stored, want 8 (sequences 10 to 17)", n)
	}
	// Another device's sequences are its own.
	other := f.device(f.acme, f.hq, "pc2")
	f.ingest(other, agentproto.LogBatch{Records: recs(10, 2)})
	if n := f.count(`SELECT count(*) FROM agent_log_records WHERE device_id = $1`, other); n != 2 {
		t.Errorf("%d records for the other device", n)
	}
	if _, err := f.svc.Ingest(f.ctx, f.dev, agentproto.LogBatch{Records: recs(0, agentproto.MaxLogBatch+1)}); !errors.Is(err, agentlogs.ErrBadBatch) {
		t.Errorf("too large a batch: %v", err)
	}
	if _, err := f.svc.Ingest(f.ctx, f.dev, agentproto.LogBatch{Records: []agentproto.LogRecord{{Seq: -5}}}); !errors.Is(err, agentlogs.ErrBadBatch) {
		t.Errorf("negative sequence: %v", err)
	}
}

func TestIngestRedactsAndBounds(t *testing.T) {
	f := newFixture(t, 14)
	f.ingest(f.dev, agentproto.LogBatch{Records: []agentproto.LogRecord{{
		Seq: 1, Time: time.Now().Add(48 * time.Hour), Source: "weird", Level: "LOUD",
		Message: "token=abc123 and ert_AbCdEf0123456789 and \x00 nul " + strings.Repeat("x", 20000),
		Attrs:   map[string]string{"api_token": "s3cret", "path": "C:\\Users\\bob", "pw": "Bearer abcdefghij"},
	}}})
	var msg, source, level, attrs string
	var at, now time.Time
	err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT message, source, level, attrs::text, logged_at, now() FROM agent_log_records WHERE device_id = $1`, f.dev).
			Scan(&msg, &source, &level, &attrs, &at, &now)
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg, "abc123") || strings.Contains(msg, "ert_AbCd") || strings.Contains(msg, "\x00") || len(msg) > agentproto.MaxLogMessage {
		t.Errorf("message not redacted or bounded: %d bytes, %.80q", len(msg), msg)
	}
	if strings.Contains(attrs, "s3cret") || strings.Contains(attrs, "abcdefghij") || !strings.Contains(attrs, `C:\\Users\\bob`) {
		t.Errorf("attributes = %s", attrs)
	}
	if source != "agent" || level != "info" {
		t.Errorf("source %q, level %q", source, level)
	}
	if at.After(now.Add(6 * time.Minute)) {
		t.Errorf("a record from the future kept its time: %v", at)
	}
}

func TestDailyCapAndDropNotes(t *testing.T) {
	f := newFixture(t, 14)
	f.exec(`INSERT INTO agent_log_days (device_id, day, stored) VALUES ($1, (now() AT TIME ZONE 'UTC')::date, $2)`, f.dev, agentlogs.DailyCap-3)
	ack := f.ingest(f.dev, agentproto.LogBatch{Records: recs(1, 10), Dropped: 7})
	if ack.Seq != 10 {
		t.Errorf("ack %d: refused records are acknowledged too", ack.Seq)
	}
	if n := f.count(`SELECT count(*) FROM agent_log_records WHERE device_id = $1 AND seq >= 0`, f.dev); n != 3 {
		t.Errorf("%d records stored past the cap, want 3", n)
	}
	var notes []string
	err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(f.ctx, `SELECT message FROM agent_log_records WHERE device_id = $1 AND seq = -1 ORDER BY id`, f.dev)
		if err != nil {
			return err
		}
		notes, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil || len(notes) != 2 || !strings.Contains(notes[0], "7 log records were dropped") || !strings.Contains(notes[1], "7 log records were not stored") {
		t.Errorf("notes = %q, %v", notes, err)
	}
	// Nothing more today.
	f.ingest(f.dev, agentproto.LogBatch{Records: recs(100, 5)})
	if n := f.count(`SELECT count(*) FROM agent_log_records WHERE device_id = $1 AND seq >= 0`, f.dev); n != 3 {
		t.Errorf("%d records after the cap", n)
	}
}

func TestReadNeedsLogViewAndRespectsTenancy(t *testing.T) {
	f := newFixture(t, 14)
	f.ingest(f.dev, agentproto.LogBatch{Records: append(recs(1, 3), agentproto.LogRecord{Seq: 4, Time: time.Now(), Source: "easypatch", Level: "error", Message: "Disk FULL here"})})
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	ro := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	outsider := f.user("out@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.glob})
	page, err := f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{Limit: 100}, false)
	if err != nil || len(page.Items) != 4 || page.Items[0].Message != "record 1" || page.RetentionDays != 14 {
		t.Fatalf("technician: %+v, %v", page, err)
	}
	if _, err := f.svc.Read(f.ctx, ro, f.dev, agentlogs.Query{}, false); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only: %v", err)
	}
	if _, err := f.svc.Read(f.ctx, outsider, f.dev, agentlogs.Query{}, false); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization's administrator: %v", err)
	}
	for name, tc := range map[string]struct {
		q    agentlogs.Query
		want int
	}{
		"source":   {agentlogs.Query{Sources: []string{"easypatch"}}, 1},
		"level":    {agentlogs.Query{Level: "warn"}, 1},
		"text":     {agentlogs.Query{Text: "disk full"}, 1},
		"percent":  {agentlogs.Query{Text: "%"}, 0},
		"after":    {agentlogs.Query{After: page.Items[1].ID}, 2},
		"before":   {agentlogs.Query{Before: page.Items[1].ID}, 1},
		"newest 2": {agentlogs.Query{Limit: 2}, 2},
		"future":   {agentlogs.Query{Since: time.Now().Add(time.Hour)}, 0},
	} {
		p, err := f.svc.Read(f.ctx, tech, f.dev, tc.q, false)
		if err != nil || len(p.Items) != tc.want {
			t.Errorf("%s: %d records, %v; want %d", name, len(p.Items), err, tc.want)
		}
	}
	if p, _ := f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{Limit: 2}, false); !p.More || p.Items[1].Message != "Disk FULL here" {
		t.Errorf("the newest two, oldest first: %+v", p)
	}
	if _, err := f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{Level: "loud"}, false); err == nil {
		t.Error("an unknown level was accepted")
	}
}

func TestRowLevelSecurityHidesOtherTenants(t *testing.T) {
	f := newFixture(t, 14)
	f.ingest(f.dev, agentproto.LogBatch{Records: recs(1, 2)})
	outsider := f.user("out@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.glob})
	var n int
	err := f.db.ReadTx(f.ctx, outsider.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT count(*) FROM agent_log_records`).Scan(&n)
	})
	if err != nil || n != 0 {
		t.Errorf("another organization sees %d records, %v", n, err)
	}
	err = f.db.InTx(f.ctx, outsider.Scope, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO agent_log_records (device_id, seq, source, logged_at, level, message) VALUES ($1, 99, 'agent', now(), 'info', 'x')`, f.dev)
		return err
	})
	if err == nil {
		t.Error("a user scope inserted a record")
	}
}

func TestVerboseModeAndFollow(t *testing.T) {
	f := newFixture(t, 14)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	ro := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	if _, err := f.svc.SetDeviceVerbose(f.ctx, ro, f.dev, 2); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only turned verbose on: %v", err)
	}
	for _, h := range []int{-1, 25} {
		if _, err := f.svc.SetDeviceVerbose(f.ctx, tech, f.dev, h); err == nil {
			t.Errorf("%d hours accepted", h)
		}
	}
	until, err := f.svc.SetDeviceVerbose(f.ctx, tech, f.dev, 0)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(until); d < 119*time.Minute || d > 121*time.Minute {
		t.Errorf("the default is 2 hours, got %v", d)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.logs_verbose' AND device_id = $1`, f.dev); n != 1 {
		t.Errorf("%d audit entries", n)
	}
	ack := f.ingest(f.dev, agentproto.LogBatch{})
	if ack.Logs == nil || ack.Logs.VerboseUntil != until.Unix() || ack.Logs.FollowUntil != 0 {
		t.Errorf("instructions = %+v", ack.Logs)
	}
	// Reading with follow tells the agent to send every two seconds.
	if _, err := f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{}, true); err != nil {
		t.Fatal(err)
	}
	if in, _ := f.svc.Instructions(f.ctx, f.dev); in == nil || in.FollowUntil == 0 {
		t.Errorf("follow = %+v", in)
	}
	page, _ := f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{}, false)
	if page.Verbose == nil || page.Verbose.Scope != "device" {
		t.Errorf("verbose = %+v", page.Verbose)
	}
	// It ends by itself.
	f.exec(`UPDATE agent_log_verbose SET until = now() - interval '1 minute'; UPDATE agent_log_follow SET until = now() - interval '1 minute'`)
	if in, _ := f.svc.Instructions(f.ctx, f.dev); in != nil {
		t.Errorf("instructions after the end: %+v", in)
	}
	if err := f.svc.Purge(f.ctx); err != nil {
		t.Fatal(err)
	}
	// Turned off by hand.
	if _, err := f.svc.SetDeviceVerbose(f.ctx, tech, f.dev, 3); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ClearDeviceVerbose(f.ctx, tech, f.dev); err != nil {
		t.Fatal(err)
	}
	if in, _ := f.svc.Instructions(f.ctx, f.dev); in != nil {
		t.Errorf("instructions after turning off: %+v", in)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.logs_verbose_off'`); n != 1 {
		t.Errorf("%d turn-off entries", n)
	}
}

func TestVerboseForAGroupReachesItsDevices(t *testing.T) {
	f := newFixture(t, 14)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	outsider := f.user("out@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.glob})
	group := f.id(`INSERT INTO device_groups (organization_id, site_id, name) VALUES ($1, $2, 'Servers') RETURNING id`, f.acme, f.hq)
	f.exec(`UPDATE devices SET device_group_id = $1 WHERE id = $2`, group, f.dev)
	other := f.device(f.acme, f.hq, "pc2")
	if _, err := f.svc.SetGroupVerbose(f.ctx, outsider, group, 2); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization: %v", err)
	}
	until, err := f.svc.SetGroupVerbose(f.ctx, tech, group, 4)
	if err != nil {
		t.Fatal(err)
	}
	if in, _ := f.svc.Instructions(f.ctx, f.dev); in == nil || in.VerboseUntil != until.Unix() {
		t.Errorf("the group's device: %+v", in)
	}
	if in, _ := f.svc.Instructions(f.ctx, other); in != nil {
		t.Errorf("a device outside the group: %+v", in)
	}
	page, _ := f.svc.Read(f.ctx, tech, f.dev, agentlogs.Query{}, false)
	if page.Verbose == nil || page.Verbose.Scope != "group" {
		t.Errorf("verbose = %+v", page.Verbose)
	}
	if err := f.svc.ClearGroupVerbose(f.ctx, tech, group); err != nil {
		t.Fatal(err)
	}
	if in, _ := f.svc.Instructions(f.ctx, f.dev); in != nil {
		t.Errorf("after turning off: %+v", in)
	}
}

func TestPurgeDeletesPastRetentionInBatches(t *testing.T) {
	f := newFixture(t, 3)
	f.exec(`INSERT INTO agent_log_records (device_id, seq, source, logged_at, received_at, level, message)
		SELECT $1, g, 'agent', now() - interval '10 days', now() - interval '4 days', 'info', 'old' FROM generate_series(1, 12000) g`, f.dev)
	f.exec(`INSERT INTO agent_log_records (device_id, seq, source, logged_at, level, message)
		SELECT $1, 100000 + g, 'agent', now(), 'info', 'new' FROM generate_series(1, 5) g`, f.dev)
	f.exec(`INSERT INTO agent_log_days (device_id, day) VALUES ($1, (now() - interval '9 days')::date)`, f.dev)
	if err := f.svc.Purge(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM agent_log_records`); n != 5 {
		t.Errorf("%d records left, want 5", n)
	}
	if n := f.count(`SELECT count(*) FROM agent_log_days WHERE day < (now() - interval '5 days')::date`); n != 0 {
		t.Errorf("%d old day counts left", n)
	}
	// The retention is kept within 1 to 90 days.
	for in, want := range map[int]int{0: 1, 500: 90, 30: 30} {
		s := agentlogs.New(f.db, nil, in, slog.New(slog.NewTextHandler(io.Discard, nil)))
		tech := f.user(fmt.Sprintf("t%d@example.com", in), rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
		p, err := s.Read(f.ctx, tech, f.dev, agentlogs.Query{}, false)
		if err != nil || p.RetentionDays != want {
			t.Errorf("retention %d: %d days, %v; want %d", in, p.RetentionDays, err, want)
		}
	}
}

func TestDownloadFormatsAndAudits(t *testing.T) {
	f := newFixture(t, 14)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	ro := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	t0 := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	f.ingest(f.dev, agentproto.LogBatch{Records: []agentproto.LogRecord{
		{Seq: 1, Time: t0, Source: "agent", Level: "warn", Message: "line one\nline two", Attrs: map[string]string{"k": "v"}},
		{Seq: 2, Time: t0.Add(time.Second), Source: "easypatch", Level: "info", Message: "next"},
	}})
	var text, jsonl bytes.Buffer
	if n, err := f.svc.Download(f.ctx, tech, f.dev, agentlogs.Query{}, agentlogs.Text, &text); err != nil || n != 2 {
		t.Fatalf("text download: %d, %v", n, err)
	}
	const layout = "2006-01-02T15:04:05.000Z"
	if want := t0.Format(layout) + " WARN  [agent] line one\\nline two k=\"v\"\n" + t0.Add(time.Second).Format(layout) + " INFO  [easypatch] next\n"; text.String() != want {
		t.Errorf("text = %q", text.String())
	}
	if _, err := f.svc.Download(f.ctx, tech, f.dev, agentlogs.Query{Sources: []string{"easypatch"}}, agentlogs.JSONL, &jsonl); err != nil {
		t.Fatal(err)
	}
	if want := `{"time":"` + t0.Add(time.Second).Format(time.RFC3339) + `","source":"easypatch","level":"info","message":"next"}` + "\n"; jsonl.String() != want {
		t.Errorf("jsonl = %q", jsonl.String())
	}
	if _, err := f.svc.Download(f.ctx, ro, f.dev, agentlogs.Query{}, agentlogs.Text, io.Discard); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.logs_download'`); n != 2 {
		t.Errorf("%d download audit entries, want 2", n)
	}
}
