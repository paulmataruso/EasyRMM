//go:build integration

package logstore_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/logblock"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/logstore"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// storeDB makes a log store database as the deployment does: its own roles,
// a database owned by easyrmm_logs_owner, the schema migrated as that owner,
// and a runtime pool that assumes easyrmm_logs_app.
func storeDB(t *testing.T) (db *database.DB, superDSN string) {
	t.Helper()
	base := os.Getenv(testdb.EnvVar)
	if base == "" {
		t.Fatalf("%s is not set", testdb.EnvVar)
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	for _, r := range []string{"easyrmm_logs_owner", "easyrmm_logs_app"} {
		if _, err := admin.Exec(ctx, fmt.Sprintf(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN CREATE ROLE %s NOLOGIN; END IF; END $$`, r, r)); err != nil && !database.IsUniqueViolation(err) {
			t.Fatal(err)
		}
	}
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	name := "easyrmm_logs_t_" + hex.EncodeToString(suffix)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name+" OWNER easyrmm_logs_owner"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			_ = c.Close(context.Background())
		}
	})
	if _, err := admin.Exec(ctx, "GRANT CONNECT ON DATABASE "+name+" TO easyrmm_logs_app"); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	superDSN = u.String()
	cfg, err := pgx.ParseConfig(superDSN)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["role"] = "easyrmm_logs_owner"
	if err := logstore.Migrate(ctx, cfg, quiet); err != nil {
		t.Fatal(err)
	}
	// Running the migration again changes nothing.
	if err := logstore.Migrate(ctx, cfg, quiet); err != nil {
		t.Fatal(err)
	}
	db, err = database.Open(ctx, superDSN, database.PoolOptions{MaxConns: 6, AfterConnectSQL: "SET ROLE easyrmm_logs_app", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db, superDSN
}

var t0 = time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)

func sealed(t *testing.T, source string, evs ...logblock.Event) agentproto.CollectedBlock {
	t.Helper()
	b, err := logblock.Seal(source, logblock.ClassFor(source), evs)
	if err != nil {
		t.Fatal(err)
	}
	return agentproto.CollectedBlock{Source: source, Class: b.Class, Start: b.Start, End: b.End, Count: b.Count, Raw: b.Raw, Codec: b.Codec, Data: b.Data}
}

func ev(offset time.Duration, msg string) logblock.Event {
	return logblock.Event{Time: t0.Add(offset), Level: "info", Message: msg}
}

func batch(seq0 int64, blocks ...agentproto.CollectedBlock) agentproto.CollectedBatch {
	for i := range blocks {
		blocks[i].Seq = seq0 + int64(i)
	}
	return agentproto.CollectedBatch{Blocks: blocks}
}

type fx struct {
	t         *testing.T
	ctx       context.Context
	main      *database.DB
	logs      *database.DB
	superDSN  string
	store     *logstore.Store
	svc       *logstore.Service
	acme, hq  uuid.UUID
	glob, plt uuid.UUID
	dev       uuid.UUID
}

func newFx(t *testing.T) *fx {
	t.Helper()
	inst := testdb.New(t)
	logs, dsn := storeDB(t)
	f := &fx{t: t, ctx: context.Background(), main: inst.DB, logs: logs, superDSN: dsn}
	f.store = logstore.New(logs, quiet)
	f.svc = logstore.NewService(f.store, inst.DB)
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.glob = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.plt = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, f.glob)
	f.dev = f.device(f.acme, f.hq, "pc1")
	return f
}

func (f *fx) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.main.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) device(org, site uuid.UUID, name string) uuid.UUID {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, 'linux', $4, now() - interval '1 day', now()) RETURNING id`, org, site, name, key)
}

func (f *fx) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

func (f *fx) device1() logstore.Device {
	return logstore.Device{ID: f.dev, Organization: f.acme, Site: f.hq}
}

func (f *fx) ingest(d logstore.Device, b agentproto.CollectedBatch) agentproto.CollectedAck {
	f.t.Helper()
	ack, err := f.store.Ingest(f.ctx, d, b)
	if err != nil {
		f.t.Fatal(err)
	}
	return ack
}

func (f *fx) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.logs.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestIngestStoresEachBlockOnceAndKeepsFacts(t *testing.T) {
	f := newFx(t)
	b := batch(10,
		sealed(t, "linux.journal", ev(0, "one"), ev(10*time.Minute, "two"), ev(70*time.Minute, "three")),
		sealed(t, "linux.auth", logblock.Event{Time: t0, Level: "warn", ID: "sshd", Message: "Failed password"}),
	)
	ack := f.ingest(f.device1(), b)
	if ack.Seq != 11 || ack.Refused != 0 {
		t.Fatalf("ack %+v", ack)
	}
	if n := f.count(`SELECT count(*) FROM log_blocks WHERE device_id = $1`, f.dev); n != 2 {
		t.Fatalf("%d blocks", n)
	}
	// The same batch again, and a longer one that repeats it: stored once.
	if ack := f.ingest(f.device1(), b); ack.Seq != 11 {
		t.Fatalf("repeat acked %d", ack.Seq)
	}
	b2 := batch(10, b.Blocks[0], b.Blocks[1], sealed(t, "linux.journal", ev(2*time.Hour, "four")))
	if ack := f.ingest(f.device1(), b2); ack.Seq != 12 {
		t.Fatalf("longer batch acked %d", ack.Seq)
	}
	if n := f.count(`SELECT count(*) FROM log_blocks WHERE device_id = $1`, f.dev); n != 3 {
		t.Fatalf("%d blocks after repeats", n)
	}
	// Hourly facts count events once: two journal events in the first hour.
	if n := f.count(`SELECT events FROM log_hourly_facts WHERE device_id = $1 AND source = 'linux.journal' AND hour = $2`, f.dev, t0); n != 2 {
		t.Fatalf("first hour holds %d events", n)
	}
	// Security class sources and operational ones land in their own partitions.
	if n := f.count(`SELECT count(*) FROM log_blocks WHERE source = 'linux.auth' AND tableoid::regclass::text LIKE 'log_blocks_security%'`); n != 1 {
		t.Fatal("the auth block is not in the security partition")
	}
	if n := f.count(`SELECT count(*) FROM log_blocks WHERE source = 'linux.journal' AND tableoid::regclass::text LIKE 'log_blocks_operational%'`); n != 2 {
		t.Fatal("the journal blocks are not in the operational partition")
	}
}

func TestIngestRefusesBadBlocksAndMovesOn(t *testing.T) {
	f := newFx(t)
	good := sealed(t, "linux.journal", ev(0, "ok"))
	badClass := good
	badClass.Class = "forever"
	badData := good
	badData.Data = []byte("not deflate")
	future := sealed(t, "linux.journal", logblock.Event{Time: time.Now().Add(72 * time.Hour), Message: "from the future"})
	ancient := sealed(t, "app.debug", logblock.Event{Time: time.Now().Add(-30 * 24 * time.Hour), Message: "old debug"})
	badSource := good
	badSource.Source = "Bad Source!"
	ack := f.ingest(f.device1(), batch(1, badClass, badData, future, ancient, badSource, good))
	if ack.Seq != 6 || ack.Refused != 5 {
		t.Fatalf("ack %+v", ack)
	}
	if n := f.count(`SELECT count(*) FROM log_blocks`); n != 1 {
		t.Fatalf("%d blocks", n)
	}
	var refused int
	if err := f.logs.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT refused_blocks FROM log_streams WHERE device_id = $1`, f.dev).Scan(&refused)
	}); err != nil || refused != 5 {
		t.Fatalf("refused_blocks %d %v", refused, err)
	}
}

func TestIngestChecksTheBatch(t *testing.T) {
	f := newFx(t)
	g := sealed(t, "linux.journal", ev(0, "x"))
	for name, b := range map[string]agentproto.CollectedBatch{
		"empty":      {},
		"zero seq":   {Blocks: []agentproto.CollectedBlock{g}},
		"unordered":  {Blocks: []agentproto.CollectedBlock{withSeq(g, 5), withSeq(g, 4)}},
		"too many":   batch(1, g, g, g, g, g, g, g, g, g),
		"duplicates": {Blocks: []agentproto.CollectedBlock{withSeq(g, 5), withSeq(g, 5)}},
	} {
		if _, err := f.store.Ingest(f.ctx, f.device1(), b); !errors.Is(err, logstore.ErrBadBatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func withSeq(b agentproto.CollectedBlock, s int64) agentproto.CollectedBlock { b.Seq = s; return b }

func TestIngestDeviceDailyQuota(t *testing.T) {
	f := newFx(t)
	// Rewrite history instead of sending 256 MiB: one stored block counts
	// for a day's quota after its size is set by the owner.
	f.ingest(f.device1(), batch(1, sealed(t, "linux.journal", ev(0, "first"))))
	super, err := pgx.Connect(f.ctx, f.superDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(f.ctx)
	if _, err := super.Exec(f.ctx, `UPDATE log_blocks SET compressed_data = repeat('x', $1)::bytea`, logstore.DailyBytes); err != nil {
		t.Fatal(err)
	}
	ack := f.ingest(f.device1(), batch(2, sealed(t, "linux.journal", ev(time.Minute, "over"))))
	if ack.Seq != 2 || ack.Refused != 1 {
		t.Fatalf("ack %+v", ack)
	}
	// Another device is unaffected.
	other := logstore.Device{ID: f.device(f.acme, f.hq, "pc2"), Organization: f.acme, Site: f.hq}
	if ack := f.ingest(other, batch(1, sealed(t, "linux.journal", ev(0, "fine")))); ack.Refused != 0 {
		t.Fatalf("another device refused: %+v", ack)
	}
}

func TestDevScopeHoldsOtherOrganizationsBack(t *testing.T) {
	f := newFx(t)
	restore := devscope.Set(f.glob)
	defer restore()
	if _, err := f.store.Ingest(f.ctx, f.device1(), batch(1, sealed(t, "linux.journal", ev(0, "x")))); !errors.Is(err, logstore.ErrNotAllowed) {
		t.Fatalf("an organization outside the scope was stored: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM log_blocks`); n != 0 {
		t.Fatal("stored")
	}
}

func TestRead(t *testing.T) {
	f := newFx(t)
	f.ingest(f.device1(), batch(1,
		sealed(t, "linux.journal", ev(0, "disk almost full"), ev(5*time.Minute, "nginx started"), ev(30*time.Minute, "Disk check ok")),
		sealed(t, "linux.audit",
			logblock.Event{Time: t0.Add(10 * time.Minute), ID: "EXECVE", Message: "EXECVE", Sensitive: map[string]string{"cmdline": "curl -u svc:hunter2 http://x"}},
			logblock.Event{Time: t0.Add(20 * time.Minute), ID: "USER_LOGIN", Message: "USER_LOGIN", Fields: map[string]string{"acct": "bob"}}),
	))
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	since, until := t0.Add(-time.Hour), t0.Add(3*time.Hour)

	res, err := f.svc.Read(f.ctx, admin, f.dev, logstore.Query{Since: since, Until: until})
	if err != nil || len(res.Items) != 5 {
		t.Fatalf("%v %d", err, len(res.Items))
	}
	if !res.Items[0].Time.After(res.Items[4].Time) || res.Items[0].Message != "Disk check ok" {
		t.Fatalf("not newest first: %+v", res.Items)
	}
	if len(res.Sources) != 2 || !res.CanSeeSensitive {
		t.Fatalf("sources %v sensitive %v", res.Sources, res.CanSeeSensitive)
	}

	// Source filter and a case-insensitive search.
	res, _ = f.svc.Read(f.ctx, admin, f.dev, logstore.Query{Since: since, Until: until, Sources: []string{"linux.journal"}, Text: "DISK"})
	if len(res.Items) != 2 {
		t.Fatalf("search: %d", len(res.Items))
	}
	// A time range inside the block.
	res, _ = f.svc.Read(f.ctx, admin, f.dev, logstore.Query{Since: t0.Add(4 * time.Minute), Until: t0.Add(11 * time.Minute)})
	if len(res.Items) != 2 {
		t.Fatalf("range: %d", len(res.Items))
	}

	// Command lines: shown and searched for log.view_sensitive only.
	res, _ = f.svc.Read(f.ctx, admin, f.dev, logstore.Query{Since: since, Until: until, Text: "hunter2"})
	if len(res.Items) != 1 || res.Items[0].Sensitive["cmdline"] == "" {
		t.Fatalf("admin: %+v", res.Items)
	}
	res, err = f.svc.Read(f.ctx, tech, f.dev, logstore.Query{Since: since, Until: until, Text: "hunter2"})
	if err != nil || len(res.Items) != 0 {
		t.Fatalf("a search found a command line for a caller who may not see it: %v %+v", err, res.Items)
	}
	res, _ = f.svc.Read(f.ctx, tech, f.dev, logstore.Query{Since: since, Until: until})
	if len(res.Items) != 5 || res.CanSeeSensitive {
		t.Fatalf("tech: %d", len(res.Items))
	}
	for _, e := range res.Items {
		if len(e.Sensitive) != 0 {
			t.Fatalf("command line shown to a caller who may not see it: %+v", e)
		}
	}

	// Paging by limit and Next.
	page, _ := f.svc.Read(f.ctx, admin, f.dev, logstore.Query{Since: since, Until: until, Limit: 2})
	if len(page.Items) != 2 || !page.More || page.Next == nil {
		t.Fatalf("page 1: %+v", page)
	}
	page2, _ := f.svc.Read(f.ctx, admin, f.dev, logstore.Query{Since: since, Until: *page.Next, Limit: 10})
	if len(page2.Items) != 3 || page2.More {
		t.Fatalf("page 2: %d more=%v", len(page2.Items), page2.More)
	}
}

func TestReadOnlyWhatTheCallerMaySee(t *testing.T) {
	f := newFx(t)
	f.ingest(f.device1(), batch(1, sealed(t, "linux.journal", ev(0, "private"))))
	q := logstore.Query{Since: t0.Add(-time.Hour), Until: t0.Add(time.Hour)}

	outsider := f.user("out@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.glob})
	_, err := f.svc.Read(f.ctx, outsider, f.dev, q)
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Kind != apperr.KindNotFound {
		t.Fatalf("another organization's administrator: %v", err)
	}
	// Row-level security holds even if the service's check were skipped: the
	// outsider's scope sees no blocks and no facts.
	for _, scope := range []database.Scope{outsider.Scope, {}} {
		res, err := f.store.Read(f.ctx, scope, f.dev, q, true)
		if err != nil || len(res.Items) != 0 || len(res.Sources) != 0 {
			t.Fatalf("RLS leaked: %v %+v", err, res)
		}
		tl, err := f.store.Timeline(f.ctx, scope, f.dev, q)
		if err != nil || len(tl.Buckets) != 0 {
			t.Fatalf("RLS leaked facts: %v %+v", err, tl)
		}
	}
	// A site-scoped person sees their site's devices only.
	other := f.device(f.acme, f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Branch') RETURNING id`, f.acme), "pc-branch")
	f.ingest(logstore.Device{ID: other, Organization: f.acme, Site: f.id(`SELECT site_id FROM devices WHERE id = $1`, other)}, batch(1, sealed(t, "linux.journal", ev(0, "branch"))))
	site := f.user("site@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	if res, err := f.svc.Read(f.ctx, site, f.dev, q); err != nil || len(res.Items) != 1 {
		t.Fatalf("own site: %v", err)
	}
	if _, err := f.svc.Read(f.ctx, site, other, q); err == nil {
		t.Fatal("a device of another site was readable")
	}
	if res, err := f.store.Read(f.ctx, site.Scope, other, q, true); err != nil || len(res.Items) != 0 {
		t.Fatalf("RLS leaked another site's blocks: %v", err)
	}
}

func TestTimeline(t *testing.T) {
	f := newFx(t)
	f.ingest(f.device1(), batch(1,
		sealed(t, "linux.journal", ev(0, "a"), ev(time.Minute, "b"), ev(65*time.Minute, "c")),
		sealed(t, "linux.auth", logblock.Event{Time: t0.Add(2 * time.Minute), Level: "warn", Message: "bad"}),
	))
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	tl, err := f.svc.Timeline(f.ctx, admin, f.dev, logstore.Query{Since: t0, Until: t0.Add(3 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, b := range tl.Buckets {
		got[fmt.Sprintf("%s/%s/%s", b.Hour.Format("15"), b.Source, b.Level)] = b.Events
	}
	h0, h1 := t0.Format("15"), t0.Add(time.Hour).Format("15")
	if got[h0+"/linux.journal/info"] != 2 || got[h1+"/linux.journal/info"] != 1 || got[h0+"/linux.auth/warn"] != 1 || len(got) != 3 {
		t.Fatalf("buckets %v", got)
	}
}

func TestPartitionsAndRetention(t *testing.T) {
	f := newFx(t)
	// Partitions are made ahead, and making them again changes nothing.
	n, err := f.store.EnsurePartitions(f.ctx)
	if err != nil || n != 0 {
		t.Fatalf("second ensure made %d: %v", n, err)
	}
	cur := time.Now().UTC().Format("200601")
	for _, cls := range logblock.Classes() {
		if c := f.count(`SELECT count(*) FROM pg_class WHERE relname = $1`, "log_blocks_"+cls+"_"+cur); c != 1 {
			t.Fatalf("no %s partition for this month", cls)
		}
	}
	// A block from a device with a wrong clock (two years back) still has
	// somewhere to go: the default partition, which retention then clears.
	super, err := pgx.Connect(f.ctx, f.superDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(f.ctx)
	old := time.Now().UTC().AddDate(-2, 0, 0)
	for _, cls := range logblock.Classes() {
		if _, err := super.Exec(f.ctx, `INSERT INTO log_blocks (device_id, organization_id, site_id, seq, source, retention_class, start_time, end_time,
			event_count, raw_bytes, codec, compressed_data, facts) VALUES ($1, $2, $3, 1, 'x.y', $4, $5, $5, 1, 1, 'deflate', '\x00', '{}')`,
			f.dev, f.acme, f.hq, cls, old); err != nil {
			t.Fatal(err)
		}
	}
	// And rows inside a class's time stay while rows past it go: a debug
	// block 8 days old is past 7 days, a security block 8 days old is not.
	eight := time.Now().UTC().Add(-8 * 24 * time.Hour)
	for _, cls := range []string{"debug", "security", "operational"} {
		if _, err := super.Exec(f.ctx, `INSERT INTO log_blocks (device_id, organization_id, site_id, seq, source, retention_class, start_time, end_time,
			event_count, raw_bytes, codec, compressed_data, facts) VALUES ($1, $2, $3, 2, 'x.y', $4, $5, $5, 1, 1, 'deflate', '\x00', '{}')`,
			f.dev, f.acme, f.hq, cls, eight); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := super.Exec(f.ctx, `INSERT INTO log_hourly_facts VALUES ($1, $2, $3, $4, 'x.y', 'info', 1, 1)`, f.dev, f.acme, f.hq, old); err != nil {
		t.Fatal(err)
	}
	// An empty monthly partition that lies wholly past retention is dropped.
	if _, err := super.Exec(f.ctx, `CREATE TABLE log_blocks_debug_202001 PARTITION OF log_blocks_debug FOR VALUES FROM ('2020-01-01') TO ('2020-02-01')`); err != nil {
		t.Fatal(err)
	}

	parts, blocks, err := f.store.Purge(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The 2020 partition at least, and the debug partition of last month
	// too once it lies more than nine days past.
	if parts < 1 || f.count(`SELECT count(*) FROM pg_class WHERE relname = 'log_blocks_debug_202001'`) != 0 {
		t.Fatalf("dropped %d partitions, and the old one is not among them", parts)
	}
	if blocks != 4 { // three 2-year-old blocks (security's is 2 years > 1) + the 8-day-old debug one
		t.Fatalf("deleted %d blocks", blocks)
	}
	if f.count(`SELECT count(*) FROM log_blocks WHERE seq = 2`) != 2 {
		t.Fatal("blocks inside their class's time were deleted")
	}
	if f.count(`SELECT count(*) FROM log_blocks WHERE seq = 2 AND retention_class = 'debug'`) != 0 {
		t.Fatal("the debug block past 7 days stays")
	}
	if f.count(`SELECT count(*) FROM log_hourly_facts`) != 0 {
		t.Fatal("old hourly facts stay")
	}
	if err := f.store.Maintain(f.ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRoleCannotChangeWhatItMustNot(t *testing.T) {
	f := newFx(t)
	f.ingest(f.device1(), batch(1, sealed(t, "linux.journal", ev(0, "x"))))
	err := f.logs.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `DELETE FROM log_blocks`)
		return err
	})
	if err == nil {
		t.Fatal("the runtime role deleted blocks")
	}
	err = f.logs.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `DROP TABLE log_blocks_debug_default`)
		return err
	})
	if err == nil {
		t.Fatal("the runtime role dropped a partition")
	}
	// Without a scope, a write is refused by row-level security.
	err = f.logs.InTx(f.ctx, database.Scope{Orgs: []uuid.UUID{f.acme}}, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO log_streams (device_id, organization_id, site_id) VALUES ($1, $2, $3)`, uuid.New(), f.acme, f.hq)
		return err
	})
	if !database.IsRLSViolation(err) {
		t.Fatalf("a scoped insert was allowed: %v", err)
	}
}

func TestUnavailableStore(t *testing.T) {
	f := newFx(t)
	var nilStore *logstore.Store
	if _, err := nilStore.Ingest(f.ctx, f.device1(), batch(1, sealed(t, "linux.journal", ev(0, "x")))); !errors.Is(err, logstore.ErrUnavailable) {
		t.Fatal(err)
	}
	svc := logstore.NewService(nil, f.main)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	if _, err := svc.Read(f.ctx, admin, f.dev, logstore.Query{}); !errors.Is(err, logstore.ErrUnavailable) {
		t.Fatalf("a service without a store: %v", err)
	}
	// A store whose schema is not yet migrated is unavailable, not an error
	// from a missing table.
	short, stop := context.WithTimeout(f.ctx, 500*time.Millisecond)
	defer stop()
	f.store.Start(short, nil) // nil owner: migrated by hand, ready at once, then upkeep until ctx ends
	if !f.store.Ready() {
		t.Fatal("a store migrated by hand is not ready")
	}
	canceled, cancel := context.WithCancel(f.ctx)
	cancel()
	f.store.Start(canceled, mustConfig(t, "postgres://nobody@127.0.0.1:1/none"))
	if f.store.Ready() {
		t.Fatal("a store that could not be migrated is ready")
	}
	if _, err := f.store.Ingest(f.ctx, f.device1(), batch(1, sealed(t, "linux.journal", ev(0, "x")))); !errors.Is(err, logstore.ErrUnavailable) {
		t.Fatal(err)
	}
	if !strings.Contains(logstore.ErrUnavailable.Error(), "not available") {
		t.Fatal("message")
	}
}

func mustConfig(t *testing.T, dsn string) *pgx.ConnConfig {
	t.Helper()
	c, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
