//go:build integration

package database_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/migrations"
)

// ADR-0053 slice 3: the database itself enforces who may use a channel, with
// the service's checks bypassed (every insert here is made at platform scope,
// straight into the tables).
type notifyFixture struct {
	t     *testing.T
	ctx   context.Context
	inst  *testdb.Instance
	orgA  uuid.UUID
	orgB  uuid.UUID
	plat  uuid.UUID // a platform channel
	chanA uuid.UUID // organization A's channel
	chanB uuid.UUID
}

func newNotifyFixture(t *testing.T) *notifyFixture {
	t.Helper()
	f := &notifyFixture{t: t, ctx: context.Background(), inst: testdb.New(t)}
	f.orgA = f.id(`INSERT INTO organizations (name) VALUES ('A') RETURNING id`)
	f.orgB = f.id(`INSERT INTO organizations (name) VALUES ('B') RETURNING id`)
	f.plat = f.channel(uuid.Nil, "platform mail")
	f.chanA = f.channel(f.orgA, "a hook")
	f.chanB = f.channel(f.orgB, "b hook")
	return f
}

func (f *notifyFixture) sys(fn func(tx pgx.Tx) error) error {
	return f.inst.DB.InTx(f.ctx, database.System, fn)
}

func (f *notifyFixture) exec(q string, args ...any) error {
	return f.sys(func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, q, args...)
		return err
	})
}

func (f *notifyFixture) id(q string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.sys(func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, q, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// channel makes an email channel and its details.
func (f *notifyFixture) channel(owner uuid.UUID, name string) uuid.UUID {
	f.t.Helper()
	var org any
	if owner != uuid.Nil {
		org = owner
	}
	id := uuid.New()
	if err := f.sys(func(tx pgx.Tx) error {
		if _, err := tx.Exec(f.ctx, `INSERT INTO notification_channels (id, organization_id, owner, kind, name) VALUES ($1, $2, $3, 'email', $4)`, id, org, owner, name); err != nil {
			return err
		}
		_, err := tx.Exec(f.ctx, `INSERT INTO notification_channel_details (channel_id, owner, recipients, last_error) VALUES ($1, $2, '{a@example.com}', $3)`, id, owner, "secret detail of "+name)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *notifyFixture) count(scope database.Scope, q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.inst.DB.ReadTx(f.ctx, scope, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, q, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *notifyFixture) wantConstraint(err error, name string) {
	f.t.Helper()
	if err == nil {
		f.t.Fatalf("no error, want constraint %s", name)
	}
	if got := database.ConstraintName(err); got != name {
		f.t.Fatalf("constraint %q (%v), want %s", got, err, name)
	}
}

func TestChannelOwnerKeyIsEnforcedByTheDatabase(t *testing.T) {
	f := newNotifyFixture(t)
	// A nil organization_id is refused.
	f.wantConstraint(f.exec(`INSERT INTO notification_channels (organization_id, owner, kind, name) VALUES ($1, $1, 'email', 'nil org')`, uuid.Nil),
		"notification_channels_org_not_nil")
	// The owner key must equal organization_id (or the nil UUID for none).
	f.wantConstraint(f.exec(`INSERT INTO notification_channels (organization_id, owner, kind, name) VALUES ($1, $2, 'email', 'wrong owner')`, f.orgA, f.orgB),
		"notification_channels_owner")
	f.wantConstraint(f.exec(`INSERT INTO notification_channels (organization_id, owner, kind, name) VALUES (NULL, $1, 'email', 'platform with an owner')`, f.orgA),
		"notification_channels_owner")
	// Names are unique per owner, ignoring case; another owner may reuse one.
	f.wantConstraint(f.exec(`INSERT INTO notification_channels (organization_id, owner, kind, name) VALUES ($1, $1, 'email', 'A HOOK')`, f.orgA),
		"notification_channels_name")
	f.channel(f.orgB, "a hook")
	// No organization may have the nil UUID.
	f.wantConstraint(f.exec(`INSERT INTO organizations (id, name) VALUES ($1, 'nil')`, uuid.Nil), "organizations_id_not_nil")
	// A name of 101 characters is refused.
	f.wantConstraint(f.exec(`INSERT INTO notification_channels (organization_id, owner, kind, name) VALUES ($1, $1, 'email', $2)`, f.orgA, strings.Repeat("n", 101)),
		"notification_channels_name_check")
	// Details of one owner cannot hang on another owner's channel.
	err := f.exec(`INSERT INTO notification_channel_details (channel_id, owner) VALUES ($1, $2)`, f.chanA, f.orgB)
	if !database.IsForeignKeyViolation(err) && !database.IsUniqueViolation(err) {
		t.Fatalf("details with another owner: %v", err)
	}
}

func TestSharesAdmitPlatformChannelsOnly(t *testing.T) {
	f := newNotifyFixture(t)
	if err := f.exec(`INSERT INTO notification_channel_shares (channel_id, organization_id) VALUES ($1, $2)`, f.plat, f.orgA); err != nil {
		t.Fatalf("sharing a platform channel: %v", err)
	}
	// An organization's own channel cannot be shared: the share's owner is the nil UUID.
	if err := f.exec(`INSERT INTO notification_channel_shares (channel_id, organization_id) VALUES ($1, $2)`, f.chanB, f.orgA); !database.IsForeignKeyViolation(err) {
		t.Fatalf("sharing an organization's channel: %v", err)
	}
	f.wantConstraint(f.exec(`INSERT INTO notification_channel_shares (channel_id, owner, organization_id) VALUES ($1, $2, $2)`, f.chanB, f.orgB),
		"notification_channel_shares_owner_check")
}

func TestDeliveryIsAboutItsOwnersOrganizationOnly(t *testing.T) {
	f := newNotifyFixture(t)
	ins := func(owner, charged, channel uuid.UUID, about []uuid.UUID) error {
		return f.exec(`INSERT INTO notification_deliveries (owner, charged_org, channel_id, kind, event, about, message)
			VALUES ($1, $2, $3, 'event', 'notices.opened', $4, '{}')`, owner, charged, channel, about)
	}
	if err := ins(f.orgA, f.orgA, f.chanA, []uuid.UUID{f.orgA}); err != nil {
		t.Fatal(err)
	}
	f.wantConstraint(ins(f.orgA, f.orgA, f.chanA, []uuid.UUID{f.orgB}), "notification_deliveries_owner_about")
	f.wantConstraint(ins(f.orgA, f.orgA, f.chanA, []uuid.UUID{f.orgA, f.orgB}), "notification_deliveries_owner_about")
	f.wantConstraint(ins(f.orgA, f.orgB, f.chanA, []uuid.UUID{}), "notification_deliveries_owner_charged")
	// A platform channel's delivery may be about anyone and is charged to the organization whose rule produced it.
	if err := ins(uuid.Nil, f.orgA, f.plat, []uuid.UUID{f.orgA, f.orgB}); err != nil {
		t.Fatal(err)
	}
	// A delivery carries its channel's owner by a composite key: another owner's channel is refused.
	if err := ins(f.orgA, f.orgA, f.chanB, []uuid.UUID{}); !database.IsForeignKeyViolation(err) {
		t.Fatalf("delivery to another owner's channel: %v", err)
	}
	// Pending is the only status with no end.
	f.wantConstraint(f.exec(`INSERT INTO notification_deliveries (owner, charged_org, channel_id, kind, event, message, status) VALUES ($1, $1, $2, 'event', 'x', '{}', 'sent')`, f.orgA, f.chanA),
		"notification_deliveries_ended")
}

func TestRowLevelSecurityBetweenOrganizations(t *testing.T) {
	f := newNotifyFixture(t)
	a := database.Scope{Orgs: []uuid.UUID{f.orgA}}
	b := database.Scope{Orgs: []uuid.UUID{f.orgB}}
	if n := f.count(a, `SELECT count(*) FROM notification_channels`); n != 1 {
		t.Fatalf("organization A sees %d channels, want its own only", n)
	}
	if n := f.count(a, `SELECT count(*) FROM notification_channels WHERE id = $1`, f.chanB); n != 0 {
		t.Fatal("A reads B's channel")
	}
	if n := f.count(a, `SELECT count(*) FROM notification_channel_details WHERE channel_id = $1`, f.chanB); n != 0 {
		t.Fatal("A reads B's channel's details")
	}
	if n := f.count(database.Scope{}, `SELECT count(*) FROM notification_channels`); n != 0 {
		t.Fatalf("an empty scope sees %d channels", n)
	}
	// A platform channel is invisible until shared; shared, its name and kind
	// are visible but never its details, and no organization scope reads them.
	if n := f.count(a, `SELECT count(*) FROM notification_channels WHERE id = $1`, f.plat); n != 0 {
		t.Fatal("an unshared platform channel is visible")
	}
	if err := f.exec(`INSERT INTO notification_channel_shares (channel_id, organization_id) VALUES ($1, $2)`, f.plat, f.orgA); err != nil {
		t.Fatal(err)
	}
	if n := f.count(a, `SELECT count(*) FROM notification_channels WHERE id = $1`, f.plat); n != 1 {
		t.Fatal("a shared platform channel is not visible to the organization")
	}
	if n := f.count(b, `SELECT count(*) FROM notification_channels WHERE id = $1`, f.plat); n != 0 {
		t.Fatal("a platform channel shared with A is visible to B")
	}
	// A Read-Only user's organization is in scope_orgs too: still no platform details.
	for _, s := range []database.Scope{a, b, {}, {Sites: []uuid.UUID{uuid.New()}, ReadOrgs: []uuid.UUID{f.orgA}}} {
		if n := f.count(s, `SELECT count(*) FROM notification_channel_details WHERE channel_id = $1`, f.plat); n != 0 {
			t.Fatalf("scope %+v reads a platform channel's details", s)
		}
	}
	// A shared platform channel is read-only to the organization.
	if err := f.inst.DB.InTx(f.ctx, a, func(tx pgx.Tx) error {
		tag, err := tx.Exec(f.ctx, `UPDATE notification_channels SET name = 'hijacked' WHERE id = $1`, f.plat)
		if err == nil && tag.RowsAffected() != 0 {
			t.Error("an organization renamed a platform channel")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.inst.DB.InTx(f.ctx, a, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO notification_channels (organization_id, owner, kind, name) VALUES (NULL, $1, 'email', 'forged platform')`, uuid.Nil)
		return err
	}); !database.IsRLSViolation(err) {
		t.Fatalf("an organization made a platform channel: %v", err)
	}
	if err := f.inst.DB.InTx(f.ctx, a, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO notification_channel_shares (channel_id, organization_id) VALUES ($1, $2)`, f.plat, f.orgB)
		return err
	}); !database.IsRLSViolation(err) {
		t.Fatalf("an organization shared a platform channel: %v", err)
	}
	// An organization's scope inserts only its own tests.
	ins := func(kind string, owner, channel uuid.UUID) error {
		return f.inst.DB.InTx(f.ctx, a, func(tx pgx.Tx) error {
			_, err := tx.Exec(f.ctx, `INSERT INTO notification_deliveries (owner, charged_org, channel_id, kind, event, message) VALUES ($1, $1, $2, $3, 'x', '{}')`, owner, channel, kind)
			return err
		})
	}
	if err := ins("test", f.orgA, f.chanA); err != nil {
		t.Fatalf("own test: %v", err)
	}
	if err := ins("event", f.orgA, f.chanA); !database.IsRLSViolation(err) {
		t.Fatalf("an organization queued an event: %v", err)
	}
	if err := ins("test", f.orgB, f.chanB); !database.IsRLSViolation(err) {
		t.Fatalf("a test for another organization: %v", err)
	}
	// Approvals: an organization's scope may only ask.
	if err := f.inst.DB.InTx(f.ctx, a, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO notification_channel_approvals (channel_id, owner, host, port, state, prefixes, approved_at)
			VALUES ($1, $2, 'h', 443, 'approved', '{10.0.0.1/32}', now())`, f.chanA, f.orgA)
		return err
	}); !database.IsRLSViolation(err) {
		t.Fatalf("an organization approved its own destination: %v", err)
	}
	if err := f.inst.DB.InTx(f.ctx, a, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO notification_channel_approvals (channel_id, owner, host, port) VALUES ($1, $2, 'h', 443)`, f.chanA, f.orgA)
		return err
	}); err != nil {
		t.Fatalf("an organization asking: %v", err)
	}
	// Quotas are platform scope only.
	if err := f.inst.DB.InTx(f.ctx, a, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO notification_quotas (organization_id, channels) VALUES ($1, 9999)`, f.orgA)
		return err
	}); !database.IsRLSViolation(err) {
		t.Fatalf("an organization wrote its own quota: %v", err)
	}
}

func TestNoticesAndTheirJournal(t *testing.T) {
	f := newNotifyFixture(t)
	a := database.Scope{Orgs: []uuid.UUID{f.orgA}}
	n1 := f.id(`INSERT INTO notices (organization_id, kind, subject, title) VALUES ($1, 'channel_failing', 'c1', 'x') RETURNING id`, f.orgA)
	f.id(`INSERT INTO notices (organization_id, kind, subject, title) VALUES ($1, 'channel_failing', 'c1', 'y') RETURNING id`, f.orgB)
	if got := f.count(database.System, `SELECT count(*) FROM notification_events WHERE subject_type = 'notice' AND event = 'opened'`); got != 2 {
		t.Fatalf("%d opened rows, want one for each notice", got)
	}
	// One open notice for the same thing and organization.
	if err := f.exec(`INSERT INTO notices (organization_id, kind, subject, title) VALUES ($1, 'channel_failing', 'c1', 'again')`, f.orgA); !database.IsUniqueViolation(err) {
		t.Fatalf("second open notice: %v", err)
	}
	// Organization scope reads and acknowledges its own; it cannot open or read another's.
	if n := f.count(a, `SELECT count(*) FROM notices`); n != 1 {
		t.Fatalf("A sees %d notices", n)
	}
	if err := f.inst.DB.InTx(f.ctx, a, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `UPDATE notices SET acknowledged_at = now() WHERE id = $1`, n1)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.inst.DB.InTx(f.ctx, a, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO notices (organization_id, kind, subject, title) VALUES ($1, 'x_kind', 's', 'forged')`, f.orgA)
		return err
	}); !database.IsRLSViolation(err) {
		t.Fatalf("an organization opened a notice: %v", err)
	}
	if err := f.exec(`UPDATE notices SET resolved_at = now() WHERE id = $1`, n1); err != nil {
		t.Fatal(err)
	}
	// Changing the detail is no event: opened, acknowledged, resolved only.
	if err := f.exec(`UPDATE notices SET detail = 'more' WHERE id = $1`, n1); err != nil {
		t.Fatal(err)
	}
	var events string
	if err := f.sys(func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT string_agg(event, ',' ORDER BY id) FROM notification_events WHERE subject_id = $1`, n1).Scan(&events)
	}); err != nil || events != "opened,acknowledged,resolved" {
		t.Fatalf("events %q (%v)", events, err)
	}
	// The runtime role has no INSERT on the journal and cannot rewrite what a row recorded.
	if err := f.exec(`INSERT INTO notification_events (subject_type, subject_id, event) VALUES ('notice', $1, 'forged')`, n1); err == nil {
		t.Fatal("the runtime role forged a journal row")
	}
	if err := f.exec(`UPDATE notification_events SET event = 'rewritten'`); err == nil {
		t.Fatal("the runtime role rewrote a journal row")
	}
	if err := f.exec(`UPDATE notification_events SET status = 'planned', planned_at = now(), failed_runs = 1, error = 'x'`); err != nil {
		t.Fatalf("planner's columns: %v", err)
	}
	// Only platform scope reads the journal.
	if n := f.count(a, `SELECT count(*) FROM notification_events`); n != 0 {
		t.Fatalf("an organization reads the journal (%d rows)", n)
	}
}

func TestNotificationMigrationGoesDownAndUp(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["role"] = "easyrmm_owner"
	sqlDB := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = sqlDB.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	super, err := pgx.Connect(ctx, inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(context.Background()) })
	count := func(q string) int {
		t.Helper()
		var n int
		if err := super.QueryRow(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	const names = `('notification_channels', 'notification_channel_details', 'notification_channel_shares', 'notification_channel_approvals',
		 'notification_deliveries', 'notification_delivery_recipients', 'notification_quotas', 'notices', 'notification_events')`
	tables := `SELECT count(*) FROM information_schema.tables WHERE table_name IN ` + names
	forced := `SELECT count(*) FROM pg_class WHERE relname IN ` + names + ` AND relrowsecurity AND relforcerowsecurity`
	if count(tables) != 9 || count(forced) != 9 {
		t.Fatalf("after up: %d tables, %d with forced row-level security, want 9 each", count(tables), count(forced))
	}
	before := int64(-1)
	for _, src := range provider.ListSources() {
		if strings.Contains(src.Path, "_notification_channels.sql") {
			before = src.Version - 1
		}
	}
	if before < 0 {
		t.Fatal("the migration is not in the sources")
	}
	if _, err := provider.DownTo(ctx, before); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := count(tables); got != 0 {
		t.Fatalf("after down: %d tables, want 0", got)
	}
	if got := count(`SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'notices_journal%'`); got != 0 {
		t.Fatal("the journal's triggers survived the down migration")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if got := count(tables); got != 9 {
		t.Fatalf("after up again: %d tables, want 9", got)
	}
}
