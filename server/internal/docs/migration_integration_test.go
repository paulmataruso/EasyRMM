//go:build integration

package docs_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/docs"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/migrations"
)

// TestCustomerRecordMigration takes 00036 down and up again with a record
// in it, and checks what the database itself refuses.
func TestCustomerRecordMigration(t *testing.T) {
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
	id := func(sql string, args ...any) string {
		t.Helper()
		var id string
		if err := super.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return id
	}
	refused := func(what, sql string, args ...any) error {
		t.Helper()
		_, err := super.Exec(ctx, sql, args...)
		if err == nil {
			t.Errorf("%s was accepted", what)
		}
		return err
	}

	org := id(`INSERT INTO organizations (name, main_phone, business_hours) VALUES ('Acme', '555 0100', '{"monday": []}') RETURNING id`)
	site := id(`INSERT INTO sites (organization_id, name, address_line1, country_code) VALUES ($1, 'HQ', '1 Example Road', 'GB') RETURNING id`, org)
	other := id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Branch') RETURNING id`, org)
	building := id(`INSERT INTO site_places (organization_id, site_id, depth, kind, name) VALUES ($1, $2, 1, 'building', 'Main') RETURNING id`, org, site)
	id(`INSERT INTO contacts (organization_id, site_id, name, priority) VALUES ($1, $2, 'Hal Desk', 'primary') RETURNING id`, org, site)

	// What the database refuses whatever the server sends.
	if err := refused("a place one level below its parent's depth", `INSERT INTO site_places (organization_id, site_id, parent_id, depth, kind, name)
		VALUES ($1, $2, $3, 3, 'room', 'X')`, org, site, building); !database.IsForeignKeyViolation(err) {
		t.Errorf("depth: %v", err)
	}
	if err := refused("a place inside another site's", `INSERT INTO site_places (organization_id, site_id, parent_id, depth, kind, name)
		VALUES ($1, $2, $3, 2, 'room', 'X')`, org, other, building); !database.IsForeignKeyViolation(err) {
		t.Errorf("another site's parent: %v", err)
	}
	if err := refused("a place five deep", `INSERT INTO site_places (organization_id, site_id, depth, kind, name) VALUES ($1, $2, 5, 'room', 'X')`,
		org, site); !database.IsCheckViolation(err) {
		t.Errorf("five deep: %v", err)
	}
	if err := refused("a parent of a place at the top", `UPDATE site_places SET parent_id = id WHERE id = $1`, building); err == nil {
		t.Error("a place inside itself")
	}
	if err := refused("a second primary at a site", `INSERT INTO contacts (organization_id, site_id, name, priority) VALUES ($1, $2, 'X', 'primary')`,
		org, site); !database.IsUniqueViolation(err) {
		t.Errorf("a second primary: %v", err)
	}
	for what, sql := range map[string]string{
		"a lowercase country":    `UPDATE sites SET country_code = 'gb' WHERE id = $1`,
		"hours as a list":        `UPDATE sites SET business_hours = '[]' WHERE id = $1`,
		"a blank contact name":   `INSERT INTO contacts (organization_id, site_id, name) SELECT organization_id, id, '  ' FROM sites WHERE id = $1`,
		"an unknown priority":    `INSERT INTO contacts (organization_id, site_id, name, priority) SELECT organization_id, id, 'X', 'urgent' FROM sites WHERE id = $1`,
		"an unknown kind":        `INSERT INTO site_places (organization_id, site_id, depth, kind, name) SELECT organization_id, id, 1, 'cupboard', 'X' FROM sites WHERE id = $1`,
		"oversized hours":        `UPDATE sites SET business_hours = jsonb_build_object('note', repeat(md5(random()::text), 400)) WHERE id = $1`,
		"a postal code too long": `UPDATE sites SET postal_code = repeat('1', 21) WHERE id = $1`,
	} {
		if err := refused(what, sql, site); !database.IsCheckViolation(err) {
			t.Errorf("%s: %v", what, err)
		}
	}

	// Down to the migration before 00036, whichever that is once the
	// migrations numbered before it have merged.
	var before int64
	for _, src := range provider.ListSources() {
		if src.Version < 36 {
			before = max(before, src.Version)
		}
	}
	if before == 0 {
		t.Fatal("no migration before 00036")
	}
	if _, err := provider.DownTo(ctx, before); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := super.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name IN ('organizations', 'sites')
		AND column_name IN ('main_phone', 'main_email', 'website', 'business_hours', 'after_hours_note', 'address_line1', 'country_code')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d columns after down: %v", n, err)
	}
	if err := super.QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE tablename IN ('contacts', 'site_places')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d tables after down: %v", n, err)
	}
	// Time zones stored before 00036, when any name the server could open
	// was taken: each spelling of a zone becomes the zone's name.
	zoned := id(`INSERT INTO organizations (name, timezone) VALUES ('Zoned', './Europe/London') RETURNING id`)
	spelled := id(`INSERT INTO sites (organization_id, name, timezone) VALUES ($1, 'Spelled', './/America//./New_York') RETURNING id`, zoned)
	plain := id(`INSERT INTO sites (organization_id, name, timezone) VALUES ($1, 'Plain', 'Etc/GMT+5') RETURNING id`, zoned)
	if _, err := provider.UpTo(ctx, 36); err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]map[string]string{
		"organizations": {zoned: "Europe/London"},
		"sites":         {spelled: "America/New_York", plain: "Etc/GMT+5"},
	} {
		for row, tz := range want {
			if got := id(`SELECT timezone FROM `+table+` WHERE id = $1`, row); got != tz {
				t.Errorf("%s %s: time zone %q, want %q", table, row, got, tz)
			}
		}
	}
	rows, err := super.Query(ctx, `SELECT timezone FROM organizations UNION SELECT timezone FROM sites`)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	for _, tz := range stored {
		if !docs.ValidZone(tz) {
			t.Errorf("a time zone the server would refuse is stored: %q", tz)
		}
	}
	var forced bool
	if err := super.QueryRow(ctx, `SELECT bool_and(relrowsecurity AND relforcerowsecurity) FROM pg_class WHERE relname IN ('contacts', 'site_places')`).Scan(&forced); err != nil || !forced {
		t.Fatalf("row-level security after up: %v %v", forced, err)
	}
}
