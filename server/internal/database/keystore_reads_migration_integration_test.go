//go:build integration

package database_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/migrations"
)

// The keystore reads migration (ADR-0081, slice 2) goes down and up again: its
// add-on roles are accepted by role_assignments only while it is up, and every
// organization table keeps forced row-level security.
func TestKeystoreReadsMigrationGoesDownAndUp(t *testing.T) {
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
	const tables = `SELECT count(*) FROM information_schema.tables WHERE table_name IN
		('keystore_org_settings', 'recovery_key_requests', 'keystore_log_cursor', 'keystore_alerts', 'keystore_notices')`
	const forced = `SELECT count(*) FROM pg_class WHERE relname IN ('keystore_org_settings', 'recovery_key_requests', 'keystore_alerts', 'keystore_notices')
		AND relrowsecurity AND relforcerowsecurity`
	if got := count(tables); got != 5 || count(forced) != 4 {
		t.Fatalf("after up: %d tables, %d with forced row-level security", got, count(forced))
	}
	addOn := func() error {
		_, err := super.Exec(ctx, `WITH u AS (INSERT INTO users (email, display_name) VALUES ('x'||gen_random_uuid()||'@example.com', 'x') RETURNING id),
			o AS (INSERT INTO organizations (name) VALUES ('O'||gen_random_uuid()) RETURNING id)
			INSERT INTO role_assignments (user_id, role, organization_id) SELECT u.id, 'key_reader', o.id FROM u, o`)
		return err
	}
	if err := addOn(); err != nil {
		t.Fatalf("an add-on role is refused while up: %v", err)
	}
	var before int64 = -1
	for _, src := range provider.ListSources() {
		if strings.Contains(src.Path, "_keystore_reads.sql") {
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
	if err := addOn(); err == nil {
		t.Fatal("an add-on role is accepted after down")
	}
	if got := count(`SELECT count(*) FROM role_assignments WHERE role = 'key_reader'`); got != 0 {
		t.Fatalf("add-on assignments left after down: %d", got)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if got := count(tables); got != 5 {
		t.Fatalf("after up again: %d tables, want 5", got)
	}
	if err := addOn(); err != nil {
		t.Fatalf("an add-on role is refused after up again: %v", err)
	}
}
