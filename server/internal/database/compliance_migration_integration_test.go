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

// The compliance migrations (ADR-0078, slice C1) go down, with a scan and
// results in place, and up again.
func TestComplianceMigrationsGoDownAndUp(t *testing.T) {
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
	const objects = `SELECT count(*) FROM pg_class WHERE relname LIKE 'compliance\_%' AND relkind IN ('r', 'v')`
	up := count(objects)
	if up != 16 {
		t.Fatalf("after up: %d compliance tables and views, want 16", up)
	}
	var org, scan string
	if err := super.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('Down') RETURNING id::text`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	if err := super.QueryRow(ctx, `INSERT INTO compliance_scans (organization_id, trigger, selection, state) VALUES ($1, 'manual', '{}', 'done') RETURNING id::text`, org).Scan(&scan); err != nil {
		t.Fatal(err)
	}
	var site, dev string
	if err := super.QueryRow(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'S') RETURNING id::text`, org).Scan(&site); err != nil {
		t.Fatal(err)
	}
	if err := super.QueryRow(ctx, `INSERT INTO devices (organization_id, site_id, name, hostname, platform) VALUES ($1, $2, 'd', 'd', 'linux') RETURNING id::text`, org, site).Scan(&dev); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(ctx, `INSERT INTO compliance_results_history (organization_id, scan_id, device_id, control_id, control_version, state, checked_at)
		VALUES ($1, $2, $3, 'linux.ssh.x11-forwarding', 1, 'in_place', now())`, org, scan, dev); err != nil {
		t.Fatal(err)
	}
	var before int64 = -1
	for _, src := range provider.ListSources() {
		if strings.Contains(src.Path, "_compliance_library.sql") {
			before = src.Version - 1
		}
	}
	if before < 0 {
		t.Fatal("the compliance migrations are not in the sources")
	}
	if _, err := provider.DownTo(ctx, before); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := count(objects); got != 0 {
		t.Fatalf("after down: %d objects, want 0", got)
	}
	if got := count(`SELECT count(*) FROM pg_proc WHERE proname LIKE 'compliance\_%'`); got != 0 {
		t.Fatalf("after down: %d functions left", got)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if got := count(objects); got != up {
		t.Fatalf("after up again: %d objects, want %d", got, up)
	}
}
