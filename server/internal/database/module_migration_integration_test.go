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

// The snapshot and module alert migrations (ADR-0073, slices 6 and 7) go
// down, with a module policy and a snapshot in place, and up again.
func TestModuleSnapshotAndAlertMigrationsGoDownAndUp(t *testing.T) {
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
	const objects = `SELECT (SELECT count(*) FROM information_schema.tables WHERE table_name IN ('windows_module_snapshots', 'windows_module_conditions'))
		+ (SELECT count(*) FROM information_schema.columns WHERE table_name = 'alert_policies' AND column_name IN ('module', 'default_key'))`
	if got := count(objects); got != 4 {
		t.Fatalf("after up: %d objects, want 4", got)
	}
	if _, err := super.Exec(ctx, `SELECT set_config('easyrmm.scope_all', 'on', false)`); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(ctx, `WITH o AS (INSERT INTO organizations (name) VALUES ('Acme') RETURNING id)
		INSERT INTO alert_policies (organization_id, name, kind, threshold, minutes, severity, module, default_key)
		SELECT id, 'Defender: Tamper Protection off', 'defender_tamper_off', NULL, 1, 'warning', 'defender', 'tamper_off' FROM o`); err != nil {
		t.Fatal(err)
	}
	var before int64 = -1
	for _, src := range provider.ListSources() {
		if strings.Contains(src.Path, "_module_snapshots.sql") {
			before = src.Version - 1
		}
	}
	if before < 0 {
		t.Fatal("the snapshot migration is not in the sources")
	}
	if _, err := provider.DownTo(ctx, before); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := count(objects); got != 0 {
		t.Fatalf("after down: %d objects, want 0", got)
	}
	if got := count(`SELECT count(*) FROM alert_policies WHERE kind = 'defender_tamper_off'`); got != 0 {
		t.Fatalf("after down: %d module policies", got)
	}
	if _, err := super.Exec(ctx, `INSERT INTO alert_policies (name, kind, threshold, minutes, severity) VALUES ('x', 'defender_tamper_off', NULL, 1, 'warning')`); err == nil {
		t.Fatal("after down: a module kind was accepted by the old check")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if got := count(objects); got != 4 {
		t.Fatalf("after up again: %d objects, want 4", got)
	}
}
