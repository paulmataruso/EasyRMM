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

// The agent trust migration (ADR-0055, slice 5b1) goes down and up again, and
// both tables keep forced row-level security that follows the device.
func TestDeviceTLSTrustMigrationGoesDownAndUp(t *testing.T) {
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
	const tables = `SELECT count(*) FROM information_schema.tables WHERE table_name IN ('device_tls_trust', 'device_tls_state')`
	const forced = `SELECT count(*) FROM pg_class WHERE relname IN ('device_tls_trust', 'device_tls_state') AND relrowsecurity AND relforcerowsecurity`
	if got := count(tables); got != 2 || count(forced) != 2 {
		t.Fatalf("after up: %d tables, %d with forced row-level security", got, count(forced))
	}
	var before int64 = -1
	for _, src := range provider.ListSources() {
		if strings.Contains(src.Path, "_device_tls_trust.sql") {
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
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if got := count(tables); got != 2 || count(forced) != 2 {
		t.Fatalf("after up again: %d tables, %d forced", got, count(forced))
	}
}
