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

// The keystore migration (ADR-0081, section 11) goes down and up again, and
// leaves every table with forced row-level security.
func TestKeystoreMigrationGoesDownAndUp(t *testing.T) {
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
		('keystore_kek_versions', 'keystore_org_keys', 'device_encrypted_volumes', 'recovery_key_escrows')`
	const forced = `SELECT count(*) FROM pg_class WHERE relname IN ('keystore_org_keys', 'device_encrypted_volumes', 'recovery_key_escrows')
		AND relrowsecurity AND relforcerowsecurity`
	if got := count(tables); got != 4 {
		t.Fatalf("after up: %d tables, want 4", got)
	}
	if got := count(forced); got != 3 {
		t.Fatalf("after up: %d tables with forced row-level security, want 3", got)
	}
	var before int64 = -1
	for _, src := range provider.ListSources() {
		if strings.Contains(src.Path, "_keystore.sql") {
			before = src.Version - 1
		}
	}
	if before < 0 {
		t.Fatal("the keystore migration is not in the sources")
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
	if got := count(tables); got != 4 {
		t.Fatalf("after up again: %d tables, want 4", got)
	}
}
