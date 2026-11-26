//go:build integration

package jobs

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/migrations"
)

// The guard table's migration goes down and up again.
func TestHardeningGuardMigrationDownUp(t *testing.T) {
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
	has := func() bool {
		var n int
		if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM pg_tables WHERE tablename = 'hardening_guards'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	if !has() {
		t.Fatal("the table is not there after the migrations")
	}
	if _, err := provider.DownTo(ctx, 48); err != nil {
		t.Fatal(err)
	}
	if has() {
		t.Fatal("the table is still there after down")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if !has() {
		t.Fatal("the table did not come back")
	}
}
