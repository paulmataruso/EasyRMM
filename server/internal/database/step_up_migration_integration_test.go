//go:build integration

package database_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/migrations"
)

// The step-up migration (ADR-0055) goes down and up again, its columns with it.
func TestStepUpMigrationGoesDownAndUp(t *testing.T) {
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
	columns := func() int {
		t.Helper()
		var n int
		if err := super.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'sessions' AND column_name IN
			('stepped_up_at', 'sso_provider_id', 'step_up_state_hash', 'step_up_nonce', 'step_up_verifier', 'step_up_provider_id', 'step_up_started_at', 'step_up_return')`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := columns(); got != 8 {
		t.Fatalf("after up: %d columns, want 8", got)
	}
	if _, err := provider.DownTo(ctx, 50); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := columns(); got != 0 {
		t.Fatalf("after down: %d columns, want 0", got)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if got := columns(); got != 8 {
		t.Fatalf("after up again: %d columns, want 8", got)
	}
}
