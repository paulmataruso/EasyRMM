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

// The winmod migration (ADR-0073, slice 5) goes down, with a winmod job in
// place, and up again.
func TestWinmodMigrationGoesDownAndUp(t *testing.T) {
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
	const objects = `SELECT (SELECT count(*) FROM information_schema.tables WHERE table_name IN ('winmod_job_secrets', 'winmod_run_results'))
		+ (SELECT count(*) FROM information_schema.columns WHERE table_name = 'jobs' AND column_name IN ('winmod', 'hidden'))`
	if got := count(objects); got != 4 {
		t.Fatalf("after up: %d objects, want 4", got)
	}
	if _, err := super.Exec(ctx, `INSERT INTO jobs (id, script_name, shell, body, body_sha256, timeout_seconds, expires_at, created_at, kind, winmod, hidden)
		VALUES (gen_random_uuid(), 't', 'powershell', 'x', decode(repeat('00', 32), 'hex'), 60, now() + interval '1 hour', now(), 'winmod', '{}', true)`); err != nil {
		t.Fatal(err)
	}
	// Down to the migration before this one, whatever comes after it.
	var before int64 = -1
	for _, src := range provider.ListSources() {
		if strings.Contains(src.Path, "_winmod.sql") {
			before = src.Version - 1
		}
	}
	if before < 0 {
		t.Fatal("the winmod migration is not in the sources")
	}
	if _, err := provider.DownTo(ctx, before); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := count(objects); got != 0 {
		t.Fatalf("after down: %d objects, want 0", got)
	}
	if got := count(`SELECT count(*) FROM jobs WHERE kind = 'winmod'`); got != 0 {
		t.Fatalf("after down: %d winmod jobs", got)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if got := count(objects); got != 4 {
		t.Fatalf("after up again: %d objects, want 4", got)
	}
}
