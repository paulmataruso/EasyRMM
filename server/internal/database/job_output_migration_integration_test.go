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

// TestJobOutputMigration takes 00028 (ADR-0063) down and up again over
// runs kept before it: output already kept counts from when its run
// finished, sizes and argument counts are computed, the server's role
// loses the output and arguments, and down gives them back.
func TestJobOutputMigration(t *testing.T) {
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
	must := func(sql string, args ...any) {
		t.Helper()
		if _, err := super.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	str := func(sql string, args ...any) string {
		t.Helper()
		var s string
		if err := super.QueryRow(ctx, sql, args...).Scan(&s); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return s
	}
	privileges := func() string {
		t.Helper()
		return str(`SELECT has_table_privilege('easyrmm_app', 'job_runs', 'SELECT') || ' ' ||
			has_column_privilege('easyrmm_app', 'job_runs', 'stdout', 'SELECT') || ' ' ||
			has_column_privilege('easyrmm_app', 'jobs', 'args', 'SELECT') || ' ' ||
			has_column_privilege('easyrmm_app', 'job_runs', 'status', 'SELECT')`)
	}

	if _, err := provider.DownTo(ctx, 27); err != nil {
		t.Fatal(err)
	}
	if p := privileges(); p != "true true true true" {
		t.Fatalf("before 00028: %s", p)
	}
	must(`INSERT INTO organizations (id, name) VALUES ('00000000-0000-0000-0000-00000000000a', 'Acme')`)
	must(`INSERT INTO sites (id, organization_id, name) VALUES ('00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-00000000000a', 'HQ')`)
	must(`INSERT INTO devices (id, organization_id, site_id, name, hostname, platform)
		VALUES ('00000000-0000-0000-0000-00000000000c', '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000b', 'srv', 'srv', 'linux'),
			('00000000-0000-0000-0000-00000000000d', '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000b', 'srv2', 'srv2', 'linux')`)
	must(`INSERT INTO jobs (id, script_name, shell, body, body_sha256, args, timeout_seconds, expires_at, created_by_label)
		VALUES ('00000000-0000-0000-0000-0000000000d1', 'x', 'sh', 'x', decode(repeat('00', 32), 'hex'), '{a,b,c}', 60, now() + interval '1 day', 'test')`)
	run := func(id, device, stdout, stderr string) {
		must(`INSERT INTO job_runs (id, job_id, organization_id, site_id, device_id, status, expires_at, started_at, finished_at, stdout, stderr)
			VALUES ($1, '00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000b',
				$2, 'succeeded', now(), now() - interval '20 days', now() - interval '20 days', $3, $4)`,
			id, device, stdout, stderr)
	}
	run("00000000-0000-0000-0000-0000000000e1", "00000000-0000-0000-0000-00000000000c", "héllo\n", "")
	run("00000000-0000-0000-0000-0000000000e2", "00000000-0000-0000-0000-00000000000d", "", "")

	if _, err := provider.UpTo(ctx, 28); err != nil {
		t.Fatal(err)
	}
	if p := privileges(); p != "false false false true" {
		t.Errorf("after 00028: %s", p)
	}
	if s := str(`SELECT string_agg(stdout_bytes || '/' || stderr_bytes || '/' || coalesce((output_stored_at = finished_at)::text, '') || '/' ||
			(output_stored_at IS NULL)::text, ' ' ORDER BY id) FROM job_runs`); s != "7/0/true/false 0/0//true" {
		t.Errorf("runs after 00028: %q", s)
	}
	if s := str(`SELECT arg_count::text FROM jobs`); s != "3" {
		t.Errorf("argument count %s", s)
	}
	// Output and its time go together, and removed output stays removed.
	for _, sql := range []string{
		`UPDATE job_runs SET output_stored_at = NULL WHERE id = '00000000-0000-0000-0000-0000000000e1'`,
		`UPDATE job_runs SET output_stored_at = now() WHERE id = '00000000-0000-0000-0000-0000000000e2'`,
		`UPDATE job_runs SET output_removed_at = now() WHERE id = '00000000-0000-0000-0000-0000000000e1'`,
	} {
		if _, err := super.Exec(ctx, sql); err == nil {
			t.Errorf("accepted: %s", sql)
		}
	}

	if _, err := provider.DownTo(ctx, 27); err != nil {
		t.Fatal(err)
	}
	if p := privileges(); p != "true true true true" {
		t.Errorf("after down: %s", p)
	}
	if s := str(`SELECT count(*)::text FROM information_schema.columns WHERE table_name IN ('jobs', 'job_runs')
			AND column_name IN ('stdout_bytes', 'stderr_bytes', 'output_stored_at', 'output_removed_at', 'arg_count')`); s != "0" {
		t.Errorf("%s columns left after down", s)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
}
