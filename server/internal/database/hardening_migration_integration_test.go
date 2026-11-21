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

// TestHardeningMigration takes 00027 (ADR-0051) down and up again: down
// removes hardening jobs and what they found and puts the jobs table's
// limits back; up takes a job body larger than a library script. Going
// down past 00012 removes software jobs the same way.
func TestHardeningMigration(t *testing.T) {
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
	exec := func(sql string, args ...any) error {
		_, err := super.Exec(ctx, sql, args...)
		return err
	}
	must := func(sql string, args ...any) {
		t.Helper()
		if err := exec(sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	must(`INSERT INTO organizations (id, name) VALUES ('00000000-0000-0000-0000-00000000000a', 'Acme')`)
	must(`INSERT INTO sites (id, organization_id, name) VALUES ('00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-00000000000a', 'HQ')`)
	must(`INSERT INTO devices (id, organization_id, site_id, name, hostname, platform)
		VALUES ('00000000-0000-0000-0000-00000000000c', '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000b', 'srv', 'srv', 'linux')`)
	job := func(kind, hardening string, bodyBytes int) error {
		return exec(`INSERT INTO jobs (id, script_name, shell, body, body_sha256, timeout_seconds, expires_at, created_by_label, kind, hardening)
			VALUES (gen_random_uuid(), 'x', 'sh', $1, decode(repeat('00', 32), 'hex'), 60, now() + interval '1 day', 'test', $2, $3::jsonb)`,
			strings.Repeat("x", bodyBytes), kind, hardening)
	}
	if err := job("hardening", `{"mode":"check"}`, 300<<10); err != nil {
		t.Fatalf("a large hardening job: %v", err)
	}
	if err := job("hardening", "", 10); err == nil {
		t.Error("a hardening job without its hardening")
	}
	if err := job("script", `{"mode":"check"}`, 10); err == nil {
		t.Error("a script job with hardening")
	}
	if err := job("hardening", `{"mode":"check"}`, 600<<10); err == nil {
		t.Error("a job body over 512 KiB")
	}
	must(`INSERT INTO device_hardening (device_id, module, state, detail, checked_at)
		VALUES ('00000000-0000-0000-0000-00000000000c', 'ssh', 'partly', '{}', now())`)
	if err := exec(`INSERT INTO device_hardening (device_id, module, state, detail, checked_at)
		VALUES ('00000000-0000-0000-0000-00000000000c', 'mac', 'hardened', '{}', now())`); err == nil {
		t.Error("an unknown state")
	}

	if _, err := provider.DownTo(ctx, 26); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := super.QueryRow(ctx, `SELECT count(*) FROM jobs`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d jobs after down, %v", n, err)
	}
	if err := exec(`INSERT INTO jobs (id, script_name, shell, body, body_sha256, timeout_seconds, expires_at, created_by_label, kind)
		VALUES (gen_random_uuid(), 'x', 'sh', $1, decode(repeat('00', 32), 'hex'), 60, now() + interval '1 day', 'test', 'script')`, strings.Repeat("x", 65<<10)); err == nil {
		t.Error("down kept the larger job body")
	}
	if _, err := provider.UpTo(ctx, 27); err != nil {
		t.Fatal(err)
	}
	if err := job("hardening", `{"mode":"check"}`, 300<<10); err != nil {
		t.Fatalf("after up again: %v", err)
	}

	// 00012's down removes software jobs the same way.
	must(`INSERT INTO jobs (id, script_name, shell, body, body_sha256, timeout_seconds, expires_at, created_by_label, kind, software)
		VALUES (gen_random_uuid(), 'Install jq', 'sh', 'x', decode(repeat('00', 32), 'hex'), 60, now() + interval '1 day', 'test',
			'software', '{"action":"install","manager":"system","package":"jq"}')`)
	if _, err := provider.DownTo(ctx, 11); err != nil {
		t.Fatal(err)
	}
	if err := super.QueryRow(ctx, `SELECT count(*) FROM jobs`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d jobs after going down past 00012, %v", n, err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
}
