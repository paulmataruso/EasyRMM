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

// TestPowerShell7Migration takes 00033 and 00034 (ADR-0064) up and down
// over rows kept before them: the checks are added unvalidated, then
// validated; each device's PowerShell 7 flag is filled from its stored
// inventory; the new columns are bounded and readable by the server's role,
// PowerShell 7 rows are allowed, and down removes them with the columns,
// keeping the rest.
func TestPowerShell7Migration(t *testing.T) {
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
	refused := func(sql string) {
		t.Helper()
		if _, err := super.Exec(ctx, sql); err == nil {
			t.Errorf("accepted: %s", sql)
		}
	}
	str := func(sql string) string {
		t.Helper()
		var s string
		if err := super.QueryRow(ctx, sql).Scan(&s); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return s
	}
	const (
		org    = "00000000-0000-0000-0000-00000000000a"
		site   = "00000000-0000-0000-0000-00000000000b"
		device = "00000000-0000-0000-0000-00000000000c"
		usable = "00000000-0000-0000-0000-0000000000c2"
		bare   = "00000000-0000-0000-0000-0000000000c3"
		none   = "00000000-0000-0000-0000-0000000000c4"
	)
	job := func(id, shell, extra, values string) {
		t.Helper()
		must(`INSERT INTO jobs (id, script_name, shell, body, body_sha256, args, timeout_seconds, expires_at, created_by_label` + extra + `)
			VALUES ('` + id + `', 'x', '` + shell + `', 'x', decode(repeat('00', 32), 'hex'), '{}', 60, now() + interval '1 day', 'test'` + values + `)`)
		must(`INSERT INTO job_runs (job_id, organization_id, site_id, device_id, status, expires_at) VALUES ($1, $2, $3, $4, 'queued', now() + interval '1 day')`,
			id, org, site, device)
	}

	if _, err := provider.DownTo(ctx, 32); err != nil {
		t.Fatal(err)
	}
	must(`INSERT INTO organizations (id, name) VALUES ($1, 'Acme')`, org)
	must(`INSERT INTO sites (id, organization_id, name) VALUES ($1, $2, 'HQ')`, site, org)
	must(`INSERT INTO devices (id, organization_id, site_id, name, hostname, platform) VALUES ($1, $2, $3, 'pc', 'pc', 'windows')`, device, org, site)
	// Inventories from before: PowerShell 7 found but not usable, usable,
	// a list without it, none at all.
	for id, data := range map[string]string{
		device: `{"powerShell": [{"edition": "Desktop", "usable": true}, {"edition": "Core", "usable": false, "store": true}]}`,
		usable: `{"powerShell": [{"edition": "Desktop", "usable": true}, {"edition": "Core", "usable": true}]}`,
		bare:   `{"os": {"id": "windows"}}`,
	} {
		must(`INSERT INTO devices (id, organization_id, site_id, name, hostname, platform) VALUES ($1, $2, $3, $4, 'pc', 'windows') ON CONFLICT DO NOTHING`,
			id, org, site, "pc "+id[len(id)-2:])
		must(`INSERT INTO device_inventory (device_id, hash, data) VALUES ($1, repeat('0', 64), $2)`, id, data)
	}
	must(`INSERT INTO devices (id, organization_id, site_id, name, hostname, platform) VALUES ($1, $2, $3, 'pc c4', 'pc', 'windows')`, none, org, site)
	must(`INSERT INTO scripts (name, shell, body) VALUES ('Before', 'powershell', 'x')`)
	job("00000000-0000-0000-0000-0000000000d1", "powershell", "", "")
	refused(`INSERT INTO scripts (name, shell, body) VALUES ('Seven', 'pwsh', 'x')`)

	// 00033 adds its checks without reading the rows; 00034, in a
	// transaction of its own, validates them.
	checks := `SELECT string_agg(conname || ':' || convalidated, ' ' ORDER BY conname) FROM pg_constraint
		WHERE conrelid IN ('scripts'::regclass, 'jobs'::regclass, 'job_runs'::regclass, 'devices'::regclass) AND contype = 'c'
		  AND conname IN ('scripts_shell_check', 'scripts_pwsh_fallback', 'jobs_shell_check', 'jobs_pwsh_fallback', 'jobs_requires_check',
		      'job_runs_program_edition_check', 'job_runs_program_version_check', 'job_runs_program_arch_check', 'job_runs_program_path_check',
		      'devices_agent_accepts_check', 'devices_agent_accepts_build_check', 'devices_powershell7_blocked_check')`
	flags := `SELECT string_agg(coalesce(powershell7::text, 'null') || coalesce(powershell7_blocked, ''), ' ' ORDER BY id) FROM devices`
	if _, err := provider.UpTo(ctx, 33); err != nil {
		t.Fatal(err)
	}
	if s := str(checks); strings.Count(s, ":false") != 12 {
		t.Errorf("after 00033: %s", s)
	}
	if s := str(flags); s != "null null null null" {
		t.Errorf("flags after 00033: %s", s)
	}
	if _, err := provider.UpTo(ctx, 34); err != nil {
		t.Fatal(err)
	}
	if s := str(checks); strings.Count(s, ":true") != 12 {
		t.Errorf("after 00034: %s", s)
	}
	// In id order: found but not usable, usable, no list, no inventory.
	if s := str(flags); s != "false true null null" {
		t.Errorf("flags after 00034: %s", s)
	}
	if s := str(`SELECT string_agg(has_column_privilege('easyrmm_app', t, c, 'SELECT')::text, ' ') FROM (VALUES
			('jobs', 'pwsh_fallback'), ('jobs', 'requires'), ('job_runs', 'program_edition'), ('job_runs', 'program_version'),
			('job_runs', 'program_arch'), ('job_runs', 'program_path'), ('job_runs', 'program_fallback'),
			('devices', 'agent_accepts'), ('devices', 'agent_accepts_build'), ('devices', 'powershell7'), ('devices', 'powershell7_blocked')) AS v(t, c)`); s != "true true true true true true true true true true true" {
		t.Errorf("the server's role reads %s", s)
	}
	// Rows from before: no fallback, nothing required, no program.
	if s := str(`SELECT j.pwsh_fallback || ' ' || cardinality(j.requires) || ' ' || (r.program_path IS NULL) || ' ' || r.program_fallback
			FROM jobs j JOIN job_runs r ON r.job_id = j.id`); s != "false 0 true false" {
		t.Errorf("a job from before: %s", s)
	}
	must(`INSERT INTO scripts (name, shell, pwsh_fallback, body, updated_at) VALUES ('Seven', 'pwsh', true, 'x', now() - interval '1 day')`)
	// Changing the fallback is an edit of the script.
	must(`UPDATE scripts SET pwsh_fallback = false WHERE name = 'Seven'`)
	if s := str(`SELECT (updated_at > now() - interval '1 hour')::text FROM scripts WHERE name = 'Seven'`); s != "true" {
		t.Error("changing the fallback did not touch the script")
	}
	job("00000000-0000-0000-0000-0000000000d2", "pwsh", ", pwsh_fallback, requires", ", true, '{job.pwsh}'")
	must(`UPDATE job_runs SET status = 'succeeded', finished_at = now(), program_edition = 'Core', program_version = '7.6.10', program_arch = 'arm64',
			program_path = 'C:\Program Files\PowerShell\7\pwsh.exe' WHERE job_id = '00000000-0000-0000-0000-0000000000d2'`)
	must(`UPDATE devices SET agent_accepts = '{job.pwsh}', agent_accepts_build = repeat('a', 64)`)
	must(`UPDATE devices SET powershell7 = false, powershell7_blocked = repeat('b', 500) WHERE id = $1`, device)
	for _, sql := range []string{
		`INSERT INTO scripts (name, shell, pwsh_fallback, body) VALUES ('Five', 'powershell', true, 'x')`,
		`UPDATE jobs SET pwsh_fallback = true WHERE id = '00000000-0000-0000-0000-0000000000d1'`,
		`UPDATE jobs SET requires = '{job.pwsh,NULL}'`,
		`UPDATE jobs SET requires = array_fill('x'::text, ARRAY[33])`,
		`UPDATE job_runs SET program_edition = 'Preview'`,
		`UPDATE job_runs SET program_arch = 'amd64'`,
		`UPDATE job_runs SET program_version = repeat('7', 65)`,
		`UPDATE job_runs SET program_path = repeat('p', 521)`,
		`UPDATE devices SET agent_accepts = array_fill('x'::text, ARRAY[33])`,
		`UPDATE devices SET agent_accepts = '{NULL}'`,
		`UPDATE devices SET agent_accepts_build = repeat('a', 65)`,
		`UPDATE devices SET powershell7 = false, powershell7_blocked = repeat('b', 501)`,
		`UPDATE devices SET powershell7 = true, powershell7_blocked = 'blocked'`,
		`UPDATE devices SET powershell7 = NULL, powershell7_blocked = 'blocked'`,
	} {
		refused(sql)
	}

	if _, err := provider.DownTo(ctx, 32); err != nil {
		t.Fatal(err)
	}
	if s := str(`SELECT (SELECT string_agg(name, ' ') FROM scripts) || ' / ' || (SELECT string_agg(shell, ' ') FROM jobs) || ' / ' ||
			(SELECT count(*) FROM job_runs)`); s != "Before / powershell / 1" {
		t.Errorf("after down: %s", s)
	}
	if s := str(`SELECT count(*)::text FROM information_schema.columns WHERE table_name IN ('scripts', 'jobs', 'job_runs', 'devices')
			AND (column_name IN ('pwsh_fallback', 'requires', 'agent_accepts', 'agent_accepts_build') OR column_name LIKE 'program\_%'
			  OR column_name LIKE 'powershell7%')`); s != "0" {
		t.Errorf("%s columns left after down", s)
	}
	refused(`INSERT INTO scripts (name, shell, body) VALUES ('Seven', 'pwsh', 'x')`)
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
}
