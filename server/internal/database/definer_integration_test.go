//go:build integration

package database_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/migrations"
)

// The functions that run as easyrmm_owner, as migrations leave them. The
// guard below finds them in the catalog; this list only keeps it from
// passing on an empty catalog.
var definerFunctions = []string{
	"easyrmm_audit_append(timestamp with time zone,text,uuid,text,uuid,uuid,uuid,text,text,text,text,inet,text,jsonb)",
	"easyrmm_audit_verify(bigint,integer)",
	"easyrmm_job_arguments(uuid,boolean,uuid[],uuid[],boolean,uuid[],uuid[],timestamp with time zone,text,uuid,text,inet,text)",
	"easyrmm_job_delivery_args(uuid,uuid[])",
	"easyrmm_job_run_output(uuid,boolean,uuid[],uuid[],boolean,uuid[],uuid[],timestamp with time zone,text,uuid,text,inet,text)",
	"easyrmm_purge_audit(interval)",
}

// TestEveryDefinerFunctionNamesPgTempLast fails the build when a function
// that runs as its owner does not end its search_path with pg_temp, which
// would let a caller's temporary types and tables come first.
func TestEveryDefinerFunctionNamesPgTempLast(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	super, err := pgx.Connect(ctx, inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(context.Background()) })

	rows, err := super.Query(ctx, `SELECT p.oid::regprocedure::text, coalesce(p.proconfig, '{}')
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for rows.Next() {
		var name string
		var config []string
		if err := rows.Scan(&name, &config); err != nil {
			t.Fatal(err)
		}
		found[name] = true
		path := ""
		for _, c := range config {
			if v, ok := strings.CutPrefix(c, "search_path="); ok {
				path = v
			}
		}
		parts := strings.Split(path, ",")
		if last := strings.Trim(strings.TrimSpace(parts[len(parts)-1]), `"`); last != "pg_temp" {
			t.Errorf("%s runs as its owner with search_path %q: end it with pg_temp", name, path)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, name := range definerFunctions {
		if !found[name] {
			t.Errorf("%s is not in the catalog as SECURITY DEFINER", name)
		}
	}
}

// TestTemporaryObjectsCannotReachTheOwner proves both layers against a
// caller who puts its own types in its temporary schema. The runtime role
// may not create temporary objects at all. And when a session has them
// anyway (made here as the superuser, then acting as the runtime role),
// every function that runs as easyrmm_owner ignores them, where a function
// without pg_temp last runs the planted code as the owner.
func TestTemporaryObjectsCannotReachTheOwner(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()

	// Layer one: no temporary objects for the runtime role or PUBLIC.
	appCfg, err := pgx.ParseConfig(inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	appCfg.RuntimeParams["role"] = "easyrmm_app"
	app, err := pgx.ConnectConfig(ctx, appCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close(context.Background()) })
	for _, sql := range []string{
		`CREATE TEMP TABLE planted (a integer)`,
		`CREATE DOMAIN pg_temp.jsonb AS pg_catalog.jsonb`,
	} {
		var pgErr *pgconn.PgError
		if _, err := app.Exec(ctx, sql); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s as easyrmm_app: %v, want permission denied", sql, err)
		}
	}

	// The planted code reports by notice, which reaches the client even
	// when the statement then fails and its changes are rolled back.
	superCfg, err := pgx.ParseConfig(inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	var notices []string
	superCfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) { notices = append(notices, n.Message) }
	super, err := pgx.ConnectConfig(ctx, superCfg)
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
	if s := str(`SELECT has_database_privilege('easyrmm_app', current_database(), 'TEMPORARY') || ' ' ||
			has_database_privilege('public', current_database(), 'TEMPORARY')`); s != "false false" {
		t.Errorf("TEMPORARY for easyrmm_app and PUBLIC: %s", s)
	}

	// A run with output, a job with arguments, and a run just delivered.
	must(`INSERT INTO organizations (id, name) VALUES ('00000000-0000-0000-0000-00000000000a', 'Acme')`)
	must(`INSERT INTO sites (id, organization_id, name) VALUES ('00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-00000000000a', 'HQ')`)
	must(`INSERT INTO devices (id, organization_id, site_id, name, hostname, platform)
		VALUES ('00000000-0000-0000-0000-00000000000c', '00000000-0000-0000-0000-00000000000a', '00000000-0000-0000-0000-00000000000b', 'srv', 'srv', 'linux')`)
	must(`INSERT INTO jobs (id, script_name, shell, body, body_sha256, args, timeout_seconds, expires_at, created_by_label)
		VALUES ('00000000-0000-0000-0000-0000000000d1', 'x', 'sh', 'x', decode(repeat('00', 32), 'hex'), '{a,b}', 60, now() + interval '1 day', 'test'),
			('00000000-0000-0000-0000-0000000000d2', 'y', 'sh', 'y', decode(repeat('00', 32), 'hex'), '{c}', 60, now() + interval '1 day', 'test')`)
	must(`INSERT INTO job_runs (id, job_id, organization_id, site_id, device_id, status, expires_at, started_at, finished_at, stdout, output_stored_at)
		VALUES ('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000d1', '00000000-0000-0000-0000-00000000000a',
			'00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-00000000000c', 'succeeded', now(), now(), now(), 'out', now())`)
	must(`INSERT INTO job_runs (id, job_id, organization_id, site_id, device_id, status, expires_at, sent_at)
		VALUES ('00000000-0000-0000-0000-0000000000e2', '00000000-0000-0000-0000-0000000000d2', '00000000-0000-0000-0000-00000000000a',
			'00000000-0000-0000-0000-00000000000b', '00000000-0000-0000-0000-00000000000c', 'sent', now() + interval '1 hour', now())`)
	// A function made the way the earlier ones were, without pg_temp. It is
	// created in another session: creating it compiles it, and a session
	// keeps what it compiled.
	ownerCfg := appCfg.Copy()
	ownerCfg.RuntimeParams["role"] = "easyrmm_owner"
	owner, err := pgx.ConnectConfig(ctx, ownerCfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = owner.Exec(ctx, `CREATE FUNCTION public.without_pg_temp() RETURNS boolean
		LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
		DECLARE about jsonb;
		BEGIN
			about := jsonb_build_object('a', 1);
			RETURN about IS NOT NULL;
		END $$`)
	_ = owner.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Layer two. This session names pg_temp last itself, so only the
	// functions' own search_path decides. Each planted type reports who
	// checked a value of it.
	must(`SET search_path = pg_catalog, public, pg_temp`)
	must(`CREATE FUNCTION pg_temp.planted(anyelement) RETURNS boolean LANGUAGE plpgsql AS $$
		BEGIN
			RAISE NOTICE 'planted code ran as %', current_user;
			RETURN true;
		END $$`)
	for _, typ := range []string{"jsonb", "text", "bytea", "uuid", "inet", "timestamptz"} {
		must(`CREATE DOMAIN pg_temp.` + typ + ` AS pg_catalog.` + typ + ` CHECK (pg_temp.planted(VALUE))`)
	}
	asApp := func(sql string) (string, []string) {
		t.Helper()
		notices = nil
		must(`SET ROLE easyrmm_app`)
		var got string
		if err := super.QueryRow(ctx, sql).Scan(&got); err != nil {
			got = "error: " + err.Error()
		}
		must(`RESET ROLE`)
		return got, notices
	}
	must(`SET easyrmm.scope_all = 'on'`)
	// Once for the variable's NULL start, once for the value assigned.
	got, ran := asApp(`SELECT public.without_pg_temp()::text`)
	if want := []string{"planted code ran as easyrmm_owner", "planted code ran as easyrmm_owner"}; got != "true" || !slices.Equal(ran, want) {
		t.Fatalf("a function without pg_temp: %s, planted code %q: the test proves nothing", got, ran)
	}

	const actor = `'user', '00000000-0000-0000-0000-0000000000f1', 'tester', NULL, 'test'`
	for _, c := range []struct{ sql, want string }{
		{`SELECT result FROM easyrmm_job_run_output('00000000-0000-0000-0000-0000000000e1', true, NULL, NULL, true, NULL, NULL, now(), ` + actor + `)`, "ok"},
		{`SELECT result FROM easyrmm_job_run_output('00000000-0000-0000-0000-0000000000e1', true, NULL, NULL, false, NULL, NULL, now(), ` + actor + `)`, "forbidden"},
		{`SELECT result FROM easyrmm_job_arguments('00000000-0000-0000-0000-0000000000d1', true, NULL, NULL, true, NULL, NULL, now(), ` + actor + `)`, "ok"},
		{`SELECT result FROM easyrmm_job_arguments('00000000-0000-0000-0000-0000000000d1', true, NULL, NULL, false, NULL, NULL, now(), ` + actor + `)`, "forbidden"},
		{`SELECT array_to_string(run_args, ',') FROM easyrmm_job_delivery_args('00000000-0000-0000-0000-00000000000c', ARRAY['00000000-0000-0000-0000-0000000000e2']::uuid[])`, "c"},
		{`SELECT (easyrmm_audit_append(now(), 'system', NULL, 'tester', NULL, NULL, NULL, 'test.planted', 'test', 'x', 'success', NULL, 'test', '{}') > 0)::text`, "true"},
		{`SELECT checked || '/' || coalesce(first_bad_id::text, 'intact') FROM easyrmm_audit_verify(0, 1000)`, "5/intact"},
		{`SELECT easyrmm_purge_audit('30 days')::text`, "0"},
	} {
		got, ran := asApp(c.sql)
		if got != c.want {
			t.Errorf("%s = %q, want %q", c.sql, got, c.want)
		}
		if len(ran) > 0 {
			t.Errorf("%s: %q", c.sql, ran)
		}
	}
}

// TestDefinerSearchPathMigration takes 00029 down and up: down gives the
// earlier functions their old search_path and the runtime role TEMPORARY
// back; up names pg_temp last and revokes TEMPORARY, and when it cannot
// (another role grants it, or another role owns the database) it still
// pins the functions and logs a warning with the statements to run.
func TestDefinerSearchPathMigration(t *testing.T) {
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
	must := func(sql string) {
		t.Helper()
		if _, err := super.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	state := func() string {
		t.Helper()
		var s string
		if err := super.QueryRow(ctx, `SELECT (SELECT string_agg(array_to_string(proconfig, ';'), ' | ' ORDER BY proname)
				FROM pg_proc WHERE proname IN ('easyrmm_audit_append', 'easyrmm_audit_verify', 'easyrmm_purge_audit'))
			|| ' | app temp ' || has_database_privilege('easyrmm_app', current_database(), 'TEMPORARY')`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	down := func() {
		t.Helper()
		if _, err := provider.DownTo(ctx, 28); err != nil {
			t.Fatal(err)
		}
	}
	// Up the way the server runs it, with what it logs.
	up := func() string {
		t.Helper()
		var log bytes.Buffer
		if err := database.MigrateWithConfig(ctx, cfg, slog.New(slog.NewTextHandler(&log, nil))); err != nil {
			t.Fatalf("up: %v", err)
		}
		return log.String()
	}
	const (
		before = "search_path=pg_catalog, public | search_path=pg_catalog, public | search_path=pg_catalog, public | app temp true"
		pinned = "search_path=pg_catalog, public, pg_temp | search_path=pg_catalog, public, pg_temp | search_path=pg_catalog, public, pg_temp"
		after  = pinned + " | app temp false"
		kept   = pinned + " | app temp true"
	)
	if s := state(); s != after {
		t.Errorf("migrated: %s", s)
	}
	down()
	if s := state(); s != before {
		t.Errorf("after down: %s", s)
	}

	// Another role granted the runtime role TEMPORARY: the revoke leaves
	// that grant, and up says so.
	grantor := inst.Name + "_grantor"
	must(`CREATE ROLE ` + grantor + ` NOLOGIN`)
	t.Cleanup(func() {
		_, _ = super.Exec(context.Background(), `REVOKE TEMPORARY ON DATABASE `+inst.Name+` FROM `+grantor+` CASCADE`)
		_, _ = super.Exec(context.Background(), `DROP ROLE `+grantor)
	})
	must(`GRANT TEMPORARY ON DATABASE ` + inst.Name + ` TO ` + grantor + ` WITH GRANT OPTION`)
	must(`SET ROLE ` + grantor)
	must(`GRANT TEMPORARY ON DATABASE ` + inst.Name + ` TO easyrmm_app`)
	must(`RESET ROLE`)
	log := up()
	if s := state(); s != kept {
		t.Errorf("after up with another grant: %s", s)
	}
	if !strings.Contains(log, "level=WARN") || !strings.Contains(log, "easyrmm_app can still create temporary tables in database "+inst.Name) ||
		!strings.Contains(log, "FROM <that role> CASCADE") {
		t.Errorf("up with another grant logged: %s", log)
	}
	must(`REVOKE TEMPORARY ON DATABASE ` + inst.Name + ` FROM ` + grantor + ` CASCADE`)
	if s := state(); s != after {
		t.Errorf("after revoking the other grant: %s", s)
	}

	// Another role owns the database: the functions are pinned, TEMPORARY
	// stays, and up says what to run.
	down()
	must(`ALTER DATABASE ` + inst.Name + ` OWNER TO CURRENT_USER`)
	// The public schema belongs to the database's owner, so an installation
	// under another owner grants easyrmm_owner what the later migrations
	// need to create there, as a superuser would by hand.
	must(`GRANT CREATE ON SCHEMA public TO easyrmm_owner`)
	log = up()
	if s := state(); s != kept {
		t.Errorf("after up under another owner: %s", s)
	}
	if !strings.Contains(log, "level=WARN") ||
		!strings.Contains(log, "database "+inst.Name+" is not owned by easyrmm_owner, so TEMPORARY was not revoked") ||
		!strings.Contains(log, "REVOKE TEMPORARY ON DATABASE "+inst.Name+" FROM PUBLIC, easyrmm_app;") ||
		!strings.Contains(log, "ALTER DATABASE "+inst.Name+" OWNER TO easyrmm_owner;") {
		t.Errorf("up under another owner logged: %s", log)
	}

	must(`ALTER DATABASE ` + inst.Name + ` OWNER TO easyrmm_owner`)
	down()
	if s := state(); s != before {
		t.Errorf("after down again: %s", s)
	}
	if log := up(); strings.Contains(log, "level=WARN") {
		t.Errorf("up logged a warning: %s", log)
	}
	if s := state(); s != after {
		t.Errorf("after up: %s", s)
	}
}
