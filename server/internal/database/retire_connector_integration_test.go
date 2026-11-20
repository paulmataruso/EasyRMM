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

// TestRetireConnectorMigration upgrades a database that still has an
// EasyPatch server set up in Settings (00023, ADR-0046): the server is
// forgotten with its links, which name its ids, and the audit log says so.
// Without one, links are the engine's and stay.
func TestRetireConnectorMigration(t *testing.T) {
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
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := super.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	count := func(sql string) (n int) {
		t.Helper()
		if err := super.QueryRow(ctx, sql).Scan(&n); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return n
	}
	upgrade := func(withServer bool) {
		t.Helper()
		if _, err := provider.DownTo(ctx, 22); err != nil {
			t.Fatal(err)
		}
		exec(`DELETE FROM easypatch_organizations`)
		exec(`DELETE FROM organizations`)
		exec(`INSERT INTO organizations (name) VALUES ('Acme')`)
		exec(`INSERT INTO easypatch_organizations (organization_id, easypatch_id, easypatch_name)
			SELECT id, gen_random_uuid(), 'Acme Patch' FROM organizations`)
		if withServer {
			exec(`INSERT INTO easypatch_connection (url, token_sealed) VALUES ('https://patch.example.com', 'sealed')`)
		}
		if _, err := provider.UpTo(ctx, 23); err != nil {
			t.Fatal(err)
		}
		if n := count(`SELECT count(*) FROM pg_tables WHERE tablename = 'easypatch_connection'`); n != 0 {
			t.Fatal("easypatch_connection is still there")
		}
	}

	upgrade(false)
	if n := count(`SELECT count(*) FROM easypatch_organizations`); n != 1 {
		t.Fatalf("without a server, %d links; want the engine's 1", n)
	}
	if n := count(`SELECT count(*) FROM audit_log WHERE action = 'easypatch.connection_delete'`); n != 0 {
		t.Fatalf("without a server, %d audit records", n)
	}

	upgrade(true)
	if n := count(`SELECT count(*) FROM easypatch_organizations`); n != 0 {
		t.Fatalf("the server's %d links stay", n)
	}
	var label, url, reason string
	if err := super.QueryRow(ctx, `SELECT actor_label, details->>'url', details->>'reason' FROM audit_log
		WHERE action = 'easypatch.connection_delete' AND actor_type = 'system'`).Scan(&label, &url, &reason); err != nil {
		t.Fatal(err)
	}
	if label != "easypatch" || url != "https://patch.example.com" || reason != "replaced by the patching engine in this deployment" {
		t.Fatalf("audit: %s %s %s", label, url, reason)
	}
	var bad *int64
	if err := super.QueryRow(ctx, `SELECT first_bad_id FROM easyrmm_audit_verify(0, 1000)`).Scan(&bad); err != nil || bad != nil {
		t.Fatalf("audit chain: first bad %v, %v", bad, err)
	}
}
