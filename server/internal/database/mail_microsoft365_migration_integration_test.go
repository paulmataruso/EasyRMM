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

// TestMailMicrosoft365Migration takes 00035 (ADR-0053, slice 2) down and up
// again: an application signs in only with its IDs and one credential,
// sealed, and never without TLS; the engine's digests are kept by key; the
// accounts' buckets are platform-scope only; and down removes a console's
// mail server an application signed in to, keeping a password's.
func TestMailMicrosoft365Migration(t *testing.T) {
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
	str := func(sql string, args ...any) string {
		t.Helper()
		var s string
		if err := super.QueryRow(ctx, sql, args...).Scan(&s); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return s
	}
	const tenant, client = "00000000-0000-4000-8000-00000000a001", "00000000-0000-4000-8000-00000000c001"
	// The migration just before 00035, whichever changes number theirs
	// below it, so that down undoes 00035 alone.
	var before int64
	for _, src := range provider.ListSources() {
		if src.Version < 35 && src.Version > before {
			before = src.Version
		}
	}
	app := `UPDATE mail_server SET host = 'smtp.office365.com', port = 587, security = $1, sign_in = 'microsoft365', from_address = 'rmm@example.com',
		tenant_id = $2, client_id = $3, client_credential = $4, client_secret_sealed = $5, client_certificate = $6, client_key_sealed = $7`

	// Up: every way an application's row can be wrong is refused.
	for name, args := range map[string][]any{
		"no tenant":            {"starttls", "", client, "secret", "v1.k1.x", "", ""},
		"no client":            {"starttls", tenant, "", "secret", "v1.k1.x", "", ""},
		"client not a GUID":    {"starttls", tenant, "contoso", "secret", "v1.k1.x", "", ""},
		"no credential":        {"starttls", tenant, client, "", "", "", ""},
		"secret, none sealed":  {"starttls", tenant, client, "secret", "", "", ""},
		"secret and a key":     {"starttls", tenant, client, "secret", "v1.k1.x", "", "v1.k1.y"},
		"certificate, no key":  {"starttls", tenant, client, "certificate", "", "PEM", ""},
		"certificate, no cert": {"starttls", tenant, client, "certificate", "", "", "v1.k1.y"},
		"without TLS":          {"none", tenant, client, "secret", "v1.k1.x", "", ""},
	} {
		if err := exec(app, args...); err == nil || !strings.Contains(err.Error(), "check") {
			t.Errorf("%s: %v", name, err)
		}
	}
	must(app, "tls", tenant, client, "certificate", "", "PEM", "v1.k1.y")
	must(app, "starttls", tenant, client, "secret", "v1.k1.x", "", "")
	// A password's row may not carry an application's.
	if err := exec(`UPDATE mail_server SET sign_in = 'password', username = 'rmm', password_sealed = 'v1.k1.z'`); err == nil {
		t.Fatal("a password with an application's IDs")
	}
	must(`INSERT INTO mail_engine_given (digests) VALUES ('{"k1": "00", "k0": "11"}')`)
	if err := exec(`UPDATE mail_engine_given SET digests = '[]'`); err == nil {
		t.Fatal("digests that are not an object")
	}
	must(`INSERT INTO mail_account_buckets (account_id, full_at) VALUES ('00000000-0000-0000-0000-0000000000a1', now())`)
	if s := str(`SELECT relforcerowsecurity::text || ' ' || has_table_privilege('easyrmm_app', 'mail_account_buckets', 'DELETE')::text
		FROM pg_class WHERE relname = 'mail_account_buckets'`); s != "true true" {
		t.Fatalf("buckets: %s", s)
	}

	// Down: the application's mail server goes, the limits stay.
	must(`UPDATE mail_server SET per_minute = 7`)
	if _, err := provider.DownTo(ctx, before); err != nil {
		t.Fatal(err)
	}
	if s := str(`SELECT host || '|' || sign_in || '|' || per_minute FROM mail_server`); s != "|none|7" {
		t.Fatalf("down: %s", s)
	}
	if s := str(`SELECT count(*)::text FROM mail_engine_given`); s != "0" {
		t.Fatalf("down: %s digests", s)
	}
	if err := exec(`UPDATE mail_server SET sign_in = 'microsoft365'`); err == nil {
		t.Fatal("down: microsoft365 taken")
	}
	// A password's mail server survives the way up and down.
	must(`UPDATE mail_server SET host = 'smtp.example.com', sign_in = 'password', username = 'rmm', password_sealed = 'v1.k1.z', from_address = 'rmm@example.com'`)
	if _, err := provider.UpTo(ctx, 35); err != nil {
		t.Fatal(err)
	}
	if s := str(`SELECT host || '|' || sign_in || '|' || tenant_id || '|' || client_credential FROM mail_server`); s != "smtp.example.com|password||" {
		t.Fatalf("up again: %s", s)
	}
	if _, err := provider.DownTo(ctx, before); err != nil {
		t.Fatal(err)
	}
	if s := str(`SELECT host || '|' || sign_in FROM mail_server`); s != "smtp.example.com|password" {
		t.Fatalf("down again: %s", s)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
}
