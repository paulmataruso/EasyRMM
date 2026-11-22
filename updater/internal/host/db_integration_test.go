//go:build integration

package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/paulmataruso/easyrmm/server/migrations"
)

// The updater's SQL against EasyRMM's schema, through psql in the test
// database's container (make test-db) as its superuser over the local
// socket, as the updater runs it in the deployment's postgres service.

// testDBContainer is the container make test-db starts.
func testDBContainer() string {
	if c := os.Getenv("EASYRMM_TEST_DB_CONTAINER"); c != "" {
		return c
	}
	return "easyrmm-testdb"
}

// psqlRunner runs the updater's `docker compose exec postgres psql` in
// the test database's container, against database instead of easyrmm and
// on the container's port.
type psqlRunner struct {
	t        *testing.T
	database string
	port     string
}

func (r psqlRunner) Run(ctx context.Context, _ string, stdin []byte, args ...string) ([]byte, error) {
	prefix := []string{"compose", "exec", "-T", "--user", "postgres", "postgres", "psql"}
	if !slices.Equal(args[:len(prefix)], prefix) {
		r.t.Fatalf("unexpected docker %v", args)
	}
	psql := slices.Clone(args[len(prefix):])
	for i, a := range psql {
		switch {
		case a == "15432" && psql[i-1] == "-p":
			psql[i] = r.port
		case a == "easyrmm" && psql[i-1] == "-d":
			psql[i] = r.database
		}
	}
	cmd := exec.CommandContext(ctx, "docker", append([]string{"exec", "-i", "--user", "postgres", testDBContainer(), "psql"}, psql...)...)
	cmd.Stdin = strings.NewReader(string(stdin))
	out, err := cmd.Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		r.t.Logf("psql: %s", ee.Stderr)
	}
	return out, err
}

// migrated is a new database with every migration, dropped when the test
// ends.
func migrated(t *testing.T) (*pgx.Conn, psqlRunner) {
	t.Helper()
	ctx := context.Background()
	base := os.Getenv("EASYRMM_TEST_DATABASE_URL")
	if base == "" {
		t.Fatal("EASYRMM_TEST_DATABASE_URL is not set; run `make test-db` and export the printed value")
	}
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'easyrmm_owner') THEN CREATE ROLE easyrmm_owner NOLOGIN; END IF;
		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'easyrmm_app') THEN CREATE ROLE easyrmm_app NOLOGIN; END IF;
	END $$`); err != nil && !strings.Contains(err.Error(), "23505") {
		t.Fatal(err)
	}
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	name := "easyrmm_updater_" + hex.EncodeToString(suffix)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name+" OWNER easyrmm_owner"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	cfg, err := pgx.ParseConfig(u.String())
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["role"] = "easyrmm_owner"
	sqlDB := stdlib.OpenDB(*cfg)
	defer sqlDB.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	super, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { super.Close(context.Background()) })
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	return super, psqlRunner{t: t, database: name, port: port}
}

func appendAudit(t *testing.T, db *pgx.Conn, n int) {
	t.Helper()
	for range n {
		if _, err := db.Exec(context.Background(), `SELECT easyrmm_audit_append(now(), 'system', NULL, 'test', NULL, NULL, NULL,
			'test.recorded', '', '', 'success', NULL, '', '{}'::jsonb)`); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditRollbackSQL(t *testing.T) {
	ctx := context.Background()
	db, r := migrated(t)
	d := Docker{R: r}

	// An empty chain.
	head, err := d.readAuditHead(ctx, "/d")
	if err != nil || head.LastID != 0 || head.Head != "" {
		t.Fatalf("empty: %+v, %v", head, err)
	}
	appendAudit(t, db, 3)
	head, err = d.readAuditHead(ctx, "/d")
	if err != nil {
		t.Fatal(err)
	}
	var want string
	if err := db.QueryRow(ctx, `SELECT encode(entry_hash, 'hex') FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&want); err != nil {
		t.Fatal(err)
	}
	if head.LastID != 3 || head.Head != want {
		t.Fatalf("head %+v, want 3 and %s", head, want)
	}

	// The discarded database had written up to ID 10; the restored one
	// stops at 3. The rollback's record comes after 10 and keeps the chain.
	discarded := &auditHead{LastID: 10, Head: strings.Repeat("ab", 32)}
	taken := time.Date(2026, 11, 21, 3, 0, 0, 0, time.UTC)
	if err := d.recordRollback(ctx, "/d", discarded, rollbackRecord{From: "v1.1.0", To: "v1.0.0", Reason: "it's \"broken\"; DROP TABLE x", BackupTaken: taken}); err != nil {
		t.Fatal(err)
	}
	var id int64
	var action, actor, target, details string
	if err := db.QueryRow(ctx, `SELECT id, action, actor_label, target_id, details::text FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&id, &action, &actor, &target, &details); err != nil {
		t.Fatal(err)
	}
	if id != 11 || action != "updater.rolled_back" || actor != "easyrmm-updater" || target != "v1.1.0" {
		t.Errorf("record %d %s %s %s", id, action, actor, target)
	}
	var rec rollbackRecord
	if err := json.Unmarshal([]byte(details), &rec); err != nil || rec.DiscardedHead != discarded.Head || rec.DiscardedLastID == nil ||
		*rec.DiscardedLastID != 10 || rec.Reason != `it's "broken"; DROP TABLE x` || !rec.BackupTaken.Equal(taken) {
		t.Errorf("details %s (%v)", details, err)
	}
	var checked int64
	var bad *int64
	if err := db.QueryRow(ctx, `SELECT checked, first_bad_id FROM easyrmm_audit_verify(0, 1000)`).Scan(&checked, &bad); err != nil {
		t.Fatal(err)
	}
	if bad != nil {
		t.Errorf("the chain breaks at %d", *bad)
	}
	appendAudit(t, db, 1)
	if err := db.QueryRow(ctx, `SELECT max(id) FROM audit_log`).Scan(&id); err != nil || id != 12 {
		t.Errorf("the next record is %d (%v)", id, err)
	}

	// Unknown: a million past the highest ID.
	if err := d.recordRollback(ctx, "/d", nil, rollbackRecord{From: "v1.2.0", To: "v1.1.0", Reason: "x", BackupTaken: taken}); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT id, details::text FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&id, &details); err != nil {
		t.Fatal(err)
	}
	if id != 12+unknownHeadMargin+1 || !strings.Contains(details, `"discardedHead": "unknown"`) {
		t.Errorf("unknown head: %d %s", id, details)
	}
	// A discarded database below the restored one moves nothing back.
	if err := d.recordRollback(ctx, "/d", &auditHead{LastID: 2}, rollbackRecord{From: "v1.3.0", To: "v1.2.0", BackupTaken: taken}); err != nil {
		t.Fatal(err)
	}
	var next int64
	if err := db.QueryRow(ctx, `SELECT max(id) FROM audit_log`).Scan(&next); err != nil || next != id+1 {
		t.Errorf("after a lower head: %d, want %d (%v)", next, id+1, err)
	}
	if err := db.QueryRow(ctx, `SELECT first_bad_id FROM easyrmm_audit_verify(0, 1000)`).Scan(&bad); err != nil || bad != nil {
		t.Errorf("the chain: %v, %v", bad, err)
	}
}

func TestLossSinceSQL(t *testing.T) {
	ctx := context.Background()
	db, r := migrated(t)
	d := Docker{R: r}
	since := time.Now().Add(-time.Minute)
	loss, err := d.lossSince(ctx, "/d", since)
	if err != nil || loss.DeviceCount != 0 || len(loss.Devices) != 0 || loss.Jobs != 0 || loss.Audit != 0 {
		t.Fatalf("nothing since: %+v, %v", loss, err)
	}
	appendAudit(t, db, 4)
	var org, site string
	if err := db.QueryRow(ctx, `SELECT id::text FROM organizations LIMIT 1`).Scan(&org); err != nil {
		if _, err := db.Exec(ctx, `INSERT INTO organizations (name) VALUES ('Org')`); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(ctx, `SELECT id::text FROM organizations LIMIT 1`).Scan(&org); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'Site')`, org); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT id::text FROM sites LIMIT 1`).Scan(&site); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"desk-1", "desk-2"} {
		if _, err := db.Exec(ctx, `INSERT INTO devices (organization_id, site_id, name) VALUES ($1, $2, $3)`, org, site, n); err != nil {
			t.Fatal(err)
		}
	}
	loss, err = d.lossSince(ctx, "/d", since)
	if err != nil {
		t.Fatal(err)
	}
	if loss.DeviceCount != 2 || !slices.Equal(loss.Devices, []string{"desk-1", "desk-2"}) || loss.Audit != 4 || loss.Jobs != 0 {
		t.Errorf("loss %+v", loss)
	}
	if loss, err = d.lossSince(ctx, "/d", time.Now().Add(time.Hour)); err != nil || loss.DeviceCount != 0 || loss.Audit != 0 {
		t.Errorf("nothing after: %+v, %v", loss, err)
	}
}
