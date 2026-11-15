//go:build integration

package database_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	orgA, orgB, siteA1, siteA2, siteB1 uuid.UUID
}

func seed(t *testing.T, db *database.DB) fixture {
	t.Helper()
	var f fixture
	err := db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		ctx := context.Background()
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`).Scan(&f.orgA); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`).Scan(&f.orgB); err != nil {
			return err
		}
		for _, s := range []struct {
			org  uuid.UUID
			name string
			dst  *uuid.UUID
		}{{f.orgA, "HQ", &f.siteA1}, {f.orgA, "Branch", &f.siteA2}, {f.orgB, "Main", &f.siteB1}} {
			if err := tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, $2) RETURNING id`, s.org, s.name).Scan(s.dst); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO device_groups (organization_id, site_id, name) VALUES ($1, $2, 'Servers'), ($3, $4, 'Servers')`,
			f.orgA, f.siteA1, f.orgB, f.siteB1)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func countRows(t *testing.T, db *database.DB, scope database.Scope, table string) int {
	t.Helper()
	var n int
	err := db.ReadTx(context.Background(), scope, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRowLevelSecurityIsolatesTenants(t *testing.T) {
	inst := testdb.New(t)
	f := seed(t, inst.DB)

	cases := []struct {
		name                      string
		scope                     database.Scope
		orgs, sites, deviceGroups int
	}{
		{"empty scope sees nothing", database.Scope{}, 0, 0, 0},
		{"system sees everything", database.System, 2, 3, 2},
		{"org A", database.Scope{Orgs: []uuid.UUID{f.orgA}}, 1, 2, 1},
		{"org B", database.Scope{Orgs: []uuid.UUID{f.orgB}}, 1, 1, 1},
		{"single site with parent org readable", database.Scope{Sites: []uuid.UUID{f.siteA2}, ReadOrgs: []uuid.UUID{f.orgA}}, 1, 1, 0},
		{"single site without parent org", database.Scope{Sites: []uuid.UUID{f.siteA1}}, 0, 1, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countRows(t, inst.DB, c.scope, "organizations"); got != c.orgs {
				t.Errorf("organizations: got %d want %d", got, c.orgs)
			}
			if got := countRows(t, inst.DB, c.scope, "sites"); got != c.sites {
				t.Errorf("sites: got %d want %d", got, c.sites)
			}
			if got := countRows(t, inst.DB, c.scope, "device_groups"); got != c.deviceGroups {
				t.Errorf("device_groups: got %d want %d", got, c.deviceGroups)
			}
		})
	}
}

func TestRowLevelSecurityBlocksCrossTenantWrites(t *testing.T) {
	inst := testdb.New(t)
	f := seed(t, inst.DB)
	ctx := context.Background()
	scopeA := database.Scope{Orgs: []uuid.UUID{f.orgA}}

	// Creating a site in another tenant's organization is rejected.
	err := inst.DB.InTx(ctx, scopeA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'Sneaky')`, f.orgB)
		return err
	})
	if !database.IsRLSViolation(err) {
		t.Fatalf("cross-tenant insert: want RLS violation, got %v", err)
	}

	// Updating another tenant's rows silently matches nothing.
	err = inst.DB.InTx(ctx, scopeA, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE sites SET name = 'Owned' WHERE id = $1`, f.siteB1)
		if err == nil && tag.RowsAffected() != 0 {
			t.Errorf("cross-tenant update touched %d rows", tag.RowsAffected())
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// Moving an own site into another tenant is rejected by WITH CHECK.
	err = inst.DB.InTx(ctx, scopeA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE device_groups SET organization_id = $1, site_id = $2 WHERE site_id = $3`, f.orgB, f.siteB1, f.siteA1)
		return err
	})
	if !database.IsRLSViolation(err) {
		t.Fatalf("moving a row out of scope: want RLS violation, got %v", err)
	}

	// Organization-scoped users cannot create organizations.
	err = inst.DB.InTx(ctx, scopeA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (name) VALUES ('New Co')`)
		return err
	})
	if !database.IsRLSViolation(err) {
		t.Fatalf("org insert by tenant scope: want RLS violation, got %v", err)
	}
}

func TestCompositeForeignKeyKeepsOrgAndSiteConsistent(t *testing.T) {
	inst := testdb.New(t)
	f := seed(t, inst.DB)
	err := inst.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO device_groups (organization_id, site_id, name) VALUES ($1, $2, 'Mismatch')`, f.orgA, f.siteB1)
		return err
	})
	if !database.IsForeignKeyViolation(err) {
		t.Fatalf("want foreign key violation for mismatched org/site, got %v", err)
	}
}

func TestScopeDoesNotLeakAcrossTransactions(t *testing.T) {
	inst := testdb.New(t)
	seed(t, inst.DB)
	ctx := context.Background()
	if err := inst.DB.ReadTx(ctx, database.System, func(pgx.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	// A raw query outside a scoped transaction must see nothing, even on a
	// pooled connection that previously ran with the system scope.
	for i := 0; i < 10; i++ {
		var n int
		if err := inst.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM organizations").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("unscoped query saw %d organizations", n)
		}
	}
}

func TestRuntimeRoleCannotTamperWithAuditLog(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT easyrmm_audit_append(now(), 'system', NULL, 'test', NULL, NULL, NULL,
			'test.event', '', '', 'success', NULL, '', '{}'::jsonb)`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`INSERT INTO audit_log (occurred_at, actor_type, action, outcome, entry_hash) VALUES (now(), 'system', 'forged.event', 'success', '\x00')`,
		`UPDATE audit_log SET outcome = 'failure'`,
		`DELETE FROM audit_log`,
		`TRUNCATE audit_log`,
		`ALTER TABLE organizations DISABLE ROW LEVEL SECURITY`,
		`SELECT easyrmm_purge_audit(interval '1 day')`,
	} {
		err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, stmt)
			return err
		})
		if err == nil {
			t.Errorf("runtime role was allowed to run %q", stmt)
		}
	}
	var purged int64
	err = inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT easyrmm_purge_audit(interval '30 days')`).Scan(&purged)
	})
	if err != nil || purged != 0 {
		t.Fatalf("retention purge: purged=%d err=%v", purged, err)
	}
}

func TestMigrateIsIdempotentAndErrorHelpers(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	// Re-running migrations against an up-to-date database is a no-op.
	if err := database.Migrate(ctx, inst.SuperDSN, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("second migration run: %v", err)
	}
	if err := database.Migrate(ctx, "not a dsn ::", slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("invalid DSN accepted")
	}
	if err := inst.DB.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (name) VALUES ('Dup'), ('dup')`)
		return err
	})
	if !database.IsUniqueViolation(err) || database.ConstraintName(err) != "organizations_name_key" {
		t.Fatalf("unique violation not recognized: %v (%q)", err, database.ConstraintName(err))
	}
	err = inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (name) VALUES ('   ')`)
		return err
	})
	if !database.IsCheckViolation(err) {
		t.Fatalf("check violation not recognized: %v", err)
	}
	if database.ConstraintName(errors.New("plain")) != "" || database.IsUniqueViolation(nil) {
		t.Fatal("helpers misclassify non-PostgreSQL errors")
	}
}

func TestTransactionRollsBackOnErrorAndPanic(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	boom := errors.New("boom")
	err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organizations (name) VALUES ('Rolled back')`); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("error not propagated: %v", err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic swallowed")
			}
		}()
		_ = inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO organizations (name) VALUES ('Panicked')`); err != nil {
				return err
			}
			panic("handler bug")
		})
	}()
	if n := countRows(t, inst.DB, database.System, "organizations"); n != 0 {
		t.Fatalf("%d rows survived rollback", n)
	}
	// Read-only transactions reject writes.
	err = inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO organizations (name) VALUES ('RO')`)
		return err
	})
	if err == nil {
		t.Fatal("write succeeded in a read-only transaction")
	}
	// A canceled context fails cleanly before any work.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := inst.DB.InTx(cctx, database.System, func(pgx.Tx) error { return nil }); err == nil {
		t.Fatal("transaction began on a canceled context")
	}
}
