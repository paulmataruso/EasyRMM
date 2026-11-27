// Package testdb provisions disposable PostgreSQL databases for integration
// tests.
//
// It needs a PostgreSQL superuser connection string in
// EASYRMM_TEST_DATABASE_URL (see `make test-db`). Each call creates a fresh
// database owned by the easyrmm_owner role, applies all migrations as that
// role, and returns a runtime pool that assumes the easyrmm_app role, so row-
// level security and privilege restrictions behave exactly as in production.
// The database is dropped when the test finishes.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// EnvVar names the superuser connection string variable.
const EnvVar = "EASYRMM_TEST_DATABASE_URL"

// Instance is a provisioned test database.
type Instance struct {
	DB *database.DB
	// SuperDSN connects to the test database as the superuser, for test
	// set-up that must bypass the runtime role's restrictions.
	SuperDSN string
	Name     string
}

// New provisions a migrated database. Integration tests are compiled only
// with the "integration" build tag; when that tag is set a missing
// EASYRMM_TEST_DATABASE_URL fails the test instead of skipping it, so CI can
// never pass without running them.
func New(t testing.TB) *Instance {
	t.Helper()
	base := os.Getenv(EnvVar)
	if base == "" {
		t.Fatalf("%s is not set; run `make test-db` and export the printed value", EnvVar)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("testdb: connecting as superuser: %v", err)
	}
	defer admin.Close(context.Background())

	for _, stmt := range []string{
		`DO $$ BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'easyrmm_owner') THEN
				CREATE ROLE easyrmm_owner NOLOGIN;
			END IF;
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'easyrmm_app') THEN
				CREATE ROLE easyrmm_app NOLOGIN;
			END IF;
		END $$`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil && !database.IsUniqueViolation(err) {
			t.Fatalf("testdb: creating roles: %v", err)
		}
	}

	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	name := "easyrmm_t_" + hex.EncodeToString(suffix)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name+" OWNER easyrmm_owner"); err != nil {
		t.Fatalf("testdb: creating database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(ctx, base)
		if err != nil {
			t.Logf("testdb: cleanup connect: %v", err)
			return
		}
		defer c.Close(ctx)
		if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Logf("testdb: dropping %s: %v", name, err)
		}
	})
	if _, err := admin.Exec(ctx, "GRANT CONNECT ON DATABASE "+name+" TO easyrmm_app"); err != nil {
		t.Fatalf("testdb: grant connect: %v", err)
	}

	dsn, err := withDatabase(base, name)
	if err != nil {
		t.Fatal(err)
	}
	migCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migCfg.RuntimeParams["role"] = "easyrmm_owner"
	if err := database.MigrateWithConfig(ctx, migCfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("testdb: migrating: %v", err)
	}

	db, err := database.Open(ctx, dsn, database.PoolOptions{MaxConns: 8, AfterConnectSQL: "SET ROLE easyrmm_app", Version: "test"})
	if err != nil {
		t.Fatalf("testdb: opening runtime pool: %v", err)
	}
	t.Cleanup(db.Close)
	return &Instance{DB: db, SuperDSN: dsn, Name: name}
}

func withDatabase(dsn, name string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return "", fmt.Errorf("testdb: %s must be a postgres:// URL", EnvVar)
	}
	u.Path = "/" + name
	return u.String(), nil
}
