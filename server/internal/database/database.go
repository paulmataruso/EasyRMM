// Package database owns PostgreSQL connectivity: the runtime connection
// pool, schema migrations, and tenant-scoped transactions.
//
// Every query that touches tenant data runs inside a transaction opened with
// a Scope. The scope is written into transaction-local settings that the
// row-level security policies in the schema read, so a query that forgets a
// tenant filter still cannot return another tenant's rows.
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/paulmataruso/easyrmm/server/migrations"
)

// Scope describes which tenant rows a transaction may see.
type Scope struct {
	// All grants every row. Used for super administrators and for internal
	// system work (audit writes, background jobs, authentication lookups).
	All bool
	// Orgs grants every row belonging to these organizations.
	Orgs []uuid.UUID
	// Sites grants rows belonging to these individual sites.
	Sites []uuid.UUID
	// ReadOrgs lets site-scoped users read (only read) the organization
	// records their sites belong to.
	ReadOrgs []uuid.UUID
}

// System is the unrestricted scope for internal work. Request handlers must
// never use it for data a user asked for.
var System = Scope{All: true}

// DB wraps the runtime connection pool.
type DB struct {
	Pool *pgxpool.Pool
}

// PoolOptions tunes the runtime pool.
type PoolOptions struct {
	MaxConns int32
	// AfterConnectSQL runs on every new connection. Tests use it to assume
	// the runtime role on a superuser connection.
	AfterConnectSQL string
}

// Open connects the runtime pool and verifies connectivity.
func Open(ctx context.Context, dsn string, opts PoolOptions) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("database: parsing connection string: %w", err)
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second
	cfg.ConnConfig.RuntimeParams["application_name"] = "easyrmm-server"
	// Fail fast on runaway statements instead of holding locks forever.
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "30000"
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "60000"
	if opts.AfterConnectSQL != "" {
		stmt := opts.AfterConnectSQL
		cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			_, err := c.Exec(ctx, stmt)
			return err
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database: creating pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: connecting: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Close releases all connections.
func (db *DB) Close() { db.Pool.Close() }

// Ping checks connectivity, for health checks.
func (db *DB) Ping(ctx context.Context) error { return db.Pool.Ping(ctx) }

// InTx runs fn in a read-write transaction restricted to scope. The
// transaction commits if fn returns nil and rolls back otherwise.
func (db *DB) InTx(ctx context.Context, scope Scope, fn func(pgx.Tx) error) error {
	return db.run(ctx, scope, pgx.TxOptions{}, fn)
}

// ReadTx runs fn in a read-only transaction restricted to scope.
func (db *DB) ReadTx(ctx context.Context, scope Scope, fn func(pgx.Tx) error) error {
	return db.run(ctx, scope, pgx.TxOptions{AccessMode: pgx.ReadOnly}, fn)
}

func (db *DB) run(ctx context.Context, scope Scope, opts pgx.TxOptions, fn func(pgx.Tx) error) (err error) {
	tx, err := db.Pool.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("database: begin: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	if err = applyScope(ctx, tx, scope); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("database: commit: %w", err)
	}
	return nil
}

func applyScope(ctx context.Context, tx pgx.Tx, s Scope) error {
	all := ""
	if s.All {
		all = "on"
	}
	_, err := tx.Exec(ctx, `SELECT
		set_config('easyrmm.scope_all', $1, true),
		set_config('easyrmm.scope_orgs', $2, true),
		set_config('easyrmm.scope_sites', $3, true),
		set_config('easyrmm.scope_read_orgs', $4, true)`,
		all, uuidArrayLiteral(s.Orgs), uuidArrayLiteral(s.Sites), uuidArrayLiteral(s.ReadOrgs))
	if err != nil {
		return fmt.Errorf("database: applying scope: %w", err)
	}
	return nil
}

// uuidArrayLiteral renders a PostgreSQL array literal. UUIDs contain only hex
// digits and dashes, so no quoting is needed.
func uuidArrayLiteral(ids []uuid.UUID) string {
	if len(ids) == 0 {
		return "{}"
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = id.String()
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Migrate applies all pending migrations using the owner connection string.
// A PostgreSQL advisory lock serializes concurrent server starts.
func Migrate(ctx context.Context, ownerDSN string, log *slog.Logger) error {
	cfg, err := pgx.ParseConfig(ownerDSN)
	if err != nil {
		return fmt.Errorf("database: parsing migration connection string: %w", err)
	}
	return MigrateWithConfig(ctx, cfg, log)
}

// MigrateWithConfig is Migrate for an already parsed configuration. A
// warning a migration raises, with its hint, goes to the log: some name a
// statement for the operator to run by hand.
func MigrateWithConfig(ctx context.Context, cfg *pgx.ConnConfig, log *slog.Logger) error {
	cfg = cfg.Copy()
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
		if n.Severity == "WARNING" {
			log.Warn("database migration: "+n.Message, "hint", n.Hint)
		}
	}
	sqlDB := stdlib.OpenDB(*cfg)
	defer sqlDB.Close()
	return migrateSQL(ctx, sqlDB, log)
}

func migrateSQL(ctx context.Context, sqlDB *sql.DB, log *slog.Logger) error {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("database: migration lock: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS,
		goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("database: migration provider: %w", err)
	}
	results, err := provider.Up(ctx)
	for _, r := range results {
		if r.Error == nil {
			log.Info("applied database migration", "version", r.Source.Version, "file", r.Source.Path, "duration", r.Duration)
		}
	}
	if err != nil {
		return fmt.Errorf("database: migrating: %w", err)
	}
	return nil
}

// IsUniqueViolation reports whether err is a unique-constraint violation.
func IsUniqueViolation(err error) bool { return hasCode(err, "23505") }

// IsForeignKeyViolation reports whether err is a foreign-key violation:
// a missing referenced row, or a referenced row still in use. PostgreSQL
// reports the latter as restrict_violation (23001) for ON DELETE RESTRICT
// constraints and foreign_key_violation (23503) for NO ACTION ones.
func IsForeignKeyViolation(err error) bool { return hasCode(err, "23503") || hasCode(err, "23001") }

// IsCheckViolation reports whether err is a check-constraint violation.
func IsCheckViolation(err error) bool { return hasCode(err, "23514") }

// IsRLSViolation reports whether err is a row-level-security rejection of a
// write.
func IsRLSViolation(err error) bool { return hasCode(err, "42501") }

func hasCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}

// ConstraintName returns the violated constraint, if any.
func ConstraintName(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}
