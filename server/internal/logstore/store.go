// Package logstore is the server's side of ADR-0060, slice 2: the log store,
// a PostgreSQL instance of its own that holds the logs agents' collectors
// sealed into compressed blocks, with hourly facts, partitioned by retention
// class and time under row-level security. Nothing in the main database
// depends on it: a store that is not configured or is down degrades logs and
// nothing else.
package logstore

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/logblock"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Limits of what a device may send.
const (
	// DailyBytes is the most compressed bytes one device stores in 24 hours;
	// blocks past it are refused (and counted), the stream moving on.
	DailyBytes = 256 << 20
	// MaxClockSkew is how far ahead of the server a block may end.
	MaxClockSkew = 24 * time.Hour
	// PartitionMonthsAhead is how many months of partitions are made ahead.
	PartitionMonthsAhead = 2
)

var (
	// ErrUnavailable is a store that is not configured or cannot be reached.
	ErrUnavailable = errors.New("logstore: the log store is not available")
	// ErrBadBatch is a batch the server cannot read.
	ErrBadBatch = errors.New("logstore: not a valid batch of log blocks")
	// ErrNotAllowed is a device the server takes no logs from yet (the
	// development scope holds its organization back).
	ErrNotAllowed = errors.New("logstore: logs are not collected for this organization")
)

var sourceRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// Store is the log store.
type Store struct {
	db    *database.DB
	log   *slog.Logger
	now   func() time.Time
	ready atomic.Bool
}

// New wraps a pool opened on the log store as easyrmm_logs_app (or a
// superuser that assumed it, in tests).
func New(db *database.DB, log *slog.Logger) *Store {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Store{db: db, log: log, now: time.Now}
	s.ready.Store(true)
	return s
}

// Start makes the store unavailable until its schema is migrated, then runs
// its upkeep every hour until ctx ends. The migration is retried every
// minute, so a store that comes up after the server is used as soon as it
// does; the server never waits for it. owner is the owner role's connection
// configuration, or nil when the schema is migrated by hand.
func (s *Store) Start(ctx context.Context, owner *pgx.ConnConfig) {
	s.ready.Store(owner == nil)
	for owner != nil && !s.ready.Load() {
		err := Migrate(ctx, owner, s.log)
		if err == nil {
			s.ready.Store(true)
			break
		}
		if ctx.Err() != nil {
			return
		}
		s.log.Warn("log store: migrating failed; logs are unavailable until it works", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
	for {
		if err := s.Maintain(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("log store: upkeep failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

// Ready says whether the store's schema is in place and it can be used.
func (s *Store) Ready() bool { return s != nil && s.ready.Load() }

// unavailable turns an error from a store that cannot be reached into
// ErrUnavailable.
func (s *Store) unavailable(ctx context.Context, err error) error {
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if s.db.Ping(pctx) != nil {
		return ErrUnavailable
	}
	return err
}

// Migrate brings the store's schema up to date, as its owner role. It uses
// its own migrations, which never run against the main database.
func Migrate(ctx context.Context, cfg *pgx.ConnConfig, log *slog.Logger) error {
	sqlDB := stdlib.OpenDB(*cfg.Copy())
	defer sqlDB.Close()
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("logstore: migration lock: %w", err)
	}
	fsys, err := fsSub()
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, fsys, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("logstore: migration provider: %w", err)
	}
	results, err := provider.Up(ctx)
	for _, r := range results {
		if r.Error == nil {
			log.Info("applied log store migration", "version", r.Source.Version, "file", r.Source.Path, "duration", r.Duration)
		}
	}
	if err != nil {
		return fmt.Errorf("logstore: migrating: %w", err)
	}
	return nil
}

// Ping says whether the store answers.
func (s *Store) Ping(ctx context.Context) error {
	if !s.Ready() {
		return ErrUnavailable
	}
	return s.db.Ping(ctx)
}

// Device is who a batch is from.
type Device struct {
	ID, Organization, Site uuid.UUID
}

// Ingest stores a batch of a device's blocks, in order, each once, and
// answers with the stream's position. A block at or below the position is a
// repeat and is skipped; one that is malformed or over the device's quota is
// refused, counted, and passed over so that one bad block never blocks the
// stream. Nothing a block says about itself is trusted: its events are
// opened and its facts, count and bounds are computed from them.
func (s *Store) Ingest(ctx context.Context, d Device, b agentproto.CollectedBatch) (agentproto.CollectedAck, error) {
	if !s.Ready() {
		return agentproto.CollectedAck{}, ErrUnavailable
	}
	if !devscope.Allowed(d.Organization) {
		return agentproto.CollectedAck{}, ErrNotAllowed
	}
	if len(b.Blocks) == 0 || len(b.Blocks) > agentproto.MaxCollectedBlocks {
		return agentproto.CollectedAck{}, ErrBadBatch
	}
	for i, blk := range b.Blocks {
		if blk.Seq <= 0 || (i > 0 && blk.Seq <= b.Blocks[i-1].Seq) {
			return agentproto.CollectedAck{}, ErrBadBatch
		}
	}
	var ack agentproto.CollectedAck
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		ack = agentproto.CollectedAck{}
		var acked int64
		// The stream's row, locked, so that two requests of one device take
		// turns and a repeat is seen as one.
		if err := tx.QueryRow(ctx, `INSERT INTO log_streams (device_id, organization_id, site_id) VALUES ($1, $2, $3)
			ON CONFLICT (device_id) DO UPDATE SET organization_id = $2, site_id = $3, updated_at = now()
			RETURNING acked_seq`, d.ID, d.Organization, d.Site).Scan(&acked); err != nil {
			return err
		}
		var used int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(octet_length(compressed_data)), 0) FROM log_blocks
			WHERE device_id = $1 AND received_at > now() - interval '24 hours'`, d.ID).Scan(&used); err != nil {
			return err
		}
		now := s.now()
		stored, refused := 0, 0
		high := acked
		for _, blk := range b.Blocks {
			if blk.Seq <= acked {
				continue
			}
			high = blk.Seq
			sealed, err := verify(blk, now)
			if err != nil {
				s.log.Warn("a collected log block was refused", "device_id", d.ID, "seq", blk.Seq, "reason", err.Error())
				refused++
				continue
			}
			if used+int64(len(blk.Data)) > DailyBytes {
				s.log.Warn("a device passed its daily limit of collected logs", "device_id", d.ID)
				refused++
				continue
			}
			factsJSON, err := factsJSON(sealed.Facts)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO log_blocks (device_id, organization_id, site_id, seq, source, retention_class,
					start_time, end_time, event_count, raw_bytes, codec, compressed_data, facts)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
				d.ID, d.Organization, d.Site, blk.Seq, sealed.Source, sealed.Class,
				sealed.Start, sealed.End, sealed.Count, sealed.Raw, sealed.Codec, blk.Data, factsJSON); err != nil {
				return err
			}
			for _, h := range sealed.Facts.Hourly {
				if _, err := tx.Exec(ctx, `INSERT INTO log_hourly_facts (device_id, organization_id, site_id, hour, source, level, events, bytes)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
					ON CONFLICT (device_id, hour, source, level) DO UPDATE
					SET events = log_hourly_facts.events + excluded.events, bytes = log_hourly_facts.bytes + excluded.bytes`,
					d.ID, d.Organization, d.Site, h.Hour, sealed.Source, h.Level, h.Count, h.Bytes); err != nil {
					return err
				}
			}
			used += int64(len(blk.Data))
			stored++
		}
		if high > acked {
			if _, err := tx.Exec(ctx, `UPDATE log_streams SET acked_seq = $2, stored_blocks = stored_blocks + $3,
				refused_blocks = refused_blocks + $4, updated_at = now() WHERE device_id = $1`, d.ID, high, stored, refused); err != nil {
				return err
			}
		}
		ack = agentproto.CollectedAck{Seq: high, Refused: refused}
		return nil
	})
	if err != nil {
		return agentproto.CollectedAck{}, fmt.Errorf("logstore: storing blocks: %w", s.unavailable(ctx, err))
	}
	return ack, nil
}

// verify opens a block and returns what it holds, with the bounds, count and
// facts the events give rather than the ones the block claims.
func verify(blk agentproto.CollectedBlock, now time.Time) (*logblock.Sealed, error) {
	if !sourceRE.MatchString(blk.Source) {
		return nil, errors.New("source")
	}
	if !logblock.ValidClass(blk.Class) {
		return nil, errors.New("class")
	}
	if len(blk.Data) == 0 || len(blk.Data) > agentproto.MaxCollectedBlock {
		return nil, errors.New("size")
	}
	evs, err := logblock.Open(blk.Codec, blk.Data)
	if err != nil {
		return nil, err
	}
	if len(evs) == 0 {
		return nil, errors.New("no events")
	}
	// The facts come from sealing again what was opened: the block the
	// device sent is stored as it came, and its summary is the server's own.
	sealed, err := logblock.Seal(blk.Source, blk.Class, evs)
	if err != nil {
		return nil, err
	}
	if sealed.End.After(now.Add(MaxClockSkew)) {
		return nil, errors.New("the block ends in the future")
	}
	if sealed.Start.Before(now.Add(-logblock.Retention[blk.Class] - 24*time.Hour)) {
		return nil, errors.New("the block is older than its retention")
	}
	sealed.Codec, sealed.Data = blk.Codec, blk.Data
	return sealed, nil
}

// EnsurePartitions makes the months ahead's partitions.
func (s *Store) EnsurePartitions(ctx context.Context) (int, error) {
	var n int
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT easyrmm_logs_ensure_partitions($1)`, PartitionMonthsAhead).Scan(&n)
	})
	return n, err
}

// Purge applies each class's retention.
func (s *Store) Purge(ctx context.Context) (partitions int, blocks int64, err error) {
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT partitions_dropped, blocks_deleted FROM easyrmm_logs_purge()`).Scan(&partitions, &blocks)
	})
	return partitions, blocks, err
}

// Maintain is the store's daily upkeep: partitions ahead, then retention. It
// is a task of the server's maintenance loop; a failure is logged there.
func (s *Store) Maintain(ctx context.Context) error {
	if _, err := s.EnsurePartitions(ctx); err != nil {
		return fmt.Errorf("logstore: making partitions: %w", err)
	}
	p, b, err := s.Purge(ctx)
	if err != nil {
		return fmt.Errorf("logstore: applying retention: %w", err)
	}
	if p > 0 || b > 0 {
		s.log.Info("log store: removed logs past retention", "partitions", p, "blocks", b)
	}
	return nil
}

// OpenPool makes the runtime pool on the log store. It does not connect: a
// store that is down at start is used when it comes up.
func OpenPool(ctx context.Context, dsn, version string) (*database.DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("logstore: parsing connection string: %w", err)
	}
	cfg.MaxConns = 8
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second
	cfg.ConnConfig.RuntimeParams["application_name"] = database.AppName(version)
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "30000"
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "60000"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("logstore: creating pool: %w", err)
	}
	return &database.DB{Pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() {
	if s != nil {
		s.db.Close()
	}
}
