package tlscert

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// notifyChannel carries the name of a certificate whenever one is stored, so
// that other servers on the same database load it (ADR-0055).
const notifyChannel = "easyrmm_tls"

// Storage is CertMagic's storage (certmagic.Storage, with its Locker) in
// PostgreSQL. Every value is sealed with EASYRMM_SECRET_KEY, with its key as
// associated data, so that a value copied to another row does not open. The
// private keys of accounts and certificates are in it, and never leave it
// except into CertMagic's memory: nothing here logs a value.
type Storage struct {
	db     *database.DB
	sealer *secrets.Sealer

	mu    sync.Mutex
	locks map[string]*heldLock
}

// NewStorage returns the storage.
func NewStorage(db *database.DB, sealer *secrets.Sealer) *Storage {
	return &Storage{db: db, sealer: sealer, locks: map[string]*heldLock{}}
}

var (
	_ certmagic.Storage = (*Storage)(nil)
	_ certmagic.Locker  = (*Storage)(nil)
)

func aad(key string) []byte { return []byte("tls-storage:" + key) }

// Store writes a value, sealed.
func (s *Storage) Store(ctx context.Context, key string, value []byte) error {
	sealed, err := s.sealer.Seal(value, aad(key))
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tls_storage (key, value) VALUES ($1, $2)
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, modified = now()`, key, sealed); err != nil {
			return err
		}
		if strings.HasSuffix(key, ".crt") {
			_, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, notifyChannel, path.Base(path.Dir(key)))
			return err
		}
		return nil
	})
}

// Load reads a value; a missing key is fs.ErrNotExist.
func (s *Storage) Load(ctx context.Context, key string) ([]byte, error) {
	var sealed string
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT value FROM tls_storage WHERE key = $1`, key).Scan(&sealed)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fs.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	plain, err := s.sealer.Open(sealed, aad(key))
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", key, err)
	}
	return plain, nil
}

// Delete removes a key, or every key under it when it is a folder.
func (s *Storage) Delete(ctx context.Context, key string) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM tls_storage WHERE key = $1 OR starts_with(key, $2)`, key, strings.TrimSuffix(key, "/")+"/")
		return err
	})
}

// Exists reports whether the key, or a folder of that name, exists.
func (s *Storage) Exists(ctx context.Context, key string) bool {
	_, err := s.Stat(ctx, key)
	return err == nil
}

// List returns the keys under prefix. Not recursive, it returns the
// immediate children, folders included, as CertMagic's account lookup needs
// (it keeps the entries Stat reports as not terminal).
func (s *Storage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	p := strings.TrimSuffix(prefix, "/") + "/"
	var keys []string
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT key FROM tls_storage WHERE starts_with(key, $1) ORDER BY key`, p)
		if err != nil {
			return err
		}
		defer rows.Close()
		seen := map[string]bool{}
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				return err
			}
			if !recursive {
				rest := strings.TrimPrefix(k, p)
				k = p + strings.SplitN(rest, "/", 2)[0]
				if seen[k] {
					continue
				}
				seen[k] = true
			}
			keys = append(keys, k)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fs.ErrNotExist
	}
	return keys, nil
}

// Stat describes a key. A key with keys under it is not terminal.
func (s *Storage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	info := certmagic.KeyInfo{Key: key}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var n, size int64
		var modified time.Time
		var terminal bool
		err := tx.QueryRow(ctx, `SELECT count(*), coalesce(max(length(value)), 0), coalesce(max(modified), 'epoch'), coalesce(bool_or(key = $1), false)
			FROM tls_storage WHERE key = $1 OR starts_with(key, $2)`, key, strings.TrimSuffix(key, "/")+"/").Scan(&n, &size, &modified, &terminal)
		if err != nil {
			return err
		}
		if n == 0 {
			return fs.ErrNotExist
		}
		info.Modified, info.Size, info.IsTerminal = modified, size, terminal
		return nil
	})
	return info, err
}

// Reseal seals again, with the current key, every value sealed with a
// previous one: account keys and certificate keys are otherwise never
// written again.
func (s *Storage) Reseal(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT key, value FROM tls_storage FOR UPDATE`)
		if err != nil {
			return err
		}
		type kv struct{ k, v string }
		var old []kv
		for rows.Next() {
			var e kv
			if err := rows.Scan(&e.k, &e.v); err != nil {
				rows.Close()
				return err
			}
			if s.sealer.NeedsReseal(e.v) {
				old = append(old, e)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, e := range old {
			plain, err := s.sealer.Open(e.v, aad(e.k))
			if err != nil {
				return fmt.Errorf("tls: opening a stored key (was EASYRMM_SECRET_KEY changed without listing the old key in EASYRMM_SECRET_KEYS_PREVIOUS?): %w", err)
			}
			sealed, err := s.sealer.Seal(plain, aad(e.k))
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE tls_storage SET value = $2 WHERE key = $1`, e.k, sealed); err != nil {
				return err
			}
		}
		return nil
	})
}

// heldLock is an advisory lock on a connection of its own, taken out of the
// pool. PostgreSQL releases it when that connection ends, so a server that
// dies leaves none behind; lost is closed when the connection stops
// answering, and whoever held the lock abandons what it was doing under it.
type heldLock struct {
	conn *pgx.Conn
	lost chan struct{}
	stop chan struct{}
}

const lockPoll = 200 * time.Millisecond

// lockPing is how often a held lock's connection is asked whether it lives.
var lockPing = 5 * time.Second

func lockKey(name string) int64 {
	sum := sha256.Sum256([]byte("easyrmm tls lock " + name))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

// Lock blocks until the named lock is held, or ctx ends.
func (s *Storage) Lock(ctx context.Context, name string) error {
	c, err := s.db.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	key := lockKey(name)
	for {
		var got bool
		if err := c.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = c.Hijack().Close(closeCtx)
			cancel()
			return err
		}
		if got {
			break
		}
		select {
		case <-ctx.Done():
			c.Release()
			return ctx.Err()
		case <-time.After(lockPoll):
		}
	}
	h := &heldLock{conn: c.Hijack(), lost: make(chan struct{}), stop: make(chan struct{})}
	s.mu.Lock()
	s.locks[name] = h
	s.mu.Unlock()
	go h.watch()
	return nil
}

func (h *heldLock) watch() {
	t := time.NewTicker(lockPing)
	defer t.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := h.conn.Ping(ctx)
			cancel()
			if err != nil {
				close(h.lost)
				return
			}
		}
	}
}

// Unlock releases a lock taken with Lock.
func (s *Storage) Unlock(ctx context.Context, name string) error {
	s.mu.Lock()
	h := s.locks[name]
	delete(s.locks, name)
	s.mu.Unlock()
	if h == nil {
		return fmt.Errorf("tls: lock %q is not held", name)
	}
	close(h.stop)
	// Released before the connection closes, so that another server trying
	// straight after does not find it held.
	_, err := h.conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, lockKey(name))
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = h.conn.Close(closeCtx)
	return err
}

// Lost returns a channel closed when the connection of the named lock, held
// here, stopped answering: the lock is gone, and another server may hold it.
func (s *Storage) Lost(name string) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h := s.locks[name]; h != nil {
		return h.lost
	}
	c := make(chan struct{})
	close(c)
	return c
}
