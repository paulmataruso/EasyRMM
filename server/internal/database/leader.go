package database

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Leader chooses one of EasyRMM's servers at a time to do something, with
// a session-level advisory lock held on a connection of its own, taken
// out of the pool. When that server stops, or its connection drops, the
// lock goes with it, and another server's next Lead takes it.
type Leader struct {
	db  *DB
	key int64

	mu sync.Mutex
	// conn holds the lock; nil while this server does not lead.
	conn *pgx.Conn
}

// Leader is the leadership the advisory lock key gives.
func (db *DB) Leader(key int64) *Leader { return &Leader{db: db, key: key} }

// Lead reports whether this server leads: it holds the lock, on a
// connection that still answers, or takes it now. A connection that no
// longer answers is closed, since the lock went with it.
func (l *Leader) Lead(ctx context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn != nil {
		err := l.conn.Ping(ctx)
		if err == nil {
			return true, nil
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		l.drop()
	}
	c, err := l.db.Pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	var got bool
	if err := c.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, l.key).Scan(&got); err != nil {
		// It may have taken the lock before failing: the connection goes,
		// and the lock with it, rather than back to the pool.
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Hijack().Close(closeCtx)
		return false, err
	}
	if !got {
		c.Release()
		return false, nil
	}
	// The connection leaves the pool: a lock held on a pooled connection
	// would go with it to whatever used it next.
	l.conn = c.Hijack()
	return true, nil
}

// Close gives up the lead, if this server has it.
func (l *Leader) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.drop()
}

// drop closes the lock's connection, which ends the lock. Call it with mu
// held.
func (l *Leader) drop() {
	if l.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = l.conn.Close(ctx)
	l.conn = nil
}
