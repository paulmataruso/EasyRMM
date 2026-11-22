package database

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Leader chooses one of EasyRMM's servers at a time to do something, with
// a session-level advisory lock held on a connection of its own, taken
// out of the pool. When that server stops, or its connection drops, the
// lock goes with it, and another server's next Lead takes it. Both ends
// notice a connection that died without a word within about a minute:
// PostgreSQL by TCP keepalives and a TCP user timeout set on the session
// (leaderKeepalive), the leader by a bounded ping at each Lead and
// keepalives of its own. It needs a session that stays one connection to
// PostgreSQL: a pooler in transaction mode (PgBouncer's) is not
// supported.
type Leader struct {
	db  *DB
	key int64

	mu sync.Mutex
	// conn holds the lock; nil while this server does not lead.
	conn *pgx.Conn
}

// leaderPing bounds the ping by which a leader checks it still leads.
const leaderPing = 5 * time.Second

// leaderKeepalive is how a dead connection holding the lock is noticed.
// After this long idle, a keepalive probe goes every leaderKeepalive/3,
// and three unanswered drop the connection, about 30 seconds in all; data
// unacknowledged for 2 × leaderKeepalive drops it too.
const leaderKeepalive = 15 * time.Second

// Leader is the leadership the advisory lock key gives.
func (db *DB) Leader(key int64) *Leader { return &Leader{db: db, key: key} }

// Lead reports whether this server leads: it holds the lock, on a
// connection that still answers, or takes it now. A connection that no
// longer answers is closed, since the lock went with it.
func (l *Leader) Lead(ctx context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn != nil {
		pctx, cancel := context.WithTimeout(ctx, leaderPing)
		err := l.conn.Ping(pctx)
		cancel()
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
	if err := l.keepalive(ctx); err != nil {
		l.drop()
		return false, err
	}
	return true, nil
}

// keepalive has both ends of the lock's connection notice it dying without
// a word: PostgreSQL by the session's TCP settings (which it ignores on a
// Unix socket), this server by keepalives on its socket.
func (l *Leader) keepalive(ctx context.Context) error {
	secs := int(leaderKeepalive / time.Second)
	if _, err := l.conn.Exec(ctx, fmt.Sprintf(`SET tcp_keepalives_idle = %d; SET tcp_keepalives_interval = %d; SET tcp_keepalives_count = 3;
		SET tcp_user_timeout = %d`, secs, secs/3, 2*secs*1000)); err != nil {
		return err
	}
	nc := l.conn.PgConn().Conn()
	if t, ok := nc.(interface{ NetConn() net.Conn }); ok {
		nc = t.NetConn()
	}
	if tcp, ok := nc.(*net.TCPConn); ok {
		return tcp.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: leaderKeepalive, Interval: leaderKeepalive / 3, Count: 3})
	}
	return nil
}

// Close gives up the lead, if this server has it. The lock is released
// before its connection closes: PostgreSQL ends a closed connection's
// session, and the lock with it, only after the close has returned here,
// so another server trying straight after could otherwise still find it
// held.
func (l *Leader) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), leaderPing)
		// A connection that no longer answers took the lock with it.
		_, _ = l.conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, l.key)
		cancel()
	}
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
