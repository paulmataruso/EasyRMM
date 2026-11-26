//go:build integration && !windows

package database_test

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// The connection that holds the lock is set so that both ends notice it
// dying without a word within about a minute: PostgreSQL by the session's
// TCP settings, this server by keepalives on its socket.
func TestLeaderKeepalive(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	l := inst.DB.Leader(4471209853398)
	t.Cleanup(l.Close)
	if ok, err := l.Lead(ctx); !ok || err != nil {
		t.Fatalf("lead: %v %v", ok, err)
	}
	conn := database.LeaderConn(l)
	for name, want := range map[string]string{"tcp_keepalives_idle": "15", "tcp_keepalives_interval": "5",
		"tcp_keepalives_count": "3", "tcp_user_timeout": "30000"} {
		var got string
		if err := conn.QueryRow(ctx, "SHOW "+name).Scan(&got); err != nil || got != want {
			t.Errorf("%s = %q, want %q (%v)", name, got, want, err)
		}
	}
	nc := conn.PgConn().Conn()
	if u, ok := nc.(interface{ NetConn() net.Conn }); ok {
		nc = u.NetConn()
	}
	tcp, ok := nc.(*net.TCPConn)
	if !ok {
		t.Fatalf("the test database is not reached over TCP: %T", nc)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var on, idle int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		if on, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE); serr == nil {
			idle, serr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE)
		}
	}); err != nil || serr != nil || on != 1 || idle != 15 {
		t.Fatalf("socket keepalive %d, idle %d: %v %v", on, idle, err, serr)
	}
}
