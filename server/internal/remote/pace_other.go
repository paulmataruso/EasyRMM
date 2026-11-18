//go:build !linux

package remote

import (
	"net"
	"sync/atomic"
)

// pace is Linux-only (sock_diag); elsewhere writes are not held.
func pace(c net.Conn, _ int, _ *atomic.Int64, _ func()) (net.Conn, bool) { return c, false }
