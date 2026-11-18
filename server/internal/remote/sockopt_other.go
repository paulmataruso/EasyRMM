//go:build !linux

package remote

import (
	"net"
	"syscall"
)

// boundSendQueue is Linux-only (TCP_NOTSENT_LOWAT); elsewhere the kernel's
// own send buffer sizing applies.
func boundSendQueue(net.Conn, int) error { return nil }

// boundReceive is Linux-only; elsewhere receive buffers autotune.
func boundReceive(net.Conn, int) error { return nil }

// smallUpstream is Linux-only; elsewhere connections keep the kernel's
// defaults.
func smallUpstream(string, string, syscall.RawConn) error { return nil }
