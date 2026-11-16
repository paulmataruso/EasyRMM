//go:build linux

package remote

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// boundSendQueue limits the bytes c's kernel may hold unsent
// (TCP_NOTSENT_LOWAT). Bytes in flight are not limited, so throughput on a
// fast link is not either.
func boundSendQueue(c net.Conn, n int) error {
	return setsockopt(c, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, n)
}

// boundReceive fixes c's receive buffer at n (the kernel doubles it),
// turning receive autotuning off for c.
func boundReceive(c net.Conn, n int) error {
	return setsockopt(c, unix.SOL_SOCKET, unix.SO_RCVBUF, n)
}

func setsockopt(c net.Conn, level, name, value int) error {
	tc := tcpConn(c)
	if tc == nil {
		return nil
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), level, name, value) //nolint:gosec // a socket descriptor fits an int
	}); err != nil {
		return err
	}
	return serr
}

// smallUpstream is a dialer Control function: before connecting, it sets a
// small receive buffer (so a small window), a small segment size (so the
// peer sizes its send buffer small), and bounds what this side may hold
// unsent.
func smallUpstream(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		s := int(fd) //nolint:gosec // a socket descriptor fits an int
		for _, o := range [...]struct{ level, name, value int }{
			{unix.SOL_SOCKET, unix.SO_RCVBUF, relayUpstreamBuffer},
			{unix.IPPROTO_TCP, unix.TCP_MAXSEG, relayUpstreamSegment},
			{unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, relayUpstreamUnsent},
		} {
			if serr = unix.SetsockoptInt(s, o.level, o.name, o.value); serr != nil {
				return
			}
		}
	}); err != nil {
		return err
	}
	return serr
}
