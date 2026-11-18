//go:build linux

package remote

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// sock_diag (linux/inet_diag.h). golang.org/x/sys has the constants but not
// the request and reply layouts.
const (
	sockDiagByFamily = 20
	nlHeaderLen      = 16
	diagSockIDLen    = 48
	diagRequestLen   = 8 + diagSockIDLen
	// In a reply, inet_diag_msg follows the header: family, state, timer
	// and retransmits (one byte each), the socket id, expires, then the
	// receive and send queues.
	diagRecvQueueAt = nlHeaderLen + 4 + diagSockIDLen + 4
	diagReplyLen    = diagRecvQueueAt + 8
)

// peerQueue reads the receive queue of the other end of a loopback TCP
// connection: the bytes the peer process has received but not read yet.
// MeshCentral runs on the same host (ADR-0004), so its sockets are visible
// to sock_diag, which needs no privileges.
type peerQueue struct {
	fd  int
	req []byte
	buf []byte
}

func newPeerQueue(c *net.TCPConn) (*peerQueue, error) {
	local, ok1 := c.LocalAddr().(*net.TCPAddr)
	remote, ok2 := c.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 || !remote.IP.IsLoopback() {
		return nil, errors.New("not a loopback TCP connection")
	}
	family := unix.AF_INET6
	if local.IP.To4() != nil && remote.IP.To4() != nil {
		family = unix.AF_INET
	}
	// The peer's socket: its local end is our remote one.
	req := make([]byte, nlHeaderLen+diagRequestLen)
	binary.NativeEndian.PutUint32(req[0:], nlHeaderLen+diagRequestLen)
	binary.NativeEndian.PutUint16(req[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST)
	r := req[nlHeaderLen:]
	r[0] = byte(family)
	r[1] = unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(r[4:], 0xffffffff) // any state
	id := r[8:]
	binary.BigEndian.PutUint16(id[0:], uint16(remote.Port)) //nolint:gosec // a port fits 16 bits
	binary.BigEndian.PutUint16(id[2:], uint16(local.Port))  //nolint:gosec // a port fits 16 bits
	putDiagAddr(id[4:20], remote.IP, family)
	putDiagAddr(id[20:36], local.IP, family)
	// Interface 0, and the "no cookie" cookie: match by address alone.
	binary.NativeEndian.PutUint32(id[40:], 0xffffffff)
	binary.NativeEndian.PutUint32(id[44:], 0xffffffff)

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("sock_diag socket: %w", err)
	}
	q := &peerQueue{fd: fd, req: req, buf: make([]byte, 4096)}
	if _, err := q.unread(); err != nil {
		q.close()
		return nil, err
	}
	return q, nil
}

func putDiagAddr(dst []byte, ip net.IP, family int) {
	if family == unix.AF_INET {
		copy(dst, ip.To4())
		return
	}
	copy(dst, ip.To16())
}

// unread returns the peer's receive queue.
func (q *peerQueue) unread() (int, error) {
	if err := unix.Sendto(q.fd, q.req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, fmt.Errorf("sock_diag request: %w", err)
	}
	n, _, err := unix.Recvfrom(q.fd, q.buf, 0)
	if err != nil {
		return 0, fmt.Errorf("sock_diag reply: %w", err)
	}
	if n < nlHeaderLen {
		return 0, errors.New("sock_diag reply too short")
	}
	switch binary.NativeEndian.Uint16(q.buf[4:]) {
	case unix.NLMSG_ERROR:
		if n >= nlHeaderLen+4 {
			// The kernel's errno, negated.
			if e := int32(binary.NativeEndian.Uint32(q.buf[nlHeaderLen:])); e < 0 { //nolint:gosec // reinterpreting the reply's signed field
				return 0, fmt.Errorf("sock_diag: %w", unix.Errno(uint32(-e)))
			}
		}
		return 0, errors.New("sock_diag: no socket")
	case sockDiagByFamily:
		if n < diagReplyLen {
			return 0, errors.New("sock_diag reply too short")
		}
		return int(binary.NativeEndian.Uint32(q.buf[diagRecvQueueAt:])), nil
	}
	return 0, errors.New("sock_diag: unexpected reply")
}

func (q *peerQueue) close() { _ = unix.Close(q.fd) }

// pacedConn holds writes while the peer has more than limit bytes unread.
// A peer that stops reading leaves the data in this process's caller (here,
// the agent's connection, and the agent) instead of in the peer's kernel
// buffer, which grows to hundreds of kilobytes on loopback.
type pacedConn struct {
	net.Conn
	limit int
	// held, when set, adds up the time writes were held; release, when
	// set, is called once on Close.
	held    *atomic.Int64
	release func()

	mu     sync.Mutex
	q      *peerQueue
	closed bool
}

// Polling while the peer does not read: quickly at first, so a short pause
// costs at most a millisecond, then less often.
const (
	paceFastPolls = 20
	paceFast      = time.Millisecond
	paceSlow      = 4 * time.Millisecond
)

// pace wraps c when it is a loopback TCP connection whose peer's queue can
// be read, and reports whether it did; otherwise it returns c.
func pace(c net.Conn, limit int, held *atomic.Int64, release func()) (net.Conn, bool) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return c, false
	}
	q, err := newPeerQueue(tc)
	if err != nil {
		return c, false
	}
	return &pacedConn{Conn: c, limit: limit, q: q, held: held, release: release}, true
}

func (c *pacedConn) Write(b []byte) (int, error) {
	for polls := 0; ; polls++ {
		busy, closed := c.peerState()
		if closed {
			// Close marks the connection closed before it closes the socket:
			// a write it held must not slip onto the socket in between.
			return 0, net.ErrClosed
		}
		if !busy {
			break
		}
		wait := paceFast
		if polls >= paceFastPolls {
			wait = paceSlow
		}
		start := time.Now()
		time.Sleep(wait)
		if c.held != nil {
			c.held.Add(int64(time.Since(start)))
		}
	}
	return c.Conn.Write(b)
}

// peerBusy reports whether the peer has more than limit bytes unread. If the
// queue cannot be read (or the connection is closed), writes go ahead.
func (c *pacedConn) peerBusy() bool {
	busy, _ := c.peerState()
	return busy
}

// peerState is peerBusy, and whether Close was called.
func (c *pacedConn) peerState() (busy, closed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false, true
	}
	if c.q == nil {
		return false, false
	}
	n, err := c.q.unread()
	if err != nil {
		c.q.close()
		c.q = nil
		return false, false
	}
	return n > c.limit, false
}

func (c *pacedConn) Close() error {
	c.mu.Lock()
	release := !c.closed && c.release != nil
	c.closed = true
	if c.q != nil {
		c.q.close()
		c.q = nil
	}
	c.mu.Unlock()
	if release {
		c.release()
	}
	return c.Conn.Close()
}
