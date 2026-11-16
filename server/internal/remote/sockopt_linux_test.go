//go:build linux

package remote

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// sockopt reads an integer socket option from c.
func sockopt(t *testing.T, c net.Conn, level, name int) int {
	t.Helper()
	tc := tcpConn(c)
	if tc == nil {
		t.Fatalf("no TCP connection under %T", c)
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := raw.Control(func(fd uintptr) { v, gerr = unix.GetsockoptInt(int(fd), level, name) }); err != nil { //nolint:gosec // a socket descriptor fits an int
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	if s == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return c, s
}

type wrapped struct{ net.Conn }

func (w wrapped) NetConn() net.Conn { return w.Conn }

func TestTCPConnUnwraps(t *testing.T) {
	c, _ := tcpPair(t)
	for name, conn := range map[string]net.Conn{
		"plain":   c,
		"tls":     tls.Client(c, &tls.Config{InsecureSkipVerify: true}), //nolint:gosec // never handshakes
		"wrapper": wrapped{tls.Server(c, &tls.Config{})},
	} {
		if tcpConn(conn) != c {
			t.Errorf("%s: tcpConn did not find the TCP connection", name)
		}
	}
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if tcpConn(a) != nil {
		t.Error("tcpConn found a TCP connection under a pipe")
	}
	if err := boundSendQueue(a, 1024); err != nil {
		t.Errorf("boundSendQueue on a pipe: %v", err)
	}
}

func TestBoundSendQueue(t *testing.T) {
	c, _ := tcpPair(t)
	if err := boundSendQueue(tls.Server(c, &tls.Config{}), 48<<10); err != nil {
		t.Fatal(err)
	}
	if got := sockopt(t, c, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT); got != 48<<10 {
		t.Errorf("TCP_NOTSENT_LOWAT = %d, want %d", got, 48<<10)
	}
	_ = c.Close()
	if err := boundSendQueue(c, 1024); err == nil {
		t.Error("boundSendQueue on a closed connection succeeded")
	}
}

func TestSmallUpstream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if s, err := ln.Accept(); err == nil {
			defer func() { _ = s.Close() }()
			_, _ = s.Read(make([]byte, 1))
		}
	}()
	c, err := (&net.Dialer{Control: smallUpstream}).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// The kernel doubles SO_RCVBUF for its own bookkeeping.
	if got := sockopt(t, c, unix.SOL_SOCKET, unix.SO_RCVBUF); got < relayUpstreamBuffer || got > 2*relayUpstreamBuffer {
		t.Errorf("SO_RCVBUF = %d, want about %d", got, relayUpstreamBuffer)
	}
	if got := sockopt(t, c, unix.IPPROTO_TCP, unix.TCP_MAXSEG); got > relayUpstreamSegment {
		t.Errorf("TCP_MAXSEG = %d, want at most %d", got, relayUpstreamSegment)
	}
	if got := sockopt(t, c, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT); got != relayUpstreamUnsent {
		t.Errorf("TCP_NOTSENT_LOWAT = %d, want %d", got, relayUpstreamUnsent)
	}
}

// The browser's side of a desktop relay gets a bounded send queue; other
// connections keep the kernel's default.
func TestTrackingWriterBoundsDesktopRelays(t *testing.T) {
	g := newTestGateway(t, "http://127.0.0.1:1", true)
	for _, desktop := range []bool{true, false} {
		got := make(chan int, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			tw := &trackingWriter{ResponseWriter: w, g: g, session: uuid.New(), desktop: desktop, log: g.log}
			conn, _, err := tw.Hijack()
			if err != nil {
				t.Error(err)
				got <- -1
				return
			}
			defer func() { _ = conn.Close() }()
			got <- sockopt(t, conn.(*trackedConn).Conn, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
		}))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		if resp, err := srv.Client().Do(req); err == nil {
			_ = resp.Body.Close()
		}
		v := <-got
		cancel()
		srv.Close()
		if desktop && v != desktopSendQueue {
			t.Errorf("desktop relay: TCP_NOTSENT_LOWAT = %d, want %d", v, desktopSendQueue)
		}
		if !desktop && v == desktopSendQueue {
			t.Errorf("other connection: TCP_NOTSENT_LOWAT = %d, want the default", v)
		}
	}
}

// The agent's side of a desktop relay gets a bounded receive buffer.
func TestAgentDesktopWriterBoundsBuffer(t *testing.T) {
	got := make(chan int, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := agentDesktopWriter{ResponseWriter: w, log: newTestGateway(t, "http://127.0.0.1:1", true).log}.Hijack()
		if err != nil {
			t.Error(err)
			got <- -1
			return
		}
		defer func() { _ = conn.Close() }()
		got <- sockopt(t, conn, unix.SOL_SOCKET, unix.SO_RCVBUF)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if resp, err := srv.Client().Do(req); err == nil {
		_ = resp.Body.Close()
	}
	// The kernel doubles SO_RCVBUF for its own bookkeeping.
	if v := <-got; v != 2*agentDesktopBuffer {
		t.Errorf("SO_RCVBUF = %d, want %d", v, 2*agentDesktopBuffer)
	}
	rec := httptest.NewRecorder()
	a := agentDesktopWriter{ResponseWriter: rec}
	if a.Unwrap() != rec {
		t.Error("Unwrap")
	}
	if _, _, err := a.Hijack(); err == nil {
		t.Error("Hijack on a writer that cannot hijack succeeded")
	}
}

// unreadOn returns how many bytes c has received but not read (SIOCINQ).
func unreadOn(t *testing.T, c net.Conn) int {
	t.Helper()
	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	var ierr error
	if err := raw.Control(func(fd uintptr) { n, ierr = unix.IoctlGetInt(int(fd), unix.SIOCINQ) }); err != nil { //nolint:gosec // a socket descriptor fits an int
		t.Fatal(err)
	}
	if ierr != nil {
		t.Fatal(ierr)
	}
	return n
}

// Through the gateway, an agent's desktop relay leaves MeshCentral little
// unread when MeshCentral stops reading; other relays are not held.
func TestGatewayPacesAgentDesktopRelays(t *testing.T) {
	for _, tc := range []struct {
		p     string
		paced bool
	}{{"2", true}, {"1", false}} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		upstream := make(chan net.Conn, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
				_ = c.Close()
				return
			}
			_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			upstream <- c // and read nothing more
		}()
		g := newTestGateway(t, "http://"+ln.Addr().String(), true)
		srv := httptest.NewServer(g)

		agent, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(agent, "GET /meshrelay.ashx?p="+tc.p+"&id=t1&rauth=r&nodeid=node//abc HTTP/1.1\r\nHost: mesh.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(agent), nil)
		if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("p=%s: upgrade: %v %v", tc.p, resp, err)
		}
		_ = resp.Body.Close() // a 101 has no body; the connection stays open
		mesh := <-upstream
		go func() { _, _ = agent.Write(make([]byte, 4<<20)) }()
		time.Sleep(300 * time.Millisecond)
		unread := unreadOn(t, mesh)
		if tc.paced && (unread == 0 || unread > meshUnreadLimit+64<<10) {
			t.Errorf("desktop relay: MeshCentral holds %d unread, want at most about %d", unread, meshUnreadLimit)
		}
		if !tc.paced && unread <= meshUnreadLimit+64<<10 {
			t.Errorf("terminal relay: MeshCentral holds %d unread; only desktop relays are paced", unread)
		}
		// The time the pictures were held is counted for the device.
		held, active := g.heldFor("node//abc")
		if tc.paced && (!active || held < 100*time.Millisecond) {
			t.Errorf("desktop relay: held %v (active %v), want most of the wait", held, active)
		}
		if !tc.paced && active {
			t.Error("terminal relay counted as held desktop pictures")
		}
		_ = agent.Close()
		_ = mesh.Close()
		if tc.paced {
			waitFor(t, "the relay's counter to go", func() bool { _, active := g.heldFor("node//abc"); return !active })
		}
		srv.Close()
		_ = ln.Close()
	}
}
