//go:build linux

package remote

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor polls cond for up to five seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestPeerQueueReadsTheOtherEnd(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			addr := "127.0.0.1:0"
			if network == "tcp6" {
				addr = "[::1]:0"
			}
			ln, err := net.Listen(network, addr)
			if err != nil {
				t.Skipf("no %s loopback: %v", network, err)
			}
			defer func() { _ = ln.Close() }()
			accepted := make(chan net.Conn, 1)
			go func() { c, _ := ln.Accept(); accepted <- c }()
			c, err := net.Dial(network, ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			peer := <-accepted
			defer func() { _ = peer.Close() }()

			q, err := newPeerQueue(c.(*net.TCPConn))
			if err != nil {
				t.Fatal(err)
			}
			defer q.close()
			if n, err := q.unread(); err != nil || n != 0 {
				t.Fatalf("idle peer: %d, %v", n, err)
			}
			if _, err := c.Write(make([]byte, 5000)); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the peer's queue", func() bool { n, _ := q.unread(); return n == 5000 })
			if _, err := io.ReadFull(peer, make([]byte, 5000)); err != nil {
				t.Fatal(err)
			}
			if n, err := q.unread(); err != nil || n != 0 {
				t.Fatalf("after the peer read: %d, %v", n, err)
			}
			// A closed peer (gone, or closing) holds nothing back.
			_ = peer.Close()
			if n, err := q.unread(); err == nil && n != 0 {
				t.Fatalf("closed peer: %d unread", n)
			}
		})
	}
}

func TestPaceHoldsWritesWhileThePeerDoesNotRead(t *testing.T) {
	c, peer := tcpPair(t)
	var held atomic.Int64
	released := 0
	p, paced := pace(c, 8<<10, &held, func() { released++ })
	pc, ok := p.(*pacedConn)
	if !paced || !ok {
		t.Fatalf("pace returned %T, %v", p, paced)
	}
	// Up to the limit, writes go straight through.
	if _, err := p.Write(make([]byte, 16<<10)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the peer's queue", func() bool { return pc.peerBusy() })
	done := make(chan error, 1)
	go func() { _, err := p.Write([]byte("next")); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("write went through while the peer held 16 KiB: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := io.ReadFull(peer, make([]byte, 16<<10)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write still held after the peer read")
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "next" {
		t.Fatalf("peer read %q, %v", buf, err)
	}
	if h := time.Duration(held.Load()); h < 40*time.Millisecond {
		t.Errorf("held %v, want the time the write waited", h)
	}

	// A held write ends when the connection closes.
	if _, err := p.Write(make([]byte, 16<<10)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the peer's queue", func() bool { return pc.peerBusy() })
	go func() { _, err := p.Write([]byte("x")); done <- err }()
	time.Sleep(20 * time.Millisecond)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("write on a closed connection succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write still held after close")
	}
	if pc.peerBusy() {
		t.Error("a closed connection reports a busy peer")
	}
	_ = p.Close()
	if released != 1 {
		t.Errorf("released %d times, want once", released)
	}
}

func TestPaceLeavesOtherConnectionsAlone(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if c, paced := pace(a, 1, nil, nil); c != a || paced {
		t.Error("paced a pipe")
	}
	c, peer := tcpPair(t)
	pp, _ := pace(c, 1, nil, nil)
	p := pp.(*pacedConn)
	// If the queue cannot be read any more, writes are not held.
	p.mu.Lock()
	p.q.close()
	p.q.fd = -1
	p.mu.Unlock()
	if p.peerBusy() {
		t.Error("busy without a readable queue")
	}
	if p.q != nil {
		t.Error("a failing queue was kept")
	}
	if _, err := p.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("peer read %q, %v", buf, err)
	}
}
