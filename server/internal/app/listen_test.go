package app

import (
	"context"
	"net"
	"sync"
	"testing"
)

// reserved are the listeners tests opened for a server, by address, until
// the server listens there and takes them.
var reserved sync.Map

// The server under test takes a reserved address's listener instead of
// binding the port again; every other address it binds as it does in
// production.
func init() {
	bind := listen
	listen = func(ctx context.Context, addr string) (net.Listener, error) {
		if ln, ok := reserved.LoadAndDelete(addr); ok {
			return ln.(net.Listener), nil
		}
		return bind(ctx, addr)
	}
}

// reserveAddr opens a loopback listener on a port the kernel picks and
// returns its address, for a server under test to listen on. The port
// stays bound until the server takes the listener, so no other test or
// process can take it first and answer the test's requests instead (as
// one did on CI: /readyz answered 421). A listener the server never takes
// is closed when the test ends.
func reserveAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	reserved.Store(addr, ln)
	t.Cleanup(func() {
		if ln, ok := reserved.LoadAndDelete(addr); ok {
			_ = ln.(net.Listener).Close()
		}
	})
	return addr
}
