package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestRunCommands(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		if got := run(args); got != 0 {
			t.Errorf("run(%v) = %d, want 0", args, got)
		}
	}
	if got := run([]string{"bogus"}); got != 2 {
		t.Errorf("unknown command = %d, want 2", got)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	t.Setenv("EASYRMM_PUBLIC_URL", "")
	t.Setenv("EASYRMM_SECRET_KEY", "")
	for _, cmd := range [][]string{nil, {"serve"}, {"migrate"}} {
		if got := run(cmd); got != 1 {
			t.Errorf("run(%v) with invalid configuration = %d, want 1", cmd, got)
		}
	}
}

func TestHealthcheck(t *testing.T) {
	ready := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" || !ready {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	}))
	defer srv.Close()

	t.Setenv("EASYRMM_LISTEN_HEALTH", srv.Listener.Addr().String())
	if got := run([]string{"healthcheck"}); got != 0 {
		t.Fatalf("ready server: %d", got)
	}
	ready = false
	if got := run([]string{"healthcheck"}); got != 1 {
		t.Fatalf("unready server: %d", got)
	}
	for _, addr := range []string{"10.1.2.3:18081", "example.com:18081", "nonsense", freeAddr(t)} {
		t.Setenv("EASYRMM_LISTEN_HEALTH", addr)
		if got := run([]string{"healthcheck"}); got != 1 {
			t.Errorf("healthcheck against %q = %d, want 1", addr, got)
		}
	}
}
