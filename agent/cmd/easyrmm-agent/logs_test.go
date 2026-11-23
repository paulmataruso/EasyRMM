package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/logship"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestShipLogs: the agent's logger writes through to what it wrote to, and
// its records wait in a file of the state folder, redacted, with the
// EasyPatch agent's new log lines beside them (ADR-0069).
func TestShipLogs(t *testing.T) {
	h := newHarness(t)
	if runtime.GOOS == "windows" {
		h.e.paths.OS = "windows" // the state is checked below ProgramData
	}
	if err := h.e.openStore(); err != nil {
		t.Fatal(err)
	}
	ep := h.e.paths.EasyPatchLog()
	if err := os.MkdirAll(filepath.Dir(ep), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ep, []byte("2026-11-23T10:00:00.000Z ERR Scan: failed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := h.e.shipLogs()
	if s == nil {
		t.Fatal("no shipper")
	}
	h.e.log.Info("enrolled with ert_AbCdEf0123456789")
	t.Cleanup(func() { _ = s.Buf.Close() }) // Windows will not remove the folder of an open file
	var mu sync.Mutex
	var all []agentproto.LogRecord
	s.Every = 10 * time.Millisecond
	send := func(_ context.Context, b agentproto.LogBatch) (agentproto.LogAck, error) {
		mu.Lock()
		defer mu.Unlock()
		all = append(all, b.Records...)
		return agentproto.LogAck{Seq: b.Records[len(b.Records)-1].Seq}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	s.Run(ctx, send)
	mu.Lock()
	defer mu.Unlock()
	var agent, easypatch int
	for _, r := range all {
		switch r.Source {
		case "agent":
			agent++
			if strings.Contains(r.Message, "AbCdEf") {
				t.Errorf("not redacted: %q", r.Message)
			}
		case "easypatch":
			easypatch++
			if r.Level != "error" || r.Message != "Scan: failed" {
				t.Errorf("easypatch record = %+v", r)
			}
		}
	}
	if agent != 1 || easypatch != 1 {
		t.Errorf("%d agent records, %d easypatch: %+v", agent, easypatch, all)
	}
	if _, err := os.Stat(filepath.Join(h.e.store.Dir(), "logs", "shipping.buf")); err != nil {
		t.Errorf("the buffer is not in the state folder: %v", err)
	}
	if len(s.Tails) != 2 || s.Tails[0].Source != agentproto.LogSourceEasyPatch || s.Tails[1].Source != agentproto.LogSourceMeshAgent {
		t.Errorf("tails = %+v", s.Tails)
	}
}

// TestShipLogsWithoutABuffer: where the buffer cannot be opened the agent
// logs as before and sends nothing.
func TestShipLogsWithoutABuffer(t *testing.T) {
	h := newHarness(t)
	if runtime.GOOS == "windows" {
		h.e.paths.OS = "windows" // the state is checked below ProgramData
	}
	if err := h.e.openStore(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(h.e.store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.e.store.Dir(), "logs"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if s := h.e.shipLogs(); s != nil {
		t.Errorf("shipper = %+v", s)
	}
	var s *logship.Shipper
	s.Run(context.Background(), nil) // nothing to do, and no panic
}

// TestSendLogsMapsNotFound: a server without the endpoint is not an error
// the Shipper retries at its normal pace.
func TestSendLogsMapsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c, err := client.New(client.Options{Server: srv.URL, Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(nil)
	c.SetIdentity("dev-1", key)
	if _, err := sendLogs(c)(context.Background(), agentproto.LogBatch{}); !errors.Is(err, logship.ErrUnsupported) {
		t.Errorf("err = %v", err)
	}
}
