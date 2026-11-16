package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// server answers heartbeats with a programmable result.
type server struct {
	mu        sync.Mutex
	status    int
	code      string
	available bool
	// Inventory: the hash the server claims to hold, what was uploaded,
	// and an error status for uploads.
	invHash    string
	uploads    [][]byte
	invStatus  int
	heartbeats []agentproto.HeartbeatRequest
	// update is the heartbeat answer's update instruction, JSON.
	update string
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case agentproto.PathHeartbeat:
		if s.status != 0 {
			w.WriteHeader(s.status)
			_, _ = io.WriteString(w, `{"error":{"code":"`+s.code+`","message":"m"}}`)
			return
		}
		var req agentproto.HeartbeatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.heartbeats = append(s.heartbeats, req)
		update := ""
		if s.update != "" {
			update = `,"update":` + s.update
		}
		_, _ = io.WriteString(w, `{"heartbeatSeconds":60,"inventoryHash":"`+s.invHash+`","meshAgent":{"available":`+map[bool]string{true: "true", false: "false"}[s.available]+`}`+update+`}`)
	case agentproto.PathInventory:
		if s.invStatus != 0 {
			w.WriteHeader(s.invStatus)
			_, _ = io.WriteString(w, `{"error":{"code":"inventory_invalid","message":"m"}}`)
			return
		}
		b, _ := io.ReadAll(r.Body)
		s.uploads = append(s.uploads, b)
		_, _ = io.WriteString(w, `{"hash":"h"}`)
	case agentproto.PathMeshSettings:
		_, _ = io.WriteString(w, "MeshID=0x1")
	case agentproto.PathMeshAgent:
		_, _ = io.WriteString(w, "ELF")
	}
}

// mesh is a fake MeshAgent manager.
type mesh struct {
	installed  bool
	installErr error
	started    int
	node       string
	nodeErr    error
	settings   string
	binary     string
}

func (m *mesh) Installed() bool { return m.installed }

func (m *mesh) Install(_ context.Context, download func(io.Writer) error, settings []byte) error {
	if m.installErr != nil {
		return m.installErr
	}
	var b strings.Builder
	if err := download(&b); err != nil {
		return err
	}
	m.binary, m.settings, m.installed = b.String(), string(settings), true
	return nil
}

func (m *mesh) Start(context.Context) error { m.started++; return nil }

func (m *mesh) NodeID(context.Context) (string, error) { return m.node, m.nodeErr }

func newRunner(t *testing.T, s *server, m *mesh) *Runner {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := client.New(client.Options{Server: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c.SetIdentity("dev-1", key)
	r := &Runner{
		Client: c, Store: state.Store{Dir: t.TempDir()},
		Facts: func() agentproto.Facts { return agentproto.Facts{Hostname: "h"} },
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if m != nil {
		r.Mesh = m
	}
	r.defaults()
	return r
}

func TestBeatInstallsMeshAgentWhenOffered(t *testing.T) {
	s := &server{}
	m := &mesh{}
	r := newRunner(t, s, m)
	ctx := context.Background()

	if wait, _ := r.beat(ctx); wait < 54*time.Second || wait > 66*time.Second {
		t.Errorf("next heartbeat in %v", wait)
	}
	st, _ := r.Store.LoadStatus()
	if st.LastHeartbeat.IsZero() || st.MeshAgent != "not available from the server" || m.installed {
		t.Errorf("status = %+v", st)
	}

	s.available = true
	if wait, _ := r.beat(ctx); wait != r.AfterSetup {
		t.Errorf("after installing, next heartbeat in %v", wait)
	}
	if !m.installed || m.binary != "ELF" || m.settings != "MeshID=0x1" {
		t.Fatalf("MeshAgent = %+v", m)
	}
	m.node = "AB"
	r.beat(ctx)
	if r.status.MeshNodeID != "AB" || r.status.MeshAgent != "installed" {
		t.Errorf("status = %+v", r.status)
	}

	// Run starts an installed MeshAgent and stops with its context.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil || m.started != 1 {
			t.Errorf("Run = %v, started %d", err, m.started)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestBeatInstallFailureWaits(t *testing.T) {
	s := &server{available: true}
	m := &mesh{installErr: errors.New("disk full"), nodeErr: errors.New("x")}
	r := newRunner(t, s, m)
	r.beat(context.Background())
	if !strings.Contains(r.status.MeshAgent, "install failed: disk full") {
		t.Errorf("status = %+v", r.status)
	}
	// No second attempt before InstallWait passes.
	m.installErr = nil
	r.beat(context.Background())
	if m.installed {
		t.Error("retried the install immediately")
	}
	r.lastInstall = time.Now().Add(-r.InstallWait)
	r.beat(context.Background())
	if !m.installed {
		t.Error("install not retried after the wait")
	}
}

func TestBeatFailuresBackOff(t *testing.T) {
	s := &server{status: http.StatusBadGateway, code: "x"}
	r := newRunner(t, s, nil)
	var waits []time.Duration
	for range 4 {
		w, _ := r.beat(context.Background())
		waits = append(waits, w)
	}
	for i, want := range []time.Duration{5, 10, 20, 40} {
		w := want * time.Second
		if waits[i] < w*9/10 || waits[i] > w*11/10 {
			t.Errorf("retry %d after %v, want about %v", i+1, waits[i], w)
		}
	}
	st, _ := r.Store.LoadStatus()
	if !strings.Contains(st.LastError, "502") || st.LastErrorAt.IsZero() {
		t.Errorf("status = %+v", st)
	}
	r.failures = 20
	if w, _ := r.beat(context.Background()); w > r.MaxRetry*11/10 {
		t.Errorf("backoff not capped: %v", w)
	}

	s.status, s.code = http.StatusUnauthorized, "device_unknown"
	r.failures = 0
	if w, _ := r.beat(context.Background()); w < r.MaxRetry*9/10 {
		t.Errorf("unknown device retried after %v", w)
	}
	s.code = "clock_skew"
	r.failures = 0
	if w, _ := r.beat(context.Background()); w > 6*time.Second {
		t.Errorf("clock skew retried after %v", w)
	}

	// Recovery clears the error.
	s.status = 0
	r.beat(context.Background())
	if r.status.LastError != "" || r.failures != 0 {
		t.Errorf("after recovery: %+v", r.status)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if w, _ := r.beat(ctx); w != 0 {
		t.Errorf("canceled beat waits %v", w)
	}
}

func TestJitter(t *testing.T) {
	for range 100 {
		if j := jitter(time.Minute); j < 54*time.Second || j >= 66*time.Second {
			t.Fatalf("jitter = %v", j)
		}
	}
	if jitter(0) != 0 || jitter(2) != 2 {
		t.Error("tiny durations changed")
	}
}
