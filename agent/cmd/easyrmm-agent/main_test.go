package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// fakeServer enrolls with token ert_good and accepts heartbeats.
func fakeServer(t *testing.T, beats *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case agentproto.PathEnroll:
			var in agentproto.EnrollRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in.Token != "ert_good" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":{"code":"token_invalid","message":"no"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"deviceId":"dev-42","heartbeatSeconds":60}`)
		case agentproto.PathHeartbeat:
			beats.Add(1)
			_, _ = io.WriteString(w, `{"heartbeatSeconds":60,"meshAgent":{"available":false}}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type harness struct {
	e     *env
	out   *bytes.Buffer
	calls []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	h := &harness{out: &bytes.Buffer{}}
	p := host.Paths{Root: root}
	h.e = &env{
		paths: p, store: state.Store{Dir: p.State()}, stdout: h.out,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		sd: host.Systemd{Dir: p.Units(), Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			h.calls = append(h.calls, name+" "+strings.Join(args, " "))
			return []byte("active\n"), nil
		}},
		isRoot: func() bool { return true }, hasSystemd: func() bool { return true },
	}
	return h
}

func (h *harness) run(args ...string) error {
	h.out.Reset()
	return h.e.dispatch(context.Background(), args, io.Discard)
}

func TestCommands(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"version"}, &out, io.Discard); err != nil || !strings.HasPrefix(out.String(), "easyrmm-agent dev (") {
		t.Errorf("version: %q, %v", out.String(), err)
	}
	out.Reset()
	if err := run(context.Background(), []string{"help"}, &out, io.Discard); err != nil || !strings.Contains(out.String(), "usage: easyrmm-agent") {
		t.Errorf("help: %v", err)
	}
	if err := run(context.Background(), nil, io.Discard, io.Discard); err == nil {
		t.Error("no command accepted")
	}
	if err := run(context.Background(), []string{"dance"}, io.Discard, io.Discard); err == nil {
		t.Error("unknown command accepted")
	}
}

func TestEnrollRunStatusUninstall(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newHarness(t)

	if err := h.run("status"); err != nil || !strings.Contains(h.out.String(), "Not enrolled.") {
		t.Errorf("status before enrolling: %q, %v", h.out, err)
	}
	if err := h.run("enroll"); err == nil || !strings.Contains(err.Error(), "--server is required") {
		t.Errorf("enroll without a server: %v", err)
	}
	if err := h.run("enroll", "--server", "http://rmm.example.com"); err == nil {
		t.Error("plain HTTP to a remote server accepted")
	}
	t.Setenv("EASYRMM_TOKEN", "")
	if err := h.run("enroll", "--server", srv.URL); err == nil || !strings.Contains(err.Error(), "deployment token is required") {
		t.Errorf("enroll without a token: %v", err)
	}
	if err := h.run("enroll", "--server", srv.URL, "--token", "ert_bad"); err == nil || !strings.Contains(err.Error(), "token_invalid") {
		t.Errorf("enroll with a bad token: %v", err)
	}
	if err := h.run("enroll", "--server", srv.URL, "--ca-file", filepath.Join(t.TempDir(), "none.pem"), "--token", "ert_good"); err == nil {
		t.Error("missing CA file accepted")
	}
	if err := h.run("enroll", "--bogus"); err == nil {
		t.Error("unknown flag accepted")
	}

	// The token from the environment, as the installer passes it.
	t.Setenv("EASYRMM_TOKEN", "ert_good")
	if err := h.run("enroll", "--server", srv.URL+"/"); err != nil || !strings.Contains(h.out.String(), "as device dev-42") {
		t.Fatalf("enroll: %q, %v", h.out, err)
	}
	cfg, _, err := h.e.store.Load()
	if err != nil || cfg.MeshAgentMode != "child" || cfg.Server != srv.URL {
		t.Fatalf("saved enrollment = %+v, %v", cfg, err)
	}
	if err := h.run("enroll", "--server", srv.URL); err != nil || !strings.Contains(h.out.String(), "Already enrolled") {
		t.Errorf("enrolling again: %q, %v", h.out, err)
	}
	if err := h.run("enroll", "--server", "https://other.example.com"); err == nil || !strings.Contains(err.Error(), "uninstall") {
		t.Errorf("enrolling with another server: %v", err)
	}

	// run sends a heartbeat and stops with its context.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.e.dispatch(ctx, []string{"run"}, io.Discard) }()
	// Wait for the agent to record the heartbeat and the MeshAgent answer,
	// not just for the server to see the heartbeat: on a busy machine the
	// agent could otherwise stop before saving its status.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st, err := h.e.store.LoadStatus()
		if beats.Load() > 0 && err == nil && !st.LastHeartbeat.IsZero() && st.MeshAgent != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil || beats.Load() == 0 {
		t.Fatalf("run: %v, %d heartbeats", err, beats.Load())
	}

	if err := h.run("status"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Server:     " + srv.URL, "Device:     dev-42", "Service:    active", "Heartbeat:  ", "MeshAgent:  not available from the server"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, h.out)
		}
	}

	if err := h.run("uninstall"); err != nil || !strings.Contains(h.out.String(), "removed") {
		t.Fatalf("uninstall: %q, %v", h.out, err)
	}
	if _, err := os.Stat(h.e.paths.State()); !os.IsNotExist(err) {
		t.Error("state kept after uninstall")
	}
	if err := h.run("uninstall"); err != nil {
		t.Errorf("uninstalling twice: %v", err)
	}
}

func TestInstallAsService(t *testing.T) {
	var beats atomic.Int32
	srv := fakeServer(t, &beats)
	h := newHarness(t)

	h.e.isRoot = func() bool { return false }
	if err := h.run("install", "--server", srv.URL, "--token", "ert_good"); err == nil || !strings.Contains(err.Error(), "as root") {
		t.Errorf("install without root: %v", err)
	}
	h.e.isRoot, h.e.hasSystemd = func() bool { return true }, func() bool { return false }
	if err := h.run("install", "--server", srv.URL, "--token", "ert_good"); err == nil || !strings.Contains(err.Error(), "systemd is not running") {
		t.Errorf("install without systemd: %v", err)
	}
	h.e.hasSystemd = func() bool { return true }

	// A private CA is copied into the agent's state.
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.run("install", "--server", srv.URL, "--token", "ert_good", "--ca-file", ca); err == nil {
		t.Error("a CA file without a valid certificate was accepted")
	}
	if err := h.run("install", "--server", srv.URL, "--token", "ert_good"); err != nil {
		t.Fatalf("install: %v", err)
	}
	cfg, _, _ := h.e.store.Load()
	if cfg.MeshAgentMode != "systemd" {
		t.Errorf("mode = %s", cfg.MeshAgentMode)
	}
	unit, err := os.ReadFile(filepath.Join(h.e.paths.Units(), host.AgentUnit))
	if err != nil || !strings.Contains(string(unit), "ExecStart="+h.e.paths.Binary()+" run") {
		t.Errorf("unit = %q, %v", unit, err)
	}
	if st, err := os.Stat(h.e.paths.Binary()); err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("installed binary: %v", err)
	}
	if !strings.Contains(strings.Join(h.calls, ";"), "systemctl enable --now easyrmm-agent.service") {
		t.Errorf("systemctl calls = %v", h.calls)
	}
	if !strings.Contains(h.out.String(), "running as easyrmm-agent.service") {
		t.Errorf("output = %q", h.out)
	}
	// Installing again keeps the enrollment and refreshes the service.
	if err := h.run("install", "--server", srv.URL); err != nil || !strings.Contains(h.out.String(), "Already enrolled") {
		t.Errorf("reinstall: %q, %v", h.out, err)
	}
}

func TestRunWithoutEnrollment(t *testing.T) {
	h := newHarness(t)
	if err := h.run("run"); err == nil {
		t.Error("run without an enrollment")
	}
}
