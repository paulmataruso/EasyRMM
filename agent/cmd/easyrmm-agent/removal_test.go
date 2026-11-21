package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// removalServer enrolls with token ert_good as dev-42 and records removal
// reports, answering each with status.
type removalServer struct {
	*httptest.Server
	mu      sync.Mutex
	reports []agentproto.RemovedReport
	status  int
}

func newRemovalServer(t *testing.T) *removalServer {
	t.Helper()
	s := &removalServer{status: http.StatusNoContent}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case agentproto.PathEnroll:
			_, _ = io.WriteString(w, `{"deviceId":"dev-42","heartbeatSeconds":60}`)
		case agentproto.PathRemoved:
			var rep agentproto.RemovedReport
			_ = json.NewDecoder(r.Body).Decode(&rep)
			s.mu.Lock()
			s.reports = append(s.reports, rep)
			status := s.status
			s.mu.Unlock()
			if status != http.StatusNoContent {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"error":{"code":"device_unknown","message":"gone"}}`)
				return
			}
			w.WriteHeader(status)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *removalServer) got() []agentproto.RemovedReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reports)
}

// enrolledForRemoval enrolls the harness's agent, pins a job key and
// installs its unit, and returns the key that signs instructions.
func enrolledForRemoval(t *testing.T, h *harness, srv *removalServer) ed25519.PrivateKey {
	t.Helper()
	t.Setenv("EASYRMM_TOKEN", "ert_good")
	if err := h.run("enroll", "--server", srv.URL); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	cfg, _, err := h.e.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.JobKey = agentproto.EncodeKey(pub)
	if err := h.e.store.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(h.e.paths.Units(), host.AgentUnit)
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte(host.UnitContent(h.e.paths.AgentService())), 0o644); err != nil {
		t.Fatal(err)
	}
	return priv
}

// saveInstruction writes an uninstall instruction where the agent saves it.
func saveInstruction(t *testing.T, h *harness, priv ed25519.PrivateKey, device string) string {
	t.Helper()
	now := time.Now()
	u, err := agentproto.SignUninstall(priv, agentproto.UninstallPayload{
		V: agentproto.UninstallPayloadVersion, ID: "removal-1", DeviceID: device, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(u)
	file := h.e.removalFile()
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestRemoveOnRequest(t *testing.T) {
	linuxOnly(t)
	srv := newRemovalServer(t)
	h := newHarness(t)
	priv := enrolledForRemoval(t, h, srv)
	ctx := context.Background()

	// With its unit installed, the agent starts the uninstaller as a
	// systemd unit of its own and keeps running.
	file := saveInstruction(t, h, priv, "dev-42")
	inline, err := h.e.launchRemoval(ctx, file)
	if err != nil || inline {
		t.Fatalf("launch: %v inline %v", inline, err)
	}
	exe, _ := os.Executable()
	last := h.calls[len(h.calls)-1]
	if !strings.HasPrefix(last, "systemd-run --unit=easyrmm-agent-removal-") ||
		!strings.Contains(last, " --collect --quiet ") || !strings.HasSuffix(last, "-- "+exe+" uninstall --removal "+file) {
		t.Errorf("launch %q", last)
	}

	// An instruction for another device removes nothing.
	other := saveInstruction(t, h, priv, "dev-7")
	if err := h.run("uninstall", "--removal", other); err == nil {
		t.Fatal("another device's instruction accepted")
	}
	if _, err := os.Stat(h.e.paths.State()); err != nil || len(srv.got()) != 0 {
		t.Fatalf("removed anyway: %v, reports %v", err, srv.got())
	}

	// The uninstaller removes the unit, reports, then the agent's files,
	// with the folder MeshAgent's was in.
	if err := os.MkdirAll(h.e.paths.MeshAgent(), 0o755); err != nil {
		t.Fatal(err)
	}
	file = saveInstruction(t, h, priv, "dev-42")
	h.calls = nil
	if err := h.run("uninstall", "--removal", file); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !slices.Contains(h.calls, "systemctl disable --now easyrmm-agent.service") {
		t.Errorf("calls %v", h.calls)
	}
	if got := srv.got(); len(got) != 1 || got[0] != (agentproto.RemovedReport{ID: "removal-1", Removed: true}) {
		t.Errorf("reports %+v", got)
	}
	if _, err := os.Stat(h.e.paths.State()); !os.IsNotExist(err) {
		t.Error("state kept")
	}
	if _, err := os.Stat(filepath.Join(h.e.paths.Units(), host.AgentUnit)); !os.IsNotExist(err) {
		t.Error("unit kept")
	}
	if _, err := os.Stat(filepath.Dir(h.e.paths.MeshAgent())); !os.IsNotExist(err) {
		t.Errorf("MeshAgent's folder kept: %v", err)
	}
	if !strings.Contains(h.out.String(), "removed on the server's instruction") {
		t.Errorf("output %q", h.out)
	}
}

func TestRemoveOnRequestServiceFails(t *testing.T) {
	linuxOnly(t)
	srv := newRemovalServer(t)
	h := newHarness(t)
	priv := enrolledForRemoval(t, h, srv)
	// A unit that cannot be deleted: a folder with something in it.
	unit := filepath.Join(h.e.paths.Units(), host.AgentUnit)
	if err := os.Remove(unit); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(unit, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := saveInstruction(t, h, priv, "dev-42")
	h.calls = nil
	if err := h.run("uninstall", "--removal", file); err == nil || !strings.Contains(err.Error(), "Removing the agent's service failed") {
		t.Fatalf("uninstall: %v", err)
	}
	got := srv.got()
	if len(got) != 1 || got[0].Removed || !strings.Contains(got[0].Error, "Removing the agent's service failed") {
		t.Errorf("reports %+v", got)
	}
	// The agent goes back to work; nothing of it is deleted.
	if !slices.Contains(h.calls, "systemctl restart easyrmm-agent.service") {
		t.Errorf("calls %v", h.calls)
	}
	if _, err := h.e.store.LoadStatus(); err != nil && !os.IsNotExist(err) {
		t.Error(err)
	}
	if _, _, err := h.e.store.Load(); err != nil {
		t.Errorf("enrollment gone: %v", err)
	}
}

// Without a unit the agent uninstalls in its own process; a server that
// no longer knows the device has deleted it already, which ends the
// reporting.
func TestRemoveInline(t *testing.T) {
	linuxOnly(t)
	srv := newRemovalServer(t)
	srv.status = http.StatusUnauthorized
	h := newHarness(t)
	priv := enrolledForRemoval(t, h, srv)
	if err := os.Remove(filepath.Join(h.e.paths.Units(), host.AgentUnit)); err != nil {
		t.Fatal(err)
	}
	file := saveInstruction(t, h, priv, "dev-42")
	if inline, err := h.e.launchRemoval(context.Background(), file); err != nil || !inline {
		t.Fatalf("launch: %v inline %v", inline, err)
	}
	if err := h.e.removeOnRequest(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	if got := srv.got(); len(got) != 1 || !got[0].Removed {
		t.Errorf("reports %+v", got)
	}
	if _, err := os.Stat(h.e.paths.State()); !os.IsNotExist(err) {
		t.Error("state kept")
	}
}
