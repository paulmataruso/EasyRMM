//go:build integration

package app_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// TestPatchingEngineAPI starts EasyRMM with EASYRMM_PATCHING=bundled (one-
// product plan, B3): Settings shows the engine and cannot change it, links
// work through it, and the engine refusing EasyRMM reaches the console as
// the engine being unavailable, never as a 401 or 403.
func TestPatchingEngineAPI(t *testing.T) {
	key := bytes.Repeat([]byte{5}, 32)
	engine := eptest.NewEngine(t, key)
	engine.Capabilities = []string{easypatch.CapabilityScheduledInstalls}
	epOrg := engine.Org("Acme Patch")
	bundled := func(key []byte) func(*config.Config) {
		return func(c *config.Config) {
			c.Patching = config.Patching{Mode: config.PatchingBundled, URL: engine.URL(), Key: key}
		}
	}

	h := newHarnessWith(t, false, bundled(key))
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")

	var conn struct {
		Configured    bool   `json:"configured"`
		Bundled       bool   `json:"bundled"`
		URL           string `json:"url"`
		ServerVersion string `json:"serverVersion"`
		CanOperate    bool   `json:"canOperate"`
		LastError     string `json:"lastError"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch", nil, &conn)
	if !conn.Configured || !conn.Bundled || conn.URL != engine.URL() || conn.ServerVersion != "1.9.0" || !conn.CanOperate || conn.LastError != "" {
		t.Fatalf("settings: %+v", conn)
	}
	wantStatus(t, admin.do("PUT", "/api/v1/settings/easypatch", map[string]string{"url": "https://patch.example.com", "token": "ept_" + strings.Repeat("A", 43)}),
		http.StatusConflict, "patching_bundled")
	wantStatus(t, admin.do("DELETE", "/api/v1/settings/easypatch", nil), http.StatusConflict, "patching_bundled")

	var status struct {
		Configured  bool   `json:"configured"`
		CanSchedule bool   `json:"canSchedule"`
		ConsoleURL  string `json:"consoleUrl"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching", nil, &status)
	if !status.Configured || !status.CanSchedule || status.ConsoleURL != "" {
		t.Fatalf("status: %+v", status)
	}

	admin.expect(http.StatusNoContent, "PUT", "/api/v1/settings/easypatch/organizations/"+acme, map[string]string{"easyPatchId": epOrg.String()}, nil)
	calls := engine.RequestsTo("GET", "/api/v1/organizations")
	if len(calls) == 0 || calls[len(calls)-1].Statement == nil || calls[len(calls)-1].Statement.Subject != easypatch.ServiceSubject {
		t.Fatalf("organizations were not read with EasyRMM's statement: %+v", calls)
	}

	// Another key than the engine's: refused, and shown as unavailable.
	h2 := newHarnessWith(t, false, bundled(bytes.Repeat([]byte{6}, 32)))
	admin2, _ := setUp(t, h2)
	acme2 := orgID(t, admin2, "Acme")
	wantStatus(t, admin2.do("PUT", "/api/v1/settings/easypatch/organizations/"+acme2, map[string]string{"easyPatchId": epOrg.String()}),
		http.StatusServiceUnavailable, "patching_unavailable")
	admin2.expect(http.StatusOK, "POST", "/api/v1/settings/easypatch/check", nil, &conn)
	if !conn.Bundled || !strings.Contains(conn.LastError, "401") {
		t.Fatalf("check with a wrong key: %+v", conn)
	}
}

// TestPatchingAgentsThroughTheEdge: in bundled mode, EasyPatch agents reach
// the engine on EasyRMM's own address (one-product plan, B4). Their paths go
// to the engine before EasyRMM's session and CSRF layers, nothing else
// does, and no statement from outside reaches it. Without the bundle,
// EasyRMM serves nothing under those paths.
func TestPatchingAgentsThroughTheEdge(t *testing.T) {
	var mu sync.Mutex
	var got []*http.Request
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Clone(context.Background()))
		mu.Unlock()
		w.Header().Set("X-Engine", "yes")
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(engine.Close)
	h := newHarnessWith(t, false, func(c *config.Config) {
		c.Patching = config.Patching{Mode: config.PatchingBundled, URL: engine.URL, Key: bytes.Repeat([]byte{7}, 32)}
	})
	// send answers the status and headers of a request to h.
	send := func(h *harness, method, path string, header map[string]string) (int, http.Header) {
		t.Helper()
		req, err := http.NewRequest(method, h.srv.URL+path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "rmm.test"
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := h.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header
	}

	// No session, no CSRF token, a cross-site origin: an agent's request
	// still reaches the engine, and only the engine answers it.
	for _, p := range []string{"/api/v1/agents/check-in", "/api/v1/agents/enroll", "/downloads/agent/EasyPatchAgent-1.10.0-x64.msi", "/downloads/winget/x.yaml"} {
		method := "POST"
		if strings.HasPrefix(p, "/downloads/") {
			method = "GET"
		}
		status, header := send(h, method, p, map[string]string{"Origin": "https://evil.example", easypatch.StatementHeader: "forged", "Cookie": "easyrmm_session=x"})
		if status != http.StatusAccepted || header.Get("X-Engine") != "yes" {
			t.Errorf("%s %s: %d, not the engine's answer", method, p, status)
		}
	}
	mu.Lock()
	n := len(got)
	for _, r := range got {
		if r.Header.Get(easypatch.StatementHeader) != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Forwarded-For") == "" {
			t.Errorf("%s reached the engine with %v", r.URL.Path, r.Header)
		}
	}
	mu.Unlock()
	if n != 4 {
		t.Fatalf("%d requests reached the engine, want 4", n)
	}

	// Install scripts, the engine's console API and its health are not
	// served on EasyRMM's name.
	for _, p := range []string{"/downloads/install/ABCD-1234.ps1", "/downloads/install/macos/ABCD-1234.sh", "/api/v1/organizations", "/api/v1/agents", "/health/ready"} {
		if _, header := send(h, "GET", p, nil); header.Get("X-Engine") != "" {
			t.Errorf("%s reached the engine", p)
		}
	}
	mu.Lock()
	if len(got) != n {
		t.Errorf("%d more requests reached the engine", len(got)-n)
	}
	mu.Unlock()

	// Without the bundle, EasyRMM has nothing of its own under these paths.
	plain := newHarnessWith(t, false, nil)
	for _, p := range []string{"/api/v1/agents/check-in", "/downloads/agent/EasyPatchAgent-1.10.0-x64.msi", "/downloads/winget/x.yaml"} {
		if status, _ := send(plain, "GET", p, nil); status != http.StatusNotFound {
			t.Errorf("connector mode, %s: %d", p, status)
		}
	}
}
