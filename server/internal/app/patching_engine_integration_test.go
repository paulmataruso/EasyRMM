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

// TestPatchingEngineAPI starts EasyRMM with the engine in its deployment
// (ADR-0038, ADR-0040): Settings shows the engine and cannot change it,
// organizations reach the engine as they change, and the engine refusing
// EasyRMM reaches the console as the engine being unavailable, never as a
// 401 or 403.
func TestPatchingEngineAPI(t *testing.T) {
	key := bytes.Repeat([]byte{5}, 32)
	engine := eptest.NewEngine(t, key)
	engine.Capabilities = []string{easypatch.CapabilityScheduledInstalls}
	bundled := func(key []byte) func(*config.Config) {
		return func(c *config.Config) {
			c.Patching = config.Patching{URL: engine.URL(), Key: key}
		}
	}

	h := newHarnessWith(t, false, bundled(key))
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")

	var conn struct {
		Configured    bool   `json:"configured"`
		URL           string `json:"url"`
		ServerVersion string `json:"serverVersion"`
		LastError     string `json:"lastError"`
		CACert        string `json:"caCert"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch", nil, &conn)
	if !conn.Configured || conn.URL != engine.URL() || conn.ServerVersion != "1.9.0" || conn.LastError != "" || conn.CACert != "" {
		t.Fatalf("settings: %+v", conn)
	}
	wantStatus(t, admin.do("PUT", "/api/v1/settings/easypatch", map[string]string{"url": "https://patch.example.com"}), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("DELETE", "/api/v1/settings/easypatch", nil), http.StatusNotFound, "not_found")

	var status struct {
		Configured  bool `json:"configured"`
		CanSchedule bool `json:"canSchedule"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching", nil, &status)
	if !status.Configured || !status.CanSchedule {
		t.Fatalf("status: %+v", status)
	}

	// Every organization gets its own in the engine (ADR-0040): links are
	// not chosen, and a change in EasyRMM reaches the engine at the next
	// pass rather than at the next full comparison.
	ctx := context.Background()
	wantStatus(t, admin.do("PUT", "/api/v1/settings/easypatch/organizations/"+acme, map[string]string{"easyPatchId": "0b5c7a3e-0000-4000-8000-000000000001"}),
		http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("DELETE", "/api/v1/settings/easypatch/organizations/"+acme, nil), http.StatusNotFound, "not_found")
	if res, err := h.deps.EasyPatch.Reconcile(ctx); err != nil || res.Created == 0 || len(res.Problems) != 0 {
		t.Fatalf("first pass: %+v, %v", res, err)
	}
	calls := engine.RequestsTo("GET", "/api/v1/organizations")
	if len(calls) == 0 || calls[len(calls)-1].Statement == nil || calls[len(calls)-1].Statement.Subject != easypatch.ServiceSubject {
		t.Fatalf("organizations were not read with EasyRMM's statement: %+v", calls)
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]string{"name": "Tailspin", "timezone": "Europe/Oslo"}, nil)
	if res, err := h.deps.EasyPatch.Reconcile(ctx); err != nil || res.Created != 1 {
		t.Fatalf("pass after a new organization: %+v, %v", res, err)
	}
	found := false
	for _, o := range engine.Organizations() {
		found = found || (o.Name == "Tailspin" && o.TimeZone == "Europe/Oslo")
	}
	if !found {
		t.Fatalf("the engine has no Tailspin: %+v", engine.Organizations())
	}
	var sync struct {
		At       *string  `json:"at"`
		Problems []string `json:"problems"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch/sync", nil, &sync)
	if sync.At == nil || len(sync.Problems) != 0 {
		t.Fatalf("sync: %+v", sync)
	}
	// Stopping patching takes devices the caller may manage.
	wantStatus(t, admin.do("POST", "/api/v1/patching/stop", map[string]any{"deviceIds": []string{}}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", "/api/v1/patching/allow", map[string]any{"deviceIds": []string{"0b5c7a3e-0000-4000-8000-000000000002"}}),
		http.StatusNotFound, "not_found")

	// Addressed by IP, with EasyRMM's own authority: EasyPatch agents are
	// given it to trust (ADR-0042).
	internal := newHarnessWith(t, false, func(c *config.Config) {
		bundled(key)(c)
		c.TLSMode = config.TLSInternal
	})
	admin3, _ := setUp(t, internal)
	admin3.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch", nil, &conn)
	if internal.deps.PKI == nil || conn.CACert != string(internal.deps.PKI.CAPEM()) || !strings.HasPrefix(conn.CACert, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("internal TLS: %+v", conn)
	}

	// Another key than the engine's: refused, and shown as unavailable.
	h2 := newHarnessWith(t, false, bundled(bytes.Repeat([]byte{6}, 32)))
	admin2, _ := setUp(t, h2)
	var orgs struct {
		Error string `json:"error"`
	}
	admin2.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch/organizations", nil, &orgs)
	if !strings.Contains(orgs.Error, "patching engine answered 401") {
		t.Fatalf("organizations with a wrong key: %+v", orgs)
	}
	admin2.expect(http.StatusOK, "POST", "/api/v1/settings/easypatch/check", nil, &conn)
	if !conn.Configured || !strings.Contains(conn.LastError, "401") {
		t.Fatalf("check with a wrong key: %+v", conn)
	}
}

// TestPatchingAgentsThroughTheEdge: in bundled mode, EasyPatch agents reach
// the engine on EasyRMM's own address (ADR-0039). Their paths go to the
// engine before EasyRMM's session and CSRF layers, nothing else does, and no
// statement from outside reaches it. Without the bundle, EasyRMM serves
// nothing under those paths.
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
		c.Patching = config.Patching{URL: engine.URL, Key: bytes.Repeat([]byte{7}, 32)}
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

	// An imported EasyPatch's name (ADR-0045): its agents' paths reach the
	// engine; a person is sent to EasyRMM's patching pages; a name EasyRMM
	// does not serve is still refused.
	imported := newHarnessWith(t, false, func(c *config.Config) {
		c.Patching = config.Patching{URL: engine.URL, Key: bytes.Repeat([]byte{7}, 32),
			AgentHostnames: []string{"patch.old.test"}}
	})
	at := func(host, method, path string) (int, http.Header) {
		t.Helper()
		req, err := http.NewRequest(method, imported.srv.URL+path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		c := *imported.srv.Client()
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header
	}
	for _, host := range []string{"patch.old.test", "Patch.Old.Test:443"} {
		if status, header := at(host, "POST", "/api/v1/agents/check-in"); status != http.StatusAccepted || header.Get("X-Engine") != "yes" {
			t.Errorf("an agent on %s: %d", host, status)
		}
	}
	mu.Lock()
	if len(got) != n+2 || got[n].Host != "patch.old.test" {
		t.Errorf("an imported EasyPatch's agents: %d requests reached the engine, the first for %q", len(got)-n, got[n].Host)
	}
	n = len(got)
	mu.Unlock()
	for _, p := range []string{"/", "/api/v1/organizations", "/downloads/install/ABCD-1234.ps1"} {
		if status, header := at("patch.old.test", "GET", p); status != http.StatusFound || header.Get("Location") != "https://rmm.test/patching" {
			t.Errorf("%s on the imported EasyPatch's name: %d %q", p, status, header.Get("Location"))
		}
	}
	if status, _ := at("patch.other.test", "POST", "/api/v1/agents/check-in"); status != http.StatusMisdirectedRequest {
		t.Errorf("a name EasyRMM does not serve: %d", status)
	}
	mu.Lock()
	if len(got) != n {
		t.Errorf("%d more requests reached the engine", len(got)-n)
	}
	mu.Unlock()
}
