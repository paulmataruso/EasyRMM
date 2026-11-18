//go:build integration

package app_test

import (
	"bytes"
	"net/http"
	"strings"
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
