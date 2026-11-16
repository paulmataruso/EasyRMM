//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	agentclient "github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// TestAgentUpdatesAPI rolls a build out through the console API and the
// agent API (ADR-0027).
func TestAgentUpdatesAPI(t *testing.T) {
	builds := t.TempDir()
	for name, content := range map[string]string{"easyrmm-agent-linux-amd64": "linux build v9", "VERSION": "v9\n"} {
		if err := os.WriteFile(filepath.Join(builds, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256([]byte("linux build v9"))
	buildSHA := hex.EncodeToString(sum[:])
	oldSum := sha256.Sum256([]byte("the old build"))
	oldSHA := hex.EncodeToString(oldSum[:])

	h := newHarnessWith(t, false, func(c *config.Config) { c.AgentDir = builds })
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var tok struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "t", "expiresInDays": 1}, &tok)

	ctx := context.Background()
	type agent struct {
		id string
		c  *agentclient.Client
	}
	enroll := func(host string) agent {
		t.Helper()
		key := newKey(t)
		c := h.agentClient()
		resp, err := c.Enroll(ctx, tok.Secret, key.Public().(ed25519.PublicKey), facts(host))
		if err != nil {
			t.Fatal(err)
		}
		c.SetIdentity(resp.DeviceID, key)
		return agent{id: resp.DeviceID, c: c}
	}
	beat := func(a agent, sha string) *agentproto.UpdatePayload {
		t.Helper()
		f := facts("pc-" + a.id[:4])
		f.AgentSHA256 = sha
		resp, err := a.c.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: f})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Update == nil {
			return nil
		}
		key, err := agentproto.DecodeKey(resp.JobKey)
		if err != nil {
			t.Fatal(err)
		}
		p, err := agentproto.VerifyUpdate(key, *resp.Update, a.id, time.Now())
		if err != nil {
			t.Fatalf("the instruction does not verify with the job key: %v", err)
		}
		return &p
	}
	type updateView struct {
		Status    string `json:"status"`
		Version   string `json:"version"`
		Requested bool   `json:"requested"`
	}
	type device struct {
		CanUpdateAgent bool `json:"canUpdateAgent"`
		Agent          struct {
			SHA256 string      `json:"sha256"`
			Update *updateView `json:"update"`
		} `json:"agent"`
	}
	type settings struct {
		Mode          string         `json:"mode"`
		MaxConcurrent int            `json:"maxConcurrent"`
		Stored        bool           `json:"stored"`
		Version       string         `json:"version"`
		Builds        []any          `json:"builds"`
		Fleet         map[string]int `json:"fleet"`
	}

	// By default every outdated agent updates, and the instruction names
	// the build the server serves.
	a1 := enroll("pc-1")
	p := beat(a1, oldSHA)
	if p == nil || p.SHA256 != buildSHA || p.Version != "v9" || p.File != "easyrmm-agent-linux-amd64" || p.Size != 14 {
		t.Fatalf("instruction %+v", p)
	}
	var s settings
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/agent-updates", nil, &s)
	if s.Mode != "automatic" || s.MaxConcurrent != 20 || s.Stored || s.Version != "v9" || len(s.Builds) != 1 || s.Fleet["updating"] != 1 {
		t.Fatalf("settings %+v", s)
	}
	var d device
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+a1.id, nil, &d)
	if !d.CanUpdateAgent || d.Agent.SHA256 != oldSHA || d.Agent.Update == nil || d.Agent.Update.Status != "updating" || d.Agent.Update.Version != "v9" {
		t.Fatalf("device %+v", d)
	}
	// The agent comes back with the build.
	if beat(a1, buildSHA) != nil {
		t.Fatal("told to update again")
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+a1.id, nil, &d)
	if d.Agent.Update.Status != "current" {
		t.Errorf("status %s", d.Agent.Update.Status)
	}
	wantStatus(t, admin.do("POST", "/api/v1/devices/"+a1.id+"/agent-update", nil), http.StatusConflict, "agent_current")

	// Manual: only what someone asks for.
	admin.expect(http.StatusOK, "PUT", "/api/v1/settings/agent-updates", map[string]any{"mode": "manual", "maxConcurrent": 3}, &s)
	if s.Mode != "manual" || s.MaxConcurrent != 3 || !s.Stored {
		t.Errorf("saved %+v", s)
	}
	wantStatus(t, admin.do("PUT", "/api/v1/settings/agent-updates", map[string]any{"mode": "sometimes", "maxConcurrent": 3}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PUT", "/api/v1/settings/agent-updates", map[string]any{"mode": "manual", "maxConcurrent": 0}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PUT", "/api/v1/settings/agent-updates", "nope"), http.StatusBadRequest, "")
	a2, a3 := enroll("pc-2"), enroll("pc-3")
	if beat(a2, oldSHA) != nil || beat(a3, oldSHA) != nil {
		t.Fatal("manual mode updated a device nobody asked for")
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/devices/"+a2.id+"/agent-update", nil, &d)
	if d.Agent.Update == nil || d.Agent.Update.Status != "queued" || !d.Agent.Update.Requested {
		t.Errorf("after the request %+v", d.Agent.Update)
	}
	if beat(a2, oldSHA) == nil {
		t.Error("the request did not go out")
	}
	var all struct {
		Requested int `json:"requested"`
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/settings/agent-updates/request-all", nil, &all)
	if all.Requested != 2 { // a2 (in flight, kept) and a3
		t.Errorf("requested %d", all.Requested)
	}
	if beat(a3, oldSHA) == nil {
		t.Error("request-all did not go out")
	}
	wantStatus(t, admin.do("POST", "/api/v1/devices/"+uuid.NewString()+"/agent-update", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", "/api/v1/devices/nope/agent-update", nil), http.StatusNotFound, "not_found")

	// A technician may update an agent, not change the rollout.
	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")
	wantStatus(t, tech.do("GET", "/api/v1/settings/agent-updates", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, tech.do("PUT", "/api/v1/settings/agent-updates", map[string]any{"mode": "off", "maxConcurrent": 1}), http.StatusForbidden, "forbidden")
	wantStatus(t, tech.do("POST", "/api/v1/settings/agent-updates/request-all", nil), http.StatusForbidden, "forbidden")
	tech.expect(http.StatusOK, "POST", "/api/v1/devices/"+a3.id+"/agent-update", nil, &d)
	wantStatus(t, h.client().do("GET", "/api/v1/settings/agent-updates", nil), http.StatusUnauthorized, "")

	// The audit trail.
	for action, want := range map[string]int{
		"agent_updates.update": 1, "agent_updates.request_all": 1, "device.agent_update_request": 2, "device.agent_update": 1,
	} {
		var n int
		if err := h.db.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("%s audited %d times, want %d", action, n, want)
		}
	}
}
