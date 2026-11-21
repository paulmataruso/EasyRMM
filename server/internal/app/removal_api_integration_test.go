//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	agentclient "github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// TestDeviceRemovalAPI removes devices through the console API and the
// agent API (ADR-0050).
func TestDeviceRemovalAPI(t *testing.T) {
	h := newHarness(t, false)
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
	// uninstall sends a's heartbeat and returns its uninstall instruction,
	// verified with the job key, or nil.
	uninstall := func(a agent) *agentproto.UninstallPayload {
		t.Helper()
		resp, err := a.c.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("pc")})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Uninstall == nil {
			return nil
		}
		if resp.Update != nil || resp.EasyPatchInstall != nil {
			t.Errorf("other instructions with the uninstall: %+v", resp)
		}
		key, err := agentproto.DecodeKey(resp.JobKey)
		if err != nil {
			t.Fatal(err)
		}
		p, err := agentproto.VerifyUninstall(key, *resp.Uninstall, a.id, time.Now())
		if err != nil {
			t.Fatalf("the instruction does not verify with the job key: %v", err)
		}
		return &p
	}
	type device struct {
		CanRemove bool `json:"canRemove"`
		Removal   *struct {
			RequestedAt string  `json:"requestedAt"`
			SentAt      *string `json:"sentAt"`
			Error       string  `json:"error"`
		} `json:"removal"`
	}
	type result struct {
		Status string  `json:"status"`
		Device *device `json:"device"`
	}

	// A technician sees no removal and may not ask for one.
	a1 := enroll("pc-1")
	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")
	var d device
	tech.expect(http.StatusOK, "GET", "/api/v1/devices/"+a1.id, nil, &d)
	if d.CanRemove || d.Removal != nil {
		t.Errorf("technician's view %+v", d)
	}
	wantStatus(t, tech.do("POST", "/api/v1/devices/"+a1.id+"/removal", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, tech.do("DELETE", "/api/v1/devices/"+a1.id, nil), http.StatusForbidden, "forbidden")
	wantStatus(t, admin.do("DELETE", "/api/v1/devices/"+a1.id+"/removal", nil), http.StatusConflict, "not_removing")
	wantStatus(t, admin.do("POST", "/api/v1/devices/nope/removal", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("DELETE", "/api/v1/devices/nope/removal", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("DELETE", "/api/v1/devices/nope", nil), http.StatusNotFound, "not_found")

	// The administrator asks; the device waits for its agent.
	var res result
	admin.expect(http.StatusOK, "POST", "/api/v1/devices/"+a1.id+"/removal", nil, &res)
	if res.Status != "asked" || res.Device == nil || !res.Device.CanRemove || res.Device.Removal == nil || res.Device.Removal.SentAt != nil {
		t.Fatalf("request %+v", res)
	}
	p := uninstall(a1)
	if p == nil {
		t.Fatal("no instruction")
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+a1.id, nil, &d)
	if d.Removal == nil || d.Removal.SentAt == nil {
		t.Errorf("after sending %+v", d.Removal)
	}
	// Canceled, then asked again.
	admin.expect(http.StatusOK, "DELETE", "/api/v1/devices/"+a1.id+"/removal", nil, &d)
	if d.Removal != nil || uninstall(a1) != nil {
		t.Error("still removing")
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/devices/"+a1.id+"/removal", nil, &res)
	p = uninstall(a1)
	// The agent cannot remove its service: the console shows why.
	if err := a1.c.Removed(ctx, agentproto.RemovedReport{ID: p.ID, Error: "Removing the agent's service failed: access denied"}); err != nil {
		t.Fatal(err)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+a1.id, nil, &d)
	if d.Removal == nil || d.Removal.Error != "Removing the agent's service failed: access denied" {
		t.Errorf("failure %+v", d.Removal)
	}
	// Asked again, it removes itself, and the device is gone.
	admin.expect(http.StatusOK, "POST", "/api/v1/devices/"+a1.id+"/removal", nil, &res)
	p = uninstall(a1)
	if err := a1.c.Removed(ctx, agentproto.RemovedReport{ID: p.ID, Removed: true}); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, admin.do("GET", "/api/v1/devices/"+a1.id, nil), http.StatusNotFound, "not_found")
	if _, err := a1.c.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("pc-1")}); agentclient.Code(err) != "device_unknown" {
		t.Errorf("removed agent's heartbeat: %v", err)
	}
	// A report the agent sends again finds the device gone, as it expects.
	if err := a1.c.Removed(ctx, agentproto.RemovedReport{ID: p.ID, Removed: true}); agentclient.Code(err) != "device_unknown" {
		t.Errorf("report again: %v", err)
	}

	// Removed by force: the agent that comes back gets its instruction and
	// nothing else.
	a2 := enroll("pc-2")
	wantStatus(t, admin.do("DELETE", "/api/v1/devices/"+a2.id, nil), http.StatusNoContent, "")
	wantStatus(t, admin.do("GET", "/api/v1/devices/"+a2.id, nil), http.StatusNotFound, "not_found")
	p = uninstall(a2)
	if p == nil || p.ID != a2.id {
		t.Fatalf("retired instruction %+v", p)
	}
	if _, err := a2.c.Inventory(ctx, []byte(`{}`)); agentclient.Code(err) != "device_unknown" {
		t.Errorf("retired agent's inventory: %v", err)
	}
	if err := a2.c.Removed(ctx, agentproto.RemovedReport{ID: p.ID, Removed: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := a2.c.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("pc-2")}); agentclient.Code(err) != "device_unknown" {
		t.Errorf("cleaned agent's heartbeat: %v", err)
	}

	// A report must be a report.
	a3 := enroll("pc-3")
	if err := a3.c.Removed(ctx, agentproto.RemovedReport{ID: string(make([]byte, 65))}); agentclient.Code(err) != "report_invalid" {
		t.Errorf("long id: %v", err)
	}

	// The audit trail.
	for action, want := range map[string]int{
		"device.removal_request": 3, "device.removal_cancel": 1, "device.removal_failed": 1, "device.remove": 2, "device.retired_cleanup": 1,
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
