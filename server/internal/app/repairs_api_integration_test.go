//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestRepairsAPI asks to reconnect a device's remote access through the
// console API and follows the repair through the agent API (ADR-0069).
func TestRepairsAPI(t *testing.T) {
	h := newHarnessWith(t, false, withRemote(t))
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var tok struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "t", "expiresInDays": 1}, &tok)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, tok.Secret, key.Public().(ed25519.PublicKey), facts("pc-1"))
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	jobKey, err := agentproto.DecodeKey(h.deps.Jobs.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	device := "/api/v1/devices/" + enr.DeviceID

	beat := func(rep *agentproto.RepairReport, st *agentproto.MeshAgentState) *agentproto.RepairPayload {
		t.Helper()
		resp, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("pc-1"), MeshAgent: st, Repair: rep})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Repair == nil {
			return nil
		}
		p, err := agentproto.VerifyRepair(jobKey, *resp.Repair, enr.DeviceID, time.Now())
		if err != nil {
			t.Fatalf("the instruction does not verify: %v", err)
		}
		return &p
	}

	// The device says why remote access is not connected.
	var d struct {
		Remote *struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"remote"`
		CanReconnectRemote bool `json:"canReconnectRemote"`
	}
	if p := beat(nil, &agentproto.MeshAgentState{Installed: false, Error: "install failed: x"}); p != nil {
		t.Fatalf("instruction without a repair: %+v", p)
	}
	admin.expect(http.StatusOK, "GET", device, nil, &d)
	if d.Remote == nil || d.Remote.Reason != "not_installed" || d.Remote.Message != "MeshAgent is not installed on the device." || !d.CanReconnectRemote {
		t.Fatalf("device = %+v", d)
	}
	beat(nil, &agentproto.MeshAgentState{Installed: true, Running: true})
	admin.expect(http.StatusOK, "GET", device, nil, &d)
	if d.Remote == nil || d.Remote.Reason != "not_connected" {
		t.Errorf("device = %+v", d.Remote)
	}

	// Bad requests.
	wantStatus(t, admin.do("GET", "/api/v1/devices/nope/repairs", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", "/api/v1/devices/nope/repairs", map[string]string{"target": "meshagent"}), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", device+"/repairs", "not an object"), http.StatusBadRequest, "")

	// Asking.
	var list struct {
		Items []struct {
			ID    string `json:"id"`
			State string `json:"state"`
			Steps []struct {
				Step  string `json:"step"`
				State string `json:"state"`
			} `json:"steps"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", device+"/repairs", nil, &list)
	if len(list.Items) != 0 {
		t.Fatalf("repairs before asking: %+v", list)
	}
	wantStatus(t, admin.do("POST", device+"/repairs", map[string]string{"target": "everything"}), http.StatusUnprocessableEntity, "validation_failed")
	var made struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	admin.expect(http.StatusCreated, "POST", device+"/repairs", map[string]string{"target": "meshagent"}, &made)
	if made.State != "running" {
		t.Fatalf("repair = %+v", made)
	}
	wantStatus(t, admin.do("POST", device+"/repairs", map[string]string{"target": "meshagent"}), http.StatusConflict, "repair_running")

	// The agent takes the step with its next heartbeat and reports it.
	p := beat(nil, nil)
	if p == nil || p.Target != "meshagent" || p.Step != "restart" {
		t.Fatalf("instruction = %+v", p)
	}
	if q := beat(&agentproto.RepairReport{ID: p.ID, OK: true}, nil); q != nil {
		t.Fatalf("instruction while the target gets its time: %+v", q)
	}
	admin.expect(http.StatusOK, "GET", device+"/repairs", nil, &list)
	if len(list.Items) != 1 || list.Items[0].ID != made.ID || list.Items[0].State != "running" || list.Items[0].Steps[0].State != "done" {
		t.Errorf("repairs = %+v", list)
	}
}
