//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
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
	jobKey, err := agentproto.DecodeKey(h.deps.JobKeys.Newest().Encoded())
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
	wantStatus(t, admin.do("POST", "/api/v1/devices/nope/repairs", map[string]string{}), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/devices/nope/repair-plan", nil), http.StatusNotFound, "not_found")
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
	// The site has a MeshCentral group (the harness runs none), so MeshAgent is expected on the device.
	if err := h.db.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO mesh_sites (site_id, organization_id, mesh_id, synced_name) VALUES ($1, $2, 'mesh-1234567890', 'HQ')`, hq.ID, acme)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The server decides what to repair; a target is not asked for.
	wantStatus(t, admin.do("POST", device+"/repairs", map[string]string{"target": "everything"}), http.StatusUnprocessableEntity, "validation_failed")
	var plan struct {
		Down    []string `json:"down"`
		Repairs []struct {
			Target    string `json:"target"`
			CarriedBy string `json:"carriedBy"`
		} `json:"repairs"`
		Summary string `json:"summary"`
	}
	admin.expect(http.StatusOK, "GET", device+"/repair-plan", nil, &plan)
	if len(plan.Repairs) != 1 || plan.Repairs[0].Target != "meshagent" || plan.Repairs[0].CarriedBy != "easyrmm-agent" || plan.Summary == "" {
		t.Fatalf("plan = %+v", plan)
	}
	var outcome struct {
		ID      string `json:"id"`
		Repairs []struct {
			ID     string `json:"id"`
			Target string `json:"target"`
			State  string `json:"state"`
		} `json:"repairs"`
	}
	admin.expect(http.StatusCreated, "POST", device+"/repairs", map[string]string{}, &outcome)
	if len(outcome.Repairs) != 1 || outcome.Repairs[0].State != "running" || outcome.Repairs[0].Target != "meshagent" {
		t.Fatalf("outcome = %+v", outcome)
	}
	made := outcome.Repairs[0]
	wantStatus(t, admin.do("POST", device+"/repairs", map[string]string{}), http.StatusConflict, "repair_running")

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
