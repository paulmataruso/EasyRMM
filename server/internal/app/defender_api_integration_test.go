//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestDefenderActionsAPI is ADR-0074's permission matrix and refusals through
// the console API: who may start which tier, what is refused before any job
// exists (a weakening value in a routine action, a value too broad, ours),
// and that a tier 3 action needs its confirmation and a step-up.
func TestDefenderActionsAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Windows", "expiresInDays": 1}, &token)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	win := facts("ws-02")
	win.Platform, win.OS = "windows", "Windows Server 2025 Datacenter"
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), win)
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	device := enr.DeviceID
	if _, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: windowsFacts("ws-02", "1.2.3-test")}); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, _ = ac.Poll(short, []string{agentproto.CapJobParams})

	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")
	invite(t, h, admin, "olga@acme.example", []map[string]any{{"role": "org_admin", "organizationId": acme}})
	owner := h.client()
	owner.signIn("olga@acme.example", "a long and unusual passphrase", "")

	path := func(action string) string { return "/api/v1/devices/" + device + "/winmod/defender." + action }
	body := func(params map[string]any) map[string]any { return map[string]any{"params": params} }
	notAllowed := func(r response, what string) {
		t.Helper()
		// A person who may not use an action on the device is told so as a field of the request.
		if r.status != http.StatusNotFound && r.status != http.StatusForbidden && !(r.status == http.StatusUnprocessableEntity && strings.Contains(string(r.body), "You cannot use")) {
			t.Errorf("%s: status %d, want a refusal: %s", what, r.status, r.body)
		}
	}

	// Read-Only holds nothing of the module.
	notAllowed(viewer.do("POST", path("scan_quick"), body(nil)), "a viewer starts a scan")
	notAllowed(viewer.do("POST", path("threats_read"), body(nil)), "a viewer reads threats")
	// A Technician manages: a routine action starts, and reads that carry no sensitive value run.
	var run struct {
		Action, Status string
	}
	tech.expect(http.StatusAccepted, "POST", path("scan_quick"), body(nil), &run)
	if run.Action != "defender.scan_quick" || run.Status != "queued" {
		t.Errorf("run %+v", run)
	}
	tech.expect(http.StatusAccepted, "POST", path("preferences_read"), body(nil), nil)
	tech.expect(http.StatusAccepted, "POST", path("preferences_set"), body(map[string]any{"field": "ScanAvgCPULoadFactor", "value": "30"}), nil)
	// ...but nothing that lowers protection: the routine action refuses the value, the weakening one refuses the person.
	wantStatus(t, tech.do("POST", path("preferences_set"), body(map[string]any{"field": "DisableRealtimeMonitoring", "value": "true"})), http.StatusUnprocessableEntity, "validation_failed")
	notAllowed(tech.do("POST", path("preferences_weaken"), map[string]any{"params": map[string]any{"field": "DisableRealtimeMonitoring", "value": "true"},
		"confirm": "defender.preferences_weaken:DisableRealtimeMonitoring"}), "a technician lowers protection")
	notAllowed(tech.do("POST", path("quarantine_restore"), map[string]any{"params": map[string]any{"name": "Virus:DOS/EICAR_Test_File"},
		"confirm": "defender.quarantine_restore:Virus:DOS/EICAR_Test_File"}), "a technician restores a threat")
	// A Technician cannot read what is sensitive (paths, administrators' exclusions).
	var sens struct {
		RunID string `json:"runId"`
	}
	owner.expect(http.StatusAccepted, "POST", path("exclusions_read"), body(nil), &sens)
	notAllowed(tech.do("GET", "/api/v1/winmod/runs/"+sens.RunID, nil), "a technician reads exclusions")
	owner.expect(http.StatusOK, "GET", "/api/v1/winmod/runs/"+sens.RunID, nil, nil)

	// Refused before any job: ours is never removed (by anyone), too broad is too broad, not_allowed is not allowed.
	for _, c := range []*client{tech, owner, admin} {
		r := c.do("POST", path("exclusion_remove"), body(map[string]any{"kind": "path", "value": `C:\Program Files\EasyRMM\Agent`}))
		wantStatus(t, r, http.StatusConflict, "protected_exclusion")
	}
	r := owner.do("POST", path("exclusion_add"), body(map[string]any{"kind": "path", "value": `C:\`, "reason": "because"}))
	wantStatus(t, r, http.StatusUnprocessableEntity, "too_broad")
	r = owner.do("POST", path("preferences_set"), body(map[string]any{"field": "DisableLocalAdminMerge", "value": "true"}))
	wantStatus(t, r, http.StatusUnprocessableEntity, "not_allowed")

	// A tier 3 action needs the typed confirmation, then a step-up, which this session has not made.
	add := map[string]any{"kind": "path", "value": `D:\LineOfBusiness`, "reason": "line of business app"}
	r = owner.do("POST", path("exclusion_add"), body(add))
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
	if !strings.Contains(string(r.body), `defender.exclusion_add:D:\\LineOfBusiness`) {
		t.Errorf("the refusal does not say what to confirm: %s", r.body)
	}
	r = owner.do("POST", path("exclusion_add"), map[string]any{"params": add, "confirm": `defender.exclusion_add:D:\LineOfBusiness`})
	if r.status != http.StatusUnauthorized || r.errorCode(t) != "step_up_required" {
		t.Errorf("tier 3 without a step-up: %d %s", r.status, r.body)
	}
	// Tier 2 needs the confirmation but no step-up.
	rm := map[string]any{"kind": "path", "value": `D:\LineOfBusiness`}
	wantStatus(t, owner.do("POST", path("exclusion_remove"), body(rm)), http.StatusUnprocessableEntity, "validation_failed")
	owner.expect(http.StatusAccepted, "POST", path("exclusion_remove"), map[string]any{"params": rm, "confirm": `defender.exclusion_remove:D:\LineOfBusiness`}, nil)
	tech.expect(http.StatusUnprocessableEntity, "POST", path("threats_remove"), body(nil), nil)
	tech.expect(http.StatusAccepted, "POST", path("threats_remove"), map[string]any{"confirm": "defender.threats_remove:"}, nil)
}

// TestDefenderEventsThroughTheHeartbeat sends Defender events in the agent's
// heartbeat: nothing is asked of the agent until the role is reported, then
// the answer says Events, the batch is stored and acknowledged (a repeat adds
// nothing), and the console's Events read shows it to the people who may see.
func TestDefenderEventsThroughTheHeartbeat(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Windows", "expiresInDays": 1}, &token)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	win := facts("ws-03")
	win.Platform, win.OS = "windows", "Windows Server 2025 Datacenter"
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), win)
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	device := enr.DeviceID
	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")

	batch := &agentproto.DefenderLogBatch{Epoch: "e1", Through: 9, Events: []agentproto.DefenderLogEvent{{
		RecordID: 9, EventID: 1116, At: time.Now().UTC(), Severity: "Severe", ThreatID: "T1", ThreatName: "Virus:DOS/EICAR_Test_File",
		Sensitive: map[string]string{"path": `C:\Users\alice\Downloads\eicar.txt`},
	}}}
	f := windowsFacts("ws-03", "1.2.3-test")
	resp, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: f, DefenderLog: batch})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Defender == nil || resp.Defender.Events || resp.Defender.EventsAck != nil {
		t.Fatalf("before the role is reported: %+v", resp.Defender)
	}
	// The role is reported: the next answer asks for events and acknowledges what came.
	f.Roles = []agentproto.Role{{Name: "defender", State: "present"}}
	if _, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: f}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		resp, err = ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: f, DefenderLog: batch})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Defender == nil || !resp.Defender.Events || resp.Defender.EventsAck == nil || resp.Defender.EventsAck.RecordID != 9 || resp.Defender.EventsAck.Epoch != "e1" {
			t.Fatalf("after the role is reported: %+v", resp.Defender)
		}
	}
	var list struct {
		Items []struct {
			EventID    int             `json:"eventId"`
			ThreatName string          `json:"threatName"`
			Sensitive  json.RawMessage `json:"sensitive"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+device+"/defender/events", nil, &list)
	if len(list.Items) != 1 || list.Items[0].EventID != 1116 || !strings.Contains(string(list.Items[0].Sensitive), "alice") {
		t.Errorf("admin: %+v", list.Items)
	}
	list.Items = nil
	tech.expect(http.StatusOK, "GET", "/api/v1/devices/"+device+"/defender/events", nil, &list)
	if len(list.Items) != 1 || len(list.Items[0].Sensitive) != 0 {
		t.Errorf("technician: %+v", list.Items)
	}
}
