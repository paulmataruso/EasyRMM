//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestWinmodAPI runs defender.status through the console API with the real
// agent client (ADR-0073, slice 5): the permission, the job the agent
// receives, the typed result, and that the job is not in the Jobs list.
func TestWinmodAPI(t *testing.T) {
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
	win := facts("ws-01")
	win.Platform, win.OS = "windows", "Windows Server 2025 Datacenter"
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), win)
	if err != nil {
		t.Fatal(err)
	}
	jobKey, err := agentproto.DecodeKey(enr.JobKey)
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	device := enr.DeviceID

	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")

	path := "/api/v1/devices/" + device + "/winmod/defender.status"
	// An agent that has not said it takes params is told to update.
	r := tech.do("POST", path, map[string]any{})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
	// The agent says what it accepts once a heartbeat answer told it the
	// protocol level; its poll without work is let go after a second.
	if _, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: windowsFacts("ws-01", "1.2.3-test")}); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, _ = ac.Poll(short, []string{agentproto.CapJobParams})

	// Who may, and what is not found.
	wantStatus(t, viewer.do("POST", path, map[string]any{}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, tech.do("POST", "/api/v1/devices/"+device+"/winmod/defender.nope", map[string]any{}), http.StatusNotFound, "")
	r = tech.do("POST", path, map[string]any{"params": map[string]any{"x": 1}})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")

	var run struct {
		JobID  string `json:"jobId"`
		RunID  string `json:"runId"`
		Action string `json:"action"`
		Status string `json:"status"`
	}
	tech.expect(http.StatusAccepted, "POST", path, map[string]any{}, &run)
	if run.Action != "defender.status" || run.Status != "queued" {
		t.Errorf("run %+v", run)
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/jobs", nil, &list)
	if len(list.Items) != 0 {
		t.Errorf("the Jobs list shows %d jobs", len(list.Items))
	}

	poll, err := ac.Poll(ctx, []string{agentproto.CapJobParams})
	if err != nil || len(poll.Jobs) != 1 {
		t.Fatalf("poll %+v %v", poll, err)
	}
	p, err := agentproto.VerifyJob(jobKey, poll.Jobs[0], device, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.Shell != agentproto.ShellPowerShell || p.V != agentproto.JobPayloadVersionParams || string(p.Params) != "{}" ||
		!strings.Contains(p.Script, "EASYRMM-WINMOD-RESULT-V1") {
		t.Errorf("payload: shell %s, v%d, params %s", p.Shell, p.V, p.Params)
	}
	if st, err := ac.Start(ctx, p.RunID); err != nil || !st.Proceed {
		t.Fatalf("start %+v %v", st, err)
	}
	out := `EASYRMM-WINMOD-RESULT-V1 {"ok":true,"version":1,"data":{"antivirusEnabled":true,"antispywareEnabled":true,` +
		`"realTimeProtectionEnabled":true,"behaviorMonitorEnabled":null,"ioavProtectionEnabled":true,"onAccessProtectionEnabled":true,` +
		`"nisEnabled":true,"tamperProtected":false,"runningMode":"Normal","computerState":0,"engineVersion":"1.1.1","productVersion":"4.18.1",` +
		`"serviceVersion":"4.18.1","signatureVersion":"1.421.1.0","signatureUpdatedAt":"2026-11-26T08:00:00Z","signatureAgeDays":0,` +
		`"quickScanAgeDays":null,"fullScanAgeDays":3},"error":null}` + "\n"
	if err := ac.Result(ctx, p.RunID, agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: new(int), Stdout: out, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	var res struct {
		Status string `json:"status"`
		OK     *bool  `json:"ok"`
		Data   struct {
			SignatureVersion string `json:"signatureVersion"`
			FullScanAgeDays  *int   `json:"fullScanAgeDays"`
		} `json:"data"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/winmod/runs/"+run.RunID, nil, &res)
	if res.Status != "succeeded" || res.OK == nil || !*res.OK || res.Data.SignatureVersion != "1.421.1.0" || res.Data.FullScanAgeDays == nil || *res.Data.FullScanAgeDays != 3 {
		t.Errorf("result %+v", res)
	}
	wantStatus(t, viewer.do("GET", "/api/v1/winmod/runs/"+run.RunID, nil), http.StatusNotFound, "")
	wantStatus(t, viewer.do("GET", "/api/v1/job-runs/"+run.RunID, nil), http.StatusNotFound, "")
}
