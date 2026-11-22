//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestSoftwareAPI installs a package on an enrolled device through the
// console API and checks what the agent receives (ADR-0028).
func TestSoftwareAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Software", "expiresInDays": 1}, &token)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts("pkg-01"))
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

	var dev struct {
		CanManageSoftware bool `json:"canManageSoftware"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/devices/"+device, nil, &dev)
	if !dev.CanManageSoftware {
		t.Error("a technician may not manage software on the device")
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/devices/"+device, nil, &dev)
	if dev.CanManageSoftware {
		t.Error("a read-only user may manage software")
	}

	const path = "/api/v1/jobs/software"
	wantStatus(t, tech.do("POST", path, "x"), http.StatusBadRequest, "")
	r := tech.do("POST", path, map[string]any{"deviceIds": []string{device}, "action": "install", "manager": "system", "package": "jq && reboot"})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
	if !strings.Contains(string(r.body), `"package"`) {
		t.Errorf("no package field error: %s", r.body)
	}
	r = viewer.do("POST", path, map[string]any{"deviceIds": []string{device}, "action": "install", "manager": "system", "package": "jq"})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
	if !strings.Contains(string(r.body), "You cannot manage software on pkg-01.") {
		t.Errorf("viewer: %s", r.body)
	}

	var job struct {
		ID         string `json:"id"`
		Kind       string `json:"kind"`
		ScriptName string `json:"scriptName"`
		ArgCount   int    `json:"argCount"`
		Software   *struct {
			Action, Manager, Package, Version string
		} `json:"software"`
		Total int `json:"total"`
	}
	tech.expect(http.StatusCreated, "POST", path, map[string]any{"deviceIds": []string{device}, "action": "install", "manager": "system", "package": "jq"}, &job)
	if job.Kind != "software" || job.ScriptName != "Install jq" || job.Total != 1 || job.Software == nil ||
		job.Software.Package != "jq" || job.Software.Manager != "system" || job.ArgCount != 2 {
		t.Errorf("job %+v", job)
	}

	poll, err := ac.Poll(ctx, nil)
	if err != nil || len(poll.Jobs) != 1 {
		t.Fatalf("poll %+v %v", poll, err)
	}
	p, err := agentproto.VerifyJob(jobKey, poll.Jobs[0], device, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.Shell != agentproto.ShellSh || !slices.Equal(p.Args, []string{"install", "jq"}) || !strings.Contains(p.Script, "apt-get") || strings.Contains(p.Script, "jq") {
		t.Errorf("payload: shell %s, args %q", p.Shell, p.Args)
	}

	var list struct {
		Items []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"items"`
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/jobs?kind=software&deviceId="+device, nil, &list)
	if len(list.Items) != 1 || list.Items[0].ID != job.ID {
		t.Errorf("software jobs %+v", list.Items)
	}
	tech.expect(http.StatusOK, "GET", "/api/v1/jobs?kind=script", nil, &list)
	if len(list.Items) != 0 {
		t.Errorf("script jobs %+v", list.Items)
	}
	wantStatus(t, tech.do("GET", "/api/v1/jobs?kind=patch", nil), http.StatusUnprocessableEntity, "validation_failed")
}
