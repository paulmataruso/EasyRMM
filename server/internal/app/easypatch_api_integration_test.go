//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// engineHarness starts EasyRMM with the patching engine in its deployment.
func engineHarness(t *testing.T) (*eptest.Server, *harness) {
	t.Helper()
	key := bytes.Repeat([]byte{6}, 32)
	ep := eptest.NewEngine(t, key)
	return ep, newHarnessWith(t, false, func(c *config.Config) { c.Patching = config.Patching{URL: ep.URL(), Key: key} })
}

// engineOrgNamed is the engine's organization of that name.
func engineOrgNamed(t *testing.T, ep *eptest.Server, name string) uuid.UUID {
	t.Helper()
	for _, o := range ep.Organizations() {
		if o.Name == name {
			return o.ID
		}
	}
	t.Fatalf("the engine has no organization %q: %+v", name, ep.Organizations())
	return uuid.Nil
}

// TestEasyPatchAPI: EasyRMM links an organization and a device to the
// patching engine in its deployment, and patches the device through the
// console API (ADR-0030, ADR-0040).
func TestEasyPatchAPI(t *testing.T) {
	ep, h := engineHarness(t)
	admin, _ := setUp(t, h)
	ctx := context.Background()
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Patch", "expiresInDays": 1}, &token)
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts("web-01"))
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	if _, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("web-01")}); err != nil {
		t.Fatal(err)
	}
	device := enr.DeviceID

	// Settings shows the engine; nothing there changes it.
	var conn struct {
		Configured    bool   `json:"configured"`
		ServerVersion string `json:"serverVersion"`
		LastError     string `json:"lastError"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch", nil, &conn)
	if !conn.Configured || conn.ServerVersion != eptest.EngineVersion {
		t.Fatalf("settings: %+v", conn)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/settings/easypatch/check", nil, &conn)
	if conn.LastError != "" {
		t.Fatalf("check: %+v", conn)
	}
	for _, c := range []struct{ method, path string }{
		{"PUT", "/api/v1/settings/easypatch"}, {"DELETE", "/api/v1/settings/easypatch"},
		{"PUT", "/api/v1/settings/easypatch/organizations/" + acme}, {"DELETE", "/api/v1/settings/easypatch/organizations/" + acme},
	} {
		wantStatus(t, admin.do(c.method, c.path, map[string]string{}), http.StatusNotFound, "not_found")
	}

	// EasyRMM creates Acme and its site in the engine; web-01's EasyPatch
	// agent enrolls there.
	if res, err := h.deps.EasyPatch.Reconcile(ctx); err != nil || len(res.Problems) != 0 {
		t.Fatalf("reconcile: %+v, %v", res, err)
	}
	epOrg := engineOrgNamed(t, ep, "Acme")
	endpoint := ep.AddEndpoint(epOrg, "web-01", "S-1", "1FBB-E2EA-533D-A960")
	type link struct {
		OrganizationName string `json:"organizationName"`
		EasyPatchName    string `json:"easyPatchName"`
		Devices          struct {
			Linked int `json:"linked"`
		} `json:"devices"`
	}
	var orgs struct {
		Links []link `json:"links"`
	}
	acmeLink := func() link {
		t.Helper()
		admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch/organizations", nil, &orgs)
		for _, l := range orgs.Links {
			if l.OrganizationName == "Acme" {
				return l
			}
		}
		t.Fatalf("Acme is not linked: %+v", orgs)
		return link{}
	}
	if l := acmeLink(); l.EasyPatchName != "Acme" || l.Devices.Linked != 0 {
		t.Fatalf("Acme's link: %+v", l)
	}

	// The agent reports its EasyPatch agent; the link is checked.
	body, _ := json.Marshal(agentproto.Inventory{
		System: agentproto.SystemInfo{Serial: "S-1"},
		EasyPatch: &agentproto.EasyPatchAgent{Version: "1.9.0", Status: "Active", ServerURL: "https://patch.example.com/",
			EndpointID: endpoint.ID.String(), KeyFingerprint: endpoint.Fingerprint},
	})
	if _, err := ac.Inventory(ctx, body); err != nil {
		t.Fatal(err)
	}
	if n, err := h.deps.EasyPatch.SyncLinks(ctx); n != 1 || err != nil {
		t.Fatalf("sync: %d %v", n, err)
	}
	if l := acmeLink(); l.Devices.Linked != 1 {
		t.Fatalf("Acme's link with web-01: %+v", l)
	}
	var problems struct {
		Items []any `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch/devices", nil, &problems)
	if problems.Items == nil || len(problems.Items) != 0 {
		t.Fatalf("problems: %+v", problems)
	}

	// Patching.
	var status struct {
		Configured bool
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching", nil, &status)
	if !status.Configured {
		t.Fatalf("status: %+v", status)
	}
	var fleet struct {
		Devices []struct {
			DeviceID string `json:"deviceId"`
			Link     string `json:"link"`
			Endpoint *struct {
				ComplianceStatus string `json:"complianceStatus"`
			} `json:"endpoint"`
		} `json:"devices"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/devices?organizationId="+acme+"&siteId="+hq.ID+"&compliance=MissingUpdates&q=web", nil, &fleet)
	if len(fleet.Devices) != 1 || fleet.Devices[0].DeviceID != device || fleet.Devices[0].Link != "linked" || fleet.Devices[0].Endpoint == nil {
		t.Fatalf("fleet: %+v", fleet)
	}
	for _, q := range []string{"organizationId=x", "siteId=x", "groupId=x", "compliance=Great"} {
		wantStatus(t, admin.do("GET", "/api/v1/patching/devices?"+q, nil), http.StatusUnprocessableEntity, "validation_failed")
	}
	var dev struct {
		Link     string `json:"link"`
		Endpoint struct {
			SerialNumber string `json:"serialNumber"`
		} `json:"endpoint"`
		Policy struct {
			TimeZone string `json:"timeZone"`
		} `json:"policy"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/devices/"+device, nil, &dev)
	if dev.Link != "linked" || dev.Endpoint.SerialNumber != "S-1" || dev.Policy.TimeZone != "Europe/Paris" {
		t.Fatalf("device: %+v", dev)
	}
	var items struct {
		Items []map[string]any `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/devices/"+device+"/updates?state=Failed", nil, &items)
	if len(items.Items) != 1 || items.Items[0]["state"] != "Failed" {
		t.Fatalf("updates: %+v", items)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/devices/"+device+"/installed", nil, &items)
	if len(items.Items) != 1 {
		t.Fatalf("installed: %+v", items)
	}
	var page struct {
		Items      []map[string]any `json:"items"`
		TotalCount int              `json:"totalCount"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/devices/"+device+"/history?page=1", nil, &page)
	if page.TotalCount != 1 {
		t.Fatalf("history: %+v", page)
	}
	wantStatus(t, admin.do("GET", "/api/v1/patching/devices/"+device+"/history?page=0", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/patching/devices/"+device+"/jobs?page=x", nil), http.StatusUnprocessableEntity, "validation_failed")
	for _, p := range []string{"", "/updates", "/installed", "/history", "/jobs"} {
		wantStatus(t, admin.do("GET", "/api/v1/patching/devices/nope"+p, nil), http.StatusNotFound, "not_found")
	}

	var res struct {
		Succeeded int `json:"succeeded"`
		Results   []struct {
			JobID string `json:"jobId"`
		} `json:"results"`
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/scan", map[string]any{"deviceIds": []string{device}}, &res)
	if res.Succeeded != 1 || res.Results[0].JobID == "" {
		t.Fatalf("scan: %+v", res)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/install", map[string]any{"deviceIds": []string{device}}, &res)
	if res.Succeeded != 1 {
		t.Fatalf("install: %+v", res)
	}
	// A time in the past.
	wantStatus(t, admin.do("POST", "/api/v1/patching/install", map[string]any{"deviceIds": []string{device}, "scheduledAt": "2020-12-01T02:00:00Z"}),
		http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", "/api/v1/patching/scan", map[string]any{"deviceIds": "x"}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("POST", "/api/v1/patching/install", "x"), http.StatusBadRequest, "bad_request")
	page.Items = nil
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/devices/"+device+"/jobs", nil, &page)
	if page.TotalCount != 2 {
		t.Fatalf("device jobs: %+v", page)
	}

	var jobs struct {
		Items []struct {
			ID         string `json:"id"`
			DeviceName string `json:"deviceName"`
			Status     string `json:"status"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/jobs?active=true&organizationId="+acme, nil, &jobs)
	if len(jobs.Items) != 2 || jobs.Items[0].DeviceName != "web-01" {
		t.Fatalf("jobs: %+v", jobs)
	}
	wantStatus(t, admin.do("GET", "/api/v1/patching/jobs?active=maybe", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/patching/jobs?organizationId=x", nil), http.StatusUnprocessableEntity, "validation_failed")
	// Filters: by device, type and when it was created.
	var filtered struct {
		Items []struct {
			Type string `json:"type"`
		} `json:"items"`
		Capped bool `json:"capped"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/jobs?deviceId="+device+"&type=UpdateScan&from=2020-01-01T00:00:00Z", nil, &filtered)
	if len(filtered.Items) == 0 || filtered.Capped {
		t.Fatalf("filtered jobs: %+v", filtered)
	}
	for _, j := range filtered.Items {
		if j.Type != "UpdateScan" {
			t.Fatalf("filtered jobs: %+v", filtered)
		}
	}
	for _, q := range []string{"from=yesterday", "to=2026-13-01T00:00:00Z", "status=Done", "type=Reboot", "trigger=Cron", "deviceId=x",
		"from=2026-11-02T00:00:00Z&to=2026-11-01T00:00:00Z"} {
		wantStatus(t, admin.do("GET", "/api/v1/patching/jobs?"+q, nil), http.StatusUnprocessableEntity, "validation_failed")
	}
	var job struct {
		Summary struct {
			Status string `json:"status"`
		} `json:"summary"`
		DeviceName string `json:"deviceName"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/jobs/"+jobs.Items[0].ID, nil, &job)
	if job.DeviceName != "web-01" || job.Summary.Status != "Queued" {
		t.Fatalf("job: %+v", job)
	}
	wantStatus(t, admin.do("GET", "/api/v1/patching/jobs/nope", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", "/api/v1/patching/jobs/nope/cancel", nil), http.StatusNotFound, "not_found")
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/jobs/"+jobs.Items[0].ID+"/cancel", nil, &job)
	if job.Summary.Status != eptest.StatusCanceled {
		t.Fatalf("cancel: %+v", job)
	}

	// Retry: a finished job runs again, as a new one.
	var retried struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		DeviceName string `json:"deviceName"`
	}
	wantStatus(t, admin.do("POST", "/api/v1/patching/jobs/nope/retry", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", "/api/v1/patching/jobs/"+jobs.Items[1].ID+"/retry", nil), http.StatusConflict, "invalid_state")
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/jobs/"+jobs.Items[0].ID+"/retry", nil, &retried)
	if retried.ID == jobs.Items[0].ID || retried.Status != "Queued" || retried.DeviceName != "web-01" {
		t.Fatalf("retry: %+v", retried)
	}

	// Restart: a server must be confirmed by name.
	ep.Set(func() { endpoint.RebootPending, endpoint.IsServer = true, true })
	var plan struct {
		Devices []struct {
			DeviceName string `json:"deviceName"`
			Restart    bool   `json:"restart"`
			Server     bool   `json:"server"`
		} `json:"devices"`
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/restart/plan", map[string]any{"deviceIds": []string{device}}, &plan)
	if len(plan.Devices) != 1 || !plan.Devices[0].Restart || !plan.Devices[0].Server || plan.Devices[0].DeviceName != "web-01" {
		t.Fatalf("restart plan: %+v", plan)
	}
	r := admin.do("POST", "/api/v1/patching/restart", map[string]any{"deviceIds": []string{device}})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
	if !strings.Contains(string(r.body), "confirm restarting them: web-01.") {
		t.Fatalf("unconfirmed restart: %s", r.body)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/restart", map[string]any{"deviceIds": []string{device}, "confirmServers": []string{device}}, &res)
	if res.Succeeded != 1 || res.Results[0].JobID == "" {
		t.Fatalf("restart: %+v", res)
	}
	wantStatus(t, admin.do("POST", "/api/v1/patching/restart", map[string]any{"deviceIds": []string{device}, "scheduledAt": "2026-01-01T00:00:00Z"}),
		http.StatusUnprocessableEntity, "validation_failed")
	// How users are asked, and whether a restart need be pending.
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/restart", map[string]any{"deviceIds": []string{device}, "confirmServers": []string{device},
		"mode": "PromptWithDeadline", "deadlineMinutes": 120, "expiresAfterMinutes": 60}, &res)
	if res.Succeeded != 1 {
		t.Fatalf("restart with a deadline: %+v", res)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/restart/plan", map[string]any{"deviceIds": []string{device}, "condition": "Always"}, &plan)
	if !plan.Devices[0].Restart {
		t.Fatalf("restart plan, always: %+v", plan)
	}
	for _, bad := range []map[string]any{{"mode": "Reboot"}, {"condition": "Sometimes"}, {"countdownMinutes": 0}, {"mode": "PromptWithDeadline", "deadlineMinutes": 5},
		{"expiresAfterMinutes": 2000}} {
		bad["deviceIds"], bad["confirmServers"] = []string{device}, []string{device}
		wantStatus(t, admin.do("POST", "/api/v1/patching/restart", bad), http.StatusUnprocessableEntity, "validation_failed")
	}
	wantStatus(t, admin.do("POST", "/api/v1/patching/restart/plan", map[string]any{"deviceIds": []string{device}, "condition": "Sometimes"}),
		http.StatusUnprocessableEntity, "validation_failed")

	// The device's Patches tab. web-01 is a Linux endpoint: EasyPatch refuses
	// messages and removals there.
	var guid string
	ep.Set(func() { guid = endpoint.Updates[0]["updateGuid"].(uuid.UUID).String() })
	dp := "/api/v1/patching/devices/" + device

	// Requests refused before EasyPatch is asked: a body that is not an
	// object, an id that is not one, a scope that is not one.
	notObject := []int{1}
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/patching/restart/plan"}, {"POST", "/api/v1/patching/restart"}, {"POST", "/api/v1/patching/stop"},
		{"POST", "/api/v1/patching/allow"}, {"POST", dp + "/exclusions"}, {"POST", dp + "/updates/" + guid + "/remove"},
		{"POST", "/api/v1/patching/notify"}, {"POST", "/api/v1/patching/agent-update"},
		{"POST", "/api/v1/patching/updates/" + guid + "/remove"}, {"POST", "/api/v1/patching/updates/" + guid + "/holds"},
	} {
		if r := admin.do(c.method, c.path, notObject); r.status != http.StatusBadRequest && r.status != http.StatusUnprocessableEntity {
			t.Errorf("%s %s with an array: %d %s", c.method, c.path, r.status, r.body)
		}
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/patching/devices/nope/install-preview"}, {"POST", "/api/v1/patching/devices/nope/exclusions"},
		{"DELETE", "/api/v1/patching/devices/nope/exclusions/" + guid}, {"POST", "/api/v1/patching/devices/nope/updates/" + guid + "/remove"},
		{"GET", "/api/v1/patching/updates/nope"}, {"GET", "/api/v1/patching/updates/nope/devices"},
		{"POST", "/api/v1/patching/updates/nope/remove"}, {"POST", "/api/v1/patching/updates/nope/holds"},
		{"POST", "/api/v1/patching/updates/nope/holds/" + guid + "/release"},
	} {
		if r := admin.do(c.method, c.path, map[string]any{}); r.status != http.StatusNotFound && r.status != http.StatusUnprocessableEntity {
			t.Errorf("%s %s: %d %s", c.method, c.path, r.status, r.body)
		}
	}
	for _, path := range []string{"/api/v1/patching/updates/" + guid + "?organizationId=x", "/api/v1/patching/updates/" + guid + "/devices?siteId=x"} {
		wantStatus(t, admin.do("GET", path, nil), http.StatusUnprocessableEntity, "validation_failed")
	}
	var exploited struct {
		Items []map[string]any `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/updates?knownExploited=true&organizationId="+acme, nil, &exploited)

	admin.expect(http.StatusNoContent, "POST", dp+"/exclusions", map[string]any{"updateId": guid, "reason": "breaks printing"}, nil)
	wantStatus(t, admin.do("POST", dp+"/exclusions", map[string]any{}), http.StatusUnprocessableEntity, "validation_failed")
	var preview struct {
		Mode    string           `json:"mode"`
		Items   []map[string]any `json:"items"`
		Skipped []map[string]any `json:"skipped"`
	}
	admin.expect(http.StatusOK, "GET", dp+"/install-preview?updateId="+guid, nil, &preview)
	if preview.Mode != "Selected" || len(preview.Items) != 0 || len(preview.Skipped) != 1 || preview.Skipped[0]["reason"] != "Excluded" {
		t.Fatalf("preview of the excluded update: %+v", preview)
	}
	wantStatus(t, admin.do("GET", dp+"/install-preview?updateId=x", nil), http.StatusUnprocessableEntity, "validation_failed")
	admin.expect(http.StatusNoContent, "DELETE", dp+"/exclusions/"+guid, nil, nil)
	wantStatus(t, admin.do("DELETE", dp+"/exclusions/nope", nil), http.StatusNotFound, "not_found")
	admin.expect(http.StatusOK, "GET", dp+"/install-preview", nil, &preview)
	if preview.Mode != "AllEligible" || len(preview.Items) != 2 || len(preview.Skipped) != 0 {
		t.Fatalf("preview: %+v", preview)
	}
	var refused struct {
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
		Results   []struct {
			Message string `json:"message"`
		} `json:"results"`
	}
	admin.expect(http.StatusOK, "POST", dp+"/updates/"+guid+"/remove", map[string]any{"block": true}, &refused)
	if refused.Failed != 1 || !strings.Contains(refused.Results[0].Message, "Removing updates is only available on Windows") {
		t.Fatalf("removal on Linux: %+v", refused)
	}
	wantStatus(t, admin.do("POST", dp+"/updates/nope/remove", map[string]any{}), http.StatusNotFound, "not_found")
	var presets struct {
		Items []struct {
			Preset           string `json:"preset"`
			NeedsRestartTime bool   `json:"needsRestartTime"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/messages", nil, &presets)
	if len(presets.Items) != 6 || presets.Items[5].Preset != "RestartScheduled" || !presets.Items[5].NeedsRestartTime {
		t.Fatalf("presets: %+v", presets)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/notify", map[string]any{"deviceIds": []string{device}, "preset": "SaveYourWork"}, &refused)
	if refused.Failed != 1 || !strings.Contains(refused.Results[0].Message, "Messages to users are only available on Windows") {
		t.Fatalf("message on Linux: %+v", refused)
	}
	wantStatus(t, admin.do("POST", "/api/v1/patching/notify", map[string]any{"deviceIds": []string{device}, "preset": "Hello"}),
		http.StatusUnprocessableEntity, "validation_failed")
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/agent-update", map[string]any{"deviceIds": []string{device}}, &res)
	if res.Succeeded != 1 || res.Results[0].JobID == "" {
		t.Fatalf("agent update: %+v", res)
	}

	// Patching → Updates: the catalog, an update's page and devices,
	// installing and removing it, and holds.
	var catalog struct {
		Items []struct {
			UpdateGUID   string `json:"updateGuid"`
			MissingCount int    `json:"missingCount"`
			OnHold       bool   `json:"onHold"`
		} `json:"items"`
		PageSize int `json:"pageSize"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/updates?category=Security&sort=missing&dir=desc&q=openssl", nil, &catalog)
	if len(catalog.Items) != 1 || catalog.Items[0].MissingCount != 1 || catalog.PageSize != 50 {
		t.Fatalf("catalog: %+v", catalog)
	}
	openssl := catalog.Items[0].UpdateGUID
	for _, q := range []string{"category=Firmware", "state=Gone", "sort=title", "knownExploited=maybe", "page=0", "organizationId=x", "siteId=x"} {
		wantStatus(t, admin.do("GET", "/api/v1/patching/updates?"+q, nil), http.StatusUnprocessableEntity, "validation_failed")
	}
	var update struct {
		Summary struct {
			MissingCount int `json:"missingCount"`
		} `json:"summary"`
		Vulnerabilities []map[string]any `json:"vulnerabilities"`
		Holds           []map[string]any `json:"holds"`
		CanManage       bool             `json:"canManage"`
		CanHold         bool             `json:"canHold"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/updates/"+openssl+"?organizationId="+acme, nil, &update)
	if update.Summary.MissingCount != 1 || len(update.Vulnerabilities) != 1 || update.Holds == nil || !update.CanManage || !update.CanHold {
		t.Fatalf("update: %+v", update)
	}
	wantStatus(t, admin.do("GET", "/api/v1/patching/updates/nope", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("GET", "/api/v1/patching/updates/"+uuid.NewString(), nil), http.StatusNotFound, "not_found")
	var updateDevices struct {
		Items []struct {
			DeviceID   *string `json:"deviceId"`
			DeviceName string  `json:"deviceName"`
			State      string  `json:"state"`
		} `json:"items"`
		TotalCount int `json:"totalCount"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/updates/"+openssl+"/devices?state=Missing", nil, &updateDevices)
	if updateDevices.TotalCount != 1 || updateDevices.Items[0].DeviceID == nil || *updateDevices.Items[0].DeviceID != device ||
		updateDevices.Items[0].DeviceName != "web-01" {
		t.Fatalf("update's devices: %+v", updateDevices)
	}
	wantStatus(t, admin.do("GET", "/api/v1/patching/updates/"+openssl+"/devices?state=Gone", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", "/api/v1/patching/updates/"+openssl+"/devices?page=x", nil), http.StatusUnprocessableEntity, "validation_failed")
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/updates/"+openssl+"/install", map[string]any{"deviceIds": []string{device}}, &res)
	if res.Succeeded != 1 || res.Results[0].JobID == "" {
		t.Fatalf("install the update: %+v", res)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/updates/"+openssl+"/install", map[string]any{"all": true}, &res)
	if res.Succeeded != 1 {
		t.Fatalf("install the update everywhere: %+v", res)
	}
	wantStatus(t, admin.do("POST", "/api/v1/patching/updates/"+openssl+"/install", "x"), http.StatusBadRequest, "bad_request")
	wantStatus(t, admin.do("POST", "/api/v1/patching/updates/nope/install", map[string]any{"all": true}), http.StatusNotFound, "not_found")
	var libc6 string
	ep.Set(func() { libc6 = endpoint.InstalledItems[0]["updateGuid"].(uuid.UUID).String() })
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/updates/"+libc6+"/remove", map[string]any{"all": true, "block": true, "reason": "Breaks printing"},
		&refused)
	if refused.Failed != 1 || !strings.Contains(refused.Results[0].Message, "Removing updates is only available on Windows") {
		t.Fatalf("removal from every device on Linux: %+v", refused)
	}
	var hold struct {
		ID               string `json:"id"`
		OrganizationID   string `json:"organizationId"`
		OrganizationName string `json:"organizationName"`
		CanRelease       bool   `json:"canRelease"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/patching/updates/"+openssl+"/holds", map[string]any{"organizationId": acme, "reason": "Breaks printing"}, &hold)
	if hold.OrganizationID != acme || hold.OrganizationName != "Acme" || !hold.CanRelease {
		t.Fatalf("hold: %+v", hold)
	}
	wantStatus(t, admin.do("POST", "/api/v1/patching/updates/"+openssl+"/holds", map[string]any{"organizationId": acme, "reason": "Again"}),
		http.StatusConflict, "already_held")
	wantStatus(t, admin.do("POST", "/api/v1/patching/updates/"+openssl+"/holds", map[string]any{"organizationId": acme}),
		http.StatusUnprocessableEntity, "validation_failed")
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/updates?q=openssl", nil, &catalog)
	if len(catalog.Items) != 1 || !catalog.Items[0].OnHold {
		t.Fatalf("held in the catalog: %+v", catalog)
	}

	// Retired with the product switch and its links into EasyPatch's console
	// (ADR-0046): no API route answers.
	wantStatus(t, admin.do("GET", "/api/v1/patching/switch", nil), http.StatusNotFound, "")

	// A read-only user sees patching but cannot act, nor reach Settings.
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")
	viewer.expect(http.StatusOK, "GET", "/api/v1/patching/devices", nil, &fleet)
	if len(fleet.Devices) != 1 {
		t.Fatalf("viewer fleet: %+v", fleet)
	}
	wantStatus(t, viewer.do("POST", "/api/v1/patching/scan", map[string]any{"deviceIds": []string{device}}), http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("POST", "/api/v1/patching/jobs/"+jobs.Items[1].ID+"/cancel", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("POST", "/api/v1/patching/jobs/"+jobs.Items[0].ID+"/retry", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("POST", "/api/v1/patching/restart/plan", map[string]any{"deviceIds": []string{device}}), http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("POST", "/api/v1/patching/restart", map[string]any{"deviceIds": []string{device}, "confirmServers": []string{device}}),
		http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("POST", "/api/v1/patching/devices/"+device+"/exclusions", map[string]any{"updateId": guid}), http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("DELETE", "/api/v1/patching/devices/"+device+"/exclusions/"+guid, nil), http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("POST", "/api/v1/patching/devices/"+device+"/updates/"+guid+"/remove", map[string]any{}), http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("POST", "/api/v1/patching/notify", map[string]any{"deviceIds": []string{device}, "preset": "SaveYourWork"}),
		http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("POST", "/api/v1/patching/agent-update", map[string]any{"deviceIds": []string{device}}), http.StatusForbidden, "forbidden")
	viewer.expect(http.StatusOK, "GET", "/api/v1/patching/updates", nil, &catalog)
	viewer.expect(http.StatusOK, "GET", "/api/v1/patching/updates/"+openssl, nil, &update)
	if update.CanManage || update.CanHold || len(update.Holds) != 1 || update.Holds[0]["canRelease"] != false {
		t.Fatalf("the viewer's update: %+v", update)
	}
	for _, body := range []map[string]any{{"deviceIds": []string{device}}, {"all": true}} {
		wantStatus(t, viewer.do("POST", "/api/v1/patching/updates/"+openssl+"/install", body), http.StatusForbidden, "forbidden")
		wantStatus(t, viewer.do("POST", "/api/v1/patching/updates/"+libc6+"/remove", body), http.StatusForbidden, "forbidden")
	}
	wantStatus(t, viewer.do("POST", "/api/v1/patching/updates/"+openssl+"/holds", map[string]any{"organizationId": acme, "reason": "Mine"}),
		http.StatusForbidden, "forbidden")
	release := "/api/v1/patching/updates/" + openssl + "/holds/" + hold.ID + "/release"
	wantStatus(t, viewer.do("POST", release, nil), http.StatusForbidden, "forbidden")
	admin.expect(http.StatusOK, "POST", release, nil, &hold)
	if hold.CanRelease {
		t.Fatalf("released: %+v", hold)
	}
	wantStatus(t, admin.do("POST", release, nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", "/api/v1/patching/updates/"+openssl+"/holds/nope/release", nil), http.StatusNotFound, "not_found")
	viewer.expect(http.StatusOK, "GET", "/api/v1/patching/devices/"+device+"/install-preview", nil, &preview)
	viewer.expect(http.StatusOK, "GET", "/api/v1/patching/messages", nil, &presets)
	wantStatus(t, viewer.do("GET", "/api/v1/settings/easypatch", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("GET", "/api/v1/settings/easypatch/organizations", nil), http.StatusForbidden, "forbidden")
	wantStatus(t, h.client().do("GET", "/api/v1/patching", nil), http.StatusUnauthorized, "")

	// Links from EasyPatch: its ids, resolved against EasyRMM's link tables and the caller's permissions.
	type landing struct {
		Path   string `json:"path"`
		Notice string `json:"notice"`
	}
	from := func(c *client, kind, id string) landing {
		t.Helper()
		var l landing
		c.expect(http.StatusOK, "GET", "/api/v1/patching/from-easypatch/"+kind+"/"+id, nil, &l)
		return l
	}
	for _, c := range []struct {
		kind, id string
		want     landing
	}{
		{"endpoints", endpoint.ID.String(), landing{Path: "/devices/" + device + "?tab=patches"}},
		{"organizations", epOrg.String(), landing{Path: "/organizations/" + acme}},
		{"alerts", epOrg.String(), landing{Path: "/patching?tab=alerts&organizationId=" + acme}},
		{"alerts", uuid.NewString(), landing{Path: "/patching?tab=alerts", Notice: "That patching engine organization is not linked to an EasyRMM organization you can see."}},
		{"jobs", jobs.Items[0].ID, landing{Path: "/patching?tab=jobs&job=" + jobs.Items[0].ID}},
		{"endpoints", uuid.NewString(), landing{Path: "/patching", Notice: "That patching engine endpoint is not linked to an EasyRMM device you can see."}},
		{"organizations", uuid.NewString(), landing{Path: "/patching", Notice: "That patching engine organization is not linked to an EasyRMM organization you can see."}},
	} {
		if got := from(viewer, c.kind, c.id); got != c.want {
			t.Errorf("from EasyPatch %s/%s: %+v, want %+v", c.kind, c.id, got, c.want)
		}
	}
	wantStatus(t, viewer.do("GET", "/api/v1/patching/from-easypatch/updates/"+uuid.NewString(), nil), http.StatusNotFound, "not_found")
	wantStatus(t, viewer.do("GET", "/api/v1/patching/from-easypatch/endpoints/nope", nil), http.StatusNotFound, "not_found")
	wantStatus(t, h.client().do("GET", "/api/v1/patching/from-easypatch/endpoints/"+endpoint.ID.String(), nil), http.StatusUnauthorized, "")
	// Someone patching another organization learns nothing about Acme's.
	var globex idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]any{"name": "Globex"}, &globex)
	invite(t, h, admin, "gil@globex.example", []map[string]any{{"role": "technician", "organizationId": globex.ID}})
	gil := h.client()
	gil.signIn("gil@globex.example", "a long and unusual passphrase", "")
	if l := from(gil, "endpoints", endpoint.ID.String()); l.Path != "/patching" || l.Notice == "" {
		t.Errorf("another organization's endpoint: %+v", l)
	}
	if l := from(gil, "organizations", epOrg.String()); l.Path != "/patching" || l.Notice == "" {
		t.Errorf("another organization: %+v", l)
	}

	var audit struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=patch", nil, &audit)
	got := []string{}
	for _, a := range audit.Items {
		got = append(got, a.Action)
	}
	if strings.Join(got, ",") != "patch.release_hold,patch.hold,patch.install,patch.install,patch.agent_update,patch.include,patch.exclude,"+
		"patch.restart,patch.restart,patch.retry,patch.cancel,patch.install,patch.scan" {
		t.Fatalf("patch audit: %v", got)
	}

	// Policies at every level, and tags.
	type policyView struct {
		Name    string `json:"name"`
		HasOwn  bool   `json:"hasOwn"`
		CanEdit bool   `json:"canEdit"`
		Own     struct {
			ScanIntervalMinutes *int `json:"scanIntervalMinutes"`
			InstallDelayDays    *int `json:"installDelayDays"`
		} `json:"own"`
		Inherited struct {
			ScanIntervalMinutes *int `json:"scanIntervalMinutes"`
		} `json:"inherited"`
		InheritedFrom map[string]string `json:"inheritedFrom"`
	}
	var pol policyView
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/policies/default", nil, &pol)
	if !pol.CanEdit || !pol.HasOwn || pol.Own.ScanIntervalMinutes == nil || *pol.Own.ScanIntervalMinutes != 360 {
		t.Fatalf("default policy: %+v", pol)
	}
	admin.expect(http.StatusOK, "PUT", "/api/v1/patching/policies/default", map[string]any{"scanIntervalMinutes": 360, "installDelayDays": 1}, &pol)
	if !pol.HasOwn || *pol.Own.ScanIntervalMinutes != 360 || *pol.Own.InstallDelayDays != 1 {
		t.Fatalf("saved the default policy: %+v", pol)
	}
	wantStatus(t, viewer.do("PUT", "/api/v1/patching/policies/default", map[string]any{}), http.StatusForbidden, "forbidden")
	var tag idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/patching/tags", map[string]any{"name": "Ring 1", "color": "blue", "priority": 10}, &tag)
	admin.expect(http.StatusOK, "PUT", "/api/v1/patching/tags/"+tag.ID, map[string]any{"name": "Ring 2", "color": "teal", "priority": 20}, nil)
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/policies/tag/"+tag.ID, nil, &pol)
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/patching/tags/"+tag.ID, nil, nil)
	orgPolicy := "/api/v1/patching/policies/organization/" + acme
	viewer.expect(http.StatusOK, "GET", orgPolicy, nil, &pol)
	if pol.HasOwn || pol.CanEdit || *pol.Inherited.ScanIntervalMinutes != 360 || pol.InheritedFrom["scanIntervalMinutes"] != "Default policy" {
		t.Fatalf("Acme's policy for a reader: %+v", pol)
	}
	pol = policyView{}
	admin.expect(http.StatusOK, "PUT", orgPolicy, map[string]any{"installDelayDays": 2}, &pol)
	if !pol.HasOwn || !pol.CanEdit || *pol.Own.InstallDelayDays != 2 {
		t.Fatalf("saved Acme's policy: %+v", pol)
	}
	wantStatus(t, admin.do("PUT", orgPolicy, map[string]any{"installDelayDays": 400}), http.StatusUnprocessableEntity, "validation_failed")
	admin.expect(http.StatusOK, "DELETE", orgPolicy, nil, &pol)
	if pol.HasOwn {
		t.Fatalf("reset Acme's policy: %+v", pol)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/policies/device/"+device, nil, &pol)
	if pol.Name != "web-01" || pol.InheritedFrom["scanIntervalMinutes"] != "Default policy" {
		t.Fatalf("web-01's policy: %+v", pol)
	}
	for _, path := range []string{"/api/v1/patching/policies/group/" + acme, "/api/v1/patching/policies/organization/nope",
		"/api/v1/patching/policies/default/" + acme, "/api/v1/patching/tags/of/group/" + acme} {
		wantStatus(t, admin.do("GET", path, nil), http.StatusNotFound, "not_found")
	}

	ring := ep.AddTag("Ring 0", "teal", 10).String()
	wantStatus(t, viewer.do("POST", "/api/v1/patching/tags", map[string]any{"name": "Ring 2", "color": "blue"}), http.StatusForbidden, "forbidden")
	var tags struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
		CanManage bool `json:"canManage"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/tags", nil, &tags)
	if len(tags.Items) != 1 || tags.Items[0].Name != "Ring 0" || !tags.CanManage {
		t.Fatalf("tags: %+v", tags)
	}
	var assigned struct {
		Tags []struct {
			Name          string `json:"name"`
			InheritedFrom string `json:"inheritedFrom"`
		} `json:"tags"`
		CanAssign bool `json:"canAssign"`
	}
	admin.expect(http.StatusOK, "PUT", "/api/v1/patching/tags/of/organization/"+acme, map[string]any{"tagIds": []string{ring}}, &assigned)
	if len(assigned.Tags) != 1 || !assigned.CanAssign {
		t.Fatalf("Acme's tags: %+v", assigned)
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/patching/tags/of/device/"+device, nil, &assigned)
	if len(assigned.Tags) != 1 || assigned.Tags[0].InheritedFrom != "Organization" || assigned.CanAssign {
		t.Fatalf("web-01's tags: %+v", assigned)
	}
	for _, c := range []struct{ method, path string }{
		{"PUT", "/api/v1/patching/policies/default"}, {"PUT", orgPolicy}, {"POST", "/api/v1/patching/tags"},
		{"PUT", "/api/v1/patching/tags/" + ring}, {"PUT", "/api/v1/patching/tags/of/organization/" + acme},
	} {
		if r := admin.do(c.method, c.path, notObject); r.status != http.StatusBadRequest && r.status != http.StatusUnprocessableEntity {
			t.Errorf("%s %s with an array: %d %s", c.method, c.path, r.status, r.body)
		}
	}
	for _, c := range []struct{ method, path string }{
		{"PUT", "/api/v1/patching/tags/nope"}, {"DELETE", "/api/v1/patching/tags/nope"}, {"PUT", "/api/v1/patching/tags/of/organization/nope"},
		{"PUT", "/api/v1/patching/policies/organization/nope"}, {"DELETE", "/api/v1/patching/policies/organization/nope"},
	} {
		wantStatus(t, admin.do(c.method, c.path, map[string]any{}), http.StatusNotFound, "not_found")
	}
	admin.expect(http.StatusOK, "PUT", "/api/v1/patching/tags/of/organization/"+acme, map[string]any{"tagIds": []string{}}, &assigned)
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=patch", nil, &audit)
	got = []string{}
	for _, a := range audit.Items[:4] {
		got = append(got, a.Action)
	}
	if strings.Join(got, ",") != "patch.tag_assign,patch.tag_assign,patch.policy_reset,patch.policy_update" {
		t.Errorf("policy and tag audit: %v", got)
	}

	// Patch reports.
	now := time.Now().UTC()
	ep.SetTrend(epOrg, eptest.TrendDay{Date: now.Format(time.DateOnly), Total: 2, Compliant: 1})
	ep.AddInstallation(endpoint, eptest.InstallationInfo{Title: "2026-11 Cumulative Update", KB: "KB5070001", CompletedAt: now.Add(-time.Hour)})
	var trend struct {
		Points []struct {
			Date              string  `json:"date"`
			CompliancePercent float64 `json:"compliancePercent"`
		} `json:"points"`
		Organizations int `json:"organizations"`
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/patching/reports/trend?days=7&organizationId="+acme, nil, &trend)
	if trend.Organizations != 1 || len(trend.Points) != 1 || trend.Points[0].CompliancePercent != 50 {
		t.Fatalf("trend: %+v", trend)
	}
	wantStatus(t, viewer.do("GET", "/api/v1/patching/reports/trend?days=3", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, viewer.do("GET", "/api/v1/patching/reports/trend?organizationId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	var report struct {
		Total int     `json:"total"`
		Rows  [][]any `json:"rows"`
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/reports/patch-compliance?q=web", nil, &report)
	if report.Total != 1 || report.Rows[0][2] != "web-01" {
		t.Fatalf("compliance report: %+v", report)
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/reports/patch-installations?result=Succeeded&days=7", nil, &report)
	if report.Total != 1 || report.Rows[0][4] != "KB5070001" {
		t.Fatalf("installations report: %+v", report)
	}
	if r := viewer.do("GET", "/api/v1/reports/patch-installations/csv", nil); r.status != http.StatusOK || !strings.Contains(string(r.body), "KB5070001") {
		t.Fatalf("installations CSV: %d %s", r.status, r.body)
	}
	wantStatus(t, viewer.do("GET", "/api/v1/reports/patch-installations?category=Firmware", nil), http.StatusUnprocessableEntity, "validation_failed")

	last := now.AddDate(0, -1, 0)
	month := map[string]any{"organizationId": acme, "year": last.Year(), "month": int(last.Month()), "includeEndpointList": true}
	wantStatus(t, viewer.do("POST", "/api/v1/patching/reports/monthly", month), http.StatusForbidden, "forbidden")
	var monthly struct {
		ID          string `json:"id"`
		PeriodStart string `json:"periodStart"`
		CanManage   bool   `json:"canManage"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/patching/reports/monthly", month, &monthly)
	if monthly.PeriodStart != last.Format("2006-01")+"-01" || !monthly.CanManage {
		t.Fatalf("generated: %+v", monthly)
	}
	var monthlies struct {
		Items []struct {
			ID        string `json:"id"`
			CanManage bool   `json:"canManage"`
		} `json:"items"`
		CanGenerate []string `json:"canGenerate"`
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/patching/reports/monthly?organizationId="+acme, nil, &monthlies)
	if len(monthlies.Items) != 1 || monthlies.Items[0].CanManage || len(monthlies.CanGenerate) != 0 {
		t.Fatalf("monthly reports for a reader: %+v", monthlies)
	}
	wantStatus(t, viewer.do("GET", "/api/v1/patching/reports/monthly?organizationId=nope", nil), http.StatusUnprocessableEntity, "validation_failed")
	pdf := viewer.do("GET", "/api/v1/patching/reports/monthly/"+monthly.ID+"/pdf", nil)
	if pdf.status != http.StatusOK || pdf.header.Get("Content-Type") != "application/pdf" || !strings.HasPrefix(string(pdf.body), "%PDF-") ||
		!strings.HasPrefix(pdf.header.Get("Content-Disposition"), `attachment; filename="patch-report-`) {
		t.Fatalf("PDF: %d %v", pdf.status, pdf.header)
	}
	send := "/api/v1/patching/reports/monthly/" + monthly.ID + "/send"
	r = admin.do("POST", send, map[string]any{"recipients": []string{"cfo@example.com"}})
	wantStatus(t, r, http.StatusConflict, "mail_not_configured")
	if !strings.Contains(string(r.body), "EASYRMM_SMTP_HOST") {
		t.Errorf("without a mail server: %s", r.body)
	}
	wantStatus(t, viewer.do("DELETE", "/api/v1/patching/reports/monthly/"+monthly.ID, nil), http.StatusForbidden, "forbidden")
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/patching/reports/monthly/"+monthly.ID, nil, nil)
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/patching/reports/monthly/nope/pdf"}, {"POST", "/api/v1/patching/reports/monthly/nope/send"},
		{"DELETE", "/api/v1/patching/reports/monthly/nope"}, {"PUT", "/api/v1/patching/report-schedules/nope"},
		{"GET", "/api/v1/patching/reports/monthly/" + monthly.ID + "/pdf"},
	} {
		wantStatus(t, admin.do(c.method, c.path, map[string]any{}), http.StatusNotFound, "not_found")
	}

	var schedules []struct {
		OrganizationID string   `json:"organizationId"`
		Enabled        bool     `json:"enabled"`
		Recipients     []string `json:"recipients"`
		DayOfMonth     int      `json:"dayOfMonth"`
		CanEdit        bool     `json:"canEdit"`
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/patching/report-schedules", nil, &schedules)
	if len(schedules) != 1 || schedules[0].OrganizationID != acme || schedules[0].CanEdit || schedules[0].Enabled {
		t.Fatalf("schedules for a reader: %+v", schedules)
	}
	schedule := map[string]any{"enabled": true, "recipients": []string{"cfo@example.com"}, "dayOfMonth": 3, "includeEndpointList": true}
	wantStatus(t, viewer.do("PUT", "/api/v1/patching/report-schedules/"+acme, schedule), http.StatusForbidden, "forbidden")
	var saved struct {
		Enabled    bool     `json:"enabled"`
		DayOfMonth int      `json:"dayOfMonth"`
		Recipients []string `json:"recipients"`
	}
	admin.expect(http.StatusOK, "PUT", "/api/v1/patching/report-schedules/"+acme, schedule, &saved)
	if !saved.Enabled || saved.DayOfMonth != 3 || len(saved.Recipients) != 1 {
		t.Fatalf("schedule: %+v", saved)
	}
	wantStatus(t, admin.do("PUT", "/api/v1/patching/report-schedules/"+acme, map[string]any{"dayOfMonth": 0}), http.StatusUnprocessableEntity,
		"validation_failed")
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/patching/reports/monthly"}, {"POST", send}, {"PUT", "/api/v1/patching/report-schedules/" + acme},
	} {
		if r := admin.do(c.method, c.path, notObject); r.status != http.StatusBadRequest && r.status != http.StatusUnprocessableEntity {
			t.Errorf("%s %s with an array: %d %s", c.method, c.path, r.status, r.body)
		}
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=patch", nil, &audit)
	got = []string{}
	for _, a := range audit.Items[:4] {
		got = append(got, a.Action)
	}
	if strings.Join(got, ",") != "patch.report_schedule,patch.report_delete,patch.report_download,patch.report_generate" {
		t.Errorf("report audit: %v", got)
	}

	// Server-wide settings, a super administrator's.
	var settings struct {
		Settings map[string]any `json:"settings"`
		Feeds    []any          `json:"feeds"`
		CanEdit  bool           `json:"canEdit"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/settings", nil, &settings)
	if !settings.CanEdit || settings.Settings["globalMaxConcurrentInstalls"] != 50.0 || settings.Feeds == nil {
		t.Fatalf("settings: %+v", settings)
	}
	wantStatus(t, viewer.do("GET", "/api/v1/patching/settings", nil), http.StatusForbidden, "forbidden")
	settings.Settings["globalMaxConcurrentInstalls"] = 40
	admin.expect(http.StatusOK, "PUT", "/api/v1/patching/settings", settings.Settings, &settings)
	if settings.Settings["globalMaxConcurrentInstalls"] != 40.0 {
		t.Fatalf("saved settings: %+v", settings)
	}
	var lifecycle struct {
		Items []struct {
			ID      string `json:"id"`
			Product string `json:"product"`
		} `json:"items"`
		CanEdit bool `json:"canEdit"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/lifecycle", nil, &lifecycle)
	if len(lifecycle.Items) != 2 || !lifecycle.CanEdit {
		t.Fatalf("lifecycle: %+v", lifecycle)
	}
	entry := map[string]any{"product": "Windows 11", "editionGroup": "HomePro", "buildNumber": 26200, "versionLabel": "25H2", "endOfServicing": "2027-10-12"}
	var added idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/patching/lifecycle", entry, &added)
	entry["versionLabel"] = "25H2 (1)"
	admin.expect(http.StatusOK, "PUT", "/api/v1/patching/lifecycle/"+added.ID, entry, nil)
	wantStatus(t, admin.do("PUT", "/api/v1/patching/lifecycle/"+lifecycle.Items[0].ID, entry), http.StatusUnprocessableEntity, "validation_failed")
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/patching/lifecycle/"+added.ID, nil, nil)
	wantStatus(t, admin.do("DELETE", "/api/v1/patching/lifecycle/nope", nil), http.StatusNotFound, "not_found")
	var packages struct {
		Items []struct {
			FileName string `json:"fileName"`
			URL      string `json:"url"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/agent-packages", nil, &packages)
	// Served from EasyRMM's own address, as the engine's are.
	if len(packages.Items) == 0 || packages.Items[0].URL != "/downloads/agent/"+packages.Items[0].FileName {
		t.Fatalf("packages: %+v", packages)
	}
	ep.AddAudit(eptest.AuditInfo{Username: "jo", Org: &epOrg, Action: "policy.update"})
	ep.AddAudit(eptest.AuditInfo{Action: "update.hold"})
	var engineAudit struct {
		Items []struct {
			Action           string `json:"action"`
			Actor            string `json:"actor"`
			Via              string `json:"via"`
			OrganizationName string `json:"organizationName"`
		} `json:"items"`
		TotalCount int  `json:"totalCount"`
		Everything bool `json:"everything"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/audit?area=policy.&from=2020-01-01T00:00:00Z", nil, &engineAudit)
	if len(engineAudit.Items) != 1 || engineAudit.Items[0].Actor != "jo" || engineAudit.Items[0].OrganizationName != "Acme" || !engineAudit.Everything {
		t.Fatalf("EasyPatch's audit: %+v", engineAudit)
	}
	wantStatus(t, viewer.do("GET", "/api/v1/patching/audit", nil), http.StatusForbidden, "forbidden")
	for _, q := range []string{"area=billing.", "from=yesterday", "to=2020-01-01", "organizationId=nope", "page=0"} {
		wantStatus(t, admin.do("GET", "/api/v1/patching/audit?"+q, nil), http.StatusUnprocessableEntity, "validation_failed")
	}
	for _, c := range []struct{ method, path string }{
		{"PUT", "/api/v1/patching/settings"}, {"POST", "/api/v1/patching/lifecycle"}, {"PUT", "/api/v1/patching/lifecycle/" + lifecycle.Items[0].ID},
	} {
		if r := admin.do(c.method, c.path, notObject); r.status != http.StatusBadRequest && r.status != http.StatusUnprocessableEntity {
			t.Errorf("%s %s with an array: %d %s", c.method, c.path, r.status, r.body)
		}
	}

	// Alerts, their rules and channels.
	alertID := ep.AddAlert(eptest.AlertInfo{RuleType: "UpdateHeld", Severity: "Warning", Title: "Acme Patch: 1 update on hold", Org: epOrg})
	var alerts struct {
		Items []struct {
			ID               string `json:"id"`
			OrganizationID   string `json:"organizationId"`
			OrganizationName string `json:"organizationName"`
			CanAcknowledge   bool   `json:"canAcknowledge"`
		} `json:"items"`
		Capped bool `json:"capped"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/alerts?severity=Warning&ruleType=UpdateHeld&search=hold&organizationId="+acme, nil, &alerts)
	if len(alerts.Items) != 1 || alerts.Items[0].ID != alertID.String() || alerts.Items[0].OrganizationID != acme ||
		alerts.Items[0].OrganizationName != "Acme" || !alerts.Items[0].CanAcknowledge || alerts.Capped {
		t.Fatalf("alerts: %+v", alerts)
	}
	var counts map[string]any
	viewer.expect(http.StatusOK, "GET", "/api/v1/patching/alerts/summary", nil, &counts)
	if counts["open"] != 1.0 || counts["warning"] != 1.0 || counts["capped"] != false {
		t.Fatalf("counts: %+v", counts)
	}
	ack := map[string]any{"alertIds": []string{alertID.String()}}
	wantStatus(t, viewer.do("POST", "/api/v1/patching/alerts/acknowledge", ack), http.StatusForbidden, "forbidden")
	var acked map[string]int
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/alerts/acknowledge", ack, &acked)
	if acked["acknowledged"] != 1 {
		t.Fatalf("acknowledged: %+v", acked)
	}
	for _, q := range []string{"alerts?status=Open", "alerts?severity=high", "alerts?ruleType=Offline", "alerts?organizationId=nope",
		"alerts?deviceId=nope", "alerts/summary?organizationId=nope", "notifications/deliveries?page=0"} {
		wantStatus(t, admin.do("GET", "/api/v1/patching/"+q, nil), http.StatusUnprocessableEntity, "validation_failed")
	}
	wantStatus(t, admin.do("POST", "/api/v1/patching/alerts/acknowledge", map[string]any{"alertIds": []string{}}), http.StatusUnprocessableEntity,
		"validation_failed")
	wantStatus(t, viewer.do("GET", "/api/v1/patching/alert-rules", nil), http.StatusForbidden, "forbidden")
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/alert-rules", nil, nil)
	var rule idObj
	var channel struct {
		Channel idObj `json:"channel"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/patching/alert-rules",
		map[string]any{"name": "Offline", "type": "EndpointOffline", "severity": "Warning", "threshold": 4, "enabled": true}, &rule)
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/notifications", nil, nil)
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/notifications/deliveries?status=Failed", nil, nil)
	admin.expect(http.StatusCreated, "POST", "/api/v1/patching/notifications/channels",
		map[string]any{"name": "Ops", "type": "Email", "emailRecipients": []string{"ops@example.com"}, "enabled": true}, &channel)
	gone := uuid.NewString()
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"PUT", "/api/v1/patching/alert-rules/" + gone, map[string]any{"name": "Offline", "type": "EndpointOffline", "severity": "Warning", "threshold": 4}},
		{"PUT", "/api/v1/patching/notifications/channels/" + gone, map[string]any{"name": "Ops", "type": "Email", "emailRecipients": []string{"ops@example.com"}}},
		{"POST", "/api/v1/patching/notifications/channels/" + gone + "/test", nil},
		{"POST", "/api/v1/patching/notifications/channels/" + gone + "/rotate-secret", nil},
	} {
		wantStatus(t, admin.do(c.method, c.path, c.body), http.StatusNotFound, "not_found")
	}
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/patching/alert-rules/"+rule.ID, nil, nil)
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/patching/notifications/channels/"+channel.Channel.ID, nil, nil)
	for _, path := range []string{"alert-rules/nope", "notifications/channels/nope"} {
		wantStatus(t, admin.do("DELETE", "/api/v1/patching/"+path, nil), http.StatusNotFound, "not_found")
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/patching/alerts/acknowledge"}, {"POST", "/api/v1/patching/alert-rules"}, {"PUT", "/api/v1/patching/notifications"},
		{"POST", "/api/v1/patching/notifications/channels"},
	} {
		if r := admin.do(c.method, c.path, notObject); r.status != http.StatusBadRequest && r.status != http.StatusUnprocessableEntity {
			t.Errorf("%s %s with an array: %d %s", c.method, c.path, r.status, r.body)
		}
	}
}

// TestEasyPatchAgentInstallAPI installs the EasyPatch agent through the
// console API and an agent's heartbeats (ADR-0031).
func TestEasyPatchAgentInstallAPI(t *testing.T) {
	ep, h := engineHarness(t)
	admin, _ := setUp(t, h)
	ctx := context.Background()
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Patch", "expiresInDays": 1}, &token)
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts("lin-01"))
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	jobKey, err := agentproto.DecodeKey(enr.JobKey)
	if err != nil {
		t.Fatal(err)
	}
	device := enr.DeviceID
	body, _ := json.Marshal(agentproto.Inventory{})
	if _, err := ac.Inventory(ctx, body); err != nil {
		t.Fatal(err)
	}

	// EasyRMM creates Acme and HQ in the engine.
	if res, err := h.deps.EasyPatch.Reconcile(ctx); err != nil || len(res.Problems) != 0 {
		t.Fatalf("reconcile: %+v, %v", res, err)
	}

	// Automatic installs, per organization.
	wantStatus(t, admin.do("PATCH", "/api/v1/settings/easypatch/organizations/"+acme, map[string]any{}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PATCH", "/api/v1/settings/easypatch/organizations/"+acme, "x"), http.StatusBadRequest, "bad_request")
	wantStatus(t, admin.do("PATCH", "/api/v1/settings/easypatch/organizations/nope", map[string]any{"autoInstall": true}), http.StatusNotFound, "not_found")
	admin.expect(http.StatusNoContent, "PATCH", "/api/v1/settings/easypatch/organizations/"+acme, map[string]any{"autoInstall": true}, nil)
	var orgs struct {
		Links []struct {
			AutoInstall bool `json:"autoInstall"`
		} `json:"links"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch/organizations", nil, &orgs)
	if len(orgs.Links) == 0 || !slices.ContainsFunc(orgs.Links, func(l struct {
		AutoInstall bool `json:"autoInstall"`
	}) bool {
		return l.AutoInstall
	}) {
		t.Fatalf("organizations: %+v", orgs)
	}
	admin.expect(http.StatusNoContent, "PATCH", "/api/v1/settings/easypatch/organizations/"+acme, map[string]any{"autoInstall": false}, nil)

	// Someone asks for the install.
	wantStatus(t, admin.do("POST", "/api/v1/patching/agent-install", "x"), http.StatusBadRequest, "bad_request")
	wantStatus(t, admin.do("POST", "/api/v1/patching/agent-install", map[string]any{"deviceIds": []string{}}), http.StatusUnprocessableEntity, "validation_failed")
	var res struct {
		Succeeded int `json:"succeeded"`
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/agent-install", map[string]any{"deviceIds": []string{device}}, &res)
	if res.Succeeded != 1 {
		t.Fatalf("request: %+v", res)
	}

	// An old agent's heartbeat gets no instruction; one that can install
	// gets a signed one, verified with the job key it pinned.
	hb, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("lin-01")})
	if err != nil || hb.EasyPatchInstall != nil {
		t.Fatalf("old agent: %+v %v", hb, err)
	}
	hb, err = ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("lin-01"), EasyPatch: &agentproto.EasyPatchInstallStatus{}})
	if err != nil || hb.EasyPatchInstall == nil {
		t.Fatalf("heartbeat: %+v %v", hb, err)
	}
	p, err := agentproto.VerifyEasyPatchInstall(jobKey, *hb.EasyPatchInstall, device, time.Now())
	if err != nil || p.ServerURL != "https://patch.example.com" || len(p.Packages) != 2 || len(ep.Tokens()) != 1 || p.Token != ep.Tokens()[0].Secret {
		t.Fatalf("instruction: %+v %v", p, err)
	}
	var dev struct {
		Install struct {
			State       string `json:"state"`
			RequestedBy string `json:"requestedBy"`
			Attempts    int    `json:"attempts"`
		} `json:"install"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/devices/"+device, nil, &dev)
	if dev.Install.State != "sent" || dev.Install.Attempts != 1 {
		t.Fatalf("device: %+v", dev)
	}
	// The agent reports success.
	if _, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts("lin-01"),
		EasyPatch: &agentproto.EasyPatchInstallStatus{Last: &agentproto.EasyPatchInstallReport{ID: p.ID, OK: true}}}); err != nil {
		t.Fatal(err)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/devices/"+device, nil, &dev)
	if dev.Install.State != "succeeded" {
		t.Fatalf("device after: %+v", dev)
	}

	// A read-only user cannot ask, nor change automatic installs.
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")
	wantStatus(t, viewer.do("POST", "/api/v1/patching/agent-install", map[string]any{"deviceIds": []string{device}}), http.StatusForbidden, "forbidden")
	wantStatus(t, viewer.do("PATCH", "/api/v1/settings/easypatch/organizations/"+acme, map[string]any{"autoInstall": true}), http.StatusForbidden, "forbidden")

	var audit struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=patch.agent_install", nil, &audit)
	if len(audit.Items) != 1 {
		t.Fatalf("audit: %+v", audit.Items)
	}
}
