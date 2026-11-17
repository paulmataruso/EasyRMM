//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// TestEasyPatchAPI sets EasyPatch up, links an organization and a device,
// and patches the device through the console API (ADR-0030).
func TestEasyPatchAPI(t *testing.T) {
	h := newHarness(t, false)
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

	ep := eptest.New(t)
	epOrg := ep.Org("Acme Patch")
	endpoint := ep.AddEndpoint(epOrg, "web-01", "S-1", "1FBB-E2EA-533D-A960")

	// Settings.
	var conn struct {
		Configured    bool     `json:"configured"`
		ServerVersion string   `json:"serverVersion"`
		CanOperate    bool     `json:"canOperate"`
		Capabilities  []string `json:"capabilities"`
		LastError     string   `json:"lastError"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch", nil, &conn)
	if conn.Configured || conn.Capabilities == nil {
		t.Fatalf("unset: %+v", conn)
	}
	wantStatus(t, admin.do("GET", "/api/v1/patching/devices", nil), http.StatusConflict, "easypatch_not_configured")
	wantStatus(t, admin.do("PUT", "/api/v1/settings/easypatch", map[string]string{"url": "http://x", "token": ep.Token}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PUT", "/api/v1/settings/easypatch", map[string]any{"url": ep.URL(), "token": 7}), http.StatusUnprocessableEntity, "validation_failed")
	r := admin.expect(http.StatusOK, "PUT", "/api/v1/settings/easypatch", map[string]string{"url": ep.URL(), "token": ep.Token, "caCert": ep.CAPEM}, &conn)
	if !conn.Configured || conn.ServerVersion != "1.9.0" || !conn.CanOperate || strings.Contains(string(r.body), ep.Token) {
		t.Fatalf("set: %s", r.body)
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/settings/easypatch/check", nil, &conn)
	if conn.LastError != "" {
		t.Fatalf("check: %+v", conn)
	}

	var orgs struct {
		EasyPatch []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"easyPatch"`
		Links []struct {
			OrganizationName string `json:"organizationName"`
			EasyPatchName    string `json:"easyPatchName"`
			Devices          struct {
				Linked int `json:"linked"`
			} `json:"devices"`
		} `json:"links"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch/organizations", nil, &orgs)
	if len(orgs.EasyPatch) != 1 || orgs.EasyPatch[0].Name != "Acme Patch" || len(orgs.Links) != 0 {
		t.Fatalf("organizations: %+v", orgs)
	}
	wantStatus(t, admin.do("PUT", "/api/v1/settings/easypatch/organizations/"+acme, map[string]string{"easyPatchId": "nope"}), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("PUT", "/api/v1/settings/easypatch/organizations/nope", map[string]string{"easyPatchId": epOrg.String()}), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("PUT", "/api/v1/settings/easypatch/organizations/"+acme, "x"), http.StatusBadRequest, "bad_request")
	admin.expect(http.StatusNoContent, "PUT", "/api/v1/settings/easypatch/organizations/"+acme, map[string]string{"easyPatchId": epOrg.String()}, nil)

	// The agent reports its EasyPatch agent; the link is checked.
	body, _ := json.Marshal(agentproto.Inventory{
		System: agentproto.SystemInfo{Serial: "S-1"},
		EasyPatch: &agentproto.EasyPatchAgent{Version: "1.9.0", Status: "Active", ServerURL: ep.URL() + "/",
			EndpointID: endpoint.ID.String(), KeyFingerprint: endpoint.Fingerprint},
	})
	if _, err := ac.Inventory(ctx, body); err != nil {
		t.Fatal(err)
	}
	if n, err := h.deps.EasyPatch.SyncLinks(ctx); n != 1 || err != nil {
		t.Fatalf("sync: %d %v", n, err)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/settings/easypatch/organizations", nil, &orgs)
	if len(orgs.Links) != 1 || orgs.Links[0].Devices.Linked != 1 {
		t.Fatalf("links: %+v", orgs.Links)
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
		Configured, CanOperate, CanSchedule bool
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching", nil, &status)
	if !status.Configured || !status.CanOperate || status.CanSchedule {
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
	wantStatus(t, admin.do("POST", "/api/v1/patching/install", map[string]any{"deviceIds": []string{device}, "scheduledAt": "2026-12-01T02:00:00Z"}),
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

	// Restart: EasyPatch 1.9.0 cannot tell servers apart, so the device
	// must be confirmed by name.
	ep.Set(func() { endpoint.RebootPending = true })
	var plan struct {
		ServersKnown bool `json:"serversKnown"`
		Devices      []struct {
			DeviceName string `json:"deviceName"`
			Restart    bool   `json:"restart"`
			Server     bool   `json:"server"`
		} `json:"devices"`
	}
	admin.expect(http.StatusOK, "POST", "/api/v1/patching/restart/plan", map[string]any{"deviceIds": []string{device}}, &plan)
	if plan.ServersKnown || len(plan.Devices) != 1 || !plan.Devices[0].Restart || !plan.Devices[0].Server || plan.Devices[0].DeviceName != "web-01" {
		t.Fatalf("restart plan: %+v", plan)
	}
	r = admin.do("POST", "/api/v1/patching/restart", map[string]any{"deviceIds": []string{device}})
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

	// Links to EasyPatch's console.
	link := *admin
	noFollow := *admin.http
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	link.http = &noFollow
	for path, want := range map[string]string{
		"/go/to-easypatch?device=" + device + "&tab=updates": "https://patch.example.com/endpoints/" + endpoint.ID.String() + "?from=easyrmm&tab=updates",
		"/go/to-easypatch?organization=" + acme:              "https://patch.example.com/organizations/" + epOrg.String() + "?from=easyrmm",
		"/go/to-easypatch?job=" + jobs.Items[0].ID:           "https://patch.example.com/jobs/" + jobs.Items[0].ID + "?from=easyrmm",
		"/go/to-easypatch?site=" + hq.ID:                     "https://patch.example.com/organizations/" + epOrg.String() + "?from=easyrmm",
		"/go/to-easypatch?list=jobs":                         "https://patch.example.com/jobs?from=easyrmm",
		"/go/to-easypatch":                                   "https://patch.example.com/?from=easyrmm",
	} {
		r := link.do("GET", path, nil)
		if r.status != http.StatusFound || r.header.Get("Location") != want || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %q, want %q", path, r.status, r.header.Get("Location"), want)
		}
	}
	wantStatus(t, link.do("GET", "/go/to-easypatch?device=x", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, link.do("GET", "/go/to-easypatch?device="+device+"&organization="+acme, nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, link.do("GET", "/go/to-easypatch?list=updates", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, link.do("GET", "/go/to-easypatch?list=jobs&site="+hq.ID, nil), http.StatusUnprocessableEntity, "validation_failed")

	// The product switch: shown to anyone with organization-wide access to a linked organization.
	var sw struct {
		Show      bool `json:"show"`
		Answering bool `json:"answering"`
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/patching/switch", nil, &sw)
	if !sw.Show || !sw.Answering {
		t.Fatalf("switch for the administrator: %+v", sw)
	}
	wantStatus(t, h.client().do("GET", "/api/v1/patching/switch", nil), http.StatusUnauthorized, "")
	stranger := h.client()
	stranger.http.CheckRedirect = noFollow.CheckRedirect
	r = stranger.do("GET", "/go/to-easypatch?device="+device+"&tab=jobs", nil)
	if r.status != http.StatusFound || r.header.Get("Location") != "/login?returnTo="+url.QueryEscape("/go/to-easypatch?device="+device+"&tab=jobs") {
		t.Fatalf("signed out: %d %q", r.status, r.header.Get("Location"))
	}

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
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		wantStatus(t, viewer.do(m, "/api/v1/settings/easypatch", map[string]string{}), http.StatusForbidden, "forbidden")
	}
	wantStatus(t, viewer.do("GET", "/api/v1/settings/easypatch/organizations", nil), http.StatusForbidden, "forbidden")
	viewer.expect(http.StatusOK, "GET", "/api/v1/patching/switch", nil, &sw)
	if !sw.Show {
		t.Fatalf("switch for a read-only user of the organization: %+v", sw)
	}
	wantStatus(t, h.client().do("GET", "/api/v1/patching", nil), http.StatusUnauthorized, "")

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
	if strings.Join(got, ",") != "patch.restart,patch.retry,patch.cancel,patch.install,patch.scan" {
		t.Fatalf("patch audit: %v", got)
	}

	// Unlinking and removing.
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/settings/easypatch/organizations/"+acme, nil, nil)
	wantStatus(t, admin.do("DELETE", "/api/v1/settings/easypatch/organizations/"+acme, nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("DELETE", "/api/v1/settings/easypatch/organizations/nope", nil), http.StatusNotFound, "not_found")
	viewer.expect(http.StatusOK, "GET", "/api/v1/patching/switch", nil, &sw)
	if sw.Show {
		t.Fatalf("switch once the organization is unlinked: %+v", sw)
	}
	admin.expect(http.StatusNoContent, "DELETE", "/api/v1/settings/easypatch", nil, nil)
	wantStatus(t, admin.do("DELETE", "/api/v1/settings/easypatch", nil), http.StatusNotFound, "not_found")
	wantStatus(t, admin.do("POST", "/api/v1/settings/easypatch/check", nil), http.StatusNotFound, "not_found")
	admin.expect(http.StatusOK, "GET", "/api/v1/patching", nil, &status)
	if status.Configured {
		t.Fatalf("status after removal: %+v", status)
	}
	admin.expect(http.StatusOK, "GET", "/api/v1/audit?action=easypatch", nil, &audit)
	if len(audit.Items) != 4 {
		t.Fatalf("easypatch audit: %+v", audit.Items)
	}
}

// TestEasyPatchAgentInstallAPI installs the EasyPatch agent through the
// console API and an agent's heartbeats (ADR-0031).
func TestEasyPatchAgentInstallAPI(t *testing.T) {
	h := newHarness(t, false)
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

	ep := eptest.New(t)
	epOrg := ep.Org("Acme Patch")
	ep.Site(epOrg, "HQ")
	admin.expect(http.StatusOK, "PUT", "/api/v1/settings/easypatch", map[string]string{"url": ep.URL(), "token": ep.Token, "caCert": ep.CAPEM}, nil)
	admin.expect(http.StatusNoContent, "PUT", "/api/v1/settings/easypatch/organizations/"+acme, map[string]string{"easyPatchId": epOrg.String()}, nil)

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
	if len(orgs.Links) != 1 || !orgs.Links[0].AutoInstall {
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
