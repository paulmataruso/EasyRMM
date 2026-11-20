//go:build integration

package easypatch

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// guidOf is an update's GUID in eptest's answers.
func guidOf(t *testing.T, u map[string]any) uuid.UUID {
	t.Helper()
	id, ok := u["updateGuid"].(uuid.UUID)
	if !ok {
		t.Fatalf("update %v has no GUID", u)
	}
	return id
}

// TestDeviceActions: what a device's Patches tab does beyond scans, installs
// and restarts. web-01 is a Windows endpoint, db-01 a Linux one.
func TestDeviceActions(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx
	f.ep.Set(func() { f.e1.Windows = true })
	var openssl, tzdata uuid.UUID
	f.ep.Set(func() { openssl, tzdata = guidOf(t, f.e1.Updates[0]), guidOf(t, f.e1.Updates[1]) })
	state := func(e *eptest.Endpoint, i int) (s string) {
		f.ep.Set(func() { s = e.Updates[i]["state"].(string) })
		return s
	}

	// The device carries what the tab shows.
	d, err := f.svc.Device(ctx, f.tech, f.web)
	if err != nil || d.Endpoint == nil || !slices.Contains(d.Endpoint.AgentCapabilities, AgentCanNotifyUser) ||
		!slices.Contains(d.Endpoint.AgentCapabilities, AgentCanUninstallUpdates) || d.Endpoint.AgentUpdate == nil ||
		d.Endpoint.AgentUpdate.Code != "agent_up_to_date" || d.Endpoint.SignedInUsers == nil || *d.Endpoint.SignedInUsers != 1 {
		t.Fatalf("device: %+v, %v", d.Endpoint, err)
	}
	if p := d.Policy; p == nil || p.RestartSchedule == nil || p.RestartSchedule.Mode != "PromptWithDeadline" || p.WindowsUpdate == nil ||
		p.WindowsUpdate.AutomaticUpdates == nil || p.WindowsUpdate.FeatureUpdates == nil || p.WindowsUpdate.FeatureUpdates.DeferDays == nil ||
		p.Sources["RestartSchedule"] != "Site" || p.SourceTags["ApplicationUpdates"] != "Workstations" || len(p.WindowsUpdateValues) != 1 ||
		p.ApplicationUpdates == nil || !slices.Equal(p.ApplicationUpdates.ApprovedApps, []string{"Mozilla.Firefox"}) || !slices.Equal(p.ExcludedKbs, []string{"KB5005565"}) {
		t.Fatalf("policy: %+v", d.Policy)
	}
	f.ep.Set(func() { f.e2.RebootPending = true })
	if d, err := f.svc.Device(ctx, f.admin, f.db); err != nil || d.Endpoint.Restart == nil || len(d.Endpoint.Restart.Updates) != 1 ||
		slices.Contains(d.Endpoint.AgentCapabilities, AgentCanTray) {
		t.Fatalf("pending restart: %+v, %v", d.Endpoint, err)
	}

	// Exclusions.
	wantErr(t, f.svc.Exclude(ctx, f.viewer, f.web, ExclusionInput{UpdateID: openssl}), apperr.KindForbidden, "")
	wantErr(t, f.svc.Exclude(ctx, f.tech, f.db, ExclusionInput{UpdateID: openssl}), apperr.KindNotFound, "")
	wantErr(t, f.svc.Exclude(ctx, f.outsider, f.web, ExclusionInput{UpdateID: openssl}), apperr.KindNotFound, "")
	wantField(t, f.svc.Exclude(ctx, f.tech, f.web, ExclusionInput{}), "updateId", "Choose an update")
	wantField(t, f.svc.Exclude(ctx, f.tech, f.web, ExclusionInput{UpdateID: openssl, Reason: strings.Repeat("x", 501)}), "reason", "500")
	wantErr(t, f.svc.Exclude(ctx, f.tech, f.lab, ExclusionInput{UpdateID: openssl}), apperr.KindConflict, "easypatch_no_agent")
	if err := f.svc.Exclude(ctx, f.tech, f.web, ExclusionInput{UpdateID: openssl, Reason: "  breaks the web server  "}); err != nil {
		t.Fatal(err)
	}
	if s := state(f.e1, 0); s != "Excluded" {
		t.Fatalf("excluded update: %s", s)
	}
	reqs := f.ep.RequestsTo("POST", "/api/v1/endpoints/"+f.e1.ID.String()+"/exclusions")
	if len(reqs) != 1 || reqs[0].Statement.Name != "tess@example.com" || reqs[0].Body["updateGuid"] != openssl.String() ||
		reqs[0].Body["reason"] != "breaks the web server" {
		t.Fatalf("exclusion request: %+v", reqs)
	}
	got := f.audits("patch.exclude")
	if len(got) != 1 || got[0].Label != "tess@example.com" || *got[0].Device != f.web || got[0].Details["updateId"] != openssl.String() ||
		got[0].Details["reason"] != "breaks the web server" || got[0].Details["endpointId"] != f.e1.ID.String() {
		t.Fatalf("exclusion audit: %+v", got)
	}

	// The install preview, for whoever may see the device.
	p, err := f.svc.InstallPreview(ctx, f.viewer, f.web, nil)
	if err != nil || p.Mode != "AllEligible" || len(p.Items) != 1 || p.Items[0].UpdateGUID != tzdata || len(p.Skipped) != 1 ||
		p.Skipped[0].UpdateGUID != openssl || p.Skipped[0].Reason != "Excluded" || p.TotalSizeBytes != 1543210 || p.Warnings == nil ||
		p.Filter == nil || !slices.Equal(p.Filter.Categories, []string{"Security", "Critical"}) {
		t.Fatalf("preview: %+v, %v", p, err)
	}
	p, err = f.svc.InstallPreview(ctx, f.viewer, f.web, []uuid.UUID{openssl})
	if err != nil || p.Mode != "Selected" || len(p.Items) != 0 || len(p.Skipped) != 1 {
		t.Fatalf("preview of the excluded update: %+v, %v", p, err)
	}
	if q := f.ep.RequestsTo("GET", "/api/v1/endpoints/"+f.e1.ID.String()+"/install-preview"); len(q) != 2 {
		t.Fatalf("preview requests: %+v", q)
	}
	_, err = f.svc.InstallPreview(ctx, f.viewer, f.web, make([]uuid.UUID, 1001))
	wantField(t, err, "updateIds", "1,000")
	_, err = f.svc.InstallPreview(ctx, f.outsider, f.web, nil)
	wantErr(t, err, apperr.KindNotFound, "")

	// Included again: missing, as before.
	wantErr(t, f.svc.Include(ctx, f.viewer, f.web, openssl), apperr.KindForbidden, "")
	if err := f.svc.Include(ctx, f.tech, f.web, openssl); err != nil {
		t.Fatal(err)
	}
	if s := state(f.e1, 0); s != "Missing" {
		t.Fatalf("included update: %s", s)
	}
	if got := f.audits("patch.include"); len(got) != 1 || got[0].Details["updateId"] != openssl.String() {
		t.Fatalf("include audit: %+v", got)
	}

	// Removing an installed update: Windows only, said as the device's
	// outcome.
	_, err = f.svc.RemoveUpdate(ctx, f.viewer, f.web, openssl, RemoveInput{})
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.RemoveUpdate(ctx, f.admin, f.web, openssl, RemoveInput{Reason: strings.Repeat("é", 501)})
	wantField(t, err, "reason", "500")
	res, err := f.svc.RemoveUpdate(ctx, f.admin, f.db, openssl, RemoveInput{Block: true})
	if err != nil || res.Failed != 1 || res.Results[0].OK ||
		res.Results[0].Message != "EasyPatch: db-01 is a Linux endpoint. Removing updates is only available on Windows." {
		t.Fatalf("removal on Linux: %+v, %v", res, err)
	}
	res, err = f.svc.RemoveUpdate(ctx, f.tech, f.web, openssl, RemoveInput{Block: true, Reason: "breaks printing"})
	if err != nil || res.Succeeded != 1 || res.Results[0].JobID == nil || res.Results[0].DeviceName != "web-01" {
		t.Fatalf("removal: %+v, %v", res, err)
	}
	removal := f.ep.RequestsTo("POST", "/api/v1/endpoints/"+f.e1.ID.String()+"/updates/"+openssl.String()+"/uninstall")
	if len(removal) != 1 || removal[0].Body["block"] != true || removal[0].Body["reason"] != "breaks printing" || removal[0].Statement.Name != "tess@example.com" {
		t.Fatalf("removal request: %+v", removal)
	}
	got = f.audits("patch.remove_update")
	if len(got) != 1 || got[0].Details["jobId"] != res.Results[0].JobID.String() || got[0].Details["block"] != true ||
		got[0].Details["reason"] != "breaks printing" || *got[0].Device != f.web {
		t.Fatalf("removal audit: %+v", got)
	}

	// Messages to users.
	presets, err := f.svc.MessagePresets(ctx, f.viewer)
	if err != nil || len(presets) != 6 || presets[5].Preset != "RestartScheduled" || !presets[5].NeedsRestartTime ||
		!strings.Contains(presets[5].Body, "{time}") || presets[0].Title != "Updates are installing" {
		t.Fatalf("presets: %+v, %v", presets, err)
	}
	_, err = f.svc.MessagePresets(ctx, f.none)
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.Notify(ctx, f.admin, NotifyInput{DeviceIDs: []uuid.UUID{f.web}, Preset: "Hello"})
	wantField(t, err, "preset", "Choose a message")
	_, err = f.svc.Notify(ctx, f.admin, NotifyInput{DeviceIDs: []uuid.UUID{f.web}, Preset: "RestartScheduled"})
	wantField(t, err, "restartAt", "restart time")
	past, far := time.Now().Add(-time.Minute), time.Now().Add(32*24*time.Hour)
	_, err = f.svc.Notify(ctx, f.admin, NotifyInput{DeviceIDs: []uuid.UUID{f.web}, Preset: "RestartScheduled", RestartAt: &past})
	wantField(t, err, "restartAt", "in the future")
	_, err = f.svc.Notify(ctx, f.admin, NotifyInput{DeviceIDs: []uuid.UUID{f.web}, Preset: "RestartScheduled", RestartAt: &far})
	wantField(t, err, "restartAt", "within 31 days")
	_, err = f.svc.Notify(ctx, f.tech, NotifyInput{DeviceIDs: []uuid.UUID{f.web, f.db}, Preset: "SaveYourWork"})
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.Notify(ctx, f.viewer, NotifyInput{DeviceIDs: []uuid.UUID{f.web}, Preset: "SaveYourWork"})
	wantErr(t, err, apperr.KindForbidden, "")
	// A time given with another message is not sent.
	at := time.Now().Add(time.Hour)
	res, err = f.svc.Notify(ctx, f.admin, NotifyInput{DeviceIDs: []uuid.UUID{f.web, f.db, f.lab}, Preset: "SaveYourWork", RestartAt: &at})
	if err != nil || res.Succeeded != 1 || res.Failed != 2 {
		t.Fatalf("notify: %+v, %v", res, err)
	}
	for _, r := range res.Results {
		if r.DeviceID == f.db && (r.OK || !strings.Contains(r.Message, "Messages to users are only available on Windows")) {
			t.Fatalf("db-01: %+v", r)
		}
	}
	sent := f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/notify")
	if len(sent) != 1 || sent[0].Statement.Name != "ada@example.com" {
		t.Fatalf("notify request: %+v", sent)
	}
	if m, _ := sent[0].Body["message"].(map[string]any); m["preset"] != "SaveYourWork" || m["restartAt"] != nil {
		t.Fatalf("message sent: %+v", sent[0].Body)
	}
	got = f.audits("patch.notify")
	if len(got) != 1 || *got[0].Device != f.web || got[0].Details["message"] != "SaveYourWork" || got[0].Details["restartAt"] != nil {
		t.Fatalf("notify audit: %+v", got)
	}
	res, err = f.svc.Notify(ctx, f.tech, NotifyInput{DeviceIDs: []uuid.UUID{f.web}, Preset: "RestartScheduled", RestartAt: &at})
	if err != nil || res.Succeeded != 1 {
		t.Fatalf("restart scheduled: %+v, %v", res, err)
	}
	sent = f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/notify")
	if m, _ := sent[1].Body["message"].(map[string]any); m["restartAt"] != at.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("restart time sent: %+v", sent[1].Body)
	}
	if got := f.audits("patch.notify"); got[1].Details["restartAt"] != at.UTC().Format(time.RFC3339) {
		t.Fatalf("restart time audited: %+v", got[1])
	}

	// Agent updates.
	_, err = f.svc.UpdateAgent(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.web}, UpdateIDs: []uuid.UUID{openssl}})
	wantField(t, err, "deviceIds", "devices only")
	_, err = f.svc.UpdateAgent(ctx, f.viewer, ActionInput{DeviceIDs: []uuid.UUID{f.web}})
	wantErr(t, err, apperr.KindForbidden, "")
	res, err = f.svc.UpdateAgent(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.web, f.db}})
	if err != nil || res.Succeeded != 2 {
		t.Fatalf("agent update: %+v, %v", res, err)
	}
	if u := f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/agent-update"); len(u) != 1 || u[0].Body["version"] != nil ||
		len(u[0].Body["endpointIds"].([]any)) != 2 {
		t.Fatalf("agent update request: %+v", u)
	}
	if got := f.audits("patch.agent_update"); len(got) != 2 {
		t.Fatalf("agent update audit: %+v", got)
	}

	// The engine refusing EasyRMM's changes: reads still work, and each
	// change says the engine refused it, not that the person may not.
	f.ep.Set(func() { f.ep.ReadOnly = true })
	wantErr(t, f.svc.Exclude(ctx, f.tech, f.web, ExclusionInput{UpdateID: openssl}), apperr.KindUnavailable, "patching_unavailable")
	_, err = f.svc.RemoveUpdate(ctx, f.tech, f.web, openssl, RemoveInput{})
	wantErr(t, err, apperr.KindUnavailable, "patching_unavailable")
	if _, err := f.svc.InstallPreview(ctx, f.tech, f.web, nil); err != nil {
		t.Fatalf("preview while the engine refuses changes: %v", err)
	}
	if _, err := f.svc.MessagePresets(ctx, f.tech); err != nil {
		t.Fatalf("presets while the engine refuses changes: %v", err)
	}
	f.ep.Set(func() { f.ep.ReadOnly = false })

	// The engine failing.
	f.ep.Set(func() { f.ep.Down = true })
	wantErr(t, f.svc.Exclude(ctx, f.tech, f.web, ExclusionInput{UpdateID: openssl}), apperr.KindUnavailable, "patching_unavailable")
	_, err = f.svc.InstallPreview(ctx, f.tech, f.web, nil)
	wantErr(t, err, apperr.KindUnavailable, "")
	_, err = f.svc.RemoveUpdate(ctx, f.tech, f.web, openssl, RemoveInput{})
	wantErr(t, err, apperr.KindUnavailable, "")
	_, err = f.svc.MessagePresets(ctx, f.tech)
	wantErr(t, err, apperr.KindUnavailable, "")
	f.ep.Set(func() { f.ep.Down = false })

	// Without the engine.
	f.withoutEngine()
	_, err = f.svc.MessagePresets(ctx, f.tech)
	wantErr(t, err, apperr.KindConflict, "easypatch_not_configured")
	_, err = f.svc.Notify(ctx, f.admin, NotifyInput{DeviceIDs: []uuid.UUID{f.web}, Preset: "SaveYourWork"})
	wantErr(t, err, apperr.KindConflict, "easypatch_not_configured")
}

// TestDeviceActionsStatements: with the patching engine, each action's
// statement names the person, the role it needs and the device's
// organization only (ADR-0038).
func TestDeviceActionsStatements(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	key := bytes.Repeat([]byte{7}, 32)
	engine := eptest.NewEngine(t, key)
	signer, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewEngineClient(engine.URL(), signer, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.UseEngine(client); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	epAcme := f.engineOrg(f.acme)
	e := engine.AddEndpoint(epAcme, "web-01", "", "AAAA-1111")
	engine.Set(func() { e.Windows = true })
	web := f.device(f.acme, f.hq, "web-01")
	f.report(web, "", &agentproto.EasyPatchAgent{Version: "1.9.0", Status: "Active", ServerURL: "https://patch.example.com",
		EndpointID: e.ID.String(), KeyFingerprint: e.Fingerprint})
	f.sync()
	tech := f.user("tess@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	var guid uuid.UUID
	engine.Set(func() { guid = guidOf(t, e.Updates[0]) })

	check := func(what, method, path, role string, orgs []uuid.UUID) {
		t.Helper()
		reqs := engine.RequestsTo(method, path)
		if len(reqs) == 0 {
			t.Fatalf("%s: no request to %s %s", what, method, path)
		}
		st := reqs[len(reqs)-1].Statement
		if st == nil || st.Subject != tech.Actor.ID.String() || st.Name != "tess@example.com" || st.Role != role || st.AllOrganizations ||
			!slices.Equal(st.Organizations, orgs) {
			t.Fatalf("%s's statement: %+v", what, st)
		}
	}
	endpoint := "/api/v1/endpoints/" + e.ID.String()
	if err := f.svc.Exclude(ctx, tech, web, ExclusionInput{UpdateID: guid}); err != nil {
		t.Fatal(err)
	}
	check("exclude", "POST", endpoint+"/exclusions", RoleAdmin, []uuid.UUID{epAcme})
	if err := f.svc.Include(ctx, tech, web, guid); err != nil {
		t.Fatal(err)
	}
	check("include", "DELETE", endpoint+"/exclusions/"+guid.String(), RoleAdmin, []uuid.UUID{epAcme})
	if _, err := f.svc.InstallPreview(ctx, tech, web, nil); err != nil {
		t.Fatal(err)
	}
	check("preview", "GET", endpoint+"/install-preview", RoleReadOnly, []uuid.UUID{epAcme})
	if res, err := f.svc.RemoveUpdate(ctx, tech, web, guid, RemoveInput{}); err != nil || res.Succeeded != 1 {
		t.Fatalf("removal: %+v, %v", res, err)
	}
	check("removal", "POST", endpoint+"/updates/"+guid.String()+"/uninstall", RoleAdmin, []uuid.UUID{epAcme})
	if _, err := f.svc.MessagePresets(ctx, tech); err != nil {
		t.Fatal(err)
	}
	check("presets", "GET", "/api/v1/user-messages", RoleReadOnly, nil)
	if res, err := f.svc.Notify(ctx, tech, NotifyInput{DeviceIDs: []uuid.UUID{web}, Preset: "SaveYourWork"}); err != nil || res.Succeeded != 1 {
		t.Fatalf("notify: %+v, %v", res, err)
	}
	check("notify", "POST", "/api/v1/endpoints/bulk/notify", RoleAdmin, []uuid.UUID{epAcme})
	if res, err := f.svc.UpdateAgent(ctx, tech, ActionInput{DeviceIDs: []uuid.UUID{web}}); err != nil || res.Succeeded != 1 {
		t.Fatalf("agent update: %+v, %v", res, err)
	}
	check("agent update", "POST", "/api/v1/endpoints/bulk/agent-update", RoleAdmin, []uuid.UUID{epAcme})
}
