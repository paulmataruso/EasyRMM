//go:build integration

package easypatch

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// TestBundledEngine: EasyRMM calls the patching engine in this deployment
// (one-product plan, B3) with statements that carry each person's role and
// organizations, and creates and links every organization there itself
// (ADR-0040).
func TestBundledEngine(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	key := bytes.Repeat([]byte{9}, 32)
	engine := eptest.NewEngine(t, key)
	engine.Capabilities = []string{CapabilityScheduledInstalls}
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

	// Settings shows the engine; there is no console of its own to open.
	conn, err := f.svc.Connection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !conn.Configured || conn.URL != engine.URL() || conn.ServerVersion != "1.9.0" || !slices.Contains(conn.Capabilities, CapabilityScheduledInstalls) {
		t.Fatalf("connection: %+v", conn)
	}
	if st, err := f.svc.Status(ctx, f.admin); err != nil || !st.Configured || !st.CanSchedule {
		t.Fatalf("status: %+v, %v", st, err)
	}
	if _, err := f.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	epAcme := f.engineOrg(f.acme)

	// Links and the patching pages: EasyRMM's own work acts as EasyRMM, in
	// every organization.
	e1 := engine.AddEndpoint(epAcme, "web-01", "", "AAAA-1111")
	web := f.device(f.acme, f.hq, "web-01")
	// Agents enroll with the engine's public address (EasyRMM's own, in
	// the deployment), not its loopback one.
	f.report(web, "", &agentproto.EasyPatchAgent{Version: "1.9.0", Status: "Active", ServerURL: "https://patch.example.com",
		EndpointID: e1.ID.String(), KeyFingerprint: e1.Fingerprint})
	f.sync()
	if l := f.link(web); l.state != LinkLinked {
		t.Fatalf("link: %+v", l)
	}
	for _, r := range engine.RequestsTo("GET", "/api/v1/endpoints/"+e1.ID.String()) {
		if r.Statement == nil || r.Statement.Subject != ServiceSubject || r.Statement.Role != RoleAdmin || !r.Statement.AllOrganizations {
			t.Fatalf("link check's statement: %+v", r.Statement)
		}
	}

	// A person's call carries their role and the organizations it concerns.
	tech := f.user("tess@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	fleet, err := f.svc.Fleet(ctx, tech, FleetQuery{})
	if err != nil || len(fleet.Devices) != 1 || fleet.Devices[0].Endpoint == nil || len(fleet.Errors) != 0 {
		t.Fatalf("fleet: %+v, %v", fleet, err)
	}
	reads := engine.RequestsTo("GET", "/api/v1/endpoints")
	if len(reads) == 0 {
		t.Fatal("no endpoint list was read")
	}
	if st := reads[len(reads)-1].Statement; st == nil || st.Subject != tech.Actor.ID.String() || st.Name != "tess@example.com" ||
		st.Role != RoleReadOnly || st.AllOrganizations || !slices.Equal(st.Organizations, []uuid.UUID{epAcme}) {
		t.Fatalf("fleet's statement: %+v", st)
	}
	res, err := f.svc.Scan(ctx, tech, ActionInput{DeviceIDs: []uuid.UUID{web}})
	if err != nil || res.Succeeded != 1 {
		t.Fatalf("scan: %+v, %v", res, err)
	}
	scans := engine.RequestsTo("POST", "/api/v1/endpoints/bulk/scan")
	if len(scans) != 1 {
		t.Fatalf("scans: %+v", scans)
	}
	if st := scans[0].Statement; st == nil || st.Subject != tech.Actor.ID.String() || st.Role != RoleAdmin ||
		st.AllOrganizations || !slices.Equal(st.Organizations, []uuid.UUID{epAcme}) {
		t.Fatalf("scan's statement: %+v", st)
	}
	if updates, err := f.svc.Updates(ctx, tech, web, ""); err != nil || len(updates) == 0 {
		t.Fatalf("updates: %+v, %v", updates, err)
	}
	if st := engine.RequestsTo("GET", "/api/v1/endpoints/"+e1.ID.String()+"/updates")[0].Statement; st == nil || st.Role != RoleReadOnly ||
		!slices.Equal(st.Organizations, []uuid.UUID{epAcme}) {
		t.Fatalf("updates' statement: %+v", st)
	}

	// The engine refusing EasyRMM is the engine being unavailable, never a
	// 401 or 403 that the console would take for a lost session.
	engine.Set(func() { engine.ReadOnly = true })
	_, err = f.svc.Scan(ctx, tech, ActionInput{DeviceIDs: []uuid.UUID{web}})
	wantErr(t, err, apperr.KindUnavailable, "patching_unavailable")
	engine.Set(func() { engine.ReadOnly = false })

	other, _ := NewSigner(bytes.Repeat([]byte{8}, 32))
	wrong, err := NewEngineClient(engine.URL(), other, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	g := newFixture(t)
	if err := g.svc.UseEngine(wrong); err != nil {
		t.Fatal(err)
	}
	conn, err = g.svc.CheckConnection(ctx)
	if err != nil || !conn.Configured || conn.LastError == "" || conn.LastErrorAt == nil {
		t.Fatalf("a wrong key is shown in Settings: %+v, %v", conn, err)
	}
	if orgs, err := g.svc.Organizations(ctx); err != nil || !strings.Contains(orgs.Error, "patching engine answered 401") {
		t.Fatalf("organizations with a wrong key: %+v, %v", orgs, err)
	}

	// Only loopback is accepted.
	if _, err := NewEngineClient("http://192.0.2.20:18180", signer, "1.0.0"); err == nil {
		t.Error("an engine beyond loopback was accepted")
	}
	if _, err := NewEngineClient("https://127.0.0.1:18180", signer, "1.0.0"); err == nil {
		t.Error("https was accepted for the engine")
	}
}

// engineOrg is the engine organization linked to an EasyRMM one.
func (f *fixture) engineOrg(org uuid.UUID) uuid.UUID {
	f.t.Helper()
	return f.id(`SELECT easypatch_id FROM easypatch_organizations WHERE organization_id = $1`, org)
}

// engineSite is the engine site linked to an EasyRMM one.
func (f *fixture) engineSite(site uuid.UUID) uuid.UUID {
	f.t.Helper()
	return f.id(`SELECT easypatch_id FROM easypatch_sites WHERE site_id = $1`, site)
}
