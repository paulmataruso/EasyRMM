//go:build integration

package easypatch

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// The fake's updates, the same on every endpoint: openssl is missing, tzdata
// failed and libc6 installed.
var (
	openssl = eptest.UpdateGUID("openssl 3.5.7-1~deb13u3")
	tzdata  = eptest.UpdateGUID("tzdata 2026c-0+deb13u1")
	libc6   = eptest.UpdateGUID("libc6 2.41-12+deb13u1")
)

type fleetFixture struct {
	*fixture
	engine                 *eptest.Server
	epAcme, epGlobex       uuid.UUID
	web, dbHost            uuid.UUID
	eWeb, eDB, eStray      *eptest.Endpoint
	tech, siteTech, reader access.Caller
	orgAdmin               access.Caller
}

// newFleetFixture runs the connector on a patching engine with Acme's web-01
// (HQ, Windows) and db-01 (Branch), Globex's plant-01, and an Acme endpoint
// with no EasyRMM device.
func newFleetFixture(t *testing.T) *fleetFixture {
	t.Helper()
	f := &fleetFixture{fixture: newFixture(t)}
	f.engine = f.bundle()
	f.reconcile()
	f.epAcme, f.epGlobex = f.engineOrg(f.acme), f.engineOrg(f.globex)
	f.web, f.eWeb = f.linkedDevice(f.engine, f.acme, f.hq, "WEB-01")
	f.dbHost, f.eDB = f.linkedDevice(f.engine, f.acme, f.branch, "DB-01")
	f.linkedDevice(f.engine, f.globex, f.plant, "PLANT-01")
	f.eStray = f.engine.AddEndpoint(f.epAcme, "stray-01", "", "FP-STRAY")
	// The stray endpoint is in no site.
	f.engine.Set(func() { f.eWeb.Windows, f.eStray.Site, f.eStray.SiteName = true, nil, "" })
	f.tech = f.user("tess@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	f.siteTech = f.user("sid@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	f.reader = f.user("rita@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	f.orgAdmin = f.user("otto@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	return f
}

// lastStatement is the statement of the last call to method and path.
func (f *fleetFixture) lastStatement(method, path string) *eptest.Statement {
	f.t.Helper()
	reqs := f.engine.RequestsTo(method, path)
	if len(reqs) == 0 {
		f.t.Fatalf("no request to %s %s", method, path)
	}
	return reqs[len(reqs)-1].Statement
}

func find(list []FleetUpdate, guid uuid.UUID) *FleetUpdate {
	for i := range list {
		if list[i].UpdateGUID == guid {
			return &list[i]
		}
	}
	return nil
}

// TestCatalog: the catalog counts over whole organizations the caller
// sees, or one site they may see, and the engine is told which.
func TestCatalog(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx

	// A super administrator sees both organizations; the engine counts over
	// them because the statement names both.
	p, err := f.svc.Catalog(ctx, f.admin, UpdateScope{}, CatalogQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if u := find(p.Items, openssl); u == nil || u.MissingCount != 4 || p.TotalCount != 2 || find(p.Items, libc6) != nil {
		t.Fatalf("catalog: %+v", p)
	}
	st := f.lastStatement("GET", "/api/v1/updates")
	if st.Role != RoleReadOnly || st.AllOrganizations || !slices.Equal(st.Organizations, []uuid.UUID{f.epAcme, f.epGlobex}) {
		t.Fatalf("statement: %+v", st)
	}

	// Acme's technician: Acme only, the stray endpoint included.
	p, err = f.svc.Catalog(ctx, f.tech, UpdateScope{}, CatalogQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if u := find(p.Items, openssl); u == nil || u.MissingCount != 3 {
		t.Fatalf("technician's catalog: %+v", p)
	}
	if u := find(p.Items, tzdata); u == nil || u.FailedCount != 3 {
		t.Fatalf("technician's tzdata: %+v", p)
	}
	if st := f.lastStatement("GET", "/api/v1/updates"); !slices.Equal(st.Organizations, []uuid.UUID{f.epAcme}) {
		t.Fatalf("technician's statement: %+v", st)
	}
	_, err = f.svc.Catalog(ctx, f.tech, UpdateScope{OrganizationID: f.globex}, CatalogQuery{})
	wantErr(t, err, apperr.KindNotFound, "")

	// A technician of one site chooses it; the engine counts over its site.
	_, err = f.svc.Catalog(ctx, f.siteTech, UpdateScope{}, CatalogQuery{})
	wantField(t, err, "siteId", "choose one of them")
	_, err = f.svc.Catalog(ctx, f.siteTech, UpdateScope{OrganizationID: f.acme}, CatalogQuery{})
	wantField(t, err, "siteId", "choose one of them")
	_, err = f.svc.Catalog(ctx, f.siteTech, UpdateScope{SiteID: f.branch}, CatalogQuery{})
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.Catalog(ctx, f.siteTech, UpdateScope{OrganizationID: f.globex, SiteID: f.hq}, CatalogQuery{})
	wantField(t, err, "siteId", "organization")
	p, err = f.svc.Catalog(ctx, f.siteTech, UpdateScope{SiteID: f.hq}, CatalogQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if u := find(p.Items, openssl); u == nil || u.MissingCount != 1 {
		t.Fatalf("site catalog: %+v", p)
	}

	// Filters reach the engine.
	p, err = f.svc.Catalog(ctx, f.tech, UpdateScope{}, CatalogQuery{State: "Installed"})
	if u := find(p.Items, libc6); err != nil || u == nil || u.InstalledCount != 3 || len(p.Items) != 1 {
		t.Fatalf("installed: %+v, %v", p, err)
	}
	p, err = f.svc.Catalog(ctx, f.tech, UpdateScope{}, CatalogQuery{Search: "TZDATA"})
	if err != nil || len(p.Items) != 1 || p.Items[0].UpdateGUID != tzdata {
		t.Fatalf("search: %+v, %v", p, err)
	}
	p, err = f.svc.Catalog(ctx, f.tech, UpdateScope{}, CatalogQuery{Category: "Security"})
	if err != nil || len(p.Items) != 1 || p.Items[0].UpdateGUID != openssl {
		t.Fatalf("category: %+v, %v", p, err)
	}
	exploited := true
	if p, err = f.svc.Catalog(ctx, f.tech, UpdateScope{}, CatalogQuery{KnownExploited: &exploited}); err != nil || len(p.Items) != 0 {
		t.Fatalf("known exploited: %+v, %v", p, err)
	}
	if p, err = f.svc.Catalog(ctx, f.tech, UpdateScope{}, CatalogQuery{Sort: "failed", Desc: true}); err != nil || p.Items[0].UpdateGUID != tzdata {
		t.Fatalf("by failures: %+v, %v", p, err)
	}

	_, err = f.svc.Catalog(ctx, f.tech, UpdateScope{}, CatalogQuery{Category: "Firmware"})
	wantField(t, err, "category", "Choose")
	_, err = f.svc.Catalog(ctx, f.tech, UpdateScope{}, CatalogQuery{State: "Gone"})
	wantField(t, err, "state", "Choose")
	_, err = f.svc.Catalog(ctx, f.tech, UpdateScope{}, CatalogQuery{Sort: "title"})
	wantField(t, err, "sort", "missing")
	_, err = f.svc.Catalog(ctx, f.tech, UpdateScope{}, CatalogQuery{Search: strings.Repeat("x", 201)})
	wantField(t, err, "q", "200")

	// Nobody with patch.view anywhere sees nothing.
	none := f.user("nora@example.com")
	_, err = f.svc.Catalog(ctx, none, UpdateScope{}, CatalogQuery{})
	wantErr(t, err, apperr.KindForbidden, "")

	// The engine being down is shown as such.
	f.engine.Set(func() { f.engine.Down = true })
	_, err = f.svc.Catalog(ctx, f.tech, UpdateScope{}, CatalogQuery{})
	wantErr(t, err, apperr.KindUnavailable, "patching_unavailable")
}

// TestUpdatePage: one update's counts, CVEs and holds, and the devices that
// report it.
func TestUpdatePage(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx

	v, err := f.svc.Update(ctx, f.tech, openssl, UpdateScope{})
	if err != nil {
		t.Fatal(err)
	}
	if v.Summary.MissingCount != 3 || len(v.Vulnerabilities) != 1 || v.Vulnerabilities[0].CveID != "CVE-2026-1234" || len(v.Holds) != 0 ||
		!v.CanManage || v.CanHold || v.KbNumbers == nil || v.SupersededUpdateGUIDs == nil {
		t.Fatalf("update: %+v", v)
	}
	if len(v.HoldIn) != 0 || v.CanHoldEverywhere {
		t.Fatalf("technician may hold: %+v, %v", v.HoldIn, v.CanHoldEverywhere)
	}
	if v, err := f.svc.Update(ctx, f.orgAdmin, openssl, UpdateScope{}); err != nil || !v.CanHold || !v.CanManage ||
		len(v.HoldIn) != 1 || v.HoldIn[0].ID != f.acme || v.CanHoldEverywhere {
		t.Fatalf("organization administrator: %+v, %v", v, err)
	}
	if v, err := f.svc.Update(ctx, f.admin, openssl, UpdateScope{}); err != nil || !v.CanHold || len(v.HoldIn) != 2 || !v.CanHoldEverywhere ||
		v.HoldIn[0].Name > v.HoldIn[1].Name {
		t.Fatalf("super administrator: %+v, %v", v.HoldIn, err)
	}
	if v, err := f.svc.Update(ctx, f.reader, openssl, UpdateScope{}); err != nil || v.CanHold || v.CanManage || v.HoldIn == nil {
		t.Fatalf("reader: %+v, %v", v, err)
	}
	if v, err := f.svc.Update(ctx, f.siteTech, openssl, UpdateScope{SiteID: f.hq}); err != nil || v.Summary.MissingCount != 1 {
		t.Fatalf("site: %+v, %v", v, err)
	}
	_, err = f.svc.Update(ctx, f.tech, uuid.New(), UpdateScope{})
	wantErr(t, err, apperr.KindNotFound, "")

	// Devices: linked ones with EasyRMM's names, the stray endpoint without a
	// device.
	p, err := f.svc.UpdateDevices(ctx, f.tech, tzdata, UpdateScope{}, "", 1)
	if err != nil || p.TotalCount != 3 || len(p.Items) != 3 {
		t.Fatalf("devices: %+v, %v", p, err)
	}
	byHost := map[string]UpdateDevice{}
	for _, d := range p.Items {
		byHost[d.Hostname] = d
	}
	if d := byHost["web-01"]; d.DeviceID == nil || *d.DeviceID != f.web || d.DeviceName != "WEB-01" || d.SiteName != "HQ" ||
		d.OrganizationName != "Acme" || !d.CanManage || d.State != "Failed" || d.ErrorMessage != "dpkg was interrupted" {
		t.Fatalf("web-01: %+v", d)
	}
	if d := byHost["stray-01"]; d.DeviceID != nil || d.CanManage || d.OrganizationName != "Acme" {
		t.Fatalf("stray-01: %+v", d)
	}
	if p, err := f.svc.UpdateDevices(ctx, f.reader, tzdata, UpdateScope{}, "", 1); err != nil || len(p.Items) != 3 || p.Items[0].CanManage {
		t.Fatalf("reader's devices: %+v, %v", p, err)
	}
	if p, err := f.svc.UpdateDevices(ctx, f.siteTech, tzdata, UpdateScope{SiteID: f.hq}, "", 1); err != nil || len(p.Items) != 1 ||
		p.Items[0].DeviceID == nil || *p.Items[0].DeviceID != f.web {
		t.Fatalf("site's devices: %+v, %v", p, err)
	}
	if p, err := f.svc.UpdateDevices(ctx, f.tech, libc6, UpdateScope{}, "Missing", 1); err != nil || len(p.Items) != 0 {
		t.Fatalf("missing libc6: %+v, %v", p, err)
	}
	_, err = f.svc.UpdateDevices(ctx, f.tech, libc6, UpdateScope{}, "Lost", 1)
	wantField(t, err, "state", "Choose")
}

// TestFleetInstallAndRemove: installing an update on chosen devices or on
// every device that misses it, and removing it, as Admin statements for the
// devices' organizations.
func TestFleetInstallAndRemove(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx

	res, err := f.svc.InstallUpdate(ctx, f.tech, openssl, FleetActionInput{DeviceIDs: []uuid.UUID{f.web, f.dbHost}})
	if err != nil || res.Succeeded != 2 || res.Failed != 0 {
		t.Fatalf("install: %+v, %v", res, err)
	}
	st := f.lastStatement("POST", "/api/v1/updates/"+openssl.String()+"/install")
	if st.Role != RoleAdmin || st.Subject != f.tech.Actor.ID.String() || !slices.Equal(st.Organizations, []uuid.UUID{f.epAcme}) {
		t.Fatalf("install's statement: %+v", st)
	}
	if a := f.audits("patch.install"); len(a) != 2 || a[0].Details["updateId"] != openssl.String() || a[0].Label != "tess@example.com" {
		t.Fatalf("audit: %+v", a)
	}

	// Where it is not missing, the engine leaves the device out, and the
	// result says why.
	res, err = f.svc.InstallUpdate(ctx, f.tech, libc6, FleetActionInput{DeviceIDs: []uuid.UUID{f.web}})
	if err != nil || res.Failed != 1 || !strings.Contains(res.Results[0].Message, "not missing") {
		t.Fatalf("installed already: %+v, %v", res, err)
	}

	// Every device in scope that misses it; the stray endpoint has no device
	// and is not sent.
	res, err = f.svc.InstallUpdate(ctx, f.tech, tzdata, FleetActionInput{All: true})
	if err != nil || res.Succeeded != 2 {
		t.Fatalf("install everywhere: %+v, %v", res, err)
	}
	reqs := f.engine.RequestsTo("POST", "/api/v1/updates/"+tzdata.String()+"/install")
	if ids, _ := reqs[len(reqs)-1].Body["endpointIds"].([]any); len(ids) != 2 || slices.Contains(ids, any(f.eStray.ID.String())) {
		t.Fatalf("sent: %+v", reqs[len(reqs)-1].Body)
	}
	res, err = f.svc.InstallUpdate(ctx, f.siteTech, tzdata, FleetActionInput{All: true, SiteID: f.hq})
	if err != nil || res.Succeeded != 1 || res.Results[0].DeviceID != f.web {
		t.Fatalf("install on a site: %+v, %v", res, err)
	}
	_, err = f.svc.InstallUpdate(ctx, f.siteTech, tzdata, FleetActionInput{All: true})
	wantField(t, err, "siteId", "choose one of them")
	_, err = f.svc.InstallUpdate(ctx, f.tech, tzdata, FleetActionInput{All: true, DeviceIDs: []uuid.UUID{f.web}})
	wantField(t, err, "deviceIds", "not both")
	_, err = f.svc.InstallUpdate(ctx, f.tech, tzdata, FleetActionInput{})
	wantField(t, err, "deviceIds", "Choose")

	// A reader may see but not install.
	_, err = f.svc.InstallUpdate(ctx, f.reader, tzdata, FleetActionInput{DeviceIDs: []uuid.UUID{f.web}})
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.InstallUpdate(ctx, f.reader, tzdata, FleetActionInput{All: true})
	wantErr(t, err, apperr.KindForbidden, "")
	// Someone who reads the organization and manages one site: the other
	// sites' devices are reported, not sent.
	mixed := f.user("max@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme},
		rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	res, err = f.svc.InstallUpdate(ctx, mixed, tzdata, FleetActionInput{All: true})
	if err != nil || res.Succeeded != 1 || res.Failed != 1 {
		t.Fatalf("mixed roles everywhere: %+v, %v", res, err)
	}
	for _, it := range res.Results {
		if it.DeviceID == f.dbHost && !strings.Contains(it.Message, "may not") {
			t.Fatalf("db-01 for mixed roles: %+v", it)
		}
	}

	// Removing: Windows only, excluded too when asked, with the reason.
	_, err = f.svc.RemoveUpdateFromDevices(ctx, f.tech, libc6, FleetActionInput{All: true, Block: true, Reason: strings.Repeat("x", 501)})
	wantField(t, err, "reason", "500")
	res, err = f.svc.RemoveUpdateFromDevices(ctx, f.tech, libc6, FleetActionInput{All: true, Block: true, Reason: "Breaks printing"})
	if err != nil || res.Succeeded != 1 || res.Failed != 1 {
		t.Fatalf("remove: %+v, %v", res, err)
	}
	for _, it := range res.Results {
		if it.DeviceID == f.dbHost && !strings.Contains(it.Message, "Linux endpoint") {
			t.Fatalf("db-01's refusal: %+v", it)
		}
	}
	reqs = f.engine.RequestsTo("POST", "/api/v1/updates/"+libc6.String()+"/uninstall")
	if b := reqs[len(reqs)-1].Body; b["block"] != true || b["reason"] != "Breaks printing" {
		t.Fatalf("removal body: %+v", b)
	}
	if st := reqs[len(reqs)-1].Statement; st.Role != RoleAdmin || !slices.Equal(st.Organizations, []uuid.UUID{f.epAcme}) {
		t.Fatalf("removal's statement: %+v", st)
	}
	if a := f.audits("patch.remove_update"); len(a) != 1 || a[0].Details["block"] != true || a[0].Details["reason"] != "Breaks printing" ||
		a[0].Device == nil || *a[0].Device != f.web {
		t.Fatalf("removal audit: %+v", a)
	}
	// Without block, no reason is sent.
	if _, err := f.svc.RemoveUpdateFromDevices(ctx, f.tech, libc6, FleetActionInput{DeviceIDs: []uuid.UUID{f.web}, Reason: "ignored"}); err != nil {
		t.Fatal(err)
	}
	reqs = f.engine.RequestsTo("POST", "/api/v1/updates/"+libc6.String()+"/uninstall")
	if b := reqs[len(reqs)-1].Body; b["block"] != false || b["reason"] != nil {
		t.Fatalf("removal without block: %+v", b)
	}
}

// TestHolds: organization administrators hold updates in their
// organization, super administrators everywhere; technicians may not.
func TestHolds(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx

	_, err := f.svc.HoldUpdate(ctx, f.tech, openssl, HoldInput{OrganizationID: f.acme, Reason: "Breaks printing"})
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.HoldUpdate(ctx, f.orgAdmin, openssl, HoldInput{OrganizationID: f.acme, Reason: "  "})
	wantField(t, err, "reason", "why")
	_, err = f.svc.HoldUpdate(ctx, f.orgAdmin, openssl, HoldInput{OrganizationID: f.acme, Reason: strings.Repeat("x", 501)})
	wantField(t, err, "reason", "500")
	_, err = f.svc.HoldUpdate(ctx, f.orgAdmin, openssl, HoldInput{Reason: "Everywhere"})
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.HoldUpdate(ctx, f.orgAdmin, openssl, HoldInput{OrganizationID: f.globex, Reason: "Not mine"})
	wantErr(t, err, apperr.KindNotFound, "")

	h, err := f.svc.HoldUpdate(ctx, f.orgAdmin, openssl, HoldInput{OrganizationID: f.acme, Reason: " Breaks printing "})
	if err != nil || h.OrganizationID == nil || *h.OrganizationID != f.acme || h.OrganizationName != "Acme" || !h.CanRelease ||
		h.Reason != "Breaks printing" || h.Source != "Manual" || h.CreatedBy != "easyrmm:otto@example.com" {
		t.Fatalf("hold: %+v, %v", h, err)
	}
	st := f.lastStatement("POST", "/api/v1/updates/"+openssl.String()+"/holds")
	if st.Role != RoleAdmin || st.AllOrganizations || !slices.Equal(st.Organizations, []uuid.UUID{f.epAcme}) {
		t.Fatalf("hold's statement: %+v", st)
	}
	if a := f.audits("patch.hold"); len(a) != 1 || a[0].Details["scope"] != "Acme" || a[0].Details["reason"] != "Breaks printing" {
		t.Fatalf("hold audit: %+v", a)
	}
	_, err = f.svc.HoldUpdate(ctx, f.orgAdmin, openssl, HoldInput{OrganizationID: f.acme, Reason: "Again"})
	wantErr(t, err, apperr.KindConflict, "already_held")

	// Everywhere, by a super administrator.
	every, err := f.svc.HoldUpdate(ctx, f.admin, openssl, HoldInput{Reason: "Known bad"})
	if err != nil || every.OrganizationID != nil || !every.CanRelease {
		t.Fatalf("hold everywhere: %+v, %v", every, err)
	}
	if st := f.lastStatement("POST", "/api/v1/updates/"+openssl.String()+"/holds"); st.Role != RoleSuperAdmin || !st.AllOrganizations {
		t.Fatalf("statement everywhere: %+v", st)
	}
	// One the rollout guard placed in Globex is not Acme's to see.
	globex := f.epGlobex
	f.engine.AddHold(openssl, &globex, "Automatic", "3 of 4 installs failed")

	v, err := f.svc.Update(ctx, f.tech, openssl, UpdateScope{})
	if err != nil || len(v.Holds) != 2 || !v.Summary.OnHold || v.Holds[0].OrganizationID != nil || v.Holds[0].CanRelease || v.Holds[1].CanRelease {
		t.Fatalf("technician's holds: %+v, %v", v.Holds, err)
	}
	if v, err := f.svc.Update(ctx, f.orgAdmin, openssl, UpdateScope{}); err != nil || len(v.Holds) != 2 || v.Holds[0].CanRelease || !v.Holds[1].CanRelease {
		t.Fatalf("administrator's holds: %+v, %v", v.Holds, err)
	}
	if v, err := f.svc.Update(ctx, f.admin, openssl, UpdateScope{}); err != nil || len(v.Holds) != 3 {
		t.Fatalf("super administrator's holds: %+v, %v", v.Holds, err)
	}
	if p, err := f.svc.Catalog(ctx, f.tech, UpdateScope{}, CatalogQuery{}); err != nil || !find(p.Items, openssl).OnHold || find(p.Items, tzdata).OnHold {
		t.Fatalf("catalog's holds: %+v, %v", p, err)
	}

	// Releasing.
	_, err = f.svc.ReleaseHold(ctx, f.tech, openssl, h.ID)
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.ReleaseHold(ctx, f.orgAdmin, openssl, every.ID)
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.ReleaseHold(ctx, f.orgAdmin, openssl, uuid.New())
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.ReleaseHold(ctx, f.orgAdmin, tzdata, h.ID)
	wantErr(t, err, apperr.KindNotFound, "")
	r, err := f.svc.ReleaseHold(ctx, f.orgAdmin, openssl, h.ID)
	if err != nil || r.ReleasedAt == nil || r.CanRelease || r.OrganizationName != "Acme" {
		t.Fatalf("release: %+v, %v", r, err)
	}
	if st := f.lastStatement("POST", "/api/v1/update-holds/"+h.ID.String()+"/release"); st.Role != RoleAdmin ||
		!slices.Equal(st.Organizations, []uuid.UUID{f.epAcme}) {
		t.Fatalf("release's statement: %+v", st)
	}
	if _, err := f.svc.ReleaseHold(ctx, f.admin, openssl, every.ID); err != nil {
		t.Fatal(err)
	}
	if st := f.lastStatement("POST", "/api/v1/update-holds/"+every.ID.String()+"/release"); st.Role != RoleSuperAdmin || !st.AllOrganizations {
		t.Fatalf("release everywhere: %+v", st)
	}
	if a := f.audits("patch.release_hold"); len(a) != 2 || a[0].Details["scope"] != "Acme" || a[1].Details["scope"] != "every organization" {
		t.Fatalf("release audit: %+v", a)
	}
	if v, err := f.svc.Update(ctx, f.tech, openssl, UpdateScope{}); err != nil || len(v.Holds) != 0 || v.Summary.OnHold {
		t.Fatalf("after release: %+v, %v", v.Holds, err)
	}
}

// TestUnmatchedEndpoints: the patching list names the endpoints of
// organizations the caller sees whole that no device is linked to.
func TestUnmatchedEndpoints(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx

	fl, err := f.svc.Fleet(ctx, f.tech, FleetQuery{})
	if err != nil || len(fl.Unmatched) != 1 || fl.Unmatched[0].Hostname != "stray-01" || fl.Unmatched[0].OrganizationID != f.acme ||
		fl.Unmatched[0].OrganizationName != "Acme" {
		t.Fatalf("technician: %+v, %v", fl.Unmatched, err)
	}
	if fl, err := f.svc.Fleet(ctx, f.admin, FleetQuery{}); err != nil || len(fl.Unmatched) != 1 {
		t.Fatalf("super administrator: %+v, %v", fl.Unmatched, err)
	}
	if fl, err := f.svc.Fleet(ctx, f.admin, FleetQuery{OrganizationID: f.globex}); err != nil || len(fl.Unmatched) != 0 {
		t.Fatalf("Globex: %+v, %v", fl.Unmatched, err)
	}
	if fl, err := f.svc.Fleet(ctx, f.siteTech, FleetQuery{}); err != nil || len(fl.Unmatched) != 0 || len(fl.Devices) != 1 {
		t.Fatalf("site technician: %+v, %v", fl, err)
	}
	if fl, err := f.svc.Fleet(ctx, f.tech, FleetQuery{Search: "web"}); err != nil || len(fl.Unmatched) != 0 {
		t.Fatalf("searching: %+v, %v", fl.Unmatched, err)
	}
	if fl, err := f.svc.Fleet(ctx, f.tech, FleetQuery{SiteID: f.hq}); err != nil || len(fl.Unmatched) != 0 {
		t.Fatalf("one site: %+v, %v", fl.Unmatched, err)
	}
}

// TestCatalogConnected: a connected server answers for every
// organization it has, so the catalog covers one at a time, and its
// sites are matched by name.
func TestCatalogConnected(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	_, err := f.svc.Catalog(ctx, f.admin, UpdateScope{}, CatalogQuery{})
	wantErr(t, err, apperr.KindConflict, "easypatch_not_configured")

	f.connect()
	acme, globex := f.ep.Org("Acme Patch"), f.ep.Org("Globex Patch")
	hq := f.ep.Site(acme, "hq")
	for org, ep := range map[uuid.UUID]uuid.UUID{f.acme: acme, f.globex: globex} {
		if err := f.svc.LinkOrganization(ctx, f.admin.Actor, org, ep); err != nil {
			t.Fatal(err)
		}
	}
	web := f.ep.AddEndpoint(acme, "web-01", "", "AAAA-1111")
	db := f.ep.AddEndpoint(acme, "db-01", "", "AAAA-2222")
	f.ep.Set(func() { web.Site, web.SiteName, db.Site, db.SiteName = &hq, "hq", nil, "" })

	_, err = f.svc.Catalog(ctx, f.admin, UpdateScope{}, CatalogQuery{})
	wantField(t, err, "organizationId", "one organization at a time")
	p, err := f.svc.Catalog(ctx, f.admin, UpdateScope{OrganizationID: f.acme}, CatalogQuery{})
	if u := find(p.Items, openssl); err != nil || u == nil || u.MissingCount != 2 {
		t.Fatalf("Acme: %+v, %v", p, err)
	}
	p, err = f.svc.Catalog(ctx, f.admin, UpdateScope{SiteID: f.hq}, CatalogQuery{})
	if u := find(p.Items, openssl); err != nil || u == nil || u.MissingCount != 1 {
		t.Fatalf("HQ: %+v, %v", p, err)
	}
	if reqs := f.ep.RequestsTo("GET", "/api/v1/updates"); len(reqs) != 2 {
		t.Fatalf("catalog requests: %d", len(reqs))
	}
	_, err = f.svc.Catalog(ctx, f.admin, UpdateScope{SiteID: f.branch}, CatalogQuery{})
	wantErr(t, err, apperr.KindConflict, "easypatch_site_not_found")

	// A technician of one linked organization needs no choice.
	tech := f.user("tess@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	if p, err := f.svc.Catalog(ctx, tech, UpdateScope{}, CatalogQuery{}); err != nil || find(p.Items, openssl).MissingCount != 2 {
		t.Fatalf("technician: %+v, %v", p, err)
	}

	// An organization that is not linked.
	other := f.id(`INSERT INTO organizations (name) VALUES ('Initech') RETURNING id`)
	_, err = f.svc.Catalog(ctx, f.admin, UpdateScope{OrganizationID: other}, CatalogQuery{})
	wantErr(t, err, apperr.KindConflict, "easypatch_not_linked")
}
