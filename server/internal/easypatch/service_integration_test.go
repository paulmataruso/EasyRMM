//go:build integration

package easypatch

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t                *testing.T
	ctx              context.Context
	db               *database.DB
	svc              *Service
	ep               *eptest.Server
	acme, hq, branch uuid.UUID
	globex, plant    uuid.UUID
	admin            access.Caller
	// superDSN connects to the test database as the superuser.
	superDSN string
}

// newFixture is EasyRMM on the patching engine as eptest serves it, with
// Acme (HQ and Branch) and Globex (Plant).
func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, ep: eptest.NewEngine(t, reconcileKey), superDSN: inst.SuperDSN}
	f.svc = f.engineService(f.ep)
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.branch = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Branch') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.plant = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, f.globex)
	f.admin = f.user("ada@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	return f
}

func (f *fixture) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

func (f *fixture) device(org, site uuid.UUID, name string) uuid.UUID {
	f.t.Helper()
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform) VALUES ($1, $2, $3, lower($3), 'linux') RETURNING id`,
		org, site, name)
}

// report records the inventory a device's agent sent: its serial and, when
// rep is not nil, its EasyPatch agent.
func (f *fixture) report(device uuid.UUID, serial string, rep *agentproto.EasyPatchAgent) {
	f.t.Helper()
	b, _ := json.Marshal(agentproto.Inventory{System: agentproto.SystemInfo{Serial: serial}, EasyPatch: rep})
	f.exec(`INSERT INTO device_inventory (device_id, hash, data) VALUES ($1, repeat('a', 64), $2)
		ON CONFLICT (device_id) DO UPDATE SET data = $2`, device, b)
}

// unconfigured is a service before UseEngine: patching is not set up.
func (f *fixture) unconfigured() *Service {
	return New(f.db, audit.New(f.db, nil), "1.0.0", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// withoutEngine has f run before UseEngine.
func (f *fixture) withoutEngine() *fixture {
	f.svc = f.unconfigured()
	return f
}

// enginePublicURL is the engine's public address, as eptest's server-info
// gives it: where agents enroll.
const enginePublicURL = "https://patch.example.com"

// enrolled is what an enrolled EasyPatch agent reports.
func (f *fixture) enrolled(e *eptest.Endpoint) *agentproto.EasyPatchAgent {
	return &agentproto.EasyPatchAgent{Version: "1.9.0", Status: "Active", ServerURL: enginePublicURL, EndpointID: e.ID.String(),
		KeyFingerprint: e.Fingerprint}
}

// linkOrg records org as linked to the engine's organization epOrg, as the
// reconciler does when it adopts one (ADR-0040), without a pass that would
// change the engine's organizations.
func (f *fixture) linkOrg(org, epOrg uuid.UUID, name string) {
	f.t.Helper()
	f.exec(`INSERT INTO easypatch_organizations (organization_id, easypatch_id, easypatch_name) VALUES ($1, $2, $3)`, org, epOrg, name)
}

func (f *fixture) sync() int {
	f.t.Helper()
	n, err := f.svc.SyncLinks(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

type linkRow struct {
	state, reason string
	endpoint      *uuid.UUID
}

func (f *fixture) link(device uuid.UUID) (l linkRow) {
	f.t.Helper()
	err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT state, reason, endpoint_id FROM easypatch_devices WHERE device_id = $1`, device).
			Scan(&l.state, &l.reason, &l.endpoint)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return linkRow{state: LinkNone}
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return l
}

type auditRow struct {
	Action, Label string
	Device        *uuid.UUID
	Details       map[string]any
}

func (f *fixture) audits(prefix string) []auditRow {
	f.t.Helper()
	var out []auditRow
	err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(f.ctx, `SELECT action, actor_label, device_id, details FROM audit_log WHERE action LIKE $1 || '%' ORDER BY id`, prefix)
		if err != nil {
			return err
		}
		for rows.Next() {
			var a auditRow
			if err := rows.Scan(&a.Action, &a.Label, &a.Device, &a.Details); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func wantErr(t *testing.T, err error, kind apperr.Kind, code string) {
	t.Helper()
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Kind != kind || (code != "" && ae.Code != code) {
		t.Fatalf("error %#v (%v), want kind %d code %q", ae, err, kind, code)
	}
}

func wantField(t *testing.T, err error, field, text string) {
	t.Helper()
	var ae *apperr.Error
	if !errors.As(err, &ae) || ae.Kind != apperr.KindInvalid || !strings.Contains(ae.Fields[field], text) {
		t.Fatalf("error %#v (%v), want %s: %q", ae, err, field, text)
	}
}

func TestConnection(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx

	// Before UseEngine, patching is not set up.
	none := f.unconfigured()
	c, err := none.Connection(ctx)
	if err != nil || c.Configured {
		t.Fatalf("unset: %+v, %v", c, err)
	}
	_, err = none.Organizations(ctx)
	wantErr(t, err, apperr.KindConflict, "easypatch_not_configured")
	_, err = none.CheckConnection(ctx)
	wantErr(t, err, apperr.KindNotFound, "")
	if n, err := none.SyncLinks(ctx); n != 0 || err != nil {
		t.Fatalf("sync without the engine: %d %v", n, err)
	}
	if res, err := none.Reconcile(ctx); err != nil || res.Created != 0 {
		t.Fatalf("reconcile without the engine: %+v %v", res, err)
	}
	wantErr(t, none.UseEngine(nil), apperr.KindInvalid, "")

	// The engine as Settings shows it.
	c, err = f.svc.Connection(ctx)
	if err != nil || !c.Configured || c.ServerVersion != eptest.EngineVersion || c.PublicURL != enginePublicURL || c.URL != f.ep.URL() ||
		c.CheckedAt == nil || c.LastError != "" {
		t.Fatalf("engine: %+v, %v", c, err)
	}

	// Checks record what they find.
	f.ep.Set(func() { f.ep.Version = "99.0.0" })
	c, err = f.svc.CheckConnection(ctx)
	if err != nil || c.ServerVersion != "99.0.0" || c.LastError != "" {
		t.Fatalf("check: %+v, %v", c, err)
	}
	f.ep.Set(func() { f.ep.Down = true })
	c, err = f.svc.CheckConnection(ctx)
	if err != nil || c.LastError == "" || c.LastErrorAt == nil || !strings.Contains(c.LastError, "database is not available") {
		t.Fatalf("check while down: %+v, %v", c, err)
	}
	f.ep.Set(func() { f.ep.Down = false })
	if c, _ = f.svc.CheckConnection(ctx); c.LastError != "" {
		t.Fatalf("check after: %+v", c)
	}

	// Run stops with its context.
	runCtx, cancel := context.WithCancel(ctx)
	cancel()
	f.svc.Run(runCtx)
}

// TestOrganizationsAndLinks checks which device is which engine endpoint.
// Organizations are linked as the reconciler links them; Globex is not, at
// first.
func TestOrganizationsAndLinks(t *testing.T) {
	f := newFixture(t)
	ctx := f.ctx
	epAcme, epGlobex := f.ep.Org("Acme Patch"), f.ep.Org("Globex Patch")
	f.linkOrg(f.acme, epAcme, "Acme Patch")

	ep := func(org uuid.UUID, host, serial string) *eptest.Endpoint {
		return f.ep.AddEndpoint(org, host, serial, strings.ToUpper(host[:4])+"-E2EA-533D-A960")
	}
	e1 := ep(epAcme, "web-01", "SN1")
	e2 := ep(epGlobex, "db-01", "")
	e3 := ep(epAcme, "app-01", "")
	e4 := ep(epAcme, "files-01", "SN4")
	e5 := ep(epAcme, "print-01", "")
	e6 := ep(epAcme, "old-01", "")
	e7 := ep(epAcme, "web-02", "")
	f.ep.Set(func() { e3.Revoked, e6.Status = true, "Decommissioned" })

	type tc struct {
		name, serial string
		rep          func() *agentproto.EasyPatchAgent
		state        string
		reason       string
	}
	cases := []tc{
		{"web-01", "sn1", func() *agentproto.EasyPatchAgent {
			r := f.enrolled(e1)
			r.ServerURL, r.EndpointID = r.ServerURL+"/", strings.ToUpper(r.EndpointID)
			return r
		}, LinkLinked, ""},
		{"db-01", "", func() *agentproto.EasyPatchAgent { return f.enrolled(e2) }, LinkUnlinked,
			"In the patching engine the endpoint belongs to Globex Patch, not to Acme Patch, the organization linked to this device's."},
		{"app-01", "", func() *agentproto.EasyPatchAgent { return f.enrolled(e3) }, LinkUnlinked,
			"The key fingerprint the device reported is not one of the endpoint's active credentials in the patching engine."},
		{"files-01", "OTHER", func() *agentproto.EasyPatchAgent { return f.enrolled(e4) }, LinkUnlinked,
			`Serial numbers differ: the patching engine has "SN4", EasyRMM has "OTHER".`},
		{"printer-9", "", func() *agentproto.EasyPatchAgent { return f.enrolled(e5) }, LinkUnlinked,
			`Host names differ: the patching engine has "print-01", EasyRMM has "printer-9".`},
		{"old-01", "", func() *agentproto.EasyPatchAgent { return f.enrolled(e6) }, LinkUnlinked,
			"In the patching engine the endpoint is decommissioned."},
		{"new-01", "", func() *agentproto.EasyPatchAgent { return &agentproto.EasyPatchAgent{Status: "NotEnrolled"} }, LinkUnlinked,
			"The EasyPatch agent is not enrolled and active (its status is NotEnrolled)."},
		{"broken-01", "", func() *agentproto.EasyPatchAgent {
			return &agentproto.EasyPatchAgent{Status: "Unknown", Error: "status --json failed: exit status 3"}
		}, LinkUnlinked, "The EasyPatch agent could not report its status (Unknown): status --json failed: exit status 3"},
		{"blank-01", "", func() *agentproto.EasyPatchAgent { return &agentproto.EasyPatchAgent{} }, LinkUnlinked,
			"The EasyPatch agent is not enrolled and active (its status is Unknown)."},
		{"elsewhere-01", "", func() *agentproto.EasyPatchAgent {
			r := f.enrolled(e1)
			r.ServerURL = "https://other.example.com"
			return r
		}, LinkUnlinked, "The EasyPatch agent is enrolled with https://other.example.com, not with this deployment's patching engine."},
		{"web-02.corp.example.com", "", func() *agentproto.EasyPatchAgent {
			r := f.enrolled(e7)
			r.ServerURL = "HTTPS://patch.example.com:443/" // the same address, written differently
			return r
		}, LinkLinked, ""},
		{"noid-01", "", func() *agentproto.EasyPatchAgent {
			r := f.enrolled(e1)
			r.EndpointID = ""
			return r
		}, LinkUnlinked, "The EasyPatch agent did not report its endpoint id."},
		{"ghost-01", "", func() *agentproto.EasyPatchAgent {
			r := f.enrolled(e1)
			r.EndpointID = uuid.NewString()
			return r
		}, LinkUnlinked, "The patching engine has no endpoint"},
	}
	devices := map[string]uuid.UUID{}
	for _, c := range cases {
		devices[c.name] = f.device(f.acme, f.hq, c.name)
		f.report(devices[c.name], c.serial, c.rep())
	}
	g1 := f.device(f.globex, f.plant, "db-01")
	f.report(g1, "", f.enrolled(e2))
	quiet := f.device(f.acme, f.hq, "quiet-01")
	f.report(quiet, "", nil)

	if n := f.sync(); n != len(cases)+1 {
		t.Fatalf("checked %d", n)
	}
	for _, c := range cases {
		l := f.link(devices[c.name])
		if l.state != c.state || !strings.HasPrefix(l.reason, c.reason) {
			t.Errorf("%s: %+v", c.name, l)
		}
	}
	if l := f.link(g1); l.state != LinkUnlinked || l.reason != "The device's organization has no patching organization yet: EasyRMM makes it on its next pass." {
		t.Errorf("globex: %+v", l)
	}
	if l := f.link(quiet); l.state != LinkNone {
		t.Errorf("no agent: %+v", l)
	}
	if l := f.link(devices["web-01"]); l.endpoint == nil || *l.endpoint != e1.ID {
		t.Errorf("endpoint: %+v", l)
	}

	// Nothing is due again soon.
	if n := f.sync(); n != 0 {
		t.Fatalf("checked again: %d", n)
	}

	// A second device claiming a linked endpoint is refused.
	clone := f.device(f.acme, f.branch, "web-01")
	f.report(clone, "", f.enrolled(e1))
	f.sync()
	if l := f.link(clone); l.state != LinkUnlinked || l.reason != "web-01 is already linked to this patching engine endpoint." {
		t.Errorf("clone: %+v", l)
	}

	// Settings lists the devices that are not linked.
	dl, err := f.svc.DeviceLinks(ctx)
	if err != nil || len(dl) != len(cases)-2+2 || dl[0].State != LinkUnlinked || dl[0].DeviceName == "" || dl[0].OrganizationName != "Acme" {
		t.Fatalf("device links: %d %+v, %v", len(dl), dl, err)
	}

	// EasyPatch failing keeps what was known.
	f.svc.now = func() time.Time { return time.Now().Add(7 * time.Hour) }
	f.ep.Set(func() { f.ep.Down = true })
	f.sync()
	if l := f.link(devices["web-01"]); l.state != LinkLinked {
		t.Errorf("link lost while EasyPatch was down: %+v", l)
	}
	if c, _ := f.svc.Connection(ctx); !strings.Contains(c.LastError, "database is not available") {
		t.Errorf("error not recorded: %+v", c)
	}
	f.ep.Set(func() { f.ep.Down = false })
	if n := f.sync(); n < 2 {
		t.Fatalf("old links not checked again: %d", n)
	}
	f.svc.now = time.Now

	// A refused device is tried again after 15 minutes.
	f.ep.Set(func() { e3.Revoked = false })
	f.sync()
	if l := f.link(devices["app-01"]); l.state != LinkUnlinked {
		t.Errorf("app-01 tried again at once: %+v", l)
	}
	f.svc.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	f.sync()
	f.svc.now = time.Now
	if l := f.link(devices["app-01"]); l.state != LinkLinked {
		t.Errorf("app-01 not tried again: %+v", l)
	}

	// A changed report is checked at once; a removed one is forgotten.
	f.report(devices["app-01"], "", &agentproto.EasyPatchAgent{Version: "1.9.0", Status: "Active", ServerURL: enginePublicURL,
		EndpointID: e3.ID.String(), KeyFingerprint: "0000-0000"})
	f.report(devices["web-02.corp.example.com"], "", nil)
	f.sync()
	if l := f.link(devices["app-01"]); l.state != LinkUnlinked || !strings.Contains(l.reason, "key fingerprint") {
		t.Errorf("app-01 with another key: %+v", l)
	}
	if l := f.link(devices["web-02.corp.example.com"]); l.state != LinkNone {
		t.Errorf("removed report kept: %+v", l)
	}

	// Once the reconciler links Globex, its refused device is linked at the
	// next try.
	f.linkOrg(f.globex, epGlobex, "Globex Patch")
	f.svc.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	f.sync()
	f.svc.now = time.Now
	if l := f.link(g1); l.state != LinkLinked {
		t.Errorf("globex device: %+v", l)
	}
	orgs, err := f.svc.Organizations(ctx)
	if err != nil || len(orgs.EasyPatch) != 2 || len(orgs.Links) != 2 || orgs.Error != "" {
		t.Fatalf("organizations: %+v, %v", orgs, err)
	}
	acme := orgs.Links[0]
	if acme.OrganizationName != "Acme" || acme.EasyPatchName != "Acme Patch" || acme.LinkedBy != "" ||
		acme.Devices.Linked != 1 || acme.Devices.Unlinked != 12 || acme.Devices.Pending != 0 {
		t.Fatalf("acme link: %+v", acme)
	}
	f.ep.Set(func() { f.ep.Down = true })
	orgs, err = f.svc.Organizations(ctx)
	if err != nil || len(orgs.EasyPatch) != 0 || len(orgs.Links) != 2 || !strings.Contains(orgs.Error, "database is not available") {
		t.Fatalf("organizations while down: %+v, %v", orgs, err)
	}
	f.ep.Set(func() { f.ep.Down = false })
}

// patchingFixture: Acme is linked to an EasyPatch organization. HQ has
// web-01 (linked), app-01 (refused) and lab-01 (no EasyPatch agent); Branch
// has db-01 (linked). Globex is not linked.
type patchingFixture struct {
	*fixture
	epAcme                       uuid.UUID
	e1, e2                       *eptest.Endpoint
	web, app, lab, db, plantDev  uuid.UUID
	tech, viewer, outsider, none access.Caller
}

func newPatching(t *testing.T) *patchingFixture {
	f := &patchingFixture{fixture: newFixture(t)}
	f.epAcme = f.ep.Org("Acme Patch")
	f.linkOrg(f.acme, f.epAcme, "Acme Patch")
	f.e1 = f.ep.AddEndpoint(f.epAcme, "web-01", "", "AAAA-1111")
	f.e2 = f.ep.AddEndpoint(f.epAcme, "db-01", "", "BBBB-2222")
	e3 := f.ep.AddEndpoint(f.epAcme, "app-01", "", "CCCC-3333")
	f.web = f.device(f.acme, f.hq, "web-01")
	f.app = f.device(f.acme, f.hq, "app-01")
	f.lab = f.device(f.acme, f.hq, "lab-01")
	f.db = f.device(f.acme, f.branch, "db-01")
	f.plantDev = f.device(f.globex, f.plant, "plc-01")
	f.report(f.web, "", f.enrolled(f.e1))
	f.report(f.db, "", f.enrolled(f.e2))
	bad := f.enrolled(e3)
	bad.KeyFingerprint = "FFFF-0000"
	f.report(f.app, "", bad)
	f.sync()
	f.tech = f.user("tess@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	f.viewer = f.user("rory@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	f.outsider = f.user("gus@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.globex})
	f.none = f.user("nobody@example.com")
	return f
}

func names(list []FleetDevice) []string {
	out := []string{}
	for _, d := range list {
		out = append(out, d.Name)
	}
	return out
}

func TestFleetAndViews(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx

	st, err := f.svc.Status(ctx, f.viewer)
	if err != nil || !st.Configured {
		t.Fatalf("status: %+v, %v", st, err)
	}
	_, err = f.svc.Status(ctx, f.none)
	wantErr(t, err, apperr.KindForbidden, "")

	fl, err := f.svc.Fleet(ctx, f.admin, FleetQuery{})
	if err != nil || !slices.Equal(names(fl.Devices), []string{"db-01", "app-01", "lab-01", "web-01"}) || len(fl.Errors) != 0 || fl.Truncated {
		t.Fatalf("admin fleet: %v %+v, %v", names(fl.Devices), fl, err)
	}
	web := fl.Devices[3]
	if web.Link != LinkLinked || web.Endpoint == nil || web.Endpoint.ComplianceStatus != "MissingUpdates" || !web.CanManage ||
		web.OrganizationName != "Acme" || web.SiteName != "HQ" || web.Platform != "linux" || web.CheckedAt == nil {
		t.Fatalf("web-01: %+v", web)
	}
	if a := fl.Devices[1]; a.Link != LinkUnlinked || !strings.Contains(a.Reason, "key fingerprint") || a.Endpoint != nil {
		t.Fatalf("app-01: %+v", a)
	}
	if l := fl.Devices[2]; l.Link != LinkNone {
		t.Fatalf("lab-01: %+v", l)
	}

	fl, _ = f.svc.Fleet(ctx, f.tech, FleetQuery{})
	if !slices.Equal(names(fl.Devices), []string{"app-01", "lab-01", "web-01"}) || !fl.Devices[2].CanManage {
		t.Fatalf("technician fleet: %v", names(fl.Devices))
	}
	fl, _ = f.svc.Fleet(ctx, f.viewer, FleetQuery{})
	if len(fl.Devices) != 4 || fl.Devices[3].CanManage {
		t.Fatalf("viewer fleet: %+v", fl.Devices)
	}
	fl, _ = f.svc.Fleet(ctx, f.outsider, FleetQuery{})
	if len(fl.Devices) != 0 {
		t.Fatalf("outsider fleet: %v", names(fl.Devices))
	}
	_, err = f.svc.Fleet(ctx, f.none, FleetQuery{})
	wantErr(t, err, apperr.KindForbidden, "")

	group := f.id(`INSERT INTO device_groups (organization_id, site_id, name) VALUES ($1, $2, 'Web') RETURNING id`, f.acme, f.hq)
	f.exec(`UPDATE devices SET device_group_id = $1 WHERE id = $2`, group, f.web)
	filters := []struct {
		q    FleetQuery
		want []string
	}{
		{FleetQuery{Compliance: "MissingUpdates"}, []string{"db-01", "web-01"}},
		{FleetQuery{Compliance: "unlinked"}, []string{"app-01", "lab-01"}},
		{FleetQuery{Compliance: "Compliant"}, []string{}},
		{FleetQuery{Search: "WEB"}, []string{"web-01"}},
		{FleetQuery{Search: "%"}, []string{}},
		{FleetQuery{SiteID: f.branch}, []string{"db-01"}},
		{FleetQuery{GroupID: group}, []string{"web-01"}},
		{FleetQuery{OrganizationID: f.globex}, []string{}},
	}
	for _, c := range filters {
		fl, err := f.svc.Fleet(ctx, f.admin, c.q)
		if err != nil || !slices.Equal(names(fl.Devices), c.want) {
			t.Errorf("%+v: %v, %v", c.q, names(fl.Devices), err)
		}
	}
	_, err = f.svc.Fleet(ctx, f.admin, FleetQuery{Compliance: "Great"})
	wantField(t, err, "compliance", "compliance status")
	_, err = f.svc.Fleet(ctx, f.admin, FleetQuery{Search: strings.Repeat("x", 201)})
	wantField(t, err, "q", "200")

	// The endpoint list is reused for 30 seconds.
	before := len(f.ep.RequestsTo("GET", "/api/v1/endpoints"))
	_, _ = f.svc.Fleet(ctx, f.admin, FleetQuery{})
	if after := len(f.ep.RequestsTo("GET", "/api/v1/endpoints")); after != before {
		t.Fatalf("not cached: %d → %d", before, after)
	}
	// EasyPatch down: the devices still show, with the error.
	f.svc.fleet.clear()
	f.ep.Set(func() { f.ep.Down = true })
	fl, err = f.svc.Fleet(ctx, f.admin, FleetQuery{})
	if err != nil || len(fl.Devices) != 4 || fl.Devices[3].Endpoint != nil || len(fl.Errors) != 1 || !strings.HasPrefix(fl.Errors[0], "Acme: ") {
		t.Fatalf("fleet while down: %+v, %v", fl, err)
	}
	f.ep.Set(func() { f.ep.Down = false })
	// An endpoint EasyPatch stops listing shows as not linked.
	f.svc.fleet.clear()
	f.ep.Set(func() { f.e2.Status = "Revoked" })
	fl, _ = f.svc.Fleet(ctx, f.admin, FleetQuery{})
	if d := fl.Devices[0]; d.Link != LinkUnlinked || d.Reason != "The patching engine no longer lists this endpoint as active." {
		t.Fatalf("revoked: %+v", d)
	}
	f.ep.Set(func() { f.e2.Status = "Active" })
	f.svc.fleet.clear()

	// One device.
	d, err := f.svc.Device(ctx, f.tech, f.web)
	if err != nil || d.Link != LinkLinked || d.Endpoint == nil || d.Endpoint.Summary.Hostname != "web-01" || d.Endpoint.Credentials != nil ||
		d.Policy == nil || d.Policy.MaintenanceStart != "02:00" || !d.CanManage || d.Error != "" {
		t.Fatalf("device: %+v, %v", d, err)
	}
	if d, _ := f.svc.Device(ctx, f.viewer, f.web); d.CanManage {
		t.Fatal("viewer can manage")
	}
	_, err = f.svc.Device(ctx, f.tech, f.db)
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.Device(ctx, f.outsider, f.web)
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.Device(ctx, f.admin, uuid.New())
	wantErr(t, err, apperr.KindNotFound, "")
	if d, err := f.svc.Device(ctx, f.admin, f.app); err != nil || d.Link != LinkUnlinked || d.Endpoint != nil || d.Reason == "" {
		t.Fatalf("refused device: %+v, %v", d, err)
	}
	f.ep.Set(func() { f.ep.Down = true })
	if d, err := f.svc.Device(ctx, f.admin, f.web); err != nil || d.Endpoint != nil || !strings.Contains(d.Error, "The database is not available") {
		t.Fatalf("device while down: %+v, %v", d, err)
	}
	f.ep.Set(func() { f.ep.Down = false })

	ups, err := f.svc.Updates(ctx, f.tech, f.web, "")
	if err != nil || len(ups) != 2 {
		t.Fatalf("updates: %+v, %v", ups, err)
	}
	if ups, _ := f.svc.Updates(ctx, f.tech, f.web, "Failed"); len(ups) != 1 || ups[0].ErrorMessage != "dpkg was interrupted" {
		t.Fatalf("failed updates: %+v", ups)
	}
	_, err = f.svc.Updates(ctx, f.tech, f.web, "Installed")
	wantField(t, err, "state", "update state")
	_, err = f.svc.Updates(ctx, f.tech, f.app, "")
	wantErr(t, err, apperr.KindConflict, "easypatch_not_linked")
	_, err = f.svc.Updates(ctx, f.tech, f.lab, "")
	wantErr(t, err, apperr.KindConflict, "easypatch_no_agent")
	f.exec(`UPDATE easypatch_devices SET state = 'pending', reason = '' WHERE device_id = $1`, f.app)
	_, err = f.svc.Updates(ctx, f.tech, f.app, "")
	wantErr(t, err, apperr.KindConflict, "easypatch_link_pending")
	if inst, err := f.svc.InstalledUpdates(ctx, f.viewer, f.web); err != nil || len(inst) != 1 {
		t.Fatalf("installed: %+v, %v", inst, err)
	}
	if h, err := f.svc.History(ctx, f.viewer, f.web, 0); err != nil || h.TotalCount != 1 || h.Items[0].Result != "Succeeded" {
		t.Fatalf("history: %+v, %v", h, err)
	}
	if j, err := f.svc.DeviceJobs(ctx, f.viewer, f.web, 1); err != nil || j.TotalCount != 0 || j.Items == nil {
		t.Fatalf("jobs: %+v, %v", j, err)
	}
	f.ep.Set(func() { f.ep.Down = true })
	_, err = f.svc.InstalledUpdates(ctx, f.viewer, f.web)
	wantErr(t, err, apperr.KindUnavailable, "patching_unavailable")
	_, err = f.svc.History(ctx, f.viewer, f.web, 1)
	wantErr(t, err, apperr.KindUnavailable, "")
	_, err = f.svc.DeviceJobs(ctx, f.viewer, f.web, 1)
	wantErr(t, err, apperr.KindUnavailable, "")
	_, err = f.svc.Updates(ctx, f.viewer, f.web, "")
	wantErr(t, err, apperr.KindUnavailable, "")
	f.ep.Set(func() { f.ep.Down = false })
}

func TestActions(t *testing.T) {
	f := newPatching(t)
	ctx := f.ctx

	// Scans.
	_, err := f.svc.Scan(ctx, f.viewer, ActionInput{DeviceIDs: []uuid.UUID{f.web}})
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.Scan(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.web, f.db}})
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.Scan(ctx, f.tech, ActionInput{})
	wantField(t, err, "deviceIds", "from 1 to 1000")
	_, err = f.svc.Scan(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.web}, UpdateIDs: []uuid.UUID{uuid.New()}})
	wantField(t, err, "deviceIds", "devices only")
	res, err := f.svc.Scan(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.web, f.app, f.lab, f.web}})
	if err != nil || res.Succeeded != 1 || res.Failed != 2 || len(res.Results) != 3 {
		t.Fatalf("scan: %+v, %v", res, err)
	}
	byDevice := map[uuid.UUID]ActionItem{}
	for _, r := range res.Results {
		byDevice[r.DeviceID] = r
	}
	if r := byDevice[f.web]; !r.OK || r.JobID == nil || r.DeviceName != "web-01" {
		t.Fatalf("web-01: %+v", r)
	}
	if r := byDevice[f.app]; r.OK || !strings.Contains(r.Message, "key fingerprint") {
		t.Fatalf("app-01: %+v", r)
	}
	if r := byDevice[f.lab]; r.OK || !strings.Contains(r.Message, "no EasyPatch agent") {
		t.Fatalf("lab-01: %+v", r)
	}
	scans := f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/scan")
	if len(scans) != 1 || scans[0].Statement.Name != "tess@example.com" || len(scans[0].Body["endpointIds"].([]any)) != 1 {
		t.Fatalf("scan request: %+v", scans)
	}
	got := f.audits("patch.scan")
	if len(got) != 1 || got[0].Label != "tess@example.com" || *got[0].Device != f.web || got[0].Details["jobId"] != byDevice[f.web].JobID.String() ||
		got[0].Details["device"] != "web-01" || got[0].Details["endpointId"] != f.e1.ID.String() {
		t.Fatalf("scan audit: %+v", got)
	}
	// Only devices that are not linked: nothing goes to EasyPatch.
	if res, err := f.svc.Scan(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.lab}}); err != nil || res.Failed != 1 || res.Succeeded != 0 {
		t.Fatalf("scan unlinked: %+v, %v", res, err)
	}

	// Installs of every eligible update.
	f.ep.Set(func() { f.e2.Missing = 0 })
	res, err = f.svc.Install(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.web, f.db}})
	if err != nil || res.Succeeded != 1 || res.Failed != 1 {
		t.Fatalf("install: %+v, %v", res, err)
	}
	for _, r := range res.Results {
		if r.DeviceID == f.db && (r.OK || r.Message != "db-01 has no eligible updates.") {
			t.Fatalf("db-01: %+v", r)
		}
	}
	got = f.audits("patch.install")
	if len(got) != 1 || got[0].Details["updates"] != "all eligible" || got[0].Details["scheduledAt"] != nil || *got[0].Device != f.web {
		t.Fatalf("install audit: %+v", got)
	}
	f.ep.Set(func() { f.e2.Missing = 2 })

	// Chosen updates, on one device.
	guid := uuid.New()
	_, err = f.svc.Install(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.web, f.db}, UpdateIDs: []uuid.UUID{guid}})
	wantField(t, err, "updateIds", "one device at a time")
	res, err = f.svc.Install(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.web}, UpdateIDs: []uuid.UUID{guid}})
	if err != nil || res.Succeeded != 1 || res.Results[0].JobID == nil {
		t.Fatalf("install selected: %+v, %v", res, err)
	}
	reqs := f.ep.RequestsTo("POST", "/api/v1/endpoints/"+f.e1.ID.String()+"/install-updates")
	if len(reqs) != 1 || reqs[0].Body["mode"] != "Selected" || reqs[0].Statement.Name != "tess@example.com" {
		t.Fatalf("selected request: %+v", reqs)
	}
	got = f.audits("patch.install")
	if len(got) != 2 || got[1].Details["updates"] != 1.0 || got[1].Details["jobId"] != res.Results[0].JobID.String() {
		t.Fatalf("selected audit: %+v", got)
	}
	f.ep.Set(func() { f.e1.Missing = 0 })
	res, err = f.svc.Install(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.web}, UpdateIDs: []uuid.UUID{guid}})
	if err != nil || res.Failed != 1 || res.Results[0].Message != "The patching engine refused: web-01 has no eligible updates." {
		t.Fatalf("nothing to install: %+v, %v", res, err)
	}
	f.ep.Set(func() { f.e1.Missing = 2 })
	if res, err := f.svc.Install(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.lab}, UpdateIDs: []uuid.UUID{guid}}); err != nil || res.Failed != 1 {
		t.Fatalf("selected on a device without EasyPatch: %+v, %v", res, err)
	}

	// Installs at a later time, within 31 days.
	later := time.Now().Add(2 * time.Hour)
	soon, far := time.Now().Add(30*time.Second), time.Now().Add(32*24*time.Hour)
	_, err = f.svc.Install(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.web}, ScheduledAt: &soon})
	wantField(t, err, "scheduledAt", "in the future")
	_, err = f.svc.Install(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.web}, ScheduledAt: &far})
	wantField(t, err, "scheduledAt", "within 31 days")
	res, err = f.svc.Install(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.web, f.db}, ScheduledAt: &later})
	if err != nil || res.Succeeded != 2 {
		t.Fatalf("scheduled install: %+v, %v", res, err)
	}
	bulk := f.ep.RequestsTo("POST", "/api/v1/endpoints/bulk/install-updates")
	if at := bulk[len(bulk)-1].Body["scheduledAt"]; at != later.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("scheduledAt sent: %v", at)
	}
	got = f.audits("patch.install")
	if last := got[len(got)-1]; last.Details["scheduledAt"] != later.UTC().Format(time.RFC3339) {
		t.Fatalf("scheduled audit: %+v", last)
	}

	// Jobs, as each user may see them.
	list, err := f.svc.Jobs(ctx, f.admin, JobsQuery{})
	jobs := list.Items
	if err != nil || len(jobs) != 5 || list.Capped || jobs[0].CreatedAt.Before(jobs[4].CreatedAt) || jobs[0].DeviceName == "" || !jobs[0].CanManage {
		t.Fatalf("jobs: %d %+v, %v", len(jobs), jobs, err)
	}
	tl, _ := f.svc.Jobs(ctx, f.tech, JobsQuery{Active: true})
	tj := tl.Items
	for _, j := range tj {
		if j.DeviceID != f.web {
			t.Fatalf("technician sees %s", j.DeviceName)
		}
	}
	if len(tj) != 4 {
		t.Fatalf("technician jobs: %d", len(tj))
	}
	if vj, _ := f.svc.Jobs(ctx, f.viewer, JobsQuery{OrganizationID: f.acme}); len(vj.Items) != 5 || vj.Items[0].CanManage {
		t.Fatalf("viewer jobs: %+v", vj)
	}
	if oj, _ := f.svc.Jobs(ctx, f.outsider, JobsQuery{}); len(oj.Items) != 0 {
		t.Fatalf("outsider jobs: %+v", oj)
	}
	_, err = f.svc.Jobs(ctx, f.none, JobsQuery{})
	wantErr(t, err, apperr.KindForbidden, "")

	// Filters reach EasyPatch: a type, a status, how it started, a device and
	// when it was created.
	byType := func(q JobsQuery) []string {
		t.Helper()
		l, err := f.svc.Jobs(ctx, f.admin, q)
		if err != nil {
			t.Fatalf("jobs %+v: %v", q, err)
		}
		var out []string
		for _, j := range l.Items {
			out = append(out, j.DeviceName+":"+j.Type)
		}
		return out
	}
	scanJobs := byType(JobsQuery{Type: "UpdateScan"})
	if len(scanJobs) == 0 || len(scanJobs) == 5 {
		t.Fatalf("scans: %v", scanJobs)
	}
	for _, j := range scanJobs {
		if !strings.HasSuffix(j, ":UpdateScan") {
			t.Fatalf("scans: %v", scanJobs)
		}
	}
	if got := byType(JobsQuery{Trigger: "Scheduled"}); len(got) != 0 {
		t.Fatalf("scheduled jobs: %v", got)
	}
	if got := byType(JobsQuery{Status: "Completed"}); len(got) != 0 {
		t.Fatalf("completed jobs: %v", got)
	}
	if got := byType(JobsQuery{DeviceID: f.db}); len(got) != 1 || !strings.HasPrefix(got[0], "db-01:") {
		t.Fatalf("one device's jobs: %v", got)
	}
	future := time.Now().Add(time.Hour)
	if got := byType(JobsQuery{From: &future}); len(got) != 0 {
		t.Fatalf("jobs from the future: %v", got)
	}
	if got := byType(JobsQuery{To: &future}); len(got) != 5 {
		t.Fatalf("jobs before the future: %v", got)
	}
	// A device the caller may not see, and filters EasyPatch would refuse.
	_, err = f.svc.Jobs(ctx, f.tech, JobsQuery{DeviceID: f.db})
	wantErr(t, err, apperr.KindNotFound, "")
	for field, q := range map[string]JobsQuery{"status": {Status: "Done"}, "type": {Type: "Reboot"}, "trigger": {Trigger: "Cron"},
		"to": {From: &future, To: &future}} {
		_, err = f.svc.Jobs(ctx, f.admin, q)
		wantField(t, err, field, "Choose")
	}

	var webJob, dbJob uuid.UUID
	for _, j := range jobs {
		switch j.DeviceID {
		case f.web:
			webJob = j.ID
		case f.db:
			dbJob = j.ID
		}
	}
	jd, err := f.svc.Job(ctx, f.tech, webJob)
	if err != nil || jd.DeviceName != "web-01" || len(jd.Items) != 1 || len(jd.Events) != 1 || !jd.CanManage {
		t.Fatalf("job: %+v, %v", jd, err)
	}
	_, err = f.svc.Job(ctx, f.tech, dbJob)
	wantErr(t, err, apperr.KindNotFound, "")
	_, err = f.svc.Job(ctx, f.tech, uuid.New())
	wantErr(t, err, apperr.KindNotFound, "")

	// Stopping a job.
	_, err = f.svc.CancelJob(ctx, f.viewer, webJob)
	wantErr(t, err, apperr.KindForbidden, "")
	_, err = f.svc.CancelJob(ctx, f.tech, dbJob)
	wantErr(t, err, apperr.KindNotFound, "")
	jd, err = f.svc.CancelJob(ctx, f.tech, webJob)
	if err != nil || jd.Summary.Status != eptest.StatusCanceled {
		t.Fatalf("cancel: %+v, %v", jd, err)
	}
	_, err = f.svc.CancelJob(ctx, f.tech, webJob)
	wantErr(t, err, apperr.KindConflict, "job_finished")
	got = f.audits("patch.cancel")
	if len(got) != 1 || got[0].Details["jobId"] != webJob.String() || got[0].Label != "tess@example.com" {
		t.Fatalf("cancel audit: %+v", got)
	}
	if c := f.ep.RequestsTo("POST", "/api/v1/jobs/"+webJob.String()+"/cancel"); c[0].Statement.Name != "tess@example.com" {
		t.Fatalf("cancel request: %+v", c)
	}

	// The engine failing a whole request.
	f.ep.Set(func() { f.ep.Down = true })
	_, err = f.svc.Scan(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.web}})
	wantErr(t, err, apperr.KindUnavailable, "patching_unavailable")
	_, err = f.svc.Install(ctx, f.tech, ActionInput{DeviceIDs: []uuid.UUID{f.web}, UpdateIDs: []uuid.UUID{guid}})
	wantErr(t, err, apperr.KindUnavailable, "patching_unavailable")
	_, err = f.svc.Jobs(ctx, f.tech, JobsQuery{})
	wantErr(t, err, apperr.KindUnavailable, "")
	f.ep.Set(func() { f.ep.Down = false })
	if n := len(f.audits("patch.")); n != 6 {
		t.Fatalf("%d patch audit records", n)
	}

	// Without the engine, nothing works.
	f.withoutEngine()
	_, err = f.svc.Fleet(ctx, f.admin, FleetQuery{})
	wantErr(t, err, apperr.KindConflict, "easypatch_not_configured")
	_, err = f.svc.Device(ctx, f.admin, f.web)
	wantErr(t, err, apperr.KindConflict, "easypatch_not_configured")
	_, err = f.svc.Jobs(ctx, f.admin, JobsQuery{})
	wantErr(t, err, apperr.KindConflict, "easypatch_not_configured")
	_, err = f.svc.Job(ctx, f.admin, webJob)
	wantErr(t, err, apperr.KindConflict, "easypatch_not_configured")
	_, err = f.svc.Scan(ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{f.web}})
	wantErr(t, err, apperr.KindConflict, "easypatch_not_configured")
	_, err = f.svc.Updates(ctx, f.admin, f.web, "")
	wantErr(t, err, apperr.KindConflict, "")
	if st, err := f.svc.Status(ctx, f.tech); err != nil || st.Configured {
		t.Fatalf("status: %+v, %v", st, err)
	}
}
