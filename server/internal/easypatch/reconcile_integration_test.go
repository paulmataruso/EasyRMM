//go:build integration

package easypatch

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// The reconciler (one-product plan B5, ADR-0040): each case on the
// patching engine as eptest serves it, which the contract test holds to
// the real engine's rules.

var reconcileKey = bytes.Repeat([]byte{7}, 32)

// bundle runs the fixture's connector on a patching engine.
func (f *fixture) bundle() *eptest.Server {
	f.t.Helper()
	engine := eptest.NewEngine(f.t, reconcileKey)
	f.svc = f.engineService(engine)
	return engine
}

// engineService is a connector started on engine, as at EasyRMM's start:
// with nothing remembered but the database.
func (f *fixture) engineService(engine *eptest.Server, opts ...EngineOption) *Service {
	f.t.Helper()
	signer, err := NewSigner(reconcileKey)
	if err != nil {
		f.t.Fatal(err)
	}
	client, err := NewEngineClient(engine.URL(), signer, "1.0.0")
	if err != nil {
		f.t.Fatal(err)
	}
	svc := New(f.db, audit.New(f.db, nil), nil, "1.0.0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := svc.UseEngine(f.ctx, client, opts...); err != nil {
		f.t.Fatal(err)
	}
	return svc
}

// reconcile makes a full pass.
func (f *fixture) reconcile() ReconcileResult {
	f.t.Helper()
	f.svc.Kick()
	res, err := f.svc.Reconcile(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

// later moves the connector's clock on.
func (f *fixture) later(d time.Duration) {
	at := f.svc.now().Add(d)
	f.svc.now = func() time.Time { return at }
}

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func engineOrg(t *testing.T, engine *eptest.Server, id uuid.UUID) eptest.OrgInfo {
	t.Helper()
	for _, o := range engine.Organizations() {
		if o.ID == id {
			return o
		}
	}
	t.Fatalf("the engine has no organization %s", id)
	return eptest.OrgInfo{}
}

func engineSite(t *testing.T, engine *eptest.Server, id uuid.UUID) eptest.SiteInfo {
	t.Helper()
	for _, x := range engine.Sites() {
		if x.ID == id {
			return x
		}
	}
	t.Fatalf("the engine has no site %s", id)
	return eptest.SiteInfo{}
}

func orgNames(engine *eptest.Server) []string {
	var out []string
	for _, o := range engine.Organizations() {
		out = append(out, o.Name)
	}
	slices.Sort(out)
	return out
}

// engineReport is what an agent enrolled with the engine reports.
func engineReport(e *eptest.Endpoint) *agentproto.EasyPatchAgent {
	return &agentproto.EasyPatchAgent{Version: "1.9.0", Status: "Active", ServerURL: "https://patch.example.com", EndpointID: e.ID.String(),
		KeyFingerprint: e.Fingerprint}
}

// TestReconcileOrganizations: every organization and site has its own in
// the engine, named and in the time zone as in EasyRMM.
func TestReconcileOrganizations(t *testing.T) {
	f := newFixture(t)
	engine := f.bundle()
	// The engine has an organization named as Globex, one whose name
	// differs from Acme's only by case, and an archived Initech.
	globexEP := engine.Org("Globex")
	acmeUpper := engine.Org("ACME")
	initechOld := engine.Org("Initech")
	engine.ChangeOrganization(initechOld, func(o *eptest.OrgInfo) { o.Active = false })
	f.exec(`UPDATE organizations SET timezone = 'Europe/London' WHERE id = $1`, f.acme)
	f.exec(`UPDATE sites SET timezone = 'America/New_York' WHERE id = $1`, f.branch)
	initech := f.id(`INSERT INTO organizations (name) VALUES ('Initech') RETURNING id`)

	res := f.reconcile()
	if res.Created != 5 || res.Adopted != 1 || len(res.Problems) != 0 {
		t.Fatalf("first pass: %+v", res)
	}
	// Acme is made distinct from ACME; Globex's is adopted; the archived
	// Initech is not.
	acme := engineOrg(t, engine, f.engineOrg(f.acme))
	if want := "Acme (" + shortID(f.acme) + ")"; acme.Name != want || acme.TimeZone != "Europe/London" || !acme.Active {
		t.Fatalf("Acme: %+v", acme)
	}
	if f.engineOrg(f.globex) != globexEP {
		t.Fatal("Globex's organization was not adopted")
	}
	if got := engineOrg(t, engine, f.engineOrg(initech)); got.ID == initechOld || got.Name != "Initech ("+shortID(initech)+")" {
		t.Fatalf("Initech: %+v", got)
	}
	if x := engineSite(t, engine, f.engineSite(f.branch)); x.Name != "Branch" || x.TimeZone != "America/New_York" || x.Org != acme.ID {
		t.Fatalf("Branch: %+v", x)
	}
	if x := engineSite(t, engine, f.engineSite(f.plant)); x.Name != "Plant" || x.Org != globexEP {
		t.Fatalf("Plant: %+v", x)
	}
	// Automatic installs are on for what EasyRMM links.
	if n := f.count(`SELECT count(*) FROM easypatch_organizations WHERE auto_install`); n != 3 {
		t.Fatalf("%d organizations install automatically", n)
	}
	if n := len(f.audits("easypatch.organization_create")); n != 2 {
		t.Fatalf("%d organization_create audits", n)
	}
	if n := len(f.audits("easypatch.organization_adopt")); n != 1 {
		t.Fatalf("%d organization_adopt audits", n)
	}
	if n := len(f.audits("easypatch.site_create")); n != 3 {
		t.Fatalf("%d site_create audits", n)
	}

	// A pass with nothing to do changes nothing.
	before := engine.Changes()
	if res := f.reconcile(); res.Created+res.Adopted+res.Updated+res.Restored+res.Archived != 0 {
		t.Fatalf("second pass: %+v", res)
	}
	if after := engine.Changes(); after != before {
		t.Fatalf("a pass with nothing to do wrote %d times", after-before)
	}

	// With ACME renamed, Acme gets its own name back.
	engine.ChangeOrganization(acmeUpper, func(o *eptest.OrgInfo) { o.Name = "Acme Holdings" })
	if res := f.reconcile(); res.Updated != 1 {
		t.Fatalf("plain name back: %+v", res)
	}
	if got := engineOrg(t, engine, acme.ID); got.Name != "Acme" {
		t.Fatalf("Acme: %+v", got)
	}
	if n := f.count(`SELECT count(*) FROM easypatch_organizations WHERE organization_id = $1 AND easypatch_name = 'Acme'`, f.acme); n != 1 {
		t.Fatal("the link keeps the old name")
	}

	// Renamed, and in another time zone, in EasyRMM: what EasyRMM does not
	// own in the engine stays.
	engine.ChangeOrganization(acme.ID, func(o *eptest.OrgInfo) { d := "kept"; o.Description = &d })
	f.exec(`UPDATE organizations SET name = 'Acme Corp', timezone = 'Asia/Tokyo' WHERE id = $1`, f.acme)
	f.exec(`UPDATE sites SET name = 'Head office' WHERE id = $1`, f.hq)
	if res := f.reconcile(); res.Updated != 2 {
		t.Fatalf("renamed: %+v", res)
	}
	if got := engineOrg(t, engine, acme.ID); got.Name != "Acme Corp" || got.TimeZone != "Asia/Tokyo" || got.Description == nil || *got.Description != "kept" {
		t.Fatalf("renamed Acme: %+v", got)
	}
	if x := engineSite(t, engine, f.engineSite(f.hq)); x.Name != "Head office" {
		t.Fatalf("renamed HQ: %+v", x)
	}

	// Two organizations trade names: the engine follows within two passes.
	f.exec(`UPDATE organizations SET name = 'Trading' WHERE id = $1`, f.acme)
	f.exec(`UPDATE organizations SET name = 'Acme Corp' WHERE id = $1`, f.globex)
	f.exec(`UPDATE organizations SET name = 'Globex' WHERE id = $1`, f.acme)
	f.reconcile()
	f.reconcile()
	if a, g := engineOrg(t, engine, acme.ID), engineOrg(t, engine, globexEP); a.Name != "Globex" || g.Name != "Acme Corp" {
		t.Fatalf("traded names: %q and %q", a.Name, g.Name)
	}

	// Archived in the engine's own console: restored. Deleted there: made
	// again, with its sites.
	engine.ChangeOrganization(acme.ID, func(o *eptest.OrgInfo) { o.Active = false })
	if res := f.reconcile(); res.Restored != 1 || !engineOrg(t, engine, acme.ID).Active {
		t.Fatalf("restore: %+v", res)
	}
	engine.DeleteOrganization(globexEP)
	if res := f.reconcile(); res.Created != 2 || len(res.Problems) != 0 {
		t.Fatalf("made again: %+v", res)
	}
	if again := f.engineOrg(f.globex); again == globexEP || engineOrg(t, engine, again).Name != "Acme Corp" ||
		engineSite(t, engine, f.engineSite(f.plant)).Org != again {
		t.Fatalf("Globex made again: %v", again)
	}

	// Links are EasyRMM's: they cannot be changed by hand.
	wantErr(t, f.svc.LinkOrganization(f.ctx, f.admin.Actor, f.acme, globexEP), apperr.KindConflict, "patching_linked_by_easyrmm")
}

// TestReconcileDeleted: what EasyRMM deletes is archived in the engine
// under a name that frees the old one.
func TestReconcileDeleted(t *testing.T) {
	f := newFixture(t)
	engine := f.bundle()
	f.reconcile()
	oldGlobex, oldPlant, oldBranch := f.engineOrg(f.globex), f.engineSite(f.plant), f.engineSite(f.branch)

	f.exec(`DELETE FROM sites WHERE id = $1`, f.plant)
	f.exec(`DELETE FROM organizations WHERE id = $1`, f.globex)
	if n := f.count(`SELECT count(*) FROM easypatch_forgotten`); n != 2 {
		t.Fatalf("%d records to archive", n)
	}
	// A new organization takes the name at once.
	globex := f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	st, err := f.svc.Sync(f.ctx)
	if err != nil || st.Archiving != 2 {
		t.Fatalf("sync status: %+v, %v", st, err)
	}

	res := f.reconcile()
	if res.Archived != 2 || res.Created != 1 || len(res.Problems) != 0 {
		t.Fatalf("pass: %+v", res)
	}
	today := time.Now().UTC().Format("2006-01-02")
	if o := engineOrg(t, engine, oldGlobex); o.Active || o.Name != "Globex (deleted "+today+" "+shortID(oldGlobex)+")" {
		t.Fatalf("deleted Globex: %+v", o)
	}
	if x := engineSite(t, engine, oldPlant); x.Active || !strings.HasPrefix(x.Name, "Plant (deleted ") {
		t.Fatalf("deleted Plant: %+v", x)
	}
	if o := engineOrg(t, engine, f.engineOrg(globex)); o.Name != "Globex" || !o.Active {
		t.Fatalf("new Globex: %+v", o)
	}
	if n := f.count(`SELECT count(*) FROM easypatch_forgotten`); n != 0 {
		t.Fatalf("%d records left to archive", n)
	}
	if len(f.audits("easypatch.organization_archive")) != 1 || len(f.audits("easypatch.site_archive")) != 1 {
		t.Fatal("archives not audited")
	}

	// A restart in the middle: the engine renamed the site, but EasyRMM
	// never heard. After the restart it only archives.
	f.exec(`DELETE FROM sites WHERE id = $1`, f.branch)
	path := "/api/v1/sites/" + oldBranch.String()
	engine.Set(func() { engine.LoseReply = func(m, p string) bool { return m == http.MethodPut && p == path } })
	if res := f.reconcile(); res.Archived != 0 || len(res.Problems) != 1 {
		t.Fatalf("lost reply: %+v", res)
	}
	if n := f.count(`SELECT count(*) FROM easypatch_forgotten WHERE last_error <> ''`); n != 1 {
		t.Fatal("the failure is not recorded")
	}
	engine.Set(func() { engine.LoseReply = nil })
	f.svc = f.engineService(engine)
	if res := f.reconcile(); res.Archived != 1 || len(res.Problems) != 0 {
		t.Fatalf("after the restart: %+v", res)
	}
	if n := len(engine.RequestsTo(http.MethodPut, path)); n != 1 {
		t.Fatalf("the site was renamed %d times", n)
	}
	if x := engineSite(t, engine, oldBranch); x.Active || !strings.HasPrefix(x.Name, "Branch (deleted ") {
		t.Fatalf("deleted Branch: %+v", x)
	}

	// Gone from the engine already: nothing left to do.
	engine.DeleteOrganization(f.engineOrg(globex))
	f.exec(`DELETE FROM organizations WHERE id = $1`, globex)
	if res := f.reconcile(); len(res.Problems) != 0 || f.count(`SELECT count(*) FROM easypatch_forgotten`) != 0 {
		t.Fatalf("already gone: %+v", res)
	}
}

// linkedDevice is a device of org and site whose EasyPatch agent is
// linked, with the engine's endpoint for it.
func (f *fixture) linkedDevice(engine *eptest.Server, org, site uuid.UUID, name string) (uuid.UUID, *eptest.Endpoint) {
	f.t.Helper()
	e := engine.AddEndpoint(f.engineOrg(org), strings.ToLower(name), "", "FP-"+name)
	if s := f.engineSite(site); e.Site == nil || *e.Site != s {
		engine.Set(func() { e.Site = &s })
	}
	d := f.device(org, site, name)
	f.report(d, "", engineReport(e))
	f.sync()
	if l := f.link(d); l.state != LinkLinked {
		f.t.Fatalf("%s: link %+v", name, l)
	}
	return d, e
}

func uninstallJobs(engine *eptest.Server, endpoint uuid.UUID) []eptest.Job {
	var out []eptest.Job
	for _, j := range engine.Jobs() {
		if j.Endpoint == endpoint && j.Type == "UninstallAgent" {
			out = append(out, j)
		}
	}
	return out
}

// TestReconcileMoves: a device moved to another site takes its endpoint
// along; one moved to another organization has its agent removed, to be
// installed again there.
func TestReconcileMoves(t *testing.T) {
	f := newFixture(t)
	engine := f.bundle()
	f.reconcile()
	web, e := f.linkedDevice(engine, f.acme, f.hq, "web-01")
	if res := f.reconcile(); res.Moved != 0 {
		t.Fatalf("in place already: %+v", res)
	}

	f.exec(`UPDATE devices SET site_id = $2 WHERE id = $1`, web, f.branch)
	if res := f.reconcile(); res.Moved != 1 || len(res.Problems) != 0 {
		t.Fatalf("site move: %+v", res)
	}
	if got, _ := engine.EndpointState(e.ID); got.Site == nil || *got.Site != f.engineSite(f.branch) {
		t.Fatalf("the endpoint's site: %v", got.Site)
	}
	if res := f.reconcile(); res.Moved != 0 {
		t.Fatalf("moved twice: %+v", res)
	}

	// To another organization: the engine cannot move it there.
	f.exec(`INSERT INTO easypatch_installs (device_id, state, automatic, finished_at) VALUES ($1, 'succeeded', true, now())`, web)
	f.exec(`UPDATE devices SET organization_id = $2, site_id = $3 WHERE id = $1`, web, f.globex, f.plant)
	f.sync()
	if l := f.link(web); l.state != LinkUnlinked || !strings.Contains(l.reason, "moved from Acme") {
		t.Fatalf("link after the move: %+v", l)
	}
	if res := f.reconcile(); res.Uninstalls != 1 || len(uninstallJobs(engine, e.ID)) != 1 {
		t.Fatalf("uninstall: %+v", res)
	}
	if dp, err := f.svc.Device(f.ctx, f.admin, web); err != nil || dp.Removal == nil || dp.Removal.Reason != RemovalMoved ||
		dp.Removal.State != removalUninstalling {
		t.Fatalf("device view: %+v, %v", dp, err)
	}
	// Checked again only after a while; the agent removes itself.
	if res := f.reconcile(); res.Removed != 0 {
		t.Fatalf("checked too soon: %+v", res)
	}
	engine.SetJobStatus(uninstallJobs(engine, e.ID)[0].ID, "Completed")
	f.later(recheckRemoval + time.Minute)
	if res := f.reconcile(); res.Removed != 1 {
		t.Fatalf("removed: %+v", res)
	}
	// Its install record goes, so automatic installs put the agent in
	// Globex.
	if n := f.count(`SELECT count(*) FROM easypatch_installs WHERE device_id = $1`, web); n != 0 {
		t.Fatal("the old install record holds automatic installs back")
	}
	if len(f.audits("easypatch.agent_uninstall")) != 1 || len(f.audits("easypatch.agent_remove")) != 1 {
		t.Fatal("not audited")
	}
}

// TestReconcileImportedNames: the agents of an imported EasyPatch report
// its old address (one-product plan, phase S). They link like the engine's
// own, and one in another organization than its device's is left alone:
// removing it to install another would lose its history.
func TestReconcileImportedNames(t *testing.T) {
	f := newFixture(t)
	engine := eptest.NewEngine(t, reconcileKey)
	f.svc = f.engineService(engine, AgentHostnames([]string{"patch.old.test", "easypatch.old.test"}))
	f.reconcile()

	at := func(e *eptest.Endpoint, url string) *agentproto.EasyPatchAgent {
		r := engineReport(e)
		r.ServerURL = url
		return r
	}
	for i, url := range []string{"https://patch.old.test", "https://EasyPatch.old.test:443/", "https://patch.example.com"} {
		name := fmt.Sprintf("old-%d", i)
		e := engine.AddEndpoint(f.engineOrg(f.acme), name, "", "FP-"+name)
		d := f.device(f.acme, f.hq, name)
		f.report(d, "", at(e, url))
		f.sync()
		if l := f.link(d); l.state != LinkLinked {
			t.Errorf("enrolled with %s: %+v", url, l)
		}
	}
	// Another server's agent is still not the engine's.
	e := engine.AddEndpoint(f.engineOrg(f.acme), "other", "", "FP-other")
	d := f.device(f.acme, f.hq, "other")
	f.report(d, "", at(e, "https://patch.other.test"))
	f.sync()
	if l := f.link(d); l.state != LinkUnlinked || !strings.Contains(l.reason, "enrolled with https://patch.other.test") {
		t.Fatalf("another server's agent: %+v", l)
	}

	// In another organization: explained, and its agent stays.
	e = engine.AddEndpoint(f.engineOrg(f.acme), "elsewhere", "", "FP-elsewhere")
	d = f.device(f.globex, f.plant, "elsewhere")
	f.report(d, "", at(e, "https://patch.old.test"))
	f.sync()
	if l := f.link(d); l.state != LinkUnlinked || !strings.Contains(l.reason, "came from the imported EasyPatch, so EasyRMM leaves its agent alone") {
		t.Fatalf("an imported agent in another organization: %+v", l)
	}
	if res := f.reconcile(); res.Uninstalls != 0 || f.count(`SELECT count(*) FROM easypatch_removals`) != 0 || len(uninstallJobs(engine, e.ID)) != 0 {
		t.Fatalf("an imported agent was removed: %+v", res)
	}
	// The engine's own agent in the same place is moved, as before.
	e = engine.AddEndpoint(f.engineOrg(f.acme), "moved", "", "FP-moved")
	d = f.device(f.globex, f.plant, "moved")
	f.report(d, "", engineReport(e))
	f.sync()
	if n := f.count(`SELECT count(*) FROM easypatch_removals WHERE reason = 'moved' AND device_id = $1`, d); n != 1 {
		t.Fatalf("the engine's own agent in another organization: %d removals", n)
	}
}

// TestReconcileOptOut: patching stopped for a device removes its agent,
// and nothing installs one again until patching is allowed.
func TestReconcileOptOut(t *testing.T) {
	f := newFixture(t)
	engine := f.bundle()
	f.reconcile()
	web, e := f.linkedDevice(engine, f.acme, f.hq, "web-01")
	only := ActionInput{DeviceIDs: []uuid.UUID{web}}

	// Allowed again before the next pass: nothing is removed.
	res, err := f.svc.StopPatching(f.ctx, f.admin, only)
	if err != nil || res.Succeeded != 1 || !strings.Contains(res.Results[0].Message, "removing the EasyPatch agent") {
		t.Fatalf("stop: %+v, %v", res, err)
	}
	if dp, err := f.svc.Device(f.ctx, f.admin, web); err != nil || dp.Stopped == nil || dp.Stopped.By != "ada@example.com" ||
		dp.Removal == nil || dp.Removal.State != removalPending {
		t.Fatalf("device view: %+v, %v", dp, err)
	}
	if res, err := f.svc.AllowPatching(f.ctx, f.admin, only); err != nil || res.Succeeded != 1 {
		t.Fatalf("allow: %+v, %v", res, err)
	}
	if res := f.reconcile(); res.Uninstalls != 0 || f.count(`SELECT count(*) FROM easypatch_removals`) != 0 {
		t.Fatalf("removed after all: %+v", res)
	}

	// Stopped: removed, then never installed again, automatically or when
	// asked.
	if _, err := f.svc.StopPatching(f.ctx, f.admin, only); err != nil {
		t.Fatal(err)
	}
	if res, _ := f.svc.StopPatching(f.ctx, f.admin, only); res.Results[0].Message != "Patching was already stopped." {
		t.Fatalf("stopped twice: %+v", res)
	}
	if res := f.reconcile(); res.Uninstalls != 1 {
		t.Fatalf("uninstall: %+v", res)
	}
	engine.SetJobStatus(uninstallJobs(engine, e.ID)[0].ID, "Completed")
	f.later(recheckRemoval + time.Minute)
	if res := f.reconcile(); res.Removed != 1 {
		t.Fatalf("removed: %+v", res)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	f.exec(`UPDATE devices SET agent_public_key = $2, agent_arch = 'amd64', enrolled_at = now() WHERE id = $1`, web, key)
	f.report(web, "", nil)
	if _, err := f.svc.SweepInstalls(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM easypatch_installs WHERE device_id = $1`, web); n != 0 {
		t.Fatal("an automatic install was queued for a stopped device")
	}
	var why string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		tg, err := loadTarget(f.ctx, tx, web)
		why = tg.ineligible()
		return err
	}); err != nil || !strings.Contains(why, "Patching is stopped") {
		t.Fatalf("asked for: %q, %v", why, err)
	}
	// Allowed again: automatic installs (on for what EasyRMM links) put it
	// back.
	if _, err := f.svc.AllowPatching(f.ctx, f.admin, only); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SweepInstalls(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM easypatch_installs WHERE device_id = $1 AND automatic`, web); n != 1 {
		t.Fatal("no automatic install after allowing patching again")
	}
	if len(f.audits("patch.stop")) != 2 || len(f.audits("patch.allow")) != 2 {
		t.Fatal("not audited")
	}

	// An agent too old to remove itself is revoked instead.
	db, old := f.linkedDevice(engine, f.acme, f.hq, "db-01")
	engine.Set(func() { old.CannotUninstall = true })
	if _, err := f.svc.StopPatching(f.ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{db}}); err != nil {
		t.Fatal(err)
	}
	if res := f.reconcile(); res.Revoked != 1 || res.Removed != 1 {
		t.Fatalf("too old: %+v", res)
	}
	if got, _ := engine.EndpointState(old.ID); got.Status != "Revoked" {
		t.Fatalf("too old: %s", got.Status)
	}
	if len(f.audits("easypatch.endpoint_revoke")) != 1 {
		t.Fatal("revoke not audited")
	}

	// One that never removes itself is revoked after the grace period; a
	// job that failed is sent again first.
	app, slow := f.linkedDevice(engine, f.acme, f.hq, "app-01")
	if _, err := f.svc.StopPatching(f.ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{app}}); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	engine.SetJobStatus(uninstallJobs(engine, slow.ID)[0].ID, "Expired")
	f.later(recheckRemoval + time.Minute)
	f.reconcile() // the job expired: send again
	if res := f.reconcile(); res.Uninstalls != 1 || len(uninstallJobs(engine, slow.ID)) != 2 {
		t.Fatalf("sent again: %+v", res)
	}
	f.later(uninstallGrace)
	if res := f.reconcile(); res.Revoked != 1 {
		t.Fatalf("grace: %+v", res)
	}
	if got, _ := engine.EndpointState(slow.ID); got.Status != "Revoked" {
		t.Fatalf("grace: %s", got.Status)
	}

	// Only who may manage a device's patching may stop it.
	tech := f.user("tess@example.com")
	if _, err := f.svc.StopPatching(f.ctx, tech, only); err == nil {
		t.Fatal("someone without access stopped patching")
	}
}

// TestReconcileDeletedDevice: a device deleted in EasyRMM has its agent
// removed, unless EasyRMM still has the computer under another record.
func TestReconcileDeletedDevice(t *testing.T) {
	f := newFixture(t)
	engine := f.bundle()
	f.reconcile()
	web, e := f.linkedDevice(engine, f.acme, f.hq, "web-01")
	app, e2 := f.linkedDevice(engine, f.acme, f.hq, "app-01")

	// web-01's record goes, but another record reports its agent.
	other := f.device(f.acme, f.hq, "web-01-new")
	f.report(other, "", engineReport(e))
	f.exec(`DELETE FROM devices WHERE id = $1`, web)
	if n := f.count(`SELECT count(*) FROM easypatch_removals WHERE reason = 'deleted'`); n != 1 {
		t.Fatalf("%d removals", n)
	}
	if res := f.reconcile(); res.Uninstalls != 0 || len(uninstallJobs(engine, e.ID)) != 0 {
		t.Fatalf("removed a computer EasyRMM still has: %+v", res)
	}

	f.exec(`DELETE FROM devices WHERE id = $1`, app)
	if res := f.reconcile(); res.Uninstalls != 1 || len(uninstallJobs(engine, e2.ID)) != 1 {
		t.Fatalf("deleted device: %+v", res)
	}
}

// TestReconcileRestart: a pass cut short (the engine's reply lost, then
// EasyRMM restarted) is finished by the next without doing anything twice.
func TestReconcileRestart(t *testing.T) {
	f := newFixture(t)
	engine := f.bundle()
	engine.Set(func() {
		engine.LoseReply = func(m, p string) bool { return m == http.MethodPost && p == "/api/v1/organizations" }
	})
	if res := f.reconcile(); res.Created != 0 || len(res.Problems) != 2 {
		t.Fatalf("lost replies: %+v", res)
	}
	if got := orgNames(engine); !slices.Equal(got, []string{"Acme", "Globex"}) {
		t.Fatalf("engine: %v", got)
	}
	engine.Set(func() { engine.LoseReply = nil })

	f.svc = f.engineService(engine)
	res := f.reconcile()
	if res.Adopted != 2 || res.Created != 3 || len(res.Problems) != 0 {
		t.Fatalf("after the restart: %+v", res)
	}
	if got := orgNames(engine); !slices.Equal(got, []string{"Acme", "Globex"}) {
		t.Fatalf("duplicates: %v", got)
	}

	// An uninstall the engine queued but EasyRMM never heard of is not
	// queued twice.
	web, e := f.linkedDevice(engine, f.acme, f.hq, "web-01")
	if _, err := f.svc.StopPatching(f.ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{web}}); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/endpoints/" + e.ID.String() + "/uninstall-agent"
	engine.Set(func() { engine.LoseReply = func(m, p string) bool { return p == path } })
	if res := f.reconcile(); res.Uninstalls != 0 || len(res.Problems) != 1 {
		t.Fatalf("lost uninstall reply: %+v", res)
	}
	engine.Set(func() { engine.LoseReply = nil })
	f.svc = f.engineService(engine)
	if res := f.reconcile(); res.Uninstalls != 1 || len(uninstallJobs(engine, e.ID)) != 1 {
		t.Fatalf("after the restart: %+v", res)
	}
	if n := f.count(`SELECT count(*) FROM easypatch_removals WHERE state = 'uninstalling'`); n != 1 {
		t.Fatal("not recorded as sent")
	}
}

// TestReconcileEngineDown: an engine that does not answer is retried, and
// Settings says what is waiting.
func TestReconcileEngineDown(t *testing.T) {
	f := newFixture(t)
	engine := f.bundle()
	engine.Set(func() { engine.Down = true })
	res := f.reconcile()
	if len(res.Problems) == 0 || res.Created != 0 {
		t.Fatalf("down: %+v", res)
	}
	st, err := f.svc.Sync(f.ctx)
	if err != nil || st.At == nil || len(st.Problems) == 0 {
		t.Fatalf("sync status: %+v, %v", st, err)
	}
	engine.Set(func() { engine.Down = false })
	// Not kicked: a pass with problems tries again at the next one anyway.
	if res, err := f.svc.Reconcile(f.ctx); err != nil || res.Created != 5 || len(res.Problems) != 0 {
		t.Fatalf("up again: %+v, %v", res, err)
	}
	if st, _ := f.svc.Sync(f.ctx); len(st.Problems) != 0 {
		t.Fatalf("problems left: %+v", st)
	}
	// In step: the next pass without a kick leaves organizations alone.
	before := len(engine.RequestsTo(http.MethodGet, "/api/v1/organizations"))
	if _, err := f.svc.Reconcile(f.ctx); err != nil {
		t.Fatal(err)
	}
	if after := len(engine.RequestsTo(http.MethodGet, "/api/v1/organizations")); after != before {
		t.Fatal("a full pass without a change or the interval")
	}
}

// TestReconcileConnector: with a server set up in Settings, organizations
// stay the server's: EasyRMM archives nothing there.
func TestReconcileConnector(t *testing.T) {
	f := newFixture(t)
	f.connect()
	if err := f.svc.LinkOrganization(f.ctx, f.admin.Actor, f.globex, f.ep.Org("Globex Patch")); err != nil {
		t.Fatal(err)
	}
	f.exec(`DELETE FROM sites WHERE id = $1`, f.plant)
	f.exec(`DELETE FROM organizations WHERE id = $1`, f.globex)
	if n := f.count(`SELECT count(*) FROM easypatch_forgotten`); n != 1 {
		t.Fatalf("%d forgotten", n)
	}
	before := f.ep.Changes()
	if res := f.reconcile(); res.Archived != 0 || res.Created != 0 {
		t.Fatalf("connector: %+v", res)
	}
	if f.count(`SELECT count(*) FROM easypatch_forgotten`) != 0 || f.ep.Changes() != before {
		t.Fatal("the connector changed the server's organizations")
	}
}

// TestReconcileEdges: sites archived or deleted in the engine's console, an
// organization deleted in EasyRMM while the engine creates it, and what an
// uninstall can run into.
func TestReconcileEdges(t *testing.T) {
	f := newFixture(t)
	engine := f.bundle()
	f.reconcile()

	// A site archived in the engine's console is restored; one deleted
	// there is made again.
	hq, branch := f.engineSite(f.hq), f.engineSite(f.branch)
	engine.Set(func() {})
	archiveSite(t, engine, hq)
	deleteSite(t, engine, branch)
	if res := f.reconcile(); res.Restored != 1 || res.Created != 1 || len(res.Problems) != 0 {
		t.Fatalf("sites: %+v", res)
	}
	if !engineSite(t, engine, hq).Active || f.engineSite(f.branch) == branch {
		t.Fatal("sites not put back")
	}

	// Deleted in EasyRMM while the engine creates it: its engine
	// organization is archived next.
	brief := f.id(`INSERT INTO organizations (name) VALUES ('Brief') RETURNING id`)
	engine.Set(func() {
		engine.LoseReply = func(m, p string) bool {
			if m == http.MethodPost && p == "/api/v1/organizations" {
				f.exec(`DELETE FROM organizations WHERE id = $1`, brief)
			}
			return false
		}
	})
	if res := f.reconcile(); res.Created != 0 || len(res.Problems) != 0 {
		t.Fatalf("deleted meanwhile: %+v", res)
	}
	engine.Set(func() { engine.LoseReply = nil })
	if n := f.count(`SELECT count(*) FROM easypatch_forgotten WHERE kind = 'organization' AND name = 'Brief'`); n != 1 {
		t.Fatal("the engine's organization is not to be archived")
	}
	if res := f.reconcile(); res.Archived != 1 {
		t.Fatalf("archived: %+v", res)
	}

	// Uninstalls: an endpoint gone or no longer active needs nothing; a
	// refusal is a problem for the next pass; a failed job is sent again.
	gone, e1 := f.linkedDevice(engine, f.acme, f.hq, "gone-01")
	idle, e2 := f.linkedDevice(engine, f.acme, f.hq, "idle-01")
	busy, e3 := f.linkedDevice(engine, f.acme, f.hq, "busy-01")
	engine.RemoveEndpoint(e1.ID)
	engine.Set(func() { e2.Status = "Revoked" })
	for _, d := range []uuid.UUID{gone, idle, busy} {
		if _, err := f.svc.StopPatching(f.ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{d}}); err != nil {
			t.Fatal(err)
		}
	}
	// Refused, as the engine refuses before it looks at the endpoint.
	engine.Set(func() { engine.ReadOnly = true })
	if res := f.reconcile(); res.Removed != 1 || res.Uninstalls != 0 || len(res.Problems) != 2 {
		t.Fatalf("refused: %+v", res)
	}
	if n := f.count(`SELECT count(*) FROM easypatch_removals WHERE last_error <> '' AND attempts = 1`); n != 2 {
		t.Fatal("the refusals are not recorded")
	}
	engine.Set(func() { engine.ReadOnly = false })
	if res := f.reconcile(); res.Uninstalls != 1 || res.Removed != 1 {
		t.Fatalf("sent: %+v", res)
	}
	job := uninstallJobs(engine, e3.ID)[0]
	engine.SetJobStatus(job.ID, "Failed")
	f.later(recheckRemoval + time.Minute)
	f.reconcile()
	if n := f.count(`SELECT count(*) FROM easypatch_removals WHERE state = 'pending' AND last_error LIKE 'the uninstall job failed%'`); n != 1 {
		t.Fatal("a failed uninstall is not sent again")
	}
	// The engine down while an uninstall is checked: the pass ends there.
	f.reconcile()
	engine.Set(func() { engine.Down = true })
	f.later(recheckRemoval + time.Minute)
	if res := f.reconcile(); len(res.Problems) == 0 {
		t.Fatalf("down: %+v", res)
	}
	engine.Set(func() { engine.Down = false })

	// A device whose endpoint the engine moved to another organization:
	// the placement refused, the link is checked again.
	web, e4 := f.linkedDevice(engine, f.acme, f.hq, "web-01")
	f.exec(`UPDATE devices SET site_id = $2 WHERE id = $1`, web, f.branch)
	engine.Set(func() { e4.Org = f.engineOrg(f.globex) })
	f.reconcile()
	if l := f.link(web); l.state != LinkPending {
		t.Fatalf("link after a refused move: %+v", l)
	}

	// Stopping patching while the agent installs waits; on a device whose
	// agent EasyRMM has not confirmed it leaves the agent; allowing what
	// was never stopped changes nothing.
	installing := f.device(f.acme, f.hq, "new-01")
	f.exec(`INSERT INTO easypatch_installs (device_id, state, attempt_id, sent_at) VALUES ($1, 'sent', gen_random_uuid(), now())`, installing)
	if res, err := f.svc.StopPatching(f.ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{installing}}); err != nil || res.Failed != 1 {
		t.Fatalf("while installing: %+v, %v", res, err)
	}
	other := f.device(f.acme, f.hq, "other-01")
	f.report(other, "", &agentproto.EasyPatchAgent{Version: "1.9.0", Status: "Active", ServerURL: "https://elsewhere.example.com"})
	f.sync()
	if res, err := f.svc.StopPatching(f.ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{other}}); err != nil ||
		!strings.Contains(res.Results[0].Message, "stays installed") {
		t.Fatalf("unconfirmed agent: %+v, %v", res, err)
	}
	if res, err := f.svc.AllowPatching(f.ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{installing}}); err != nil ||
		res.Results[0].Message != "Patching was not stopped." {
		t.Fatalf("allow, never stopped: %+v, %v", res, err)
	}
	if _, err := f.svc.StopPatching(f.ctx, f.admin, ActionInput{}); err == nil {
		t.Fatal("no devices accepted")
	}
	if _, err := f.svc.AllowPatching(f.ctx, f.admin, ActionInput{DeviceIDs: []uuid.UUID{web}, UpdateIDs: []uuid.UUID{uuid.New()}}); err == nil {
		t.Fatal("updates accepted")
	}
}

// TestReconcileRun: Run reconciles at a kick, and stops with its context.
func TestReconcileRun(t *testing.T) {
	f := newFixture(t)
	engine := f.bundle()
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() { f.svc.Run(ctx); close(done) }()
	f.svc.Kick()
	deadline := time.Now().Add(10 * time.Second)
	for len(engine.Organizations()) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if got := orgNames(engine); !slices.Equal(got, []string{"Acme", "Globex"}) {
		t.Fatalf("after a kick: %v", got)
	}
}

func archiveSite(t *testing.T, engine *eptest.Server, id uuid.UUID) {
	t.Helper()
	engine.ChangeSite(id, func(x *eptest.SiteInfo) { x.Active = false })
}

func deleteSite(t *testing.T, engine *eptest.Server, id uuid.UUID) {
	t.Helper()
	engine.DeleteSite(id)
}

// TestReconcileEngineFails: whichever call to the engine fails, the pass
// says what it could not do, and the next pass finishes the work, also
// when the engine did what was asked and only its reply was lost.
func TestReconcileEngineFails(t *testing.T) {
	f := newFixture(t)
	engine := f.bundle()
	f.reconcile()
	acme, hq := f.engineOrg(f.acme), f.engineSite(f.hq)
	api := "/api/v1/"
	fail := func(method, path, want string, change func()) {
		t.Helper()
		change()
		engine.Set(func() { engine.LoseReply = func(m, p string) bool { return m == method && p == path } })
		res := f.reconcile()
		engine.Set(func() { engine.LoseReply = nil })
		if !slices.ContainsFunc(res.Problems, func(p string) bool { return strings.Contains(p, want) }) {
			t.Fatalf("%s %s: %+v", method, path, res)
		}
		if res := f.reconcile(); len(res.Problems) != 0 {
			t.Fatalf("the pass after %s %s: %+v", method, path, res)
		}
	}
	nothing := func() {}
	fail("GET", api+"organizations", "Reading the patching engine's organizations", nothing)
	fail("GET", api+"organizations/"+acme.String()+"/sites", "Reading the sites of an organization", nothing)
	fail("PUT", api+"organizations/"+acme.String(), `Updating organization "Acme"`, func() {
		f.exec(`UPDATE organizations SET timezone = 'Europe/Berlin' WHERE id = $1`, f.acme)
	})
	fail("POST", api+"organizations/"+acme.String()+"/restore", `Restoring organization "Acme"`, func() {
		engine.ChangeOrganization(acme, func(x *eptest.OrgInfo) { x.Active = false })
	})
	fail("PUT", api+"sites/"+hq.String(), `Updating site "HQ"`, func() {
		f.exec(`UPDATE sites SET timezone = 'Europe/Berlin' WHERE id = $1`, f.hq)
	})
	fail("POST", api+"sites/"+hq.String()+"/restore", `Restoring site "HQ"`, func() {
		archiveSite(t, engine, hq)
	})
	// Created, though the reply was lost: the next pass adopts it.
	fail("POST", api+"organizations/"+acme.String()+"/sites", `Creating site "Annex"`, func() {
		f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Annex') RETURNING id`, f.acme)
	})
	annex := 0
	for _, x := range engine.Sites() {
		if x.Org == acme && x.Name == "Annex" {
			annex++
		}
	}
	if annex != 1 {
		t.Fatalf("%d Annex sites", annex)
	}

	// Archiving what EasyRMM deleted: reading it, renaming it and
	// archiving it.
	for _, step := range []struct{ method, suffix, want string }{
		{"GET", "", "reading it"},
		{"PUT", "", "renaming it"},
		{"POST", "/archive", "archiving it"},
	} {
		site := f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, $2) RETURNING id`, f.acme, "Gone "+step.method)
		f.reconcile()
		ep := f.engineSite(site)
		fail(step.method, api+"sites/"+ep.String()+step.suffix, "deleted in EasyRMM: "+step.want, func() {
			f.exec(`DELETE FROM sites WHERE id = $1`, site)
		})
		if x := engineSite(t, engine, ep); x.Active || !strings.Contains(x.Name, " (deleted ") {
			t.Fatalf("after %s: %+v", step.want, x)
		}
	}

	// A device moved to another site, the move refused.
	web, e := f.linkedDevice(engine, f.acme, f.hq, "web-01")
	branch := f.engineSite(f.branch)
	fail("PUT", api+"endpoints/"+e.ID.String(), "Moving an endpoint to its device's site", func() {
		f.exec(`UPDATE devices SET site_id = $2 WHERE id = $1`, web, f.branch)
	})
	if got, _ := engine.EndpointState(e.ID); got.Site == nil || *got.Site != branch {
		t.Fatalf("not moved: %+v", got.Site)
	}

	// Both names an organization could have are taken in the engine.
	tight := f.id(`INSERT INTO organizations (name) VALUES ('Initech') RETURNING id`)
	for _, name := range []string{"Initech", "Initech (" + shortID(tight) + ")"} {
		x := engine.Org(name)
		engine.ChangeOrganization(x, func(o *eptest.OrgInfo) { o.Active = false })
	}
	if res := f.reconcile(); !slices.ContainsFunc(res.Problems, func(p string) bool { return strings.HasPrefix(p, `Organization "Initech"`) }) {
		t.Fatalf("no name for Initech: %+v", res)
	}
}
