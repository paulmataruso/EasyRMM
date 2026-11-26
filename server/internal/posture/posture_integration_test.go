//go:build integration

package posture_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	calerts "github.com/paulmataruso/easyrmm/server/internal/compliance/alerts"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/posture"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/reports"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t    *testing.T
	ctx  context.Context
	db   *database.DB
	svc  *posture.Service
	org  uuid.UUID
	site uuid.UUID
	feed *fakeFeed
}

// fakeFeed is the patching engine's side of the contract: it is the engine,
// which is outside this repository's server, so it is a stand-in here.
type fakeFeed struct{ list []posture.PatchStatus }

func (f *fakeFeed) PosturePatching(context.Context) ([]posture.PatchStatus, error) {
	return f.list, nil
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, feed: &fakeFeed{}}
	f.svc = posture.New(inst.DB, f.feed, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.org = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.site = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.org)
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

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fixture) device(name, platform string) uuid.UUID {
	f.t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, agent_version, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, lower($3), $4, $5, '1.4.0', now() - interval '30 days', now()) RETURNING id`, f.org, f.site, name, platform, key)
}

func (f *fixture) module(dev uuid.UUID, module, state string, age time.Duration, detail string) {
	f.t.Helper()
	f.exec(`INSERT INTO device_hardening (device_id, module, state, detail, checked_at) VALUES ($1, $2, $3, $4::jsonb, now() - $5::interval)`,
		dev, module, state, detail, age.String())
}

func (f *fixture) load(dev uuid.UUID, platform string) *posture.Posture {
	f.t.Helper()
	var p *posture.Posture
	err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		m, err := posture.Load(f.ctx, tx, []posture.Ref{{ID: dev, Org: f.org, Platform: platform, Enrolled: true}}, time.Now())
		p = m[dev]
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func TestPostureWords(t *testing.T) {
	f := newFixture(t)
	good := f.device("good", "linux")
	f.module(good, "ssh", "in_place", 0, `{}`)
	f.module(good, "firewall", "in_place", 0, `{}`)
	f.module(good, "usb-storage", "not_applicable", 0, `{}`)
	if p := f.load(good, "linux"); p.Word != "meets" || p.Percent == nil || *p.Percent != 100 {
		t.Fatalf("all in place: %+v", p)
	}

	bad := f.device("bad", "linux")
	f.module(bad, "ssh", "not_in_place", 0, `{"reason":"root login is allowed"}`)
	f.module(bad, "kernel", "in_place", 0, `{}`)
	p := f.load(bad, "linux")
	if p.Word != "does not meet" || *p.Percent != 25 || p.Reasons[0].ControlID != "ssh" || !strings.Contains(p.Reasons[0].Detail, "root login") {
		t.Fatalf("weighted: %+v", p)
	}

	// A result older than the freshness window is stale, and stale never passes.
	old := f.device("old", "windows")
	f.module(old, "firewall", "in_place", 40*24*time.Hour, `{}`)
	f.module(old, "uac", "in_place", 0, `{}`)
	if p := f.load(old, "windows"); p.Word != "cannot tell" || p.Reasons[0].State != "stale" || *p.Percent != 40 {
		t.Fatalf("stale: %+v", p)
	}
	// The organization's own window decides what is stale.
	f.exec(`INSERT INTO compliance_org_settings (organization_id, enabled, freshness_days) VALUES ($1, true, 60)`, f.org)
	if p := f.load(old, "windows"); p.Word != "meets" {
		t.Fatalf("a 60-day window: %+v", p)
	}

	// A computer no hardening job reported on cannot be told, and has no
	// invented score from nothing: it is unknown, which is not passing.
	none := f.device("none", "linux")
	if p := f.load(none, "linux"); p.Word != "cannot tell" || *p.Percent != 0 || p.Reasons[0].ControlID != "hardening" {
		t.Fatalf("unchecked: %+v", p)
	}

	// A setting another owner manages passes on that owner's value.
	managed := f.device("managed", "windows")
	f.module(managed, "firewall", "managed_elsewhere", 0, `{"managed":[{"owner":"Group Policy","state":"in_place"}]}`)
	if p := f.load(managed, "windows"); p.Word != "meets" {
		t.Fatalf("managed elsewhere, as strict: %+v", p)
	}
	f.exec(`UPDATE device_hardening SET detail = '{"managed":[{"owner":"Group Policy","state":"managed_elsewhere"}]}' WHERE device_id = $1`, managed)
	if p := f.load(managed, "windows"); p.Word != "does not meet" {
		t.Fatalf("managed elsewhere, weaker: %+v", p)
	}

	// Posture does not cover a computer without hardening.
	var m map[uuid.UUID]*posture.Posture
	_ = f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		var err error
		m, err = posture.Load(f.ctx, tx, []posture.Ref{{ID: good, Org: f.org, Platform: "macos", Enrolled: true}, {ID: good, Org: f.org, Platform: "linux"}}, time.Now())
		return err
	})
	if len(m) != 0 {
		t.Fatalf("not covered: %v", m)
	}
}

func TestPatchingIsOneOfTheControls(t *testing.T) {
	f := newFixture(t)
	d := f.device("patched", "linux")
	f.module(d, "ssh", "in_place", 0, `{}`)
	f.exec(`INSERT INTO easypatch_devices (device_id, endpoint_id, state, linked_at, checked_at) VALUES ($1, gen_random_uuid(), 'linked', now(), now())`, d)
	// Linked and not read yet: unknown, never passing.
	if p := f.load(d, "linux"); p.Word != "cannot tell" || *p.Percent != 50 {
		t.Fatalf("not read yet: %+v", p)
	}
	f.feed.list = []posture.PatchStatus{{DeviceID: d, OrganizationID: f.org, Status: "MissingUpdates", At: time.Now()}}
	if n, err := f.svc.RefreshPatching(f.ctx); err != nil || n != 1 {
		t.Fatalf("refresh: %d %v", n, err)
	}
	p := f.load(d, "linux")
	if p.Word != "does not meet" || p.Failing != 1 || p.Reasons[0].ControlID != "patching" {
		t.Fatalf("missing updates: %+v", p)
	}
	f.feed.list[0].Status = "Compliant"
	if _, err := f.svc.RefreshPatching(f.ctx); err != nil {
		t.Fatal(err)
	}
	if p := f.load(d, "linux"); p.Word != "meets" {
		t.Fatalf("compliant: %+v", p)
	}
	// A copy the feed stopped refreshing goes stale.
	f.exec(`UPDATE posture_patching SET checked_at = now() - interval '45 days'`)
	if p := f.load(d, "linux"); p.Word != "cannot tell" || p.Reasons[0].ControlID != "patching" || p.Reasons[0].State != "stale" {
		t.Fatalf("stale copy: %+v", p)
	}
	// The dev-scope guard keeps other organizations' devices out of the copy and out of posture.
	defer devscope.Set(uuid.New())()
	f.exec(`DELETE FROM posture_patching`)
	if n, _ := f.svc.RefreshPatching(f.ctx); n != 0 {
		t.Fatalf("outside the scope, %d copied", n)
	}
	if p := f.load(d, "linux"); p != nil {
		t.Fatalf("outside the scope: %+v", p)
	}
}

func TestDevicesListColumnAndFilter(t *testing.T) {
	f := newFixture(t)
	good, bad, unk := f.device("a-good", "linux"), f.device("b-bad", "windows"), f.device("c-unknown", "linux")
	f.module(good, "ssh", "in_place", 0, `{}`)
	f.module(bad, "firewall", "failed", 0, `{}`)
	_ = unk
	other := f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform) VALUES ($1, $2, 'd-mesh', 'd-mesh', 'linux') RETURNING id`, f.org, f.site)
	svc := devices.New(f.db, false)
	list := func(filter string) map[string]*posture.Summary {
		out := map[string]*posture.Summary{}
		ds, err := svc.List(f.ctx, access.System("test"), devices.Query{Posture: filter})
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range ds {
			out[d.Name] = d.Posture
		}
		return out
	}
	all := list("")
	if len(all) != 4 || all["a-good"].Word != "meets" || all["b-bad"].Word != "does not meet" || all["c-unknown"].Word != "cannot tell" || all["d-mesh"] != nil {
		t.Fatalf("column: %+v", all)
	}
	_ = other
	for filter, want := range map[string]string{"meets": "a-good", "does_not_meet": "b-bad", "cannot_tell": "c-unknown"} {
		got := list(filter)
		if len(got) != 1 || got[want] == nil {
			t.Fatalf("filter %s: %v", filter, got)
		}
	}
	if _, err := svc.List(f.ctx, access.System("test"), devices.Query{Posture: "bogus"}); err == nil {
		t.Fatal("a filter that does not exist was accepted")
	}
}

func TestSecurityReport(t *testing.T) {
	f := newFixture(t)
	good, bad := f.device("good", "linux"), f.device("bad", "windows")
	f.module(good, "ssh", "in_place", 0, `{}`)
	f.module(bad, "firewall", "not_in_place", 0, `{"missing":["inbound rule open"]}`)
	scan := f.id(`INSERT INTO compliance_scans (organization_id, trigger, selection, state) VALUES ($1, 'manual', '{}', 'done') RETURNING id`, f.org)
	f.exec(`INSERT INTO compliance_results_history (organization_id, scan_id, device_id, control_id, control_version, state, checked_at)
		VALUES ($1, $2, $3, 'win.firewall.x', 1, 'not_in_place', now())`, f.org, scan, bad)
	rs := reports.New(f.db, audit.New(f.db, nil))
	run := func(q reports.Query) *reports.Report {
		r, err := rs.Run(f.ctx, access.System("test"), "security", q, 100)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := run(reports.Query{})
	if r.Title != "Security" || r.Total != 2 {
		t.Fatalf("%+v", r)
	}
	rows := map[string][]any{}
	for _, row := range r.Rows {
		rows[row[2].(string)] = row
	}
	if rows["good"][4] != "Meets its security policy" || rows["good"][5] != 100 || rows["good"][8] != nil {
		t.Fatalf("good: %v", rows["good"])
	}
	b := rows["bad"]
	if b[4] != "Does not meet its security policy" || b[5] != 0 || b[6] != 1 || b[8] != 1 || !strings.Contains(b[9].(string), "Firewall: does not meet - Missing: inbound rule open") {
		t.Fatalf("bad: %v", b)
	}
	if r := run(reports.Query{Posture: "does_not_meet"}); r.Total != 1 {
		t.Fatalf("filter: %d", r.Total)
	}
	var csv strings.Builder
	if err := reports.WriteCSV(&csv, r); err != nil || strings.Contains(strings.ToLower(csv.String()), "compliant") {
		t.Fatalf("csv: %v", err)
	}
	// Outside the dev scope the report shows nothing of the organization.
	defer devscope.Set(uuid.New())()
	if r := run(reports.Query{}); r.Total != 0 {
		t.Fatalf("outside the scope: %d rows", r.Total)
	}
}

func TestComplianceAlerts(t *testing.T) {
	f := newFixture(t)
	dev := f.device("host", "windows")
	now := time.Now()
	al := calerts.New(f.db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	open := func(kind string) int {
		return f.count(`SELECT count(*) FROM alerts WHERE kind = $1 AND status <> 'resolved'`, kind)
	}
	// Off until the organization turns the module on.
	scan := f.id(`INSERT INTO compliance_scans (organization_id, trigger, selection, state) VALUES ($1, 'manual', '{}', 'done') RETURNING id`, f.org)
	f.exec(`INSERT INTO compliance_results_history (organization_id, scan_id, device_id, control_id, control_version, state, checked_at)
		VALUES ($1, $2, $3, 'win.autoplay.autorun', 1, 'in_place', now() - interval '40 days')`, f.org, scan, dev)
	f.exec(`INSERT INTO compliance_fix_items (organization_id, device_id, control_id, control_version, tier, state, fail_reason)
		VALUES ($1, $2, 'win.autoplay.autorun', 1, 'T1', 'failed', 'the value did not stick')`, f.org, dev)
	if r, err := al.Evaluate(f.ctx); err != nil || r.Opened != 0 {
		t.Fatalf("module off: %+v %v", r, err)
	}
	f.exec(`INSERT INTO compliance_org_settings (organization_id, enabled) VALUES ($1, true)`, f.org)

	// Outside the dev scope nothing is raised.
	restore := devscope.Set(uuid.New())
	if r, err := al.Evaluate(f.ctx); err != nil || r.Opened != 0 {
		t.Fatalf("outside the scope: %+v %v", r, err)
	}
	restore()

	if r, err := al.Evaluate(f.ctx); err != nil || r.Opened != 2 {
		t.Fatalf("first pass: %+v %v", r, err)
	}
	if open(calerts.KindFixFailed) != 1 || open(calerts.KindScanStale) != 1 {
		t.Fatal("both alerts should be open")
	}
	// A second pass opens no duplicate.
	if _, err := al.Evaluate(f.ctx); err != nil || f.count(`SELECT count(*) FROM alerts WHERE kind LIKE 'compliance_%'`) != 2 {
		t.Fatalf("duplicates: %v", err)
	}
	if d := f.count(`SELECT count(*) FROM alerts WHERE kind = 'compliance_fix_failed' AND detail LIKE '%the value did not stick%' AND severity = 'warning'`); d != 1 {
		t.Fatal("the fix alert lacks its reason")
	}
	// A fresh result clears the stale alert; an undone item clears the fix alert.
	f.exec(`INSERT INTO compliance_results_history (organization_id, scan_id, device_id, control_id, control_version, state, checked_at)
		VALUES ($1, $2, $3, 'win.other', 1, 'in_place', now())`, f.org, scan, dev)
	f.exec(`UPDATE compliance_fix_items SET state = 'undone'`)
	if r, err := al.Evaluate(f.ctx); err != nil || r.Resolved != 2 || open(calerts.KindFixFailed)+open(calerts.KindScanStale) != 0 {
		t.Fatalf("clearing: %+v %v", r, err)
	}
	if n := f.count(`SELECT count(*) FROM alerts WHERE kind LIKE 'compliance_%' AND resolution = 'cleared'`); n != 2 {
		t.Fatalf("resolution: %d", n)
	}
	// Turning the module off resolves what is open, with its reason.
	f.exec(`UPDATE compliance_fix_items SET state = 'failed'`)
	_, _ = al.Evaluate(f.ctx)
	f.exec(`UPDATE compliance_org_settings SET enabled = false`)
	_, _ = al.Evaluate(f.ctx)
	if open(calerts.KindFixFailed) != 0 || f.count(`SELECT count(*) FROM alerts WHERE resolution = 'not_covered'`) != 1 {
		t.Fatal("an alert outlived its module")
	}
	_ = now
}

func TestDevicePostureNeedsDeviceView(t *testing.T) {
	f := newFixture(t)
	d := f.device("host", "linux")
	f.module(d, "ssh", "in_place", 0, `{}`)
	got, err := f.svc.Device(f.ctx, access.System("test"), d)
	if err != nil || !got.Covered || got.Posture.Word != "meets" || got.Phrase != "Meets its security policy" {
		t.Fatalf("%+v %v", got, err)
	}
	// A caller who sees nothing is told there is no such computer.
	nobody := f.id(`INSERT INTO users (email, display_name) VALUES ('nobody@example.test', 'n') RETURNING id`)
	p, err := rbac.NewPrincipal(nobody, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Device(f.ctx, access.User(p, database.Scope{}, audit.SystemActor("test")), d); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("a caller with no permission: %v", err)
	}
	if _, err := f.svc.Device(f.ctx, access.System("test"), uuid.New()); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("a computer that does not exist: %v", err)
	}
	// A computer posture does not cover answers, without a posture.
	mesh := f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform) VALUES ($1, $2, 'm', 'm', 'macos') RETURNING id`, f.org, f.site)
	if got, err := f.svc.Device(f.ctx, access.System("test"), mesh); err != nil || got.Covered || got.Posture != nil {
		t.Fatalf("%+v %v", got, err)
	}
}
