//go:build integration

package monitoring

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t                *testing.T
	ctx              context.Context
	db               *database.DB
	svc              *Service
	acme, hq, branch uuid.UUID
	globex, plant    uuid.UUID
	super            access.Caller
	// dsn connects to the test database as the superuser.
	dsn string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, dsn: inst.SuperDSN}
	f.svc = New(inst.DB, audit.New(inst.DB, nil), 30*24*time.Hour, 7*24*time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// A server that has served agents for a day: devices count as seen when
	// they last checked in (TestOfflineAfterStart tests the start).
	f.svc.FollowServing(func() (time.Time, bool) { return time.Now().Add(-24 * time.Hour), true })
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.branch = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Branch') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.plant = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, f.globex)
	f.super = f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
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

func (f *fixture) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

// device enrolls a device whose agent checked in agoMinutes ago.
func (f *fixture) device(org, site uuid.UUID, name string, agoMinutes int) uuid.UUID {
	f.t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, 'linux', $4, now() - interval '1 day', now() - make_interval(mins => $5)) RETURNING id`, org, site, name, key, agoMinutes)
}

// samples records one measurement a minute for the last minutes, with
// processor, memory and disk at the given percentages.
func (f *fixture) samples(device uuid.UUID, minutes int, cpu, memory, disk float64) {
	f.t.Helper()
	f.exec(`DELETE FROM device_metric_samples WHERE device_id = $1`, device)
	f.exec(`INSERT INTO device_metric_samples (device_id, at, cpu_percent, memory_percent, swap_percent, disk_percent, load1)
		SELECT $1, now() - make_interval(secs => g * 60 + 20), $3, $4, 0, $5, 0.5 FROM generate_series(0, $2 - 1) g`,
		device, minutes, cpu, memory, disk)
}

func (f *fixture) evaluate() Result {
	f.t.Helper()
	r, err := f.svc.Evaluate(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *fixture) policy(c access.Caller, in PolicyInput) *Policy {
	f.t.Helper()
	p, err := f.svc.CreatePolicy(f.ctx, c, in)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

// alerts lists every alert the super administrator can see in status.
func (f *fixture) alerts(status string) []*Alert {
	f.t.Helper()
	list, _, err := f.svc.ListAlerts(f.ctx, f.super, AlertQuery{Status: status, Limit: 500})
	if err != nil {
		f.t.Fatal(err)
	}
	return list
}

func (f *fixture) alertOn(device uuid.UUID, policy string) *Alert {
	f.t.Helper()
	for _, a := range f.alerts(FilterAll) {
		if a.DeviceID == device && a.Name == policy && a.Status != StatusResolved {
			return a
		}
	}
	return nil
}

func (f *fixture) lastResolution(device uuid.UUID) string {
	f.t.Helper()
	var s string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT coalesce(resolution, '') FROM alerts WHERE device_id = $1 ORDER BY seq DESC LIMIT 1`, device).Scan(&s)
	}); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func invalid(err error, field string) bool {
	e, ok := apperr.As(err)
	return ok && e.Kind == apperr.KindInvalid && e.Fields[field] != ""
}

func conflict(err error, code string) bool {
	e, ok := apperr.As(err)
	return ok && e.Kind == apperr.KindConflict && e.Code == code
}

func ref[T any](v T) *T { return &v }

func names(list []*Policy) []string {
	out := []string{}
	for _, p := range list {
		out = append(out, p.Name)
	}
	return out
}

func TestSeededPolicies(t *testing.T) {
	f := newFixture(t)
	list, err := f.svc.ListPolicies(f.ctx, f.super, PolicyQuery{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Device offline", "Disk almost full", "Disk errors", "Disk failing", "Disk sectors pending", "Disk too hot",
		"Disk wearing out", "EasyRMM agent silent", "High memory use", "High processor use", "Remote access down"}
	if got := names(list); !slices.Equal(got, want) {
		t.Fatalf("seeded = %v", got)
	}
	for _, p := range list {
		// Of the disk health policies only Disk failing is on (ADR-0065); the
		// two remote access policies are on (ADR-0069).
		on := p.Kind != KindDiskHealth || p.Name == "Disk failing"
		if p.Level != LevelShared || p.Enabled != on || !p.CanEdit {
			t.Errorf("%s: level %s enabled %v canEdit %v", p.Name, p.Level, p.Enabled, p.CanEdit)
		}
	}
	disk := map[string]*Policy{}
	for _, p := range list {
		if p.Kind == KindDiskHealth {
			disk[*p.CheckName] = p
		}
	}
	for check, w := range map[string]struct {
		threshold *int
		minutes   int
		severity  string
	}{
		CheckFailing: {nil, 30, SeverityCritical}, CheckErrors: {ref(1), 30, SeverityWarning}, CheckPending: {ref(1), 30, SeverityWarning},
		CheckWear: {ref(90), 30, SeverityWarning}, CheckTemperature: {nil, 60, SeverityWarning},
	} {
		p := disk[check]
		if p == nil || !same(p.Threshold, w.threshold) || p.Minutes != w.minutes || p.Severity != w.severity {
			t.Errorf("%s = %+v", check, p)
		}
	}
	if list[0].Kind != KindOffline || list[0].Threshold != nil || list[0].Minutes != 15 || list[0].Severity != SeverityCritical {
		t.Errorf("offline = %+v", list[0])
	}
	if list[1].Kind != KindDisk || *list[1].Threshold != 90 || list[1].Minutes != 5 {
		t.Errorf("disk = %+v", list[1])
	}
}

func TestPolicyAccess(t *testing.T) {
	f := newFixture(t)
	orgAdmin := f.user("orgadmin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	hqAdmin := f.user("hqadmin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	hqTech := f.user("hqtech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	globexTech := f.user("globex@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.globex})

	cpu := func(name string, org, site *uuid.UUID) PolicyInput {
		return PolicyInput{OrganizationID: org, SiteID: site, Name: name, Kind: KindCPU, Threshold: ref(80), Minutes: 10, Severity: SeverityWarning}
	}
	shared := f.policy(f.super, cpu("Shared CPU", nil, nil))
	if _, err := f.svc.CreatePolicy(f.ctx, orgAdmin, cpu("Nope", nil, nil)); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("org admin creating a shared policy: %v", err)
	}
	acmeP := f.policy(orgAdmin, cpu("Acme CPU", &f.acme, nil))
	hqP := f.policy(hqAdmin, cpu("HQ CPU", &f.acme, &f.hq))
	branchP := f.policy(orgAdmin, cpu("Branch CPU", &f.acme, &f.branch))
	globexP := f.policy(f.super, cpu("Globex CPU", &f.globex, nil))
	if acmeP.Level != LevelOrganization || hqP.Level != LevelSite || hqP.SiteName != "HQ" || hqP.OrganizationName != "Acme" {
		t.Fatalf("levels: %+v %+v", acmeP, hqP)
	}
	if _, err := f.svc.CreatePolicy(f.ctx, hqAdmin, cpu("Branch two", &f.acme, &f.branch)); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("site admin creating for another site: %v", err)
	}
	if _, err := f.svc.CreatePolicy(f.ctx, hqTech, cpu("Tech", &f.acme, &f.hq)); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("technician creating: %v", err)
	}

	// Validation and the database's own checks.
	if _, err := f.svc.CreatePolicy(f.ctx, f.super, cpu("Shared CPU", nil, nil)); !invalid(err, "name") {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := f.svc.CreatePolicy(f.ctx, f.super, cpu("shared cpu", &f.acme, nil)); err != nil {
		t.Fatalf("same name at another level: %v", err)
	}
	if _, err := f.svc.CreatePolicy(f.ctx, f.super, cpu("Siteless", nil, &f.hq)); !invalid(err, "organizationId") {
		t.Fatalf("site without organization: %v", err)
	}
	if _, err := f.svc.CreatePolicy(f.ctx, f.super, cpu("Mismatch", &f.globex, &f.hq)); !invalid(err, "siteId") {
		t.Fatalf("site of another organization: %v", err)
	}
	if _, err := f.svc.CreatePolicy(f.ctx, f.super, PolicyInput{Name: "Bad", Kind: KindOffline, Minutes: 2, Severity: SeverityCritical}); !invalid(err, "minutes") {
		t.Fatalf("offline for 2 minutes: %v", err)
	}
	if _, err := f.svc.CreatePolicy(f.ctx, f.super, PolicyInput{Name: "Bad", Kind: KindMemory, Minutes: 5, Severity: SeverityCritical}); !invalid(err, "threshold") {
		t.Fatalf("memory without threshold: %v", err)
	}
	off := f.policy(f.super, PolicyInput{Name: "Quiet", Kind: KindOffline, Threshold: ref(50), Minutes: 60, Severity: SeverityWarning, Enabled: ref(false)})
	if off.Threshold != nil || off.Enabled {
		t.Fatalf("offline policy = %+v", off)
	}

	// Who sees what.
	list := func(c access.Caller, org uuid.UUID) []string {
		t.Helper()
		l, err := f.svc.ListPolicies(f.ctx, c, PolicyQuery{OrganizationID: org})
		if err != nil {
			t.Fatal(err)
		}
		return names(l)
	}
	if got := list(hqTech, uuid.Nil); slices.Contains(got, "Branch CPU") || slices.Contains(got, "Globex CPU") || !slices.Contains(got, "HQ CPU") || !slices.Contains(got, "Acme CPU") || !slices.Contains(got, "Shared CPU") {
		t.Fatalf("HQ technician sees %v", got)
	}
	if got := list(globexTech, uuid.Nil); slices.Contains(got, "Acme CPU") || !slices.Contains(got, "Globex CPU") || !slices.Contains(got, "Shared CPU") {
		t.Fatalf("Globex technician sees %v", got)
	}
	if got := list(f.super, f.globex); slices.Contains(got, "Acme CPU") || !slices.Contains(got, "Globex CPU") || !slices.Contains(got, "Device offline") {
		t.Fatalf("Globex filter = %v", got)
	}
	techView, err := f.svc.ListPolicies(f.ctx, hqTech, PolicyQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range techView {
		if p.CanEdit {
			t.Errorf("technician can edit %s", p.Name)
		}
	}
	if p, err := f.svc.GetPolicy(f.ctx, hqAdmin, hqP.ID); err != nil || !p.CanEdit {
		t.Fatalf("site admin's own policy: %v %+v", err, p)
	}
	if p, err := f.svc.GetPolicy(f.ctx, hqAdmin, acmeP.ID); err != nil || p.CanEdit {
		t.Fatalf("site admin reading the organization's policy: %v %+v", err, p)
	}
	for _, c := range []struct {
		who  access.Caller
		id   uuid.UUID
		want error
	}{
		{globexTech, acmeP.ID, apperr.ErrNotFound},
		{hqTech, branchP.ID, apperr.ErrNotFound},
		{f.super, uuid.New(), apperr.ErrNotFound},
	} {
		if _, err := f.svc.GetPolicy(f.ctx, c.who, c.id); !errors.Is(err, c.want) {
			t.Errorf("get %s: %v", c.id, err)
		}
	}

	// Changes.
	if _, err := f.svc.UpdatePolicy(f.ctx, hqTech, hqP.ID, PolicyPatch{Name: ref("x")}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("technician updating: %v", err)
	}
	if _, err := f.svc.UpdatePolicy(f.ctx, globexTech, acmeP.ID, PolicyPatch{Name: ref("x")}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("other organization updating: %v", err)
	}
	if _, err := f.svc.UpdatePolicy(f.ctx, hqAdmin, acmeP.ID, PolicyPatch{Name: ref("x")}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("site admin updating the organization's: %v", err)
	}
	if _, err := f.svc.UpdatePolicy(f.ctx, orgAdmin, acmeP.ID, PolicyPatch{Kind: ref(KindDisk), Threshold: ref(0)}); !invalid(err, "threshold") {
		t.Fatalf("threshold 0: %v", err)
	}
	if _, err := f.svc.UpdatePolicy(f.ctx, orgAdmin, acmeP.ID, PolicyPatch{Name: ref("HQ CPU")}); err != nil {
		t.Fatalf("a name used at another level: %v", err)
	}
	up, err := f.svc.UpdatePolicy(f.ctx, orgAdmin, acmeP.ID, PolicyPatch{Kind: ref(KindOffline), Minutes: ref(30), Severity: ref(SeverityCritical), Description: ref(" Down \x07")})
	if err != nil {
		t.Fatal(err)
	}
	if up.Kind != KindOffline || up.Threshold != nil || up.Minutes != 30 || up.Severity != SeverityCritical || up.Description != "Down" {
		t.Fatalf("updated = %+v", up)
	}
	if _, err := f.svc.UpdatePolicy(f.ctx, orgAdmin, acmeP.ID, PolicyPatch{Kind: ref(KindMemory)}); !invalid(err, "threshold") {
		t.Fatalf("memory without threshold: %v", err)
	}
	if !up.UpdatedAt.After(acmeP.UpdatedAt) {
		t.Errorf("updated_at did not move")
	}
	// Nothing changed: no audit entry.
	before := f.count(`SELECT count(*) FROM audit_log WHERE action = 'alert_policy.update'`)
	if _, err := f.svc.UpdatePolicy(f.ctx, orgAdmin, acmeP.ID, PolicyPatch{Name: ref(up.Name)}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'alert_policy.update'`); n != before {
		t.Fatalf("an empty change was audited")
	}

	if err := f.svc.DeletePolicy(f.ctx, hqTech, hqP.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("technician deleting: %v", err)
	}
	if err := f.svc.DeletePolicy(f.ctx, hqAdmin, hqP.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DeletePolicy(f.ctx, f.super, globexP.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DeletePolicy(f.ctx, f.super, shared.ID); err != nil {
		t.Fatal(err)
	}
	for action, want := range map[string]int{"alert_policy.create": 7, "alert_policy.update": 2, "alert_policy.delete": 3} {
		if n := f.count(`SELECT count(*) FROM audit_log WHERE action = $1`, action); n != want {
			t.Errorf("%s audited %d times, want %d", action, n, want)
		}
	}
}

func TestEvaluate(t *testing.T) {
	f := newFixture(t)
	f.exec(`UPDATE alert_policies SET enabled = false`)
	busy := f.device(f.acme, f.hq, "busy", 0)
	idle := f.device(f.acme, f.hq, "idle", 0)
	sparse := f.device(f.acme, f.hq, "sparse", 0)
	down := f.device(f.acme, f.branch, "down", 40)
	never := f.id(`INSERT INTO devices (organization_id, site_id, name) VALUES ($1, $2, 'never') RETURNING id`, f.acme, f.hq)
	mesh := f.id(`INSERT INTO devices (organization_id, site_id, name, remote_online, last_seen_at) VALUES ($1, $2, 'mesh', true, now() - interval '2 hours') RETURNING id`, f.globex, f.plant)
	f.samples(busy, 20, 99, 50, 40)
	f.samples(idle, 20, 10, 50, 40)
	f.samples(sparse, 3, 99, 50, 40)

	cpu := f.policy(f.super, PolicyInput{Name: "CPU", Kind: KindCPU, Threshold: ref(90), Minutes: 10, Severity: SeverityWarning})
	f.policy(f.super, PolicyInput{OrganizationID: &f.acme, Name: "Offline", Kind: KindOffline, Minutes: 15, Severity: SeverityCritical})

	r := f.evaluate()
	if r.Opened != 2 || r.Resolved != 0 || r.Skipped {
		t.Fatalf("first evaluation = %+v", r)
	}
	a := f.alertOn(busy, "CPU")
	if a == nil || a.Status != StatusOpen || a.Value != 99 || a.Kind != KindCPU || *a.Threshold != 90 || a.Minutes != 10 || a.Severity != SeverityWarning || a.DeviceName != "busy" || a.SiteName != "HQ" {
		t.Fatalf("CPU alert = %+v", a)
	}
	o := f.alertOn(down, "Offline")
	if o == nil || o.Value < 39 || o.Value > 41 || o.Severity != SeverityCritical {
		t.Fatalf("offline alert = %+v", o)
	}
	for _, d := range []uuid.UUID{idle, sparse, never, mesh} {
		if f.count(`SELECT count(*) FROM alerts WHERE device_id = $1`, d) != 0 {
			t.Errorf("device %s has an alert", d)
		}
	}
	if r := f.evaluate(); r.Opened != 0 || r.Resolved != 0 {
		t.Fatalf("second evaluation = %+v", r)
	}

	// The latest value follows; the raising value stays.
	f.samples(busy, 20, 95, 50, 40)
	f.evaluate()
	if a := f.alertOn(busy, "CPU"); a.Value != 99 || a.LastValue != 95 {
		t.Fatalf("after an update: %v / %v", a.Value, a.LastValue)
	}

	// A device that stops reporting keeps its alert.
	f.exec(`DELETE FROM device_metric_samples WHERE device_id = $1`, busy)
	if r := f.evaluate(); r.Resolved != 0 || f.alertOn(busy, "CPU") == nil {
		t.Fatalf("silent device: %+v", r)
	}

	// Recovery: five quiet minutes resolve it.
	f.samples(busy, 4, 20, 50, 40)
	if r := f.evaluate(); r.Resolved != 1 || f.alertOn(busy, "CPU") != nil || f.lastResolution(busy) != "cleared" {
		t.Fatalf("recovery: %+v %q", r, f.lastResolution(busy))
	}
	f.exec(`UPDATE devices SET agent_last_seen_at = now() WHERE id = $1`, down)
	if r := f.evaluate(); r.Resolved != 1 || f.lastResolution(down) != "cleared" {
		t.Fatalf("back online: %+v", r)
	}
	if n := f.count(`SELECT count(*) FROM alerts WHERE status = 'resolved' AND resolved_at IS NOT NULL AND resolved_by_label = ''`); n != 2 {
		t.Fatalf("resolved alerts = %d", n)
	}

	// A device leaving the policy's organization.
	f.exec(`UPDATE devices SET agent_last_seen_at = now() - interval '1 hour' WHERE id = $1`, down)
	f.evaluate()
	if f.alertOn(down, "Offline") == nil {
		t.Fatal("offline again: no alert")
	}
	f.exec(`UPDATE devices SET organization_id = $2, site_id = $3 WHERE id = $1`, down, f.globex, f.plant)
	if r := f.evaluate(); r.Resolved != 1 || f.lastResolution(down) != "not_covered" || r.Opened != 0 {
		t.Fatalf("moved: %+v %q", r, f.lastResolution(down))
	}

	// Policy changes.
	f.samples(busy, 20, 99, 50, 40)
	f.evaluate()
	if f.alertOn(busy, "CPU") == nil {
		t.Fatal("busy again: no alert")
	}
	if _, err := f.svc.UpdatePolicy(f.ctx, f.super, cpu.ID, PolicyPatch{Name: ref("Hot CPU"), Severity: ref(SeverityCritical)}); err != nil {
		t.Fatal(err)
	}
	if a := f.alertOn(busy, "Hot CPU"); a == nil || a.Severity != SeverityCritical {
		t.Fatalf("renamed: %+v", a)
	}
	if _, err := f.svc.UpdatePolicy(f.ctx, f.super, cpu.ID, PolicyPatch{Threshold: ref(98)}); err != nil {
		t.Fatal(err)
	}
	if f.alertOn(busy, "Hot CPU") != nil || f.lastResolution(busy) != "policy_changed" {
		t.Fatalf("threshold change: %q", f.lastResolution(busy))
	}
	if r := f.evaluate(); r.Opened != 1 {
		t.Fatalf("re-raised: %+v", r)
	}
	if a := f.alertOn(busy, "Hot CPU"); a == nil || *a.Threshold != 98 {
		t.Fatalf("new condition: %+v", a)
	}
	if _, err := f.svc.UpdatePolicy(f.ctx, f.super, cpu.ID, PolicyPatch{Enabled: ref(false)}); err != nil {
		t.Fatal(err)
	}
	if f.lastResolution(busy) != "policy_off" || f.evaluate().Opened != 0 {
		t.Fatalf("turned off: %q", f.lastResolution(busy))
	}
	if _, err := f.svc.UpdatePolicy(f.ctx, f.super, cpu.ID, PolicyPatch{Enabled: ref(true)}); err != nil {
		t.Fatal(err)
	}
	f.evaluate()
	if err := f.svc.DeletePolicy(f.ctx, f.super, cpu.ID); err != nil {
		t.Fatal(err)
	}
	if f.lastResolution(busy) != "policy_deleted" {
		t.Fatalf("deleted: %q", f.lastResolution(busy))
	}
	var gone []*Alert
	for _, a := range f.alerts(FilterResolved) {
		if a.DeviceID == busy && a.Resolution == "policy_deleted" {
			gone = append(gone, a)
		}
	}
	if len(gone) != 1 || gone[0].PolicyID != nil || gone[0].Name != "Hot CPU" {
		t.Fatalf("alert of a deleted policy: %+v", gone)
	}

	// A MeshAgent-only device goes offline; its policy is then deleted
	// without the service (as by a cascade), leaving its alerts to the
	// evaluator. The moved device, offline for an hour, is covered too.
	o2 := f.policy(f.super, PolicyInput{Name: "Mesh down", Kind: KindOffline, Minutes: 30, Severity: SeverityWarning})
	f.exec(`UPDATE devices SET remote_online = false WHERE id = $1`, mesh)
	if r := f.evaluate(); r.Opened != 2 || f.alertOn(mesh, "Mesh down") == nil || f.alertOn(down, "Mesh down") == nil {
		t.Fatalf("offline devices: %+v", r)
	}
	f.exec(`DELETE FROM alert_policies WHERE id = $1`, o2.ID)
	if r := f.evaluate(); r.Resolved != 2 || f.lastResolution(mesh) != "policy_deleted" {
		t.Fatalf("orphaned alert: %+v", r)
	}
}

// TestOfflineAfterStart: offline policies count a device as seen no earlier
// than AgentGrace after the server began serving agents, at its start or
// when a hold ended, so that neither a restart nor an upgrade raises an
// offline alert (ADR-0052).
func TestOfflineAfterStart(t *testing.T) {
	f := newFixture(t)
	f.exec(`UPDATE alert_policies SET enabled = false`)
	f.policy(f.super, PolicyInput{Name: "Offline", Kind: KindOffline, Minutes: MinOfflineMinutes, Severity: SeverityCritical})
	long := f.device(f.acme, f.hq, "long-gone", 24*60)
	wait := AgentGrace + MinOfflineMinutes*time.Minute

	// A service just made: the server began serving agents now.
	fresh := New(f.db, audit.New(f.db, nil), 30*24*time.Hour, 7*24*time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if r, err := fresh.Evaluate(f.ctx); err != nil || r.Opened != 0 {
		t.Fatalf("at the start: %+v %v", r, err)
	}
	fresh.now = func() time.Time { return time.Now().Add(wait) }
	if r, err := fresh.Evaluate(f.ctx); err != nil || r.Opened != 1 {
		t.Fatalf("the grace and the policy's minutes after the start: %+v %v", r, err)
	}
	f.exec(`DELETE FROM alerts`)

	start := time.Now()
	since, serving := start, true
	f.svc.FollowServing(func() (time.Time, bool) { return since, serving })
	at := func(d time.Duration) Result {
		t.Helper()
		f.svc.now = func() time.Time { return start.Add(d) }
		return f.evaluate()
	}
	if r := at(0); r.Opened != 0 {
		t.Fatalf("at the start: %+v", r)
	}
	if r := at(wait - time.Second); r.Opened != 0 {
		t.Fatalf("a moment before the grace and the policy's minutes: %+v", r)
	}
	if r := at(wait); r.Opened != 1 {
		t.Fatalf("the grace and the policy's minutes after the start: %+v", r)
	}
	// The alert says how long the device has been away, not the wait.
	open := f.alertOn(long, "Offline")
	if open == nil || open.Value < 24*60+7 || open.Value > 24*60+9 {
		t.Fatalf("alert = %+v", open)
	}
	// The rule only delays openings: the alert open before a restart or a
	// hold stays the same open alert, neither resolved nor opened again.
	same := func(when string) {
		t.Helper()
		if a := f.alertOn(long, "Offline"); a == nil || a.ID != open.ID || a.Status != StatusOpen ||
			f.count(`SELECT count(*) FROM alerts WHERE device_id = $1`, long) != 1 {
			t.Fatalf("%s: the open alert is %+v, of %d", when, a, f.count(`SELECT count(*) FROM alerts WHERE device_id = $1`, long))
		}
	}

	// A restart: the alert already open stays open.
	since = start.Add(wait + time.Minute)
	if r := at(wait + time.Minute); r.Resolved != 0 || r.Opened != 0 {
		t.Fatalf("after a restart: %+v", r)
	}
	same("after a restart")

	// Held by the updater: no device counts as unseen, however long.
	recent := f.device(f.acme, f.hq, "recent", 0)
	serving = false
	if r := at(time.Hour); r.Opened != 0 || r.Resolved != 0 {
		t.Fatalf("held: %+v", r)
	}
	same("while held")
	// The hold ends: the start moves forward, and the wait begins again.
	since, serving = start.Add(2*time.Hour), true
	if r := at(2*time.Hour + wait - time.Second); r.Opened != 0 || r.Resolved != 0 {
		t.Fatalf("a moment before the wait after the hold: %+v", r)
	}
	same("after the hold")
	if r := at(2*time.Hour + wait); r.Opened != 1 || r.Resolved != 0 || f.alertOn(recent, "Offline") == nil {
		t.Fatalf("the wait after the hold: %+v", r)
	}
	same("when another device's alert opens")

	// Another restart; within its grace the device checks in, by its real
	// last check-in: then, and only then, its alert resolves.
	since = start.Add(3 * time.Hour)
	f.exec(`UPDATE devices SET agent_last_seen_at = $2 WHERE id = $1`, long, start.Add(3*time.Hour+time.Minute))
	if r := at(3*time.Hour + time.Minute); r.Resolved != 1 || r.Opened != 0 || f.alertOn(long, "Offline") != nil || f.lastResolution(long) != "cleared" {
		t.Fatalf("the device checked in: %+v %q", r, f.lastResolution(long))
	}
	if f.alertOn(recent, "Offline") == nil {
		t.Fatal("the other device's alert resolved without a check-in")
	}
}

func TestEvaluateLock(t *testing.T) {
	f := newFixture(t)
	err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(f.ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockEvaluate)); err != nil {
			return err
		}
		r, err := f.svc.Evaluate(f.ctx)
		if err == nil && !r.Skipped {
			t.Errorf("evaluated while another server held the lock: %+v", r)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.evaluate().Skipped {
		t.Fatal("skipped without a lock held")
	}
}

func TestAlerts(t *testing.T) {
	f := newFixture(t)
	f.exec(`UPDATE alert_policies SET enabled = false WHERE kind <> 'disk'`)
	hqTech := f.user("hqtech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	globexTech := f.user("globex@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.globex})
	pc := f.device(f.acme, f.hq, "pc", 0)
	other := f.device(f.acme, f.hq, "other", 0)
	press := f.device(f.globex, f.plant, "press", 0)
	for _, d := range []uuid.UUID{pc, other, press} {
		f.samples(d, 10, 5, 20, 97)
	}
	f.policy(f.super, PolicyInput{OrganizationID: &f.acme, SiteID: &f.hq, Name: "HQ memory", Kind: KindMemory, Threshold: ref(10), Minutes: 5, Severity: SeverityWarning})
	if r := f.evaluate(); r.Opened != 5 {
		t.Fatalf("opened %d", r.Opened)
	}

	list := func(c access.Caller, q AlertQuery) []*Alert {
		t.Helper()
		if q.Limit == 0 {
			q.Limit = 100
		}
		l, _, err := f.svc.ListAlerts(f.ctx, c, q)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	if got := list(hqTech, AlertQuery{}); len(got) != 4 {
		t.Fatalf("HQ technician sees %d alerts", len(got))
	}
	if got := list(globexTech, AlertQuery{}); len(got) != 1 || got[0].DeviceID != press || !got[0].CanManage {
		t.Fatalf("Globex technician sees %+v", got)
	}
	if got := list(f.super, AlertQuery{DeviceID: pc}); len(got) != 2 {
		t.Fatalf("pc has %d alerts", len(got))
	}
	if got := list(f.super, AlertQuery{Severity: SeverityCritical}); len(got) != 3 {
		t.Fatalf("critical: %d", len(got))
	}
	if got := list(f.super, AlertQuery{OrganizationID: f.globex}); len(got) != 1 {
		t.Fatalf("Globex: %d", len(got))
	}
	if got := list(f.super, AlertQuery{SiteID: f.hq, Severity: SeverityWarning}); len(got) != 2 {
		t.Fatalf("HQ warnings: %d", len(got))
	}
	if _, _, err := f.svc.ListAlerts(f.ctx, f.super, AlertQuery{Status: "open", Limit: 10}); !invalid(err, "status") {
		t.Fatalf("bad status: %v", err)
	}
	if _, _, err := f.svc.ListAlerts(f.ctx, f.super, AlertQuery{Severity: "info", Limit: 10}); !invalid(err, "severity") {
		t.Fatalf("bad severity: %v", err)
	}

	// Pages.
	var seen []uuid.UUID
	var before int64
	for range 10 {
		page, next, err := f.svc.ListAlerts(f.ctx, f.super, AlertQuery{Limit: 2, Before: before})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range page {
			seen = append(seen, a.ID)
		}
		if next == 0 {
			break
		}
		before = next
	}
	if len(seen) != 5 || len(slices.Compact(slices.Clone(seen))) != 5 {
		t.Fatalf("paged %d alerts", len(seen))
	}

	sum, err := f.svc.Summarize(f.ctx, hqTech)
	if err != nil {
		t.Fatal(err)
	}
	if sum != (Summary{Active: 4, Critical: 2, Warning: 2, Devices: 2}) {
		t.Fatalf("summary = %+v", sum)
	}
	byDevice := func(c access.Caller) map[uuid.UUID]DeviceAlerts {
		t.Helper()
		items, err := f.svc.ActiveByDevice(f.ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		out := map[uuid.UUID]DeviceAlerts{}
		for _, d := range items {
			out[d.DeviceID] = d
		}
		return out
	}
	if got := byDevice(hqTech); len(got) != 2 ||
		got[pc] != (DeviceAlerts{DeviceID: pc, OrganizationID: f.acme, SiteID: f.hq, Active: 2, Critical: 1}) ||
		got[other].Active != 2 || got[other].Critical != 1 {
		t.Fatalf("HQ technician's counts = %+v", got)
	}
	if got := byDevice(globexTech); len(got) != 1 || got[press] != (DeviceAlerts{DeviceID: press, OrganizationID: f.globex, SiteID: f.plant, Active: 1, Critical: 1}) {
		t.Fatalf("Globex technician's counts = %+v", got)
	}
	if got := byDevice(f.super); len(got) != 3 {
		t.Fatalf("super administrator's counts = %+v", got)
	}

	// Acknowledge and resolve.
	target := list(f.super, AlertQuery{DeviceID: pc, Severity: SeverityCritical})[0]
	if v := list(viewer, AlertQuery{DeviceID: pc})[0]; v.CanManage {
		t.Fatal("read-only user can manage")
	}
	if _, err := f.svc.Acknowledge(f.ctx, viewer, target.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("read-only acknowledging: %v", err)
	}
	if _, err := f.svc.Acknowledge(f.ctx, globexTech, target.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("other organization acknowledging: %v", err)
	}
	ack, err := f.svc.Acknowledge(f.ctx, hqTech, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Status != StatusAcknowledged || ack.AcknowledgedBy != "hqtech@example.com" || ack.AcknowledgedAt == nil {
		t.Fatalf("acknowledged = %+v", ack)
	}
	if again, err := f.svc.Acknowledge(f.ctx, f.super, target.ID); err != nil || again.AcknowledgedBy != "hqtech@example.com" {
		t.Fatalf("acknowledging twice: %v %+v", err, again)
	}
	if sum, _ := f.svc.Summarize(f.ctx, hqTech); sum.Acknowledged != 1 || sum.Active != 4 {
		t.Fatalf("summary after acknowledging = %+v", sum)
	}
	// An acknowledged alert still resolves when its condition clears.
	f.evaluate()
	if a, _ := f.svc.GetAlert(f.ctx, hqTech, target.ID); a.Status != StatusAcknowledged {
		t.Fatalf("evaluation changed an acknowledged alert: %s", a.Status)
	}
	res, err := f.svc.Resolve(f.ctx, hqTech, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusResolved || res.Resolution != "manual" || res.ResolvedBy != "hqtech@example.com" || res.ResolvedAt == nil {
		t.Fatalf("resolved = %+v", res)
	}
	if _, err := f.svc.Resolve(f.ctx, hqTech, target.ID); !conflict(err, "alert_resolved") {
		t.Fatalf("resolving twice: %v", err)
	}
	if _, err := f.svc.Acknowledge(f.ctx, hqTech, target.ID); !conflict(err, "alert_resolved") {
		t.Fatalf("acknowledging a resolved alert: %v", err)
	}
	if got := list(f.super, AlertQuery{Status: FilterResolved}); len(got) != 1 || got[0].ID != target.ID {
		t.Fatalf("resolved list = %+v", got)
	}
	// The condition still holds, so the next evaluation opens a new alert.
	if r := f.evaluate(); r.Opened != 1 {
		t.Fatalf("re-opened %d", r.Opened)
	}
	if got := list(f.super, AlertQuery{Status: FilterAll, DeviceID: pc}); len(got) != 3 {
		t.Fatalf("all alerts on pc: %d", len(got))
	}
	if _, err := f.svc.GetAlert(f.ctx, globexTech, target.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("other organization reading: %v", err)
	}
	if _, err := f.svc.GetAlert(f.ctx, f.super, uuid.New()); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("unknown alert: %v", err)
	}
	for action, want := range map[string]int{"alert.acknowledge": 1, "alert.resolve": 1} {
		if n := f.count(`SELECT count(*) FROM audit_log WHERE action = $1 AND device_id = $2`, action, pc); n != want {
			t.Errorf("%s audited %d times", action, n)
		}
	}

	// Retention removes resolved alerts only.
	f.exec(`UPDATE alerts SET resolved_at = now() - interval '31 days' WHERE id = $1`, target.ID)
	n, err := f.svc.Purge(f.ctx)
	if err != nil || n != 1 {
		t.Fatalf("purged %d: %v", n, err)
	}
	if left := f.count(`SELECT count(*) FROM alerts`); left != 5 {
		t.Fatalf("%d alerts left", left)
	}
	// Deleting a device removes its alerts.
	f.exec(`DELETE FROM devices WHERE id = $1`, other)
	if left := f.count(`SELECT count(*) FROM alerts`); left != 3 {
		t.Fatalf("%d alerts left after removing a device", left)
	}
}

// TestAlertDetail covers what an alert's card reads besides the alert: its
// measurements, and the policy's earlier openings on the device, each only
// for those who may see the device's alerts.
func TestAlertDetail(t *testing.T) {
	f := newFixture(t)
	f.exec(`UPDATE alert_policies SET enabled = false WHERE kind <> 'disk'`)
	hqTech := f.user("hqtech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	branchTech := f.user("branch@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.branch})
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	globexTech := f.user("globex@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.globex})
	pc := f.device(f.acme, f.hq, "pc", 0)
	press := f.device(f.globex, f.plant, "press", 0)
	f.samples(pc, 20, 5, 20, 97)
	f.samples(press, 20, 5, 20, 99)
	if r := f.evaluate(); r.Opened != 2 {
		t.Fatalf("opened %d", r.Opened)
	}
	disk := f.alertOn(pc, "Disk almost full")

	// The measurement over the alert's window: the policy's 5 minutes before
	// it opened and at least 15 minutes either side, averaged by the minute.
	m, err := f.svc.AlertMetrics(f.ctx, hqTech, disk.ID)
	if err != nil {
		t.Fatal(err)
	}
	if m.Metric != KindDisk || m.Threshold == nil || *m.Threshold != 90 || m.BucketSeconds != 60 ||
		m.From.After(disk.OpenedAt.Add(-20*time.Minute)) || len(m.Samples) < 15 {
		t.Fatalf("metrics = %+v", m)
	}
	for _, p := range m.Samples {
		if p.Value != 97 || p.At.Before(m.From.Add(-time.Minute)) || p.At.After(m.To) {
			t.Fatalf("sample %+v outside %s to %s", p, m.From, m.To)
		}
	}
	// Another device's measurements never mix in, and its alert is not
	// another organization's to read; nor another site's.
	if m, err := f.svc.AlertMetrics(f.ctx, viewer, disk.ID); err != nil || len(m.Samples) == 0 {
		t.Fatalf("read-only user of the organization: %v", err)
	}
	for name, c := range map[string]access.Caller{"other organization": globexTech, "other site": branchTech} {
		if _, err := f.svc.AlertMetrics(f.ctx, c, disk.ID); !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if m, err := f.svc.AlertMetrics(f.ctx, globexTech, f.alertOn(press, "Disk almost full").ID); err != nil || m.Samples[0].Value != 99 {
		t.Fatalf("Globex's own alert: %+v %v", m, err)
	}
	if _, err := f.svc.AlertMetrics(f.ctx, f.super, uuid.New()); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("unknown alert: %v", err)
	}
	// Offline and disk health alerts are not measured.
	offline := f.id(`INSERT INTO alerts (policy_id, device_id, name, kind, threshold, minutes, severity, value, last_value)
		SELECT id, $1, name, kind, threshold, minutes, severity, 20, 20 FROM alert_policies WHERE kind = 'offline' RETURNING id`, pc)
	if _, err := f.svc.AlertMetrics(f.ctx, f.super, offline); !conflict(err, "alert_has_no_metrics") {
		t.Fatalf("offline alert: %v", err)
	}
	// An alert opened before the oldest measurement kept (7 days here) charts
	// only what is kept, and says so, even while an older measurement waits
	// to be pruned.
	old := f.id(`INSERT INTO alerts (policy_id, device_id, name, kind, threshold, minutes, severity, value, last_value, status, opened_at, resolved_at, resolution)
		SELECT id, $1, name, kind, threshold, minutes, severity, 95, 91, 'resolved', now() - interval '10 days', now() - interval '1 hour', 'cleared'
		FROM alert_policies WHERE kind = 'disk' RETURNING id`, pc)
	f.exec(`INSERT INTO device_metric_samples (device_id, at, cpu_percent, memory_percent, swap_percent, disk_percent, load1)
		VALUES ($1, now() - interval '8 days', 5, 20, 0, 50, 0.5), ($1, now() - interval '6 days', 5, 20, 0, 60, 0.5)`, pc)
	m, err = f.svc.AlertMetrics(f.ctx, hqTech, old)
	if err != nil {
		t.Fatal(err)
	}
	if kept := time.Now().Add(-7 * 24 * time.Hour); !m.Trimmed || m.From.Before(kept.Add(-time.Minute)) || m.From.After(kept) || m.BucketSeconds != 3600 {
		t.Fatalf("old alert's window: %+v", m)
	}
	values := map[float64]bool{}
	for _, p := range m.Samples {
		values[p.Value] = true
	}
	if values[50] || !values[60] || !values[97] || len(m.Samples) > maxPoints {
		t.Fatalf("old alert's measurements: %+v", m.Samples)
	}
	if m, err := f.svc.AlertMetrics(f.ctx, hqTech, disk.ID); err != nil || m.Trimmed {
		t.Fatalf("a recent alert is not trimmed: %+v %v", m, err)
	}
	f.exec(`DELETE FROM alerts WHERE id = $1`, old)
	f.exec(`DELETE FROM device_metric_samples WHERE device_id = $1 AND at < now() - interval '1 day'`, pc)

	// The policy's earlier openings on the device: resolved by hand while
	// the condition holds, it opens again.
	if _, err := f.svc.Resolve(f.ctx, hqTech, disk.ID); err != nil {
		t.Fatal(err)
	}
	if r := f.evaluate(); r.Opened != 1 {
		t.Fatalf("re-opened %d", r.Opened)
	}
	policy := *disk.PolicyID
	list := func(c access.Caller, q AlertQuery) []*Alert {
		t.Helper()
		q.Status, q.Limit = FilterAll, 20
		l, _, err := f.svc.ListAlerts(f.ctx, c, q)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	if got := list(hqTech, AlertQuery{DeviceID: pc, PolicyID: policy}); len(got) != 2 || got[1].ID != disk.ID || got[0].Status != StatusOpen {
		t.Fatalf("the policy's alerts on pc: %+v", got)
	}
	// The shared policy covers Globex too, which Acme's technician never sees.
	if got := list(hqTech, AlertQuery{PolicyID: policy}); len(got) != 2 {
		t.Fatalf("the policy's alerts for an Acme technician: %d", len(got))
	}
	if got := list(globexTech, AlertQuery{PolicyID: policy}); len(got) != 1 || got[0].DeviceID != press {
		t.Fatalf("the policy's alerts for a Globex technician: %+v", got)
	}
	if got := list(globexTech, AlertQuery{DeviceID: pc, PolicyID: policy}); len(got) != 0 {
		t.Fatalf("Acme's alerts for a Globex technician: %+v", got)
	}
	if got := list(f.super, AlertQuery{PolicyID: policy, Subject: "0123456789abcdef"}); len(got) != 0 {
		t.Fatalf("another disk's alerts: %+v", got)
	}
	// A disk health policy's alerts, one per disk.
	failing := f.id(`SELECT id FROM alert_policies WHERE check_name = 'failing'`)
	for _, subject := range []string{"disk-a", "disk-b"} {
		f.exec(`INSERT INTO alerts (policy_id, device_id, name, kind, check_name, minutes, severity, subject, subject_label, value, last_value)
			VALUES ($1, $2, 'Disk failing', 'disk_health', 'failing', 30, 'critical', $3, $3, 1, 1)`, failing, pc, subject)
	}
	if got := list(hqTech, AlertQuery{DeviceID: pc, PolicyID: failing, Subject: "disk-b"}); len(got) != 1 || got[0].Subject != "disk-b" {
		t.Fatalf("one disk's alerts: %+v", got)
	}
	if got := list(hqTech, AlertQuery{DeviceID: pc, PolicyID: failing}); len(got) != 2 {
		t.Fatalf("the policy's disk alerts: %+v", got)
	}
	if _, _, err := f.svc.ListAlerts(f.ctx, f.super, AlertQuery{Subject: strings.Repeat("x", 65), Limit: 10}); !invalid(err, "subject") {
		t.Fatalf("long subject: %v", err)
	}
}

func TestRun(t *testing.T) {
	f := newFixture(t)
	pc := f.device(f.acme, f.hq, "pc", 0)
	f.samples(pc, 10, 5, 20, 97)
	f.exec(`INSERT INTO alerts (policy_id, device_id, name, kind, threshold, minutes, severity, status, value, last_value, resolved_at, resolution)
		SELECT id, $1, name, kind, threshold, minutes, severity, 'resolved', 95, 95, now() - interval '40 days', 'cleared'
		FROM alert_policies WHERE kind = 'disk'`, pc)
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() { f.svc.Run(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for f.alertOn(pc, "Disk almost full") == nil || f.count(`SELECT count(*) FROM alerts WHERE status = 'resolved'`) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("Run did not evaluate and purge")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
