//go:build integration

package easypatch

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Those who configure patching see the server settings; super
// administrators change them with a SuperAdmin statement.
func TestServerSettings(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx
	at := time.Date(2026, 11, 18, 4, 0, 0, 0, time.UTC)
	f.engine.SetFeeds([]map[string]any{{"name": "kev", "lastAttemptAt": at, "lastSuccessAt": at, "lastError": nil, "version": "2026.11.17",
		"itemCount": 1484}, {"name": "msrc", "lastAttemptAt": at, "lastSuccessAt": nil, "lastError": "The feed answered 503.", "version": nil,
		"itemCount": 0}})

	v, err := f.svc.ServerSettings(ctx, f.admin)
	if err != nil || !v.CanEdit || v.Settings.GlobalMaxConcurrentInstalls != 50 || !v.Settings.RolloutGuardEnabled ||
		v.Settings.ReportBrandName != nil || len(v.Feeds) != 2 || v.Feeds[0].ItemCount != 1484 || v.Feeds[1].LastError != "The feed answered 503." {
		t.Fatalf("super administrator: %+v, %v", v, err)
	}
	if st := f.lastStatement("GET", "/api/v1/settings"); st.Role != RoleReadOnly || st.AllOrganizations || len(st.Organizations) != 0 {
		t.Fatalf("read statement: %+v", st)
	}
	if v, err := f.svc.ServerSettings(ctx, f.orgAdmin); err != nil || v.CanEdit {
		t.Fatalf("organization administrator: %+v, %v", v, err)
	}
	if _, err := f.svc.ServerSettings(ctx, f.tech); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("technician: %v", err)
	}

	in := v.Settings
	brand := "  Contoso IT  "
	in.ReportBrandName, in.RolloutGuardFailurePercent = &brand, 30
	got, err := f.svc.SetServerSettings(ctx, f.admin, in)
	if err != nil || got.Settings.ReportBrandName == nil || *got.Settings.ReportBrandName != "Contoso IT" || got.Settings.RolloutGuardFailurePercent != 30 {
		t.Fatalf("saved: %+v, %v", got, err)
	}
	saved := f.engine.ServerSettings()
	if saved["reportBrandName"] != "Contoso IT" || saved["rolloutGuardFailurePercent"] != 30.0 {
		t.Fatalf("in EasyPatch: %+v", saved)
	}
	if st := f.lastStatement("PUT", "/api/v1/settings"); st.Role != RoleSuperAdmin || !st.AllOrganizations || st.Name != "ada@example.com" {
		t.Fatalf("change statement: %+v", st)
	}
	a := f.audits("patch.settings_update")
	if len(a) != 1 {
		t.Fatalf("audit: %+v", a)
	}
	changes, _ := a[0].Details["changes"].(map[string]any)
	pct, _ := changes["rolloutGuardFailurePercent"].(map[string]any)
	if len(changes) != 2 || pct["from"] != 20.0 || pct["to"] != 30.0 || changes["reportBrandName"] == nil {
		t.Fatalf("changes: %+v", a[0].Details)
	}
	// Saving the same values changes nothing and records nothing.
	puts := len(f.engine.RequestsTo("PUT", "/api/v1/settings"))
	if _, err := f.svc.SetServerSettings(ctx, f.admin, got.Settings); err != nil || len(f.engine.RequestsTo("PUT", "/api/v1/settings")) != puts ||
		len(f.audits("patch.settings_update")) != 1 {
		t.Fatalf("unchanged: %v", err)
	}

	for name, change := range map[string]func(*ServerSettings){
		"globalMaxConcurrentInstalls": func(s *ServerSettings) { s.GlobalMaxConcurrentInstalls = 0 },
		"deliveryLeaseMinutes":        func(s *ServerSettings) { s.DeliveryLeaseMinutes = 1 },
		"retentionAuditDays":          func(s *ServerSettings) { s.RetentionAuditDays = 4000 },
		"credentialRotateBeforeDays":  func(s *ServerSettings) { s.CredentialLifetimeDays, s.CredentialRotateBeforeDays = 60, 60 },
		"reportBrandName":             func(s *ServerSettings) { b := "Contoso\nIT"; s.ReportBrandName = &b },
	} {
		bad := got.Settings
		change(&bad)
		if _, err := f.svc.SetServerSettings(ctx, f.admin, bad); fieldOf(err) != name {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.svc.SetServerSettings(ctx, f.orgAdmin, got.Settings); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("organization administrator's change: %v", err)
	}
	f.engine.Set(func() { f.engine.Down = true })
	if _, err := f.svc.ServerSettings(ctx, f.admin); !isCode(err, "patching_unavailable") {
		t.Fatalf("engine down: %v", err)
	}
}

// fieldOf is the field an invalid-input error names.
func fieldOf(err error) string {
	var e *apperr.Error
	if !errors.As(err, &e) || e.Kind != apperr.KindInvalid {
		return ""
	}
	for name := range e.Fields {
		return name
	}
	return ""
}

// Super administrators keep the operating systems' end-of-servicing dates;
// others who configure patching read them.
func TestLifecycle(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx
	l, err := f.svc.Lifecycle(ctx, f.admin)
	if err != nil || !l.CanEdit || len(l.Items) != 2 || l.Items[0].Product != "Windows 11" || l.Items[1].Product != "Windows Server" {
		t.Fatalf("list: %+v, %v", l, err)
	}
	empty, notes := " ", "  Check Microsoft's date  "
	e, err := f.svc.CreateLifecycle(ctx, f.admin, LifecycleInput{Product: " Windows 11 ", EditionGroup: "HomePro", BuildNumber: 26200,
		VersionLabel: "25H2", EndOfServicing: "2027-10-12", EsuEndDate: &empty, Notes: &notes})
	if err != nil || e.ID == uuid.Nil || e.Product != "Windows 11" || e.EsuEndDate != nil || e.Notes == nil || *e.Notes != "Check Microsoft's date" {
		t.Fatalf("created: %+v, %v", e, err)
	}
	if st := f.lastStatement("POST", "/api/v1/lifecycle"); st.Role != RoleSuperAdmin || !st.AllOrganizations {
		t.Fatalf("statement: %+v", st)
	}
	if _, err := f.svc.CreateLifecycle(ctx, f.admin, e.LifecycleInput); fieldOf(err) != "buildNumber" {
		t.Fatalf("the same build again: %v", err)
	}
	esu := "2028-10-10"
	in := e.LifecycleInput
	in.EsuEndDate = &esu
	if u, err := f.svc.UpdateLifecycle(ctx, f.admin, e.ID, in); err != nil || u.EsuEndDate == nil || *u.EsuEndDate != esu {
		t.Fatalf("updated: %+v, %v", u, err)
	}
	early := "2027-01-01"
	for name, bad := range map[string]LifecycleInput{
		"product":        {Product: strings.Repeat("W", 65), EditionGroup: "HomePro", BuildNumber: 1, VersionLabel: "x", EndOfServicing: "2027-01-01"},
		"buildNumber":    {Product: "Windows 11", EditionGroup: "HomePro", BuildNumber: 0, VersionLabel: "x", EndOfServicing: "2027-01-01"},
		"endOfServicing": {Product: "Windows 11", EditionGroup: "HomePro", BuildNumber: 1, VersionLabel: "x", EndOfServicing: "13/10/2027"},
		"esuEndDate": {Product: "Windows 11", EditionGroup: "HomePro", BuildNumber: 1, VersionLabel: "x", EndOfServicing: "2027-10-12",
			EsuEndDate: &early},
	} {
		if _, err := f.svc.CreateLifecycle(ctx, f.admin, bad); fieldOf(err) != name {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := f.svc.DeleteLifecycle(ctx, f.admin, uuid.New()); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("unknown entry: %v", err)
	}
	if err := f.svc.DeleteLifecycle(ctx, f.admin, e.ID); err != nil || len(f.engine.LifecycleEntries()) != 2 {
		t.Fatalf("deleted: %v", err)
	}
	a := f.audits("patch.lifecycle_")
	if len(a) != 3 || a[0].Action != "patch.lifecycle_create" || a[1].Action != "patch.lifecycle_update" || a[1].Details["esuEndDate"] != esu ||
		a[2].Action != "patch.lifecycle_delete" || a[2].Details["versionLabel"] != "25H2" {
		t.Fatalf("audit: %+v", a)
	}

	if l, err := f.svc.Lifecycle(ctx, f.orgAdmin); err != nil || l.CanEdit || len(l.Items) != 2 {
		t.Fatalf("organization administrator: %+v, %v", l, err)
	}
	if _, err := f.svc.CreateLifecycle(ctx, f.orgAdmin, in); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("organization administrator's entry: %v", err)
	}
	if _, err := f.svc.Lifecycle(ctx, f.tech); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("technician: %v", err)
	}
}

// The agent packages download from EasyRMM's own address with the bundled
// engine.
func TestAgentPackageList(t *testing.T) {
	f := newFleetFixture(t)
	list, err := f.svc.AgentPackageList(f.ctx, f.orgAdmin)
	if err != nil || len(list) != 7 || list[0].URL != "/downloads/agent/"+list[0].FileName {
		t.Fatalf("packages: %+v, %v", list, err)
	}
	if _, err := f.svc.AgentPackageList(f.ctx, f.reader); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("reader: %v", err)
	}
}

// EasyPatch's audit log shows the organizations the caller audits whole,
// with EasyRMM's names for them and their devices; everything, with
// EasyPatch's own entries, to those who audit everywhere.
func TestEngineAudit(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx
	base := time.Now().UTC().Add(-3 * time.Hour)
	globex := f.epGlobex
	f.engine.AddAudit(eptest.AuditInfo{Action: "update.hold", TargetType: "UpdateHold", Details: `{"source":"RolloutGuard"}`, CreatedAt: base})
	f.engine.AddAudit(eptest.AuditInfo{Username: "easyrmm:otto@example.com", Org: &f.epAcme, Endpoint: &f.eWeb.ID, Action: "endpoint.update",
		CreatedAt: base.Add(time.Hour)})
	f.engine.AddAudit(eptest.AuditInfo{Username: "jo", Org: &globex, Action: "policy.update", IPAddress: "192.0.2.7", CreatedAt: base.Add(2 * time.Hour)})

	p, err := f.svc.AuditLog(ctx, f.admin, AuditQuery{})
	if err != nil || !p.Everything || p.TotalCount != 3 || len(p.Items) != 3 {
		t.Fatalf("super administrator: %+v, %v", p, err)
	}
	if e := p.Items[0]; e.Action != "policy.update" || e.Actor != "jo" || e.Via != "easypatch" || e.OrganizationName != "Globex" || e.IPAddress != "192.0.2.7" {
		t.Fatalf("newest: %+v", e)
	}
	if e := p.Items[1]; e.Actor != "otto@example.com" || e.Via != "easyrmm" || e.DeviceName != "WEB-01" || e.DeviceID == nil || *e.DeviceID != f.web {
		t.Fatalf("WEB-01's: %+v", e)
	}
	if e := p.Items[2]; e.Actor != "EasyPatch" || e.Via != "system" || e.OrganizationID != nil || e.Details != `{"source":"RolloutGuard"}` {
		t.Fatalf("EasyPatch's own: %+v", e)
	}
	if st := f.lastStatement("GET", "/api/v1/audit-logs"); st.Role != RoleAdmin || !st.AllOrganizations {
		t.Fatalf("statement: %+v", st)
	}

	// Acme's administrator: Acme's entries only.
	p, err = f.svc.AuditLog(ctx, f.orgAdmin, AuditQuery{})
	if err != nil || p.Everything || len(p.Items) != 1 || p.Items[0].Action != "endpoint.update" {
		t.Fatalf("Acme's administrator: %+v, %v", p, err)
	}
	if st := f.lastStatement("GET", "/api/v1/audit-logs"); st.Role != RoleAdmin || st.AllOrganizations || len(st.Organizations) != 1 ||
		st.Organizations[0] != f.epAcme {
		t.Fatalf("Acme's statement: %+v", st)
	}
	if _, err := f.svc.AuditLog(ctx, f.orgAdmin, AuditQuery{OrganizationID: f.globex}); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("Globex for Acme's administrator: %v", err)
	}
	// A site's administrator audits a site, not the organization.
	siteAdmin := f.user("sam@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	if p, err := f.svc.AuditLog(ctx, siteAdmin, AuditQuery{}); err != nil || len(p.Items) != 0 {
		t.Fatalf("a site's administrator: %+v, %v", p, err)
	}
	if _, err := f.svc.AuditLog(ctx, f.reader, AuditQuery{}); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("reader: %v", err)
	}

	from, to := base.Add(30*time.Minute), base.Add(90*time.Minute)
	if p, err := f.svc.AuditLog(ctx, f.admin, AuditQuery{From: &from, To: &to}); err != nil || len(p.Items) != 1 || p.Items[0].Action != "endpoint.update" {
		t.Fatalf("period: %+v, %v", p, err)
	}
	if p, err := f.svc.AuditLog(ctx, f.admin, AuditQuery{Area: "update."}); err != nil || len(p.Items) != 1 {
		t.Fatalf("area: %+v, %v", p, err)
	}
	if p, err := f.svc.AuditLog(ctx, f.admin, AuditQuery{OrganizationID: f.globex}); err != nil || p.Everything || len(p.Items) != 1 {
		t.Fatalf("Globex: %+v, %v", p, err)
	}
	if _, err := f.svc.AuditLog(ctx, f.admin, AuditQuery{Area: "billing."}); fieldOf(err) != "area" {
		t.Fatalf("unknown area: %v", err)
	}
	if _, err := f.svc.AuditLog(ctx, f.admin, AuditQuery{From: &to, To: &from}); fieldOf(err) != "to" {
		t.Fatalf("backwards: %v", err)
	}
}

// Before the engine is set up, and while it does not answer, each view
// says so; an entry changed into another's build is refused.
func TestServerWideUnavailable(t *testing.T) {
	plain := newFixture(t).withoutEngine()
	for name, call := range map[string]func() error{
		"settings":  func() error { _, err := plain.svc.ServerSettings(plain.ctx, plain.admin); return err },
		"lifecycle": func() error { _, err := plain.svc.Lifecycle(plain.ctx, plain.admin); return err },
		"packages":  func() error { _, err := plain.svc.AgentPackageList(plain.ctx, plain.admin); return err },
		"audit":     func() error { _, err := plain.svc.AuditLog(plain.ctx, plain.admin, AuditQuery{}); return err },
		"change": func() error {
			_, err := plain.svc.SetServerSettings(plain.ctx, plain.admin, ServerSettings{})
			return err
		},
	} {
		if err := call(); !isCode(err, "easypatch_not_configured") {
			t.Errorf("%s before EasyPatch is set up: %v", name, err)
		}
	}

	f := newFleetFixture(t)
	ctx := f.ctx
	l, err := f.svc.Lifecycle(ctx, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	first, second := l.Items[0], l.Items[1]
	in := second.LifecycleInput
	in.Product, in.EditionGroup, in.BuildNumber = first.Product, first.EditionGroup, first.BuildNumber
	if _, err := f.svc.UpdateLifecycle(ctx, f.admin, second.ID, in); fieldOf(err) != "buildNumber" {
		t.Fatalf("changed into another entry's build: %v", err)
	}
	if _, err := f.svc.UpdateLifecycle(ctx, f.admin, uuid.New(), second.LifecycleInput); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("an unknown entry: %v", err)
	}
	if _, err := f.svc.UpdateLifecycle(ctx, f.orgAdmin, second.ID, second.LifecycleInput); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("organization administrator's change: %v", err)
	}
	if err := f.svc.DeleteLifecycle(ctx, f.orgAdmin, second.ID); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("organization administrator's delete: %v", err)
	}
	if _, err := f.svc.Lifecycle(ctx, f.reader); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("reader: %v", err)
	}
	settings, err := f.svc.ServerSettings(ctx, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	f.engine.Set(func() { f.engine.Down = true })
	for name, call := range map[string]func() error{
		"lifecycle": func() error { _, err := f.svc.Lifecycle(ctx, f.admin); return err },
		"packages":  func() error { _, err := f.svc.AgentPackageList(ctx, f.admin); return err },
		"audit":     func() error { _, err := f.svc.AuditLog(ctx, f.admin, AuditQuery{}); return err },
		"change":    func() error { _, err := f.svc.SetServerSettings(ctx, f.admin, settings.Settings); return err },
		"add":       func() error { _, err := f.svc.CreateLifecycle(ctx, f.admin, second.LifecycleInput); return err },
		"update": func() error {
			_, err := f.svc.UpdateLifecycle(ctx, f.admin, second.ID, second.LifecycleInput)
			return err
		},
		"delete":   func() error { return f.svc.DeleteLifecycle(ctx, f.admin, second.ID) },
		"settings": func() error { _, err := f.svc.ServerSettings(ctx, f.orgAdmin); return err },
	} {
		if err := call(); !isCode(err, "patching_unavailable") {
			t.Errorf("%s with the engine down: %v", name, err)
		}
	}
}
