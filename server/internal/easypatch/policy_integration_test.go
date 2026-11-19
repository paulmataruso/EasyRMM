//go:build integration

package easypatch

import (
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Each level's policy reads with what it inherits, saves for those who may
// configure patching there, and resets; the default policy and tags' are
// for super administrators.
func TestPolicyLevels(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx

	// The default policy: every value set, editable by super administrators.
	v, err := f.svc.Policy(ctx, f.admin, LevelDefault, uuid.Nil)
	if err != nil || !v.HasOwn || !v.CanEdit || v.Name != "Default policy" || *v.Own.ScanIntervalMinutes != 360 ||
		v.InheritedFrom["scanIntervalMinutes"] != "EasyPatch's defaults" {
		t.Fatalf("default: %+v, %v", v, err)
	}
	if v, err := f.svc.Policy(ctx, f.orgAdmin, LevelDefault, uuid.Nil); err != nil || v.CanEdit {
		t.Fatalf("an organization's administrator reads the default: %+v, %v", v, err)
	}
	if _, err := f.svc.SavePolicy(ctx, f.orgAdmin, LevelDefault, uuid.Nil, PolicyLayer{ScanIntervalMinutes: ptr(120)}); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("an organization's administrator saves the default: %v", err)
	}
	own := v.Own
	own.ScanIntervalMinutes, own.AutoInstallEnabled, own.MaintenanceDays = ptr(120), ptr(true), []int{2}
	if v, err = f.svc.SavePolicy(ctx, f.admin, LevelDefault, uuid.Nil, own); err != nil || *v.Own.ScanIntervalMinutes != 120 {
		t.Fatalf("save default: %+v, %v", v, err)
	}
	if st := f.lastStatement("PUT", "/api/v1/policies/global"); st.Role != RoleSuperAdmin || !st.AllOrganizations {
		t.Fatalf("default's statement: %+v", st)
	}
	if a := f.audits("patch.policy_update"); len(a) != 1 || a[0].Details["level"] != "default" ||
		!slices.Equal(anyStrings(a[0].Details["changed"]), []string{"scanIntervalMinutes", "autoInstallEnabled", "maintenanceDays"}) {
		t.Fatalf("audit: %+v", a)
	}

	// An organization: read by anyone who sees patching in it, saved by its
	// administrators.
	v, err = f.svc.Policy(ctx, f.reader, LevelOrganization, f.acme)
	if err != nil || v.HasOwn || v.CanEdit || v.Name != "Acme" || *v.Inherited.ScanIntervalMinutes != 120 ||
		v.InheritedFrom["scanIntervalMinutes"] != "Default policy" || v.InheritedFrom["maintenanceDays"] != "Default policy" ||
		v.OrganizationID == nil || *v.OrganizationID != f.acme {
		t.Fatalf("Acme for a reader: %+v, %v", v, err)
	}
	if st := f.lastStatement("GET", "/api/v1/organizations/"+f.epAcme.String()+"/policy"); st.Role != RoleReadOnly ||
		!slices.Equal(st.Organizations, []uuid.UUID{f.epAcme}) {
		t.Fatalf("read statement: %+v", st)
	}
	if _, err := f.svc.SavePolicy(ctx, f.tech, LevelOrganization, f.acme, PolicyLayer{InstallDelayDays: ptr(3)}); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("a technician saves Acme's policy: %v", err)
	}
	if _, err := f.svc.Policy(ctx, f.orgAdmin, LevelOrganization, f.globex); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("Globex for Acme's administrator: %v", err)
	}
	if v, err = f.svc.SavePolicy(ctx, f.orgAdmin, LevelOrganization, f.acme, PolicyLayer{InstallDelayDays: ptr(3), ExcludedKbs: []string{"kb5044284"}}); err != nil ||
		!v.HasOwn || *v.Own.InstallDelayDays != 3 || !slices.Equal(v.Own.ExcludedKbs, []string{"KB5044284"}) || !v.CanEdit {
		t.Fatalf("save Acme: %+v, %v", v, err)
	}
	if st := f.lastStatement("PUT", "/api/v1/organizations/"+f.epAcme.String()+"/policy"); st.Role != RoleAdmin ||
		!slices.Equal(st.Organizations, []uuid.UUID{f.epAcme}) {
		t.Fatalf("save statement: %+v", st)
	}
	if p := f.engine.StoredPolicy(eptest.ScopeOrganization, f.epAcme); p["installDelayDays"] != float64(3) || p["scanIntervalMinutes"] != nil {
		t.Fatalf("stored: %v", p)
	}

	// A site inherits the organization's; removing the window under
	// automatic installs is refused.
	v, err = f.svc.Policy(ctx, f.siteTech, LevelSite, f.hq)
	if err != nil || *v.Inherited.InstallDelayDays != 3 || v.InheritedFrom["installDelayDays"] != "Organization" ||
		!slices.Equal(v.Inherited.ExcludedKbs, []string{"KB5044284"}) || v.CanEdit {
		t.Fatalf("HQ: %+v, %v", v, err)
	}
	if _, err := f.svc.Policy(ctx, f.siteTech, LevelSite, f.branch); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("Branch for HQ's technician: %v", err)
	}
	_, err = f.svc.SavePolicy(ctx, f.orgAdmin, LevelSite, f.hq, PolicyLayer{MaintenanceDays: []int{}})
	wantField(t, err, "maintenanceDays", "maintenance window")
	if _, err := f.svc.SavePolicy(ctx, f.orgAdmin, LevelSite, f.hq, PolicyLayer{MaintenanceDays: []int{6}, MaintenanceStart: ptr("22:00")}); err != nil {
		t.Fatal(err)
	}
	if p := f.engine.StoredPolicy(eptest.ScopeSite, f.engineSite(f.hq)); p["maintenanceStart"] != "22:00" || p["maintenanceDurationMinutes"] != float64(180) {
		t.Fatalf("HQ stored: %v", p)
	}

	// A device inherits its site's and its tags'; it cannot set a limit for
	// its site.
	ring := f.engine.AddTag("Ring 1", "blue", 10)
	f.engine.SetPolicy(eptest.ScopeTag, ring, map[string]any{"installDelayDays": 7})
	f.engine.SetTagsOf(f.epAcme, ring)
	v, err = f.svc.Policy(ctx, f.tech, LevelDevice, f.web)
	if err != nil || v.Name != "WEB-01" || *v.Inherited.InstallDelayDays != 7 || v.InheritedFrom["installDelayDays"] != "Tag Ring 1" ||
		v.InheritedFrom["maintenanceDays"] != "Site" || v.Windows || v.CanEdit || v.TimeZone != "Europe/Paris" {
		t.Fatalf("WEB-01: %+v, %v", v, err)
	}
	_, err = f.svc.SavePolicy(ctx, f.orgAdmin, LevelDevice, f.web, PolicyLayer{MaxConcurrentInstallsPerSite: ptr(2)})
	wantField(t, err, "maxConcurrentInstallsPerSite", "Only the default")
	if v, err = f.svc.SavePolicy(ctx, f.orgAdmin, LevelDevice, f.web, PolicyLayer{TrayIconEnabled: ptr(false)}); err != nil || !v.HasOwn {
		t.Fatalf("save WEB-01: %+v, %v", v, err)
	}

	// Resetting removes a level's own policy; the default goes back to
	// EasyPatch's own.
	if v, err = f.svc.ResetPolicy(ctx, f.orgAdmin, LevelOrganization, f.acme); err != nil || v.HasOwn ||
		f.engine.StoredPolicy(eptest.ScopeOrganization, f.epAcme) != nil {
		t.Fatalf("reset Acme: %+v, %v", v, err)
	}
	if _, err := f.svc.ResetPolicy(ctx, f.tech, LevelDevice, f.web); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("a technician resets: %v", err)
	}
	if v, err = f.svc.ResetPolicy(ctx, f.admin, LevelDefault, uuid.Nil); err != nil || *v.Own.ScanIntervalMinutes != 360 || *v.Own.AutoInstallEnabled {
		t.Fatalf("reset default: %+v, %v", v, err)
	}
	if a := f.audits("patch.policy_reset"); len(a) != 2 || a[0].Details["name"] != "Acme" || a[1].Details["level"] != "default" {
		t.Fatalf("reset audit: %+v", a)
	}

	// A tag's policy is for super administrators; it inherits only the
	// default policy.
	if v, err = f.svc.Policy(ctx, f.admin, LevelTag, ring); err != nil || v.Name != "Ring 1" || !v.HasOwn || *v.Own.InstallDelayDays != 7 || !v.CanEdit {
		t.Fatalf("Ring 1: %+v, %v", v, err)
	}
	if st := f.lastStatement("GET", "/api/v1/tags/"+ring.String()+"/policy"); st.Role != RoleSuperAdmin || !st.AllOrganizations {
		t.Fatalf("tag read statement: %+v", st)
	}
	if _, err := f.svc.Policy(ctx, f.orgAdmin, LevelTag, ring); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("a tag for an organization's administrator: %v", err)
	}
	if _, err := f.svc.Policy(ctx, f.admin, LevelTag, uuid.New()); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("no such tag: %v", err)
	}
	_, err = f.svc.SavePolicy(ctx, f.admin, LevelTag, ring, PolicyLayer{MaxConcurrentInstallsPerSite: ptr(2)})
	wantField(t, err, "maxConcurrentInstallsPerSite", "Only the default")
	if v, err = f.svc.ResetPolicy(ctx, f.admin, LevelTag, ring); err != nil || v.HasOwn {
		t.Fatalf("reset Ring 1: %+v, %v", v, err)
	}

	// An organization not linked yet, and a level that does not exist.
	initech := f.id(`INSERT INTO organizations (name) VALUES ('Initech') RETURNING id`)
	if _, err := f.svc.Policy(ctx, f.admin, LevelOrganization, initech); !isCode(err, "easypatch_not_linked") {
		t.Fatalf("Initech: %v", err)
	}
	if _, err := f.svc.Policy(ctx, f.admin, "group", uuid.New()); !isKind(err, apperr.KindInvalid) {
		t.Fatalf("group: %v", err)
	}
}

// A site EasyRMM has not linked is found by name, as installs find it; one
// EasyPatch does not have cannot be edited.
func TestPolicySiteByName(t *testing.T) {
	f := newFleetFixture(t)
	if _, err := f.db.Pool.Exec(f.ctx, `DELETE FROM easypatch_sites WHERE site_id = $1`, f.branch); err != nil {
		t.Fatal(err)
	}
	if v, err := f.svc.Policy(f.ctx, f.admin, LevelSite, f.branch); err != nil || v.Name != "Branch" {
		t.Fatalf("Branch by name: %+v, %v", v, err)
	}
	lab := f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Lab') RETURNING id`, f.acme)
	if _, err := f.svc.Policy(f.ctx, f.admin, LevelSite, lab); !isCode(err, "easypatch_site_not_found") {
		t.Fatalf("Lab: %v", err)
	}
}

// Tags are managed and assigned by super administrators; others see those
// in use in their organizations.
func TestTags(t *testing.T) {
	f := newFleetFixture(t)
	ctx := f.ctx
	if _, err := f.svc.CreateTag(ctx, f.orgAdmin, TagInput{Name: "Ring 1", Color: "blue"}); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("an organization's administrator adds a tag: %v", err)
	}
	ring, err := f.svc.CreateTag(ctx, f.admin, TagInput{Name: " Ring 1 ", Color: "blue", Priority: 10, Description: ptr("Pilot")})
	if err != nil || ring.Name != "Ring 1" || *ring.Description != "Pilot" {
		t.Fatalf("create: %+v, %v", ring, err)
	}
	if st := f.lastStatement("POST", "/api/v1/tags"); st.Role != RoleSuperAdmin || !st.AllOrganizations {
		t.Fatalf("create statement: %+v", st)
	}
	_, err = f.svc.CreateTag(ctx, f.admin, TagInput{Name: "ring 1", Color: "red"})
	wantField(t, err, "name", "already exists")
	_, err = f.svc.CreateTag(ctx, f.admin, TagInput{Name: "Servers", Color: "orange"})
	wantField(t, err, "color", "colors")
	servers, err := f.svc.CreateTag(ctx, f.admin, TagInput{Name: "Servers", Color: "gray"})
	if err != nil {
		t.Fatal(err)
	}

	// Assigning.
	if _, err := f.svc.SetTags(ctx, f.orgAdmin, LevelOrganization, f.acme, []uuid.UUID{ring.ID}); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("an organization's administrator assigns: %v", err)
	}
	if a, err := f.svc.SetTags(ctx, f.admin, LevelOrganization, f.acme, []uuid.UUID{ring.ID, ring.ID}); err != nil || len(a.Tags) != 1 ||
		a.Tags[0].Name != "Ring 1" || !a.CanAssign {
		t.Fatalf("assign Acme: %+v, %v", a, err)
	}
	if st := f.lastStatement("PUT", "/api/v1/organizations/"+f.epAcme.String()+"/tags"); st.Role != RoleAdmin || !st.AllOrganizations {
		t.Fatalf("assign statement: %+v", st)
	}
	if _, err := f.svc.SetTags(ctx, f.admin, LevelSite, f.hq, []uuid.UUID{servers.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetTags(ctx, f.admin, LevelDevice, f.web, []uuid.UUID{servers.ID}); err != nil {
		t.Fatal(err)
	}
	a, err := f.svc.AssignedTags(ctx, f.tech, LevelDevice, f.web)
	if err != nil || len(a.Tags) != 2 || a.Tags[0].Name != "Servers" || a.Tags[0].InheritedFrom != "" || a.Tags[1].InheritedFrom != "Organization" || a.CanAssign {
		t.Fatalf("WEB-01's tags: %+v, %v", a, err)
	}
	if a, err := f.svc.AssignedTags(ctx, f.reader, LevelSite, f.hq); err != nil || len(a.Tags) != 1 || a.Tags[0].Name != "Servers" {
		t.Fatalf("HQ's tags: %+v, %v", a, err)
	}
	// Setting the same tags again changes nothing and records nothing.
	if _, err := f.svc.SetTags(ctx, f.admin, LevelDevice, f.web, []uuid.UUID{servers.ID}); err != nil {
		t.Fatal(err)
	}
	if a := f.audits("patch.tag_assign"); len(a) != 3 || a[0].Details["name"] != "Acme" || !slices.Equal(anyStrings(a[0].Details["added"]), []string{"Ring 1"}) {
		t.Fatalf("assign audit: %+v", a)
	}
	if _, err := f.svc.SetTags(ctx, f.admin, LevelDevice, f.web, []uuid.UUID{}); err != nil || len(f.engine.TagsOf(f.eWeb.ID)) != 0 {
		t.Fatalf("clear WEB-01: %v", err)
	}
	if a := f.audits("patch.tag_assign"); !slices.Equal(anyStrings(a[len(a)-1].Details["removed"]), []string{"Servers"}) {
		t.Fatalf("removal audit: %+v", a[len(a)-1])
	}
	_, err = f.svc.SetTags(ctx, f.admin, LevelSite, f.hq, []uuid.UUID{uuid.New()})
	wantField(t, err, "tagIds", "exist")
	many := make([]uuid.UUID, 21)
	for i := range many {
		many[i] = uuid.New()
	}
	_, err = f.svc.SetTags(ctx, f.admin, LevelSite, f.hq, many)
	wantField(t, err, "tagIds", "at most 20")
	if _, err := f.svc.SetTags(ctx, f.admin, LevelTag, ring.ID, nil); !isKind(err, apperr.KindInvalid) {
		t.Fatalf("tags on a tag: %v", err)
	}
	if _, err := f.svc.AssignedTags(ctx, f.admin, LevelDefault, uuid.Nil); !isKind(err, apperr.KindInvalid) {
		t.Fatalf("tags of the default: %v", err)
	}

	// Listing: counts for those who see every organization.
	all, err := f.svc.Tags(ctx, f.admin)
	if err != nil || len(all.Items) != 2 || !all.CanManage || all.Items[0].Name != "Ring 1" || all.Items[0].OrganizationCount != 1 {
		t.Fatalf("admin's list: %+v, %v", all, err)
	}
	mine, err := f.svc.Tags(ctx, f.tech)
	if err != nil || mine.CanManage || len(mine.Items) != 2 || mine.Items[0].OrganizationCount != 0 {
		t.Fatalf("technician's list: %+v, %v", mine, err)
	}
	globexTech := f.user("gil@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.globex})
	if theirs, err := f.svc.Tags(ctx, globexTech); err != nil || len(theirs.Items) != 0 {
		t.Fatalf("Globex's technician sees Acme's tags: %+v, %v", theirs, err)
	}

	// Changing and deleting.
	if _, err := f.svc.UpdateTag(ctx, f.orgAdmin, ring.ID, TagInput{Name: "Ring 0", Color: "blue"}); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("an organization's administrator renames: %v", err)
	}
	if _, err := f.svc.UpdateTag(ctx, f.admin, uuid.New(), TagInput{Name: "Ring 0", Color: "blue"}); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("rename no tag: %v", err)
	}
	_, err = f.svc.UpdateTag(ctx, f.admin, ring.ID, TagInput{Name: "servers", Color: "blue"})
	wantField(t, err, "name", "already exists")
	if got, err := f.svc.UpdateTag(ctx, f.admin, ring.ID, TagInput{Name: "Ring 0", Color: "teal", Priority: 20}); err != nil || got.Name != "Ring 0" {
		t.Fatalf("rename: %+v, %v", got, err)
	}
	if a := f.audits("patch.tag_update"); len(a) != 1 || a[0].Details["renamedFrom"] != "Ring 1" || a[0].Details["priority"] != "10 → 20" ||
		a[0].Details["color"] != "teal" {
		t.Fatalf("update audit: %+v", a)
	}
	if err := f.svc.DeleteTag(ctx, f.orgAdmin, ring.ID); !isKind(err, apperr.KindForbidden) {
		t.Fatalf("an organization's administrator deletes: %v", err)
	}
	if err := f.svc.DeleteTag(ctx, f.admin, uuid.New()); !isKind(err, apperr.KindNotFound) {
		t.Fatalf("delete no tag: %v", err)
	}
	if err := f.svc.DeleteTag(ctx, f.admin, ring.ID); err != nil || len(f.engine.TagsOf(f.epAcme)) != 0 {
		t.Fatalf("delete: %v", err)
	}
	if a := f.audits("patch.tag_delete"); len(a) != 1 || a[0].Details["name"] != "Ring 0" {
		t.Fatalf("delete audit: %+v", a)
	}
	if a := f.audits("patch.tag_create"); len(a) != 2 {
		t.Fatalf("create audit: %+v", a)
	}
}

func isKind(err error, kind apperr.Kind) bool {
	ae, ok := apperr.As(err)
	return ok && ae.Kind == kind
}

func isCode(err error, code string) bool {
	ae, ok := apperr.As(err)
	return ok && ae.Code == code
}

func anyStrings(v any) []string {
	list, _ := v.([]any)
	out := []string{}
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// Without EasyPatch, with EasyPatch down, or when its answer is lost, every
// policy and tag call fails with EasyPatch's error and changes nothing in
// EasyRMM's audit log.
func TestPolicyFailures(t *testing.T) {
	none := newFixture(t).withoutEngine()
	for name, err := range map[string]error{
		"policy":   second(none.svc.Policy(none.ctx, none.admin, LevelDefault, uuid.Nil)),
		"save":     second(none.svc.SavePolicy(none.ctx, none.admin, LevelDefault, uuid.Nil, PolicyLayer{})),
		"reset":    second(none.svc.ResetPolicy(none.ctx, none.admin, LevelDefault, uuid.Nil)),
		"tags":     second(none.svc.Tags(none.ctx, none.admin)),
		"create":   second(none.svc.CreateTag(none.ctx, none.admin, TagInput{Name: "x", Color: "red"})),
		"update":   second(none.svc.UpdateTag(none.ctx, none.admin, uuid.New(), TagInput{Name: "x", Color: "red"})),
		"delete":   none.svc.DeleteTag(none.ctx, none.admin, uuid.New()),
		"assigned": second(none.svc.AssignedTags(none.ctx, none.admin, LevelOrganization, none.acme)),
		"assign":   second(none.svc.SetTags(none.ctx, none.admin, LevelOrganization, none.acme, nil)),
	} {
		if !isCode(err, "easypatch_not_configured") {
			t.Errorf("%s without EasyPatch: %v", name, err)
		}
	}

	f := newFleetFixture(t)
	ctx := f.ctx
	ring, err := f.svc.CreateTag(ctx, f.admin, TagInput{Name: "Ring 1", Color: "blue"})
	if err != nil {
		t.Fatal(err)
	}
	// Levels EasyRMM cannot edit: a device without an endpoint, a site of an
	// organization that is not linked, and a technician's tag list there.
	lab := f.device(f.acme, f.hq, "LAB-01")
	if _, err := f.svc.Policy(ctx, f.admin, LevelDevice, lab); !isCode(err, "easypatch_not_linked") {
		t.Errorf("LAB-01: %v", err)
	}
	initech := f.id(`INSERT INTO organizations (name) VALUES ('Initech') RETURNING id`)
	office := f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Office') RETURNING id`, initech)
	if _, err := f.svc.Policy(ctx, f.admin, LevelSite, office); !isCode(err, "easypatch_not_linked") {
		t.Errorf("Initech's office: %v", err)
	}
	ivan := f.user("ivan@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: initech})
	if l, err := f.svc.Tags(ctx, ivan); err != nil || len(l.Items) != 0 {
		t.Errorf("tags for a technician of an organization not linked: %+v, %v", l, err)
	}
	if _, err := f.svc.Tags(ctx, f.user("nobody@example.com")); !isKind(err, apperr.KindForbidden) {
		t.Errorf("tags for someone without patching: %v", err)
	}

	// A lost answer fails the call it belongs to.
	tagPath := "/api/v1/tags/" + ring.ID.String()
	orgPath := "/api/v1/organizations/" + f.epAcme.String()
	for _, c := range []struct {
		name, method, path string
		call               func() error
	}{
		{"read a parent", "GET", "/api/v1/policies/global", func() error { return second(f.svc.Policy(ctx, f.admin, LevelOrganization, f.acme)) }},
		{"read tag policies", "GET", "/api/v1/endpoints/" + f.eWeb.ID.String() + "/tag-policies",
			func() error { return second(f.svc.Policy(ctx, f.admin, LevelDevice, f.web)) }},
		{"read an endpoint", "GET", "/api/v1/endpoints/" + f.eWeb.ID.String(), func() error { return second(f.svc.Policy(ctx, f.admin, LevelDevice, f.web)) }},
		{"save", "PUT", orgPath + "/policy", func() error {
			return second(f.svc.SavePolicy(ctx, f.admin, LevelOrganization, f.acme, PolicyLayer{InstallDelayDays: ptr(1)}))
		}},
		{"save before reading", "GET", orgPath + "/policy", func() error {
			return second(f.svc.SavePolicy(ctx, f.admin, LevelOrganization, f.acme, PolicyLayer{InstallDelayDays: ptr(1)}))
		}},
		{"reset", "DELETE", orgPath + "/policy", func() error { return second(f.svc.ResetPolicy(ctx, f.admin, LevelOrganization, f.acme)) }},
		{"reset the default", "PUT", "/api/v1/policies/global", func() error { return second(f.svc.ResetPolicy(ctx, f.admin, LevelDefault, uuid.Nil)) }},
		{"list tags", "GET", "/api/v1/tags", func() error { return second(f.svc.Tags(ctx, f.admin)) }},
		{"a tag's policy", "GET", "/api/v1/tags", func() error { return second(f.svc.Policy(ctx, f.admin, LevelTag, ring.ID)) }},
		{"create", "POST", "/api/v1/tags", func() error { return second(f.svc.CreateTag(ctx, f.admin, TagInput{Name: "Ring 2", Color: "red"})) }},
		{"update", "PUT", tagPath, func() error {
			return second(f.svc.UpdateTag(ctx, f.admin, ring.ID, TagInput{Name: "Ring 3", Color: "red"}))
		}},
		{"update before reading", "GET", "/api/v1/tags", func() error {
			return second(f.svc.UpdateTag(ctx, f.admin, ring.ID, TagInput{Name: "Ring 3", Color: "red"}))
		}},
		{"delete", "DELETE", tagPath, func() error { return f.svc.DeleteTag(ctx, f.admin, ring.ID) }},
		{"delete before reading", "GET", "/api/v1/tags", func() error { return f.svc.DeleteTag(ctx, f.admin, ring.ID) }},
		{"assigned", "GET", orgPath, func() error { return second(f.svc.AssignedTags(ctx, f.admin, LevelOrganization, f.acme)) }},
		{"assign", "PUT", orgPath + "/tags", func() error {
			return second(f.svc.SetTags(ctx, f.admin, LevelOrganization, f.acme, []uuid.UUID{ring.ID}))
		}},
		{"assign before reading tags", "GET", "/api/v1/tags", func() error {
			return second(f.svc.SetTags(ctx, f.admin, LevelOrganization, f.acme, []uuid.UUID{ring.ID}))
		}},
		{"assign before reading the organization", "GET", orgPath, func() error {
			return second(f.svc.SetTags(ctx, f.admin, LevelOrganization, f.acme, []uuid.UUID{ring.ID}))
		}},
		{"a site's tags", "GET", "/api/v1/sites/" + f.engineSite(f.hq).String(), func() error {
			return second(f.svc.AssignedTags(ctx, f.admin, LevelSite, f.hq))
		}},
	} {
		f.engine.Set(func() { f.engine.LoseReply = func(m, p string) bool { return m == c.method && p == c.path } })
		if err := c.call(); err == nil {
			t.Errorf("%s with %s %s lost: no error", c.name, c.method, c.path)
		}
		f.engine.Set(func() { f.engine.LoseReply = nil })
	}

	// EasyPatch down: a site found by name cannot be found.
	if _, err := f.db.Pool.Exec(ctx, `DELETE FROM easypatch_sites WHERE site_id = $1`, f.branch); err != nil {
		t.Fatal(err)
	}
	f.engine.Set(func() { f.engine.Down = true })
	if _, err := f.svc.Policy(ctx, f.admin, LevelSite, f.branch); err == nil {
		t.Error("Branch with EasyPatch down")
	}
	f.engine.Set(func() { f.engine.Down = false })
	if a := f.audits("patch.policy"); len(a) != 0 {
		t.Errorf("failed calls recorded: %+v", a)
	}
}

func second[T any](_ T, err error) error { return err }
