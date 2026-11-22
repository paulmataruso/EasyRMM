package rbac

import (
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"
)

var (
	orgA   = uuid.MustParse("00000000-0000-0000-0000-00000000000a")
	orgB   = uuid.MustParse("00000000-0000-0000-0000-00000000000b")
	siteA1 = uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
	siteA2 = uuid.MustParse("00000000-0000-0000-0000-0000000000a2")
	siteB1 = uuid.MustParse("00000000-0000-0000-0000-0000000000b1")
	user   = uuid.MustParse("00000000-0000-0000-0000-000000000001")
)

func mustPrincipal(t *testing.T, as ...Assignment) *Principal {
	t.Helper()
	p, err := NewPrincipal(user, as)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEveryRolePermissionIsKnown(t *testing.T) {
	for role, def := range Roles {
		if def.Role != role {
			t.Errorf("role %q has mismatched key", role)
		}
		for _, perm := range def.Permissions {
			if !slices.Contains(AllPermissions, perm) {
				t.Errorf("role %q grants unknown permission %q", role, perm)
			}
		}
	}
}

func TestRoleHierarchyIsMonotonic(t *testing.T) {
	order := []Role{RoleReadOnly, RoleTechnician, RoleSiteAdmin, RoleOrgAdmin, RoleSuperAdmin}
	for i := 1; i < len(order); i++ {
		lower, higher := Roles[order[i-1]], Roles[order[i]]
		if lower.Rank >= higher.Rank {
			t.Errorf("%s must rank below %s", lower.Role, higher.Role)
		}
		for _, perm := range lower.Permissions {
			if !slices.Contains(higher.Permissions, perm) {
				t.Errorf("%s has %q but %s does not", lower.Role, perm, higher.Role)
			}
		}
	}
}

func TestReadOnlyHasNoWritePermissions(t *testing.T) {
	for _, perm := range Roles[RoleReadOnly].Permissions {
		if !slices.Contains(viewPerms, perm) {
			t.Errorf("read-only role grants %q", perm)
		}
	}
}

// TestJobViewSensitive: Technicians and above read output and arguments;
// Read-Only sees jobs without them (ADR-0063).
func TestJobViewSensitive(t *testing.T) {
	for role, want := range map[Role]bool{
		RoleReadOnly: false, RoleTechnician: true, RoleSiteAdmin: true, RoleOrgAdmin: true, RoleSuperAdmin: true,
	} {
		perms := Roles[role].Permissions
		if slices.Contains(perms, PermJobViewSensitive) != want || !slices.Contains(perms, PermJobView) {
			t.Errorf("%s: job.view_sensitive %v", role, !want)
		}
	}
	if slices.Contains(viewPerms, PermJobViewSensitive) {
		t.Error("job.view_sensitive is a view permission")
	}
}

func TestAssignmentValidation(t *testing.T) {
	cases := []struct {
		a     Assignment
		valid bool
	}{
		{Assignment{Role: RoleSuperAdmin}, true},
		{Assignment{Role: RoleSuperAdmin, OrganizationID: orgA}, false},
		{Assignment{Role: RoleOrgAdmin, OrganizationID: orgA}, true},
		{Assignment{Role: RoleOrgAdmin}, false},
		{Assignment{Role: RoleOrgAdmin, OrganizationID: orgA, SiteID: siteA1}, false},
		{Assignment{Role: RoleTechnician, OrganizationID: orgA, SiteID: siteA1}, true},
		{Assignment{Role: RoleTechnician, SiteID: siteA1}, false},
		{Assignment{Role: RoleTechnician}, false},
		{Assignment{Role: "wizard", OrganizationID: orgA}, false},
	}
	for _, c := range cases {
		err := c.a.Validate()
		if (err == nil) != c.valid {
			t.Errorf("%+v: err=%v, want valid=%v", c.a, err, c.valid)
		}
		if err != nil && !errors.Is(err, ErrInvalidAssignment) {
			t.Errorf("error does not wrap ErrInvalidAssignment: %v", err)
		}
	}
	if _, err := NewPrincipal(user, []Assignment{{Role: RoleOrgAdmin}}); err == nil {
		t.Error("NewPrincipal accepted an invalid assignment")
	}
}

func TestSuperAdminCanDoEverything(t *testing.T) {
	p := mustPrincipal(t, Assignment{Role: RoleSuperAdmin})
	if !p.IsSuperAdmin() {
		t.Fatal("IsSuperAdmin false")
	}
	for _, perm := range AllPermissions {
		if !p.Can(perm, Site(orgB, siteB1)) || !p.CanGlobal(perm) {
			t.Errorf("super admin lacks %q", perm)
		}
	}
	if !p.Scope(PermDeviceView).All {
		t.Error("super admin scope should be All")
	}
}

func TestTenantIsolationBetweenOrganizations(t *testing.T) {
	p := mustPrincipal(t, Assignment{Role: RoleOrgAdmin, OrganizationID: orgA})
	if !p.Can(PermDeviceView, Site(orgA, siteA2)) {
		t.Error("org admin cannot see a site in their org")
	}
	if !p.Can(PermUserManage, Org(orgA)) {
		t.Error("org admin cannot manage users in their org")
	}
	for _, perm := range AllPermissions {
		if p.Can(perm, Org(orgB)) || p.Can(perm, Site(orgB, siteB1)) {
			t.Errorf("org admin of A holds %q in org B", perm)
		}
	}
	// A forged resource that pairs org B's site with org A must not pass.
	if p.Can(PermDeviceView, Site(orgB, siteA1)) {
		t.Error("mismatched org/site pair granted access")
	}
}

func TestOrgAdminCannotUseGlobalPermissions(t *testing.T) {
	p := mustPrincipal(t, Assignment{Role: RoleOrgAdmin, OrganizationID: orgA})
	for perm := range globalOnly {
		if p.Can(perm, Org(orgA)) || p.CanGlobal(perm) {
			t.Errorf("org admin holds global-only %q", perm)
		}
	}
	if p.Can(PermDeviceView, Resource{}) {
		t.Error("platform resource accessible without a global grant")
	}
}

func TestSiteScopedTechnician(t *testing.T) {
	p := mustPrincipal(t, Assignment{Role: RoleTechnician, OrganizationID: orgA, SiteID: siteA1})
	if !p.Can(PermRemoteDesktop, Site(orgA, siteA1)) {
		t.Error("technician cannot remote into their site")
	}
	if p.Can(PermRemoteDesktop, Site(orgA, siteA2)) {
		t.Error("technician reached a sibling site")
	}
	if p.Can(PermDeviceRetire, Site(orgA, siteA1)) {
		t.Error("technician can retire devices")
	}
	if p.Can(PermDeviceView, Org(orgA)) {
		t.Error("site technician has organization-wide device view")
	}
	if !p.Can(PermOrgView, Org(orgA)) {
		t.Error("site technician cannot read the parent organization record")
	}
	if p.Can(PermOrgView, Org(orgB)) {
		t.Error("site technician can read an unrelated organization")
	}
	s := p.Scope(PermDeviceView)
	if s.All || len(s.Orgs) != 0 || !slices.Equal(s.Sites, []uuid.UUID{siteA1}) {
		t.Errorf("unexpected scope %+v", s)
	}
	if got := p.OrgsWithSiteAccess(); !slices.Equal(got, []uuid.UUID{orgA}) {
		t.Errorf("OrgsWithSiteAccess = %v", got)
	}
}

func TestSiteAdminNeverManagesOrgOrUsers(t *testing.T) {
	p := mustPrincipal(t, Assignment{Role: RoleSiteAdmin, OrganizationID: orgA, SiteID: siteA1})
	if p.Can(PermOrgManage, Site(orgA, siteA1)) || p.Can(PermUserManage, Site(orgA, siteA1)) {
		t.Error("site-scoped role escaped to organization management")
	}
	if !p.Can(PermEnrollManage, Site(orgA, siteA1)) {
		t.Error("site admin cannot manage enrollment for their site")
	}
}

// Changing EasyPatch's standing rules is for organization administrators
// and above, and never comes from a site grant.
func TestPatchConfigure(t *testing.T) {
	cases := []struct {
		role Role
		want bool
	}{{RoleSuperAdmin, true}, {RoleOrgAdmin, true}, {RoleSiteAdmin, false}, {RoleTechnician, false}, {RoleReadOnly, false}}
	for _, c := range cases {
		if got := slices.Contains(Roles[c.role].Permissions, PermPatchConfigure); got != c.want {
			t.Errorf("%s holds patch.configure: %v", c.role, got)
		}
	}
	org := mustPrincipal(t, Assignment{Role: RoleOrgAdmin, OrganizationID: orgA})
	if !org.Can(PermPatchConfigure, Org(orgA)) || org.Can(PermPatchConfigure, Org(orgB)) {
		t.Error("organization administrator: patch.configure outside their organization, or not in it")
	}
	site := mustPrincipal(t, Assignment{Role: RoleSiteAdmin, OrganizationID: orgA})
	if site.Can(PermPatchConfigure, Org(orgA)) || site.CanAnywhere(PermPatchConfigure) {
		t.Error("site administrator at organization scope holds patch.configure")
	}
}

func TestScopeMergesOrgAndSiteGrants(t *testing.T) {
	p := mustPrincipal(t,
		Assignment{Role: RoleTechnician, OrganizationID: orgA},
		Assignment{Role: RoleReadOnly, OrganizationID: orgA, SiteID: siteA1}, // redundant with org grant
		Assignment{Role: RoleReadOnly, OrganizationID: orgB, SiteID: siteB1},
	)
	s := p.Scope(PermDeviceView)
	if !slices.Equal(s.Orgs, []uuid.UUID{orgA}) || !slices.Equal(s.Sites, []uuid.UUID{siteB1}) {
		t.Errorf("unexpected scope %+v", s)
	}
	if p.Can(PermTerminal, Site(orgB, siteB1)) {
		t.Error("read-only site grant allowed terminal access")
	}
	if !p.Can(PermTerminal, Site(orgA, siteA1)) {
		t.Error("org technician grant lost on a site that also has a read-only grant")
	}
	if s := p.Scope(PermSettingsManage); !s.Empty() {
		t.Errorf("settings scope should be empty, got %+v", s)
	}
}

func TestNilPrincipalDeniesEverything(t *testing.T) {
	var p *Principal
	if p.Can(PermDeviceView, Site(orgA, siteA1)) || p.CanGlobal(PermDeviceView) || !p.Scope(PermDeviceView).Empty() || p.CanAssign(Assignment{Role: RoleReadOnly, OrganizationID: orgA}) {
		t.Fatal("nil principal granted something")
	}
}

func TestCanAssignPreventsEscalation(t *testing.T) {
	super := mustPrincipal(t, Assignment{Role: RoleSuperAdmin})
	orgAdmin := mustPrincipal(t, Assignment{Role: RoleOrgAdmin, OrganizationID: orgA})
	tech := mustPrincipal(t, Assignment{Role: RoleTechnician, OrganizationID: orgA})

	cases := []struct {
		name  string
		actor *Principal
		a     Assignment
		want  bool
	}{
		{"super grants super", super, Assignment{Role: RoleSuperAdmin}, true},
		{"org admin grants super", orgAdmin, Assignment{Role: RoleSuperAdmin}, false},
		{"org admin grants org admin in own org", orgAdmin, Assignment{Role: RoleOrgAdmin, OrganizationID: orgA}, true},
		{"org admin grants technician on own site", orgAdmin, Assignment{Role: RoleTechnician, OrganizationID: orgA, SiteID: siteA1}, true},
		{"org admin grants in other org", orgAdmin, Assignment{Role: RoleReadOnly, OrganizationID: orgB}, false},
		{"technician grants read-only", tech, Assignment{Role: RoleReadOnly, OrganizationID: orgA}, false},
		{"invalid assignment", super, Assignment{Role: RoleOrgAdmin}, false},
	}
	for _, c := range cases {
		if got := c.actor.CanAssign(c.a); got != c.want {
			t.Errorf("%s: CanAssign=%v want %v", c.name, got, c.want)
		}
	}
}

func TestPermissionsListing(t *testing.T) {
	p := mustPrincipal(t, Assignment{Role: RoleReadOnly, OrganizationID: orgA, SiteID: siteA1})
	got := p.Permissions()
	if slices.Contains(got, PermTerminal) || !slices.Contains(got, PermDeviceView) {
		t.Errorf("unexpected permissions %v", got)
	}
	if !slices.IsSorted(got) {
		t.Error("permissions not sorted")
	}
	if g := p.GlobalPermissions(); len(g) != 0 {
		t.Errorf("a site assignment grants platform-wide %v", g)
	}
	super := mustPrincipal(t, Assignment{Role: RoleSuperAdmin})
	if g := super.GlobalPermissions(); !slices.Contains(g, PermEnrollManage) || !slices.IsSorted(g) {
		t.Errorf("super administrator's platform-wide permissions %v", g)
	}
}

func TestCanAnywhereAndInOrg(t *testing.T) {
	site := mustPrincipal(t, Assignment{Role: RoleTechnician, OrganizationID: orgA, SiteID: siteA1})
	if !site.CanAnywhere(PermScriptView) || !site.CanInOrg(PermScriptView, orgA) {
		t.Error("a site technician cannot read their organization's scripts")
	}
	if site.CanInOrg(PermScriptView, orgB) || site.CanInOrg(PermScriptView, uuid.Nil) {
		t.Error("a site technician reads another organization's or the platform's objects")
	}
	if site.CanAnywhere(PermScriptManage) || site.CanInOrg(PermScriptManage, orgA) {
		t.Error("a technician manages scripts")
	}
	org := mustPrincipal(t, Assignment{Role: RoleSiteAdmin, OrganizationID: orgB})
	if !org.CanInOrg(PermScriptManage, orgB) || org.CanInOrg(PermScriptManage, orgA) {
		t.Error("organization grant not limited to its organization")
	}
	super := mustPrincipal(t, Assignment{Role: RoleSuperAdmin})
	if !super.CanAnywhere(PermScriptManage) || !super.CanInOrg(PermScriptManage, orgA) || !super.CanInOrg(PermScriptManage, uuid.Nil) {
		t.Error("super administrator refused")
	}
	var none *Principal
	if none.CanAnywhere(PermScriptView) || none.CanInOrg(PermScriptView, orgA) || none.CanInOrg(PermScriptView, uuid.Nil) {
		t.Error("nil principal granted something")
	}
}

func TestPlacement(t *testing.T) {
	super := Assignment{Role: RoleSuperAdmin}
	adminA := Assignment{Role: RoleOrgAdmin, OrganizationID: orgA}
	techA1 := Assignment{Role: RoleTechnician, OrganizationID: orgA, SiteID: siteA1}
	techA2 := Assignment{Role: RoleTechnician, OrganizationID: orgA, SiteID: siteA2}
	techB1 := Assignment{Role: RoleTechnician, OrganizationID: orgB, SiteID: siteB1}
	for _, c := range []struct {
		name      string
		as        []Assignment
		org, site uuid.UUID
	}{
		{"none", nil, uuid.Nil, uuid.Nil},
		{"the platform", []Assignment{super}, uuid.Nil, uuid.Nil},
		{"an organization", []Assignment{adminA}, orgA, uuid.Nil},
		{"a site", []Assignment{techA1}, orgA, siteA1},
		{"two sites of one organization", []Assignment{techA1, techA2}, orgA, uuid.Nil},
		{"the organization and a site of it", []Assignment{adminA, techA1}, orgA, uuid.Nil},
		{"two organizations", []Assignment{adminA, techB1}, uuid.Nil, uuid.Nil},
		{"the platform, then an organization", []Assignment{super, adminA}, uuid.Nil, uuid.Nil},
		{"an organization, then the platform", []Assignment{adminA, super}, uuid.Nil, uuid.Nil},
	} {
		org, site := Placement(c.as)
		if org != c.org || site != c.site {
			t.Errorf("%s: %v %v, want %v %v", c.name, org, site, c.org, c.site)
		}
		// The order does not matter.
		if len(c.as) > 1 {
			if org, _ := Placement([]Assignment{c.as[1], c.as[0]}); org != c.org {
				t.Errorf("%s, the other way round: %v", c.name, org)
			}
		}
	}
}
