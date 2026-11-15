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
}
