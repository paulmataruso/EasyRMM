package easypatch

import (
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func TestEasyPatchAccess(t *testing.T) {
	var (
		orgA, orgB, orgC = uuid.MustParse("00000000-0000-0000-0000-00000000000a"), uuid.MustParse("00000000-0000-0000-0000-00000000000b"), uuid.MustParse("00000000-0000-0000-0000-00000000000c")
		siteA            = uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
		epA, epB         = uuid.MustParse("e0000000-0000-0000-0000-00000000000a"), uuid.MustParse("e0000000-0000-0000-0000-00000000000b")
		// orgC is not linked to EasyPatch.
		linked = map[uuid.UUID]uuid.UUID{orgA: epA, orgB: epB}
	)
	at := func(role rbac.Role, org, site uuid.UUID) rbac.Assignment {
		return rbac.Assignment{Role: role, OrganizationID: org, SiteID: site}
	}
	for _, c := range []struct {
		name string
		as   []rbac.Assignment
		role string
		orgs []uuid.UUID
		none bool
		nilP bool
	}{
		{name: "no principal", nilP: true, none: true},
		{name: "no assignments", none: true},
		{name: "super administrator", as: []rbac.Assignment{{Role: rbac.RoleSuperAdmin}}, role: RoleSuperAdmin, orgs: []uuid.UUID{}},
		{name: "organization administrator", as: []rbac.Assignment{at(rbac.RoleOrgAdmin, orgA, uuid.Nil)}, role: RoleAdmin, orgs: []uuid.UUID{epA}},
		{name: "administrator of an organization not linked", as: []rbac.Assignment{at(rbac.RoleOrgAdmin, orgC, uuid.Nil)}, none: true},
		{name: "technician for an organization", as: []rbac.Assignment{at(rbac.RoleTechnician, orgB, uuid.Nil)}, role: RoleReadOnly, orgs: []uuid.UUID{epB}},
		{name: "site administrator for an organization", as: []rbac.Assignment{at(rbac.RoleSiteAdmin, orgA, uuid.Nil)}, role: RoleReadOnly, orgs: []uuid.UUID{epA}},
		// A grant on one site never opens the whole EasyPatch organization.
		{name: "site administrator for a site", as: []rbac.Assignment{at(rbac.RoleSiteAdmin, orgA, siteA)}, none: true},
		{name: "read-only in two organizations", as: []rbac.Assignment{at(rbac.RoleReadOnly, orgB, uuid.Nil), at(rbac.RoleReadOnly, orgA, uuid.Nil)},
			role: RoleReadOnly, orgs: []uuid.UUID{epA, epB}},
		// One role per person: the organization only viewed is left out, never the role lowered.
		{name: "administrator of one, read-only in another", as: []rbac.Assignment{at(rbac.RoleReadOnly, orgA, uuid.Nil), at(rbac.RoleOrgAdmin, orgB, uuid.Nil)},
			role: RoleAdmin, orgs: []uuid.UUID{epB}},
		{name: "site grant beside an organization grant", as: []rbac.Assignment{at(rbac.RoleSiteAdmin, orgA, siteA), at(rbac.RoleTechnician, orgB, uuid.Nil)},
			role: RoleReadOnly, orgs: []uuid.UUID{epB}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var p *rbac.Principal
			if !c.nilP {
				var err error
				if p, err = rbac.NewPrincipal(uuid.New(), c.as); err != nil {
					t.Fatal(err)
				}
			}
			got := easyPatchAccess(p, linked)
			switch {
			case c.none && got != nil:
				t.Fatalf("access %+v, want none", got)
			case c.none:
			case got == nil:
				t.Fatalf("no access, want %s %v", c.role, c.orgs)
			case got.Role != c.role || !slices.Equal(got.Organizations, c.orgs):
				t.Fatalf("access %s %v, want %s %v", got.Role, got.Organizations, c.role, c.orgs)
			}
		})
	}
}
