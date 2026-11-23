//go:build integration

package tenancy_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/tenancy"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type env struct {
	svc   *tenancy.Service
	db    *database.DB
	audit *audit.Logger
	sys   access.Caller
}

func newEnv(t *testing.T) *env {
	t.Helper()
	inst := testdb.New(t)
	al := audit.New(inst.DB, nil)
	return &env{svc: tenancy.New(inst.DB, al), db: inst.DB, audit: al, sys: access.System("test")}
}

func caller(t *testing.T, as ...rbac.Assignment) access.Caller {
	t.Helper()
	uid := uuid.New()
	p, err := rbac.NewPrincipal(uid, as)
	if err != nil {
		t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: uid, Label: "user@example.com"})
}

func wantKind(t *testing.T, err error, kind apperr.Kind, what string) *apperr.Error {
	t.Helper()
	ae, ok := apperr.As(err)
	if !ok || ae.Kind != kind {
		t.Fatalf("%s: got %v, want apperr kind %d", what, err, kind)
	}
	return ae
}

func wantField(t *testing.T, err error, field, what string) {
	t.Helper()
	ae := wantKind(t, err, apperr.KindInvalid, what)
	if _, ok := ae.Fields[field]; !ok {
		t.Fatalf("%s: fields %v, want %q", what, ae.Fields, field)
	}
}

// world is two organizations with a site each.
type world struct {
	orgA, orgB   *tenancy.Organization
	siteA, siteB *tenancy.Site
}

func (e *env) world(t *testing.T) world {
	t.Helper()
	ctx := context.Background()
	var w world
	var err error
	if w.orgA, err = e.svc.CreateOrganization(ctx, e.sys, tenancy.OrganizationInput{Name: "Acme", Notes: "first"}); err != nil {
		t.Fatal(err)
	}
	if w.orgB, err = e.svc.CreateOrganization(ctx, e.sys, tenancy.OrganizationInput{Name: "Globex"}); err != nil {
		t.Fatal(err)
	}
	if w.siteA, err = e.svc.CreateSite(ctx, e.sys, w.orgA.ID, tenancy.SiteInput{Name: "HQ", Timezone: "Europe/London"}); err != nil {
		t.Fatal(err)
	}
	if w.siteB, err = e.svc.CreateSite(ctx, e.sys, w.orgB.ID, tenancy.SiteInput{Name: "Plant"}); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestOrganizationLifecycleAndValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	w := e.world(t)

	if w.orgA.Name != "Acme" || w.orgA.Notes != "first" || !w.orgA.CanManage {
		t.Fatalf("created org: %+v", w.orgA)
	}
	// Validation.
	for name, in := range map[string]tenancy.OrganizationInput{
		"empty":   {Name: "   "},
		"long":    {Name: strings.Repeat("x", 201)},
		"control": {Name: "Bad\nName"},
	} {
		_, err := e.svc.CreateOrganization(ctx, e.sys, in)
		wantField(t, err, "name", name)
	}
	_, err := e.svc.CreateOrganization(ctx, e.sys, tenancy.OrganizationInput{Name: "Notes", Notes: strings.Repeat("n", 10001)})
	wantField(t, err, "notes", "long notes")
	// Duplicate names are case-insensitive and ignore surrounding spaces.
	_, err = e.svc.CreateOrganization(ctx, e.sys, tenancy.OrganizationInput{Name: "  ACME "})
	wantField(t, err, "name", "duplicate org")

	// Name exactly at the limit is accepted (runes, not bytes).
	long, err := e.svc.CreateOrganization(ctx, e.sys, tenancy.OrganizationInput{Name: strings.Repeat("é", 200)})
	if err != nil {
		t.Fatalf("200-rune name: %v", err)
	}

	// List, query filter, site counts.
	list, err := e.svc.ListOrganizations(ctx, e.sys, "")
	if err != nil || len(list) != 3 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	if list[0].Name != "Acme" || list[0].SiteCount != 1 {
		t.Fatalf("first org: %+v", list[0])
	}
	list, err = e.svc.ListOrganizations(ctx, e.sys, " glob ")
	if err != nil || len(list) != 1 || list[0].ID != w.orgB.ID {
		t.Fatalf("filtered list: %v %+v", err, list)
	}

	// Update, including rename and duplicate on rename.
	upd, err := e.svc.UpdateOrganization(ctx, e.sys, w.orgA.ID, tenancy.OrganizationInput{Name: "Acme Corp", Notes: "renamed"})
	if err != nil || upd.Name != "Acme Corp" || upd.Notes != "renamed" {
		t.Fatalf("update: %v %+v", err, upd)
	}

	// Time zones: UTC unless chosen, kept when an update leaves it out, and
	// IANA names only. Every change tells who listens.
	changes := 0
	e.svc.OnChange(func() { changes++ })
	if w.orgA.Timezone != "UTC" {
		t.Fatalf("default time zone: %q", w.orgA.Timezone)
	}
	tz, err := e.svc.UpdateOrganization(ctx, e.sys, w.orgA.ID, tenancy.OrganizationInput{Name: "Acme Corp", Timezone: " Europe/Paris ", Notes: "renamed"})
	if err != nil || tz.Timezone != "Europe/Paris" {
		t.Fatalf("time zone: %v %+v", err, tz)
	}
	if kept, err := e.svc.UpdateOrganization(ctx, e.sys, w.orgA.ID, tenancy.OrganizationInput{Name: "Acme Corp", Notes: "renamed"}); err != nil ||
		kept.Timezone != "Europe/Paris" {
		t.Fatalf("time zone left out: %v %+v", err, kept)
	}
	for _, bad := range []string{"Local", "Mars/Olympus", strings.Repeat("A", 65), "Europe//Paris"} {
		_, err := e.svc.UpdateOrganization(ctx, e.sys, w.orgA.ID, tenancy.OrganizationInput{Name: "Acme Corp", Timezone: bad})
		wantField(t, err, "timezone", "bad time zone "+bad)
	}
	if made, err := e.svc.CreateOrganization(ctx, e.sys, tenancy.OrganizationInput{Name: "Zoned", Timezone: "Asia/Tokyo"}); err != nil ||
		made.Timezone != "Asia/Tokyo" {
		t.Fatalf("created with a time zone: %v %+v", err, made)
	} else if err := e.svc.DeleteOrganization(ctx, e.sys, made.ID, nil); err != nil {
		t.Fatal(err)
	}
	if changes != 4 {
		t.Fatalf("%d changes told, want 4", changes)
	}
	if _, err := e.svc.UpdateOrganization(ctx, e.sys, w.orgA.ID, tenancy.OrganizationInput{Name: "globex"}); err == nil {
		t.Fatal("rename to existing name succeeded")
	} else {
		wantField(t, err, "name", "rename duplicate")
	}
	if _, err := e.svc.UpdateOrganization(ctx, e.sys, w.orgA.ID, tenancy.OrganizationInput{Name: ""}); err == nil {
		t.Fatal("empty rename succeeded")
	}
	if _, err := e.svc.UpdateOrganization(ctx, e.sys, uuid.New(), tenancy.OrganizationInput{Name: "x"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if _, err := e.svc.GetOrganization(ctx, e.sys, uuid.New()); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}

	// Delete: refused while sites exist, allowed when empty, audited.
	err = e.svc.DeleteOrganization(ctx, e.sys, w.orgA.ID, nil)
	if ae := wantKind(t, err, apperr.KindConflict, "delete non-empty"); ae.Code != "organization_not_empty" {
		t.Fatalf("code %q", ae.Code)
	}
	if err := e.svc.DeleteOrganization(ctx, e.sys, long.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteOrganization(ctx, e.sys, long.ID, nil); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	entries, err := e.audit.List(ctx, database.System, audit.Query{ActionPrefix: "organization"})
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	renamed := 0
	for _, en := range entries {
		actions[en.Action]++
		if en.Action == "organization.update" && en.Details["previousName"] == "Acme" {
			renamed++
		}
		if en.Action == "organization.update" && en.Details["timezone"] == "Europe/Paris" && en.Details["previousName"] != nil {
			t.Fatalf("a time zone change audited as a rename: %v", en.Details)
		}
	}
	if renamed != 1 {
		t.Fatalf("%d renames audited", renamed)
	}
	if actions["organization.create"] != 4 || actions["organization.update"] != 3 || actions["organization.delete"] != 2 {
		t.Fatalf("audit actions: %v", actions)
	}
}

func TestSitesAndDeviceGroups(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	w := e.world(t)

	if w.siteA.OrganizationName != "Acme" || w.siteA.Timezone != "Europe/London" || !w.siteA.CanManage {
		t.Fatalf("site: %+v", w.siteA)
	}
	if w.siteB.Timezone != "UTC" {
		t.Fatalf("default time zone: %q", w.siteB.Timezone)
	}
	for name, c := range map[string]struct {
		in    tenancy.SiteInput
		field string
	}{
		"empty name": {tenancy.SiteInput{Name: ""}, "name"},
		"bad tz":     {tenancy.SiteInput{Name: "X", Timezone: "Mars/Base"}, "timezone"},
		"local tz":   {tenancy.SiteInput{Name: "X", Timezone: "Local"}, "timezone"},
		"long tz":    {tenancy.SiteInput{Name: "X", Timezone: strings.Repeat("a", 65)}, "timezone"},
		"long notes": {tenancy.SiteInput{Name: "X", Notes: strings.Repeat("a", 10001)}, "notes"},
		"duplicate":  {tenancy.SiteInput{Name: "hq"}, "name"},
	} {
		_, err := e.svc.CreateSite(ctx, e.sys, w.orgA.ID, c.in)
		wantField(t, err, c.field, name)
	}
	// Same site name in another organization is fine.
	if _, err := e.svc.CreateSite(ctx, e.sys, w.orgB.ID, tenancy.SiteInput{Name: "HQ"}); err != nil {
		t.Fatalf("same name in other org: %v", err)
	}
	if _, err := e.svc.CreateSite(ctx, e.sys, uuid.New(), tenancy.SiteInput{Name: "X"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("site in missing org: %v", err)
	}

	all, err := e.svc.ListSites(ctx, e.sys, uuid.Nil, "")
	if err != nil || len(all) != 3 {
		t.Fatalf("all sites: %v %d", err, len(all))
	}
	onlyB, err := e.svc.ListSites(ctx, e.sys, w.orgB.ID, "")
	if err != nil || len(onlyB) != 2 {
		t.Fatalf("org filter: %v %d", err, len(onlyB))
	}
	q, err := e.svc.ListSites(ctx, e.sys, uuid.Nil, "plan")
	if err != nil || len(q) != 1 || q[0].ID != w.siteB.ID {
		t.Fatalf("query filter: %v %+v", err, q)
	}

	upd, err := e.svc.UpdateSite(ctx, e.sys, w.siteA.ID, tenancy.SiteInput{Name: "Head Office", Timezone: "America/New_York", Notes: "n"})
	if err != nil || upd.Name != "Head Office" || upd.Timezone != "America/New_York" || upd.Notes != "n" {
		t.Fatalf("update site: %v %+v", err, upd)
	}
	if _, err := e.svc.UpdateSite(ctx, e.sys, w.siteA.ID, tenancy.SiteInput{Name: "X", Timezone: "nope"}); err == nil {
		t.Fatal("invalid update accepted")
	}
	if _, err := e.svc.UpdateSite(ctx, e.sys, uuid.New(), tenancy.SiteInput{Name: "X"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("update missing site: %v", err)
	}
	second, err := e.svc.CreateSite(ctx, e.sys, w.orgA.ID, tenancy.SiteInput{Name: "Branch"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateSite(ctx, e.sys, second.ID, tenancy.SiteInput{Name: "head office"}); err == nil {
		t.Fatal("duplicate rename accepted")
	} else {
		wantField(t, err, "name", "site rename duplicate")
	}

	// Device groups.
	g, err := e.svc.CreateDeviceGroup(ctx, e.sys, w.siteA.ID, tenancy.DeviceGroupInput{Name: "Servers", Description: "racks"})
	if err != nil || g.OrganizationID != w.orgA.ID || g.SiteID != w.siteA.ID {
		t.Fatalf("group: %v %+v", err, g)
	}
	if _, err := e.svc.CreateDeviceGroup(ctx, e.sys, w.siteA.ID, tenancy.DeviceGroupInput{Name: "SERVERS"}); err == nil {
		t.Fatal("duplicate group accepted")
	} else {
		wantField(t, err, "name", "dup group")
	}
	_, err = e.svc.CreateDeviceGroup(ctx, e.sys, w.siteA.ID, tenancy.DeviceGroupInput{Name: "D", Description: strings.Repeat("d", 2001)})
	wantField(t, err, "description", "long description")
	if _, err := e.svc.CreateDeviceGroup(ctx, e.sys, uuid.New(), tenancy.DeviceGroupInput{Name: "X"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("group in missing site: %v", err)
	}
	g2, err := e.svc.CreateDeviceGroup(ctx, e.sys, w.siteA.ID, tenancy.DeviceGroupInput{Name: "Laptops"})
	if err != nil {
		t.Fatal(err)
	}
	groups, err := e.svc.ListDeviceGroups(ctx, e.sys, w.siteA.ID)
	if err != nil || len(groups) != 2 || groups[0].Name != "Laptops" {
		t.Fatalf("groups: %v %+v", err, groups)
	}
	site, _ := e.svc.GetSite(ctx, e.sys, w.siteA.ID)
	if site.DeviceGroupCount != 2 {
		t.Fatalf("group count %d", site.DeviceGroupCount)
	}
	ug, err := e.svc.UpdateDeviceGroup(ctx, e.sys, g.ID, tenancy.DeviceGroupInput{Name: "Servers (rack)", Description: ""})
	if err != nil || ug.Name != "Servers (rack)" {
		t.Fatalf("update group: %v %+v", err, ug)
	}
	if _, err := e.svc.UpdateDeviceGroup(ctx, e.sys, g2.ID, tenancy.DeviceGroupInput{Name: "servers (RACK)"}); err == nil {
		t.Fatal("duplicate group rename accepted")
	} else {
		wantField(t, err, "name", "group rename duplicate")
	}
	if _, err := e.svc.UpdateDeviceGroup(ctx, e.sys, g2.ID, tenancy.DeviceGroupInput{Name: ""}); err == nil {
		t.Fatal("empty group name accepted")
	}
	if _, err := e.svc.UpdateDeviceGroup(ctx, e.sys, uuid.New(), tenancy.DeviceGroupInput{Name: "x"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("update missing group: %v", err)
	}
	if err := e.svc.DeleteDeviceGroup(ctx, e.sys, g2.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteDeviceGroup(ctx, e.sys, g2.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("delete missing group: %v", err)
	}

	// Deleting a site removes its groups.
	if err := e.svc.DeleteSite(ctx, e.sys, w.siteA.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.GetSite(ctx, e.sys, w.siteA.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("deleted site still visible: %v", err)
	}
	if err := e.svc.DeleteSite(ctx, e.sys, w.siteA.ID, nil); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("delete missing site: %v", err)
	}
	if _, err := e.svc.UpdateDeviceGroup(ctx, e.sys, g.ID, tenancy.DeviceGroupInput{Name: "x"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("group of deleted site: %v", err)
	}
	entries, err := e.audit.List(ctx, database.System, audit.Query{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en.Action] = true
	}
	for _, a := range []string{"site.create", "site.update", "site.delete", "device_group.create", "device_group.update", "device_group.delete"} {
		if !seen[a] {
			t.Errorf("no %s audit entry", a)
		}
	}
}

func TestScopedCallers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	w := e.world(t)
	groupB, err := e.svc.CreateDeviceGroup(ctx, e.sys, w.siteB.ID, tenancy.DeviceGroupInput{Name: "B group"})
	if err != nil {
		t.Fatal(err)
	}
	siteA2, err := e.svc.CreateSite(ctx, e.sys, w.orgA.ID, tenancy.SiteInput{Name: "Branch"})
	if err != nil {
		t.Fatal(err)
	}

	super := caller(t, rbac.Assignment{Role: rbac.RoleSuperAdmin})
	orgAdmin := caller(t, rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.orgA.ID})
	siteAdmin := caller(t, rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.orgA.ID, SiteID: w.siteA.ID})
	tech := caller(t, rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: w.orgA.ID, SiteID: w.siteA.ID})
	ro := caller(t, rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: w.orgA.ID, SiteID: w.siteA.ID})
	nobody := caller(t)

	// Super admin sees and manages everything.
	if l, err := e.svc.ListOrganizations(ctx, super, ""); err != nil || len(l) != 2 || !l[0].CanManage || !l[1].CanManage {
		t.Fatalf("super list: %v %+v", err, l)
	}
	if _, err := e.svc.CreateOrganization(ctx, super, tenancy.OrganizationInput{Name: "Initech"}); err != nil {
		t.Fatalf("super create: %v", err)
	}

	// Organization admin: own org only.
	l, err := e.svc.ListOrganizations(ctx, orgAdmin, "")
	if err != nil || len(l) != 1 || l[0].ID != w.orgA.ID || !l[0].CanManage {
		t.Fatalf("org admin list: %v %+v", err, l)
	}
	if _, err := e.svc.GetOrganization(ctx, orgAdmin, w.orgB.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("org admin get foreign: %v", err)
	}
	if _, err := e.svc.CreateOrganization(ctx, orgAdmin, tenancy.OrganizationInput{Name: "Mine"}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("org admin create org: %v", err)
	}
	if err := e.svc.DeleteOrganization(ctx, orgAdmin, w.orgA.ID, nil); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("org admin delete org: %v", err)
	}
	// Names are unique on the server: an organization administrator edits
	// the notes but cannot rename, so cannot probe for other customers'
	// names.
	if l[0].CanRename {
		t.Fatal("org admin may rename")
	}
	var fe *apperr.Error
	if _, err := e.svc.UpdateOrganization(ctx, orgAdmin, w.orgA.ID, tenancy.OrganizationInput{Name: w.orgB.Name}); !errors.As(err, &fe) || fe.Fields["name"] != "Only a Super Administrator can rename an organization." {
		t.Fatalf("org admin renaming to a taken name: %v", err)
	}
	if _, err := e.svc.UpdateOrganization(ctx, orgAdmin, w.orgA.ID, tenancy.OrganizationInput{Name: "Acme Ltd"}); !errors.As(err, &fe) || fe.Fields["name"] == "" {
		t.Fatalf("org admin renaming: %v", err)
	}
	upd, err := e.svc.UpdateOrganization(ctx, orgAdmin, w.orgA.ID, tenancy.OrganizationInput{Name: w.orgA.Name, Notes: "edited by its admin"})
	if err != nil || upd.Notes != "edited by its admin" || upd.CanRename {
		t.Fatalf("org admin update own org: %v %+v", err, upd)
	}
	if o, err := e.svc.GetOrganization(ctx, super, w.orgA.ID); err != nil || !o.CanRename {
		t.Fatalf("super admin may not rename: %v %+v", err, o)
	}
	if _, err := e.svc.UpdateOrganization(ctx, orgAdmin, w.orgB.ID, tenancy.OrganizationInput{Name: "x"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("org admin update foreign: %v", err)
	}
	if _, err := e.svc.CreateSite(ctx, orgAdmin, w.orgA.ID, tenancy.SiteInput{Name: "New"}); err != nil {
		t.Fatalf("org admin create site: %v", err)
	}
	if _, err := e.svc.CreateSite(ctx, orgAdmin, w.orgB.ID, tenancy.SiteInput{Name: "New"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("org admin create foreign site: %v", err)
	}
	if s, err := e.svc.ListSites(ctx, orgAdmin, w.orgB.ID, ""); err != nil || len(s) != 0 {
		t.Fatalf("org admin filtering foreign org: %v %d", err, len(s))
	}
	if _, err := e.svc.ListDeviceGroups(ctx, orgAdmin, w.siteB.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("groups of foreign site: %v", err)
	}
	if _, err := e.svc.UpdateDeviceGroup(ctx, orgAdmin, groupB.ID, tenancy.DeviceGroupInput{Name: "x"}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("update foreign group: %v", err)
	}
	if err := e.svc.DeleteDeviceGroup(ctx, orgAdmin, groupB.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("delete foreign group: %v", err)
	}
	if err := e.svc.DeleteSite(ctx, orgAdmin, w.siteB.ID, nil); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("delete foreign site: %v", err)
	}

	// Site administrator: sees only their site, can read but not manage the
	// parent organization, manages the site and its groups, cannot add or
	// delete sites.
	l, err = e.svc.ListOrganizations(ctx, siteAdmin, "")
	if err != nil || len(l) != 1 || l[0].ID != w.orgA.ID || l[0].CanManage {
		t.Fatalf("site admin org list: %v %+v", err, l)
	}
	if l[0].SiteCount != 1 {
		t.Fatalf("site admin sees %d sites in the org count", l[0].SiteCount)
	}
	if o, err := e.svc.GetOrganization(ctx, siteAdmin, w.orgA.ID); err != nil || o.CanManage {
		t.Fatalf("site admin get org: %v %+v", err, o)
	}
	if _, err := e.svc.UpdateOrganization(ctx, siteAdmin, w.orgA.ID, tenancy.OrganizationInput{Name: "x"}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("site admin update org: %v", err)
	}
	sites, err := e.svc.ListSites(ctx, siteAdmin, uuid.Nil, "")
	if err != nil || len(sites) != 1 || sites[0].ID != w.siteA.ID || !sites[0].CanManage {
		t.Fatalf("site admin sites: %v %+v", err, sites)
	}
	if _, err := e.svc.GetSite(ctx, siteAdmin, siteA2.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("site admin sibling site: %v", err)
	}
	if _, err := e.svc.CreateSite(ctx, siteAdmin, w.orgA.ID, tenancy.SiteInput{Name: "Mine"}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("site admin create site: %v", err)
	}
	if err := e.svc.DeleteSite(ctx, siteAdmin, w.siteA.ID, nil); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("site admin delete site: %v", err)
	}
	if _, err := e.svc.UpdateSite(ctx, siteAdmin, w.siteA.ID, tenancy.SiteInput{Name: "HQ 2"}); err != nil {
		t.Fatalf("site admin update site: %v", err)
	}
	g, err := e.svc.CreateDeviceGroup(ctx, siteAdmin, w.siteA.ID, tenancy.DeviceGroupInput{Name: "Desks"})
	if err != nil {
		t.Fatalf("site admin create group: %v", err)
	}

	// Technician and read-only: can see, cannot change.
	for name, c := range map[string]access.Caller{"technician": tech, "read-only": ro} {
		if s, err := e.svc.ListSites(ctx, c, uuid.Nil, ""); err != nil || len(s) != 1 || s[0].CanManage {
			t.Fatalf("%s sites: %v %+v", name, err, s)
		}
		if gs, err := e.svc.ListDeviceGroups(ctx, c, w.siteA.ID); err != nil || len(gs) != 1 {
			t.Fatalf("%s groups: %v %d", name, err, len(gs))
		}
		if _, err := e.svc.UpdateSite(ctx, c, w.siteA.ID, tenancy.SiteInput{Name: "x"}); !errors.Is(err, apperr.ErrForbidden) {
			t.Fatalf("%s update site: %v", name, err)
		}
		if _, err := e.svc.CreateDeviceGroup(ctx, c, w.siteA.ID, tenancy.DeviceGroupInput{Name: "x"}); !errors.Is(err, apperr.ErrForbidden) {
			t.Fatalf("%s create group: %v", name, err)
		}
		if _, err := e.svc.UpdateDeviceGroup(ctx, c, g.ID, tenancy.DeviceGroupInput{Name: "x"}); !errors.Is(err, apperr.ErrForbidden) {
			t.Fatalf("%s update group: %v", name, err)
		}
		if err := e.svc.DeleteDeviceGroup(ctx, c, g.ID); !errors.Is(err, apperr.ErrForbidden) {
			t.Fatalf("%s delete group: %v", name, err)
		}
	}
	if err := e.svc.DeleteDeviceGroup(ctx, siteAdmin, g.ID); err != nil {
		t.Fatalf("site admin delete group: %v", err)
	}

	// No roles: nothing visible.
	if l, err := e.svc.ListOrganizations(ctx, nobody, ""); err != nil || len(l) != 0 {
		t.Fatalf("no-role org list: %v %d", err, len(l))
	}
	if s, err := e.svc.ListSites(ctx, nobody, uuid.Nil, ""); err != nil || len(s) != 0 {
		t.Fatalf("no-role site list: %v %d", err, len(s))
	}

	// Super admin may delete an organization once it is empty.
	if err := e.svc.DeleteSite(ctx, super, w.siteB.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteOrganization(ctx, super, w.orgB.ID, nil); err != nil {
		t.Fatal(err)
	}
	// Audit entries carry the organization so tenants see their own history.
	entries, err := e.audit.List(ctx, database.System, audit.Query{OrganizationID: w.orgA.ID, ActionPrefix: "device_group"})
	if err != nil || len(entries) != 2 {
		t.Fatalf("org-scoped audit entries: %v %d", err, len(entries))
	}
}

func TestValidTimezone(t *testing.T) {
	for tz, want := range map[string]bool{
		"UTC": true, "Europe/London": true, "America/Argentina/Buenos_Aires": true, "US/Eastern": true,
		"": false, "Local": false, "Not/AZone": false, "../../etc/passwd": false,
		// Spellings the system opens as Europe/London, each of which would
		// be one more zone to keep.
		"Europe//London": false, "Europe/./London": false, "./Europe/London": false, ".//Europe//./London": false,
	} {
		if got := tenancy.ValidTimezone(tz); got != want {
			t.Errorf("ValidTimezone(%q) = %v, want %v", tz, got, want)
		}
	}
}

// Automatic repairs are on for every organization and org.manage turns them
// off (ADR-0069); an update that says nothing about them leaves them be.
func TestAutomaticRepairSetting(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	org, err := e.svc.CreateOrganization(ctx, e.sys, tenancy.OrganizationInput{Name: "Acme"})
	if err != nil || !org.AutoRepair {
		t.Fatalf("a new organization: %+v, %v", org, err)
	}
	off, on := false, true
	upd, err := e.svc.UpdateOrganization(ctx, e.sys, org.ID, tenancy.OrganizationInput{Name: "Acme", AutoRepair: &off})
	if err != nil || upd.AutoRepair {
		t.Fatalf("turn off: %+v, %v", upd, err)
	}
	upd, err = e.svc.UpdateOrganization(ctx, e.sys, org.ID, tenancy.OrganizationInput{Name: "Acme", Notes: "n"})
	if err != nil || upd.AutoRepair || upd.Notes != "n" {
		t.Fatalf("an update that leaves it out: %+v, %v", upd, err)
	}
	var logged int
	if err := e.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'organization.update' AND details->>'autoRepair' = 'false'`).Scan(&logged)
	}); err != nil || logged != 1 {
		t.Errorf("the change was audited %d times: %v", logged, err)
	}
	// Whoever may manage the organization may change it; others may not.
	admin := caller(t, rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: org.ID})
	if upd, err = e.svc.UpdateOrganization(ctx, admin, org.ID, tenancy.OrganizationInput{Name: "Acme", AutoRepair: &on}); err != nil || !upd.AutoRepair {
		t.Errorf("organization administrator: %+v, %v", upd, err)
	}
	tech := caller(t, rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: org.ID})
	if _, err := e.svc.UpdateOrganization(ctx, tech, org.ID, tenancy.OrganizationInput{Name: "Acme", AutoRepair: &off}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("technician: %v", err)
	}
	if got, _ := e.svc.GetOrganization(ctx, e.sys, org.ID); got == nil || !got.AutoRepair {
		t.Errorf("a refused change was kept: %+v", got)
	}
}
