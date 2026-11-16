package remote

import (
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func site(org, name string) siteInfo {
	return siteInfo{ID: uuid.New(), OrgID: uuid.New(), OrgName: org, Name: name}
}

func meshFor(id string, s siteInfo) meshcentral.Mesh {
	return meshcentral.Mesh{ID: id, Name: s.meshName(), Description: s.meshDesc(), Type: 2}
}

func TestPlanMeshes(t *testing.T) {
	recorded := site("Acme", "HQ")      // mapping and group agree
	renamed := site("Acme", "Branch")   // group name drifted
	unrecorded := site("Globex", "Lab") // group exists but the mapping row was lost
	missing := site("Globex", "Plant")  // no group at all
	lost := site("Initech", "Office")   // mapping points at a group that is gone
	deleted := site("Gone", "Away")     // group of a site that no longer exists

	drift := meshFor("mesh//b", renamed)
	drift.Name = "old name"
	dupe := meshFor("mesh//c2", unrecorded) // a second group for the same site
	meshes := []meshcentral.Mesh{
		meshFor("mesh//a", recorded),
		drift,
		dupe,
		meshFor("mesh//c1", unrecorded),
		meshFor("mesh//z", deleted),
		{ID: "mesh//manual", Name: "Made by hand", Description: "not ours"},
	}
	mapping := map[uuid.UUID]string{
		recorded.ID: "mesh//a",
		renamed.ID:  "mesh//b",
		lost.ID:     "mesh//vanished",
	}
	p := planMeshes([]siteInfo{recorded, renamed, unrecorded, missing, lost}, meshes, mapping)

	if len(p.create) != 2 || p.create[0].ID != missing.ID || p.create[1].ID != lost.ID {
		t.Errorf("create = %v, want the missing and lost sites", p.create)
	}
	if !reflect.DeepEqual(p.adopt, map[uuid.UUID]string{unrecorded.ID: "mesh//c1"}) {
		t.Errorf("adopt = %v, want the oldest marked group", p.adopt)
	}
	if !reflect.DeepEqual(p.stale, []uuid.UUID{lost.ID}) {
		t.Errorf("stale = %v", p.stale)
	}
	if len(p.rename) != 1 || p.rename[0] != (meshRename{MeshID: "mesh//b", Name: "Acme / Branch", Desc: renamed.meshDesc()}) {
		t.Errorf("rename = %+v", p.rename)
	}
	if !reflect.DeepEqual(p.remove, []string{"mesh//c2", "mesh//z"}) {
		t.Errorf("remove = %v, want the duplicate and the deleted site's group (never the manual one)", p.remove)
	}
	want := map[uuid.UUID]string{recorded.ID: "mesh//a", renamed.ID: "mesh//b", unrecorded.ID: "mesh//c1"}
	if !reflect.DeepEqual(p.mesh, want) {
		t.Errorf("mesh = %v, want %v", p.mesh, want)
	}
	for site, mesh := range want {
		if p.known[mesh] != site {
			t.Errorf("known[%s] = %v, want %v", mesh, p.known[mesh], site)
		}
	}
}

func TestPlanMeshesNothingToDo(t *testing.T) {
	s := site("Acme", "HQ")
	p := planMeshes([]siteInfo{s}, []meshcentral.Mesh{meshFor("mesh//a", s)}, map[uuid.UUID]string{s.ID: "mesh//a"})
	if len(p.create)+len(p.adopt)+len(p.rename)+len(p.remove)+len(p.stale) != 0 {
		t.Fatalf("plan for a synchronized site = %+v", p)
	}
}

func TestPlanUsers(t *testing.T) {
	same, renamed, rightsDrift, added, gone := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	acc := map[uuid.UUID]meshcentral.Access{uuid.New(): {Desktop: true}}
	want := []userInfo{
		{ID: same, Name: "Sam", Access: acc},
		{ID: renamed, Name: "Rita New", Access: acc},
		{ID: rightsDrift, Name: "Dee", Access: acc},
		{ID: added, Name: "Ada", Access: acc},
	}
	have := []meshcentral.User{
		{ID: accountID(same), RealName: "Sam", SiteAdmin: meshcentral.TechnicianSiteRights},
		{ID: accountID(renamed), RealName: "Rita Old", SiteAdmin: meshcentral.TechnicianSiteRights},
		{ID: accountID(rightsDrift), RealName: "Dee", SiteAdmin: 0xFFFFFFFF},
		{ID: accountID(gone), RealName: "Gone", SiteAdmin: meshcentral.TechnicianSiteRights},
		{ID: "user//easyrmm-service", RealName: "EasyRMM", SiteAdmin: 0xFFFFFFFF},
		{ID: "user//admin", RealName: "Someone"},
		{ID: "user//easyrmm-not-a-uuid"},
		{ID: "user//easyrmm-" + strings.ToUpper(uuid.NewString())},
	}
	p := planUsers(want, have)
	if len(p.add) != 1 || p.add[0].ID != added {
		t.Errorf("add = %v", p.add)
	}
	if len(p.edit) != 2 || p.edit[0].ID != renamed || p.edit[1].ID != rightsDrift {
		t.Errorf("edit = %v", p.edit)
	}
	if !reflect.DeepEqual(p.remove, []string{accountID(gone)}) {
		t.Errorf("remove = %v, want only the departed user's account", p.remove)
	}
}

func TestPlanRights(t *testing.T) {
	s1, s2 := site("Acme", "HQ"), site("Acme", "Branch")
	full := meshcentral.Access{Desktop: true, Terminal: true, Files: true}
	desk := meshcentral.Access{Desktop: true}
	keep, change, revoke, fresh := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	want := []userInfo{
		{ID: keep, Access: map[uuid.UUID]meshcentral.Access{s1.ID: full}},
		{ID: change, Access: map[uuid.UUID]meshcentral.Access{s1.ID: desk}},
		{ID: fresh, Access: map[uuid.UUID]meshcentral.Access{s1.ID: full, s2.ID: desk}},
	}
	m1 := meshFor("mesh//1", s1)
	m1.Links = map[string]meshcentral.Link{
		accountID(keep):         {Rights: full.Rights()},
		accountID(change):       {Rights: full.Rights()},
		accountID(revoke):       {Rights: full.Rights()},
		"user//easyrmm-service": {Rights: 0xFFFFFFFF},
		"user//someone":         {Rights: 8},
	}
	m2 := meshFor("mesh//2", s2)
	other := meshcentral.Mesh{ID: "mesh//other", Links: map[string]meshcentral.Link{accountID(revoke): {Rights: 8}}}
	known := map[string]uuid.UUID{"mesh//1": s1.ID, "mesh//2": s2.ID}

	got := planRights(want, []meshcentral.Mesh{m2, other, m1}, known)
	wantChanges := map[rightChange]bool{
		{MeshID: "mesh//1", UserID: accountID(change), Rights: desk.Rights()}: true,
		{MeshID: "mesh//1", UserID: accountID(revoke), Rights: 0}:             true,
		{MeshID: "mesh//1", UserID: accountID(fresh), Rights: full.Rights()}:  true,
		{MeshID: "mesh//2", UserID: accountID(fresh), Rights: desk.Rights()}:  true,
	}
	if len(got) != len(wantChanges) {
		t.Fatalf("changes = %+v, want %d", got, len(wantChanges))
	}
	for _, c := range got {
		if !wantChanges[c] {
			t.Errorf("unexpected change %+v", c)
		}
	}
}

func TestMarkersAndAccounts(t *testing.T) {
	s := site("Acme", "HQ")
	if id, ok := markedSite(meshFor("mesh//x", s)); !ok || id != s.ID {
		t.Errorf("markedSite = %v %v", id, ok)
	}
	for _, desc := range []string{"", "EasyRMM site nope.", "Created by hand. EasyRMM site " + s.ID.String() + "."} {
		if _, ok := markedSite(meshcentral.Mesh{Description: desc}); ok {
			t.Errorf("markedSite(%q) matched", desc)
		}
	}
	u := uuid.New()
	if got, ok := userOfAccount(accountID(u)); !ok || got != u {
		t.Errorf("userOfAccount(accountID) = %v %v", got, ok)
	}
	if accountID(u) != "user//easyrmm-"+u.String() {
		t.Errorf("accountID = %q", accountID(u))
	}
	for _, id := range []string{"user//easyrmm-service", "user//admin", "easyrmm-" + u.String(), "user//easyrmm-test-1234"} {
		if _, ok := userOfAccount(id); ok {
			t.Errorf("userOfAccount(%q) matched", id)
		}
	}
	long := siteInfo{OrgName: strings.Repeat("ö", 100), Name: strings.Repeat("x", 100)}
	if n := len([]rune(long.meshName())); n != 128 {
		t.Errorf("meshName runes = %d, want 128", n)
	}
	if truncateRunes("héllo", 2) != "hé" || truncateRunes("abc", 5) != "abc" {
		t.Error("truncateRunes")
	}
}

func TestPlatformOf(t *testing.T) {
	for typ, want := range map[int]string{3: "windows", 4: "windows", 43: "windows", 6: "linux", 26: "linux", 16: "macos", 29: "macos", 0: "other", 999: "other"} {
		if got := platformOf(typ); got != want {
			t.Errorf("platformOf(%d) = %q, want %q", typ, got, want)
		}
	}
}

func TestAccessFor(t *testing.T) {
	org, s1, s2 := uuid.New(), uuid.New(), uuid.New()
	p, err := rbac.NewPrincipal(uuid.New(), []rbac.Assignment{
		{Role: rbac.RoleTechnician, OrganizationID: org, SiteID: s1},
		{Role: rbac.RoleReadOnly, OrganizationID: org, SiteID: s2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a := accessFor(p, org, s1); !a.Desktop || !a.Terminal || !a.Files {
		t.Errorf("technician access = %+v", a)
	}
	if a := accessFor(p, org, s2); a.Any() {
		t.Errorf("read-only access = %+v", a)
	}
	if a := accessFor(p, uuid.New(), uuid.New()); a.Any() {
		t.Errorf("access elsewhere = %+v", a)
	}
}

func TestKinds(t *testing.T) {
	for k, want := range map[Kind]string{KindDesktop: "11", KindRDP: "11", KindTerminal: "12", KindFiles: "13"} {
		if k.viewMode() != want {
			t.Errorf("%s viewMode = %s", k, k.viewMode())
		}
		if _, ok := k.permission(); !ok {
			t.Errorf("%s has no permission", k)
		}
	}
	// RDP is a remote desktop, with the same permission.
	if p, _ := KindRDP.permission(); p != rbac.PermRemoteDesktop {
		t.Errorf("RDP permission = %s", p)
	}
	if _, ok := Kind("console").permission(); ok {
		t.Error("unknown kind has a permission")
	}
}

// parseUriArgs is MeshCentral's own URL argument parser (common-0.0.1.js)
// without decoding, as the device page calls it: values containing '%' and
// a few other characters are dropped.
func parseUriArgs(href string) map[string]string {
	out := map[string]string{}
	parts := strings.FieldsFunc(href, func(r rune) bool { return r == '?' || r == '&' || r == '|' })
	for _, arg := range parts[1:] {
		i := strings.Index(arg, "=")
		name, value := arg[:max(i, 0)], arg[i+1:]
		if !strings.ContainsAny(value, `<>&"'+()#%`) {
			out[name] = value
		}
	}
	return out
}

func TestLaunchTarget(t *testing.T) {
	const node = "node//mLf6wfOfjWERUUuoXkwlnye01opMRuHWNNk@l01w9JXU7ZpX7TBHSOXyqw3zpwJ$"
	target, err := launchTarget(node, KindTerminal, "zr$AZr+FV/Hx@Z==")
	if err != nil {
		t.Fatal(err)
	}
	// What MeshCentral's page sees: the node to open and the view.
	args := parseUriArgs("https://mesh.example.com" + target)
	if args["gotonode"] != strings.TrimPrefix(node, "node//") || args["viewmode"] != "12" || args["hide"] != hideFlags {
		t.Errorf("MeshCentral reads %v from %s", args, target)
	}
	// What MeshCentral's server sees: the login token, decoded.
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("login"); got != "zr$AZr+FV/Hx@Z==" {
		t.Errorf("login token = %q", got)
	}
	if strings.Contains(target, "rdp=") {
		t.Errorf("terminal target asks for RDP: %s", target)
	}
	// An RDP session opens the desktop view and tells the session view
	// tuning to connect over RDP.
	rdp, err := launchTarget(node, KindRDP, "x")
	if err != nil {
		t.Fatal(err)
	}
	if args := parseUriArgs("https://mesh.example.com" + rdp); args["viewmode"] != "11" || args["rdp"] != "1" {
		t.Errorf("RDP target %s reads %v", rdp, args)
	}
	for _, bad := range []string{"node//a&viewmode=1", "node//a b", "node/other/abc", "node//", "mesh//abc"} {
		if _, err := launchTarget(bad, KindTerminal, "x"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
