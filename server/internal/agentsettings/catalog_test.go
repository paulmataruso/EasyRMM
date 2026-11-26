package agentsettings

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func TestCatalogEntriesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range Catalog() {
		if seen[k.Name] {
			t.Errorf("%s twice", k.Name)
		}
		seen[k.Name] = true
		if k.Title == "" || k.Line == "" || k.Permission == nil || len(k.SetAt) == 0 {
			t.Errorf("%s is incomplete", k.Name)
		}
		if k.Default < k.Min || k.Default > k.Max {
			t.Errorf("%s: default %d outside %d to %d", k.Name, k.Default, k.Min, k.Max)
		}
		for _, s := range k.EnforceAt {
			if !k.CanSetAt(s) || s == ScopeDevice {
				t.Errorf("%s enforces at %s, which it cannot set or has nothing below", k.Name, s)
			}
		}
		for _, s := range k.SetAt {
			if p := k.Permission(s); p == "" {
				t.Errorf("%s has no permission at %s", k.Name, s)
			}
		}
		got, ok := Lookup(k.Name)
		if !ok || got.Name != k.Name {
			t.Errorf("lookup of %s", k.Name)
		}
	}
	if _, ok := Lookup("agent.nothing"); ok {
		t.Error("an unknown key was found")
	}
	if Catalog()[0].Name != HeartbeatKey {
		t.Error("the heartbeat key is first")
	}
}

func TestHeartbeatKeyPermissions(t *testing.T) {
	k, _ := Lookup(HeartbeatKey)
	if k.Permission(ScopePlatform) != rbac.PermSettingsManage {
		t.Error("the platform's needs settings.manage")
	}
	for _, s := range []Scope{ScopeOrganization, ScopeSite, ScopeDevice} {
		if k.Permission(s) != rbac.PermDeviceConfigure {
			t.Errorf("%s needs %s", s, k.Permission(s))
		}
	}
	if !k.CanEnforceAt(ScopePlatform) || !k.CanEnforceAt(ScopeOrganization) || k.CanEnforceAt(ScopeSite) || k.CanEnforceAt(ScopeDevice) {
		t.Error("enforcement scopes")
	}
	// Every role that holds the permission holds it from Site Administrator
	// up, and technicians do not (they have device.edit, which this key does
	// not use).
	for role, want := range map[rbac.Role]bool{rbac.RoleSiteAdmin: true, rbac.RoleOrgAdmin: true, rbac.RoleSuperAdmin: true, rbac.RoleTechnician: false, rbac.RoleReadOnly: false} {
		held := false
		for _, p := range rbac.Roles[role].Permissions {
			held = held || p == rbac.PermDeviceConfigure
		}
		if held != want {
			t.Errorf("%s holds device.configure: %v", role, held)
		}
	}
}

func TestCheck(t *testing.T) {
	k, _ := Lookup(HeartbeatKey)
	l := DefaultLimits()
	for in, want := range map[string]string{"30": "30", "60": "60", "300": "300", " 90 ": "90", "090": "90"} {
		got, err := k.Check(json.RawMessage(in), l)
		if err != nil || string(got) != want {
			t.Errorf("%q: %s %v", in, got, err)
		}
	}
	for _, in := range []string{"", "null", "true", `"60"`, "60.0", "6e1", "29", "301", "-1", "0", "[60]", "{}", "99999999999", "NaN"} {
		if _, err := k.Check(json.RawMessage(in), l); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
	raised := Limits{MinHeartbeatSeconds: 120}
	if _, err := k.Check(json.RawMessage("119"), raised); err == nil {
		t.Error("below the platform's minimum")
	}
	if _, err := k.Check(json.RawMessage("120"), raised); err != nil {
		t.Errorf("at the platform's minimum: %v", err)
	}
	if k.Lowest(raised) != 120 || k.Lowest(l) != 30 {
		t.Error("lowest")
	}
	noFloor := Key{Min: 5}
	if noFloor.Lowest(raised) != 5 {
		t.Error("a key without a floor")
	}
}

func TestLimitsCheck(t *testing.T) {
	for n, ok := range map[int]bool{29: false, 30: true, 300: true, 301: false, 0: false} {
		if (Limits{MinHeartbeatSeconds: n}.check() == nil) != ok {
			t.Errorf("minimum %d: %v", n, ok)
		}
	}
}

func TestKeysDescribeTheCatalog(t *testing.T) {
	keys := Keys()
	if len(keys) != len(Catalog()) || keys[0].Key != HeartbeatKey || keys[0].Permissions[ScopePlatform] != "settings.manage" ||
		keys[0].Permissions[ScopeDevice] != "device.configure" || keys[0].Default != 60 || keys[0].Type != "integer" {
		t.Errorf("%+v", keys)
	}
}

func TestScopes(t *testing.T) {
	for i, s := range scopes {
		if s.rank() != i || !s.Valid() {
			t.Errorf("%s: %d", s, s.rank())
		}
	}
	if Scope("group").Valid() || Scope("").rank() != -1 {
		t.Error("an unknown scope is valid")
	}
	tg := Target{Scope: ScopeSite, OrgID: uuid.New(), SiteID: uuid.New(), DeviceID: uuid.New()}
	if tg.id() != tg.SiteID || (Target{Scope: ScopePlatform}).id() != uuid.Nil || (Target{Scope: ScopeOrganization, OrgID: tg.OrgID}).id() != tg.OrgID ||
		(Target{Scope: ScopeDevice, DeviceID: tg.DeviceID}).id() != tg.DeviceID {
		t.Error("target ids")
	}
	if tg.resource().SiteID != tg.SiteID || (Target{Scope: ScopeOrganization, OrgID: tg.OrgID}).resource().SiteID != uuid.Nil ||
		(Target{Scope: ScopePlatform}).resource().OrganizationID != uuid.Nil {
		t.Error("target resources")
	}
}
