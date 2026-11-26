package defender

import (
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

// The catalog lint of ADR-0074 section 9: permission, version, timeout,
// tier rules, and the script pins, for every action.
func TestCatalogLint(t *testing.T) {
	acts := Actions()
	c, err := winmod.NewCatalog(acts...)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, a := range c.Actions() {
		seen[strings.TrimPrefix(a.Name, "defender.")] = true
		isRead := a.Freshness > 0
		switch {
		case isRead:
			if a.Permission != rbac.PermDefenderView || a.Destructive || a.Confirm || a.Changes {
				t.Errorf("%s: a read needs view and no confirmation", a.Name)
			}
		case a.Destructive:
			// Tier 3.
			if a.Permission != rbac.PermDefenderWeaken || a.Subject == "" || !a.NeedsStepUp() || !a.NeedsConfirm() {
				t.Errorf("%s: tier 3 needs weaken, a confirmation subject and a step-up", a.Name)
			}
		case a.Confirm:
			if a.Permission != rbac.PermDefenderManage || a.NeedsStepUp() {
				t.Errorf("%s: tier 2 needs manage and a confirmation, no step-up", a.Name)
			}
		default:
			if a.Permission != rbac.PermDefenderManage {
				t.Errorf("%s: tier 1 needs manage", a.Name)
			}
		}
		if a.Sensitive && a.SensitivePermission != rbac.PermDefenderViewSensitive {
			t.Errorf("%s: a sensitive result needs view_sensitive", a.Name)
		}
		if !isRead && a.Name != "defender.status" && !a.Changes {
			t.Errorf("%s: a change drops the module's snapshots", a.Name)
		}
	}
	// Every script in the package is in the catalog, and the other way round.
	entries, _ := scriptFS.ReadDir(".")
	for _, e := range entries {
		n := strings.TrimSuffix(e.Name(), ".ps1")
		if !seen[n] {
			t.Errorf("%s.ps1 is not in the catalog", n)
		}
	}
	for n := range scriptPins {
		if !seen[n] {
			t.Errorf("the pin %q has no action", n)
		}
	}
}

// Everyone who holds weaken holds manage, so "manage and weaken" is one permission on a tier 3 action; Technicians hold
// neither weaken nor view_sensitive and Read-Only holds nothing of the module.
func TestPermissionsByRole(t *testing.T) {
	has := func(r rbac.Role, p rbac.Permission) bool { return slices.Contains(rbac.Roles[r].Permissions, p) }
	for role := range rbac.Roles {
		if has(role, rbac.PermDefenderWeaken) && !has(role, rbac.PermDefenderManage) {
			t.Errorf("%s holds weaken without manage", role)
		}
	}
	if has(rbac.RoleTechnician, rbac.PermDefenderWeaken) || has(rbac.RoleTechnician, rbac.PermDefenderViewSensitive) || !has(rbac.RoleTechnician, rbac.PermDefenderManage) {
		t.Error("a Technician manages but cannot weaken or see sensitive values")
	}
	if !has(rbac.RoleSiteAdmin, rbac.PermDefenderWeaken) || !has(rbac.RoleSiteAdmin, rbac.PermDefenderViewSensitive) {
		t.Error("a Site Administrator holds weaken and view_sensitive")
	}
	for _, p := range []rbac.Permission{rbac.PermDefenderView, rbac.PermDefenderManage, rbac.PermDefenderWeaken, rbac.PermDefenderViewSensitive} {
		if has(rbac.RoleReadOnly, p) {
			t.Errorf("Read-Only holds %s", p)
		}
	}
}

// The field table equals the pinned Set-MpPreference list, and the table
// inside the two preference scripts (their kinds, ranges and values too).
func TestFieldTableMatchesPinnedListAndScripts(t *testing.T) {
	raw, err := os.ReadFile("testdata/set-mppreference-params.txt")
	if err != nil {
		t.Fatal(err)
	}
	var pinned []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			pinned = append(pinned, l)
		}
	}
	var names []string
	for _, f := range Fields {
		names = append(names, f.Name)
	}
	slices.Sort(pinned)
	slices.Sort(names)
	if !slices.Equal(pinned, names) {
		t.Errorf("the field table and the pinned list differ:\n table  %v\n pinned %v", names, pinned)
	}
	row := regexp.MustCompile(`(?m)^\s*'(\w+)' = @\{ kind = '(\w+)'; group = '(\w+)'; tamper = \$(true|false); key = '[^']*'; value = '[^']*'; min = (\d+); max = (\d+); values = '([^']*)' \}`)
	for _, script := range []string{"preferences_read", "preferences_set", "preferences_weaken"} {
		rows := row.FindAllStringSubmatch(scriptText(script), -1)
		if len(rows) != len(Fields) {
			t.Errorf("%s: %d field rows, the table has %d", script, len(rows), len(Fields))
		}
		for _, r := range rows {
			f, ok := LookupField(r[1])
			if !ok {
				t.Errorf("%s: unknown field %s", script, r[1])
				continue
			}
			if r[2] != f.Kind || r[3] != f.Group || (r[4] == "true") != f.Tamper || r[5] != strconv.Itoa(f.Min) || r[6] != strconv.Itoa(f.Max) || r[7] != strings.Join(f.Values, ",") {
				t.Errorf("%s: %s differs from the Go table (%v)", script, f.Name, r[2:])
			}
		}
	}
}

// Lists change only with Add- and Remove-MpPreference, never Set- (ADR-0074
// section 3). The AST check enforces it; this is the Go-side belt.
func TestNoSetMpPreferenceOnAList(t *testing.T) {
	lists := regexp.MustCompile(`(?i)Set-MpPreference[^\n]*-(Exclusion\w+|AttackSurfaceReduction\w+|ControlledFolderAccess(Protected|Allowed)\w+)`)
	for n := range scriptPins {
		if lists.MatchString(scriptText(n)) {
			t.Errorf("%s uses Set-MpPreference on a list", n)
		}
	}
	for n := range scriptPins {
		if strings.Contains(scriptText(n), "Remove-MpPreference") && !slices.Contains([]string{"exclusion_remove", "cfa_folder_remove", "cfa_app_remove"}, n) {
			t.Errorf("%s calls Remove-MpPreference", n)
		}
		if strings.Contains(strings.ToLower(scriptText(n)), `\policies\`) && strings.Contains(strings.ToLower(scriptText(n)), "set-itemproperty") {
			t.Errorf("%s writes under a Policies key", n)
		}
	}
}

// No script is given text to run, and nothing touches Tamper Protection.
func TestNoActionForTamperProtection(t *testing.T) {
	for _, a := range Actions() {
		if strings.Contains(strings.ToLower(a.Name), "tamper") {
			t.Errorf("%s: nothing changes Tamper Protection", a.Name)
		}
	}
	for n := range scriptPins {
		s := scriptText(n)
		if strings.Contains(s, "TamperProtection") && strings.Contains(s, "Set-") && strings.Contains(s, "Set-MpPreference -TamperProtection") {
			t.Errorf("%s sets Tamper Protection", n)
		}
	}
}
