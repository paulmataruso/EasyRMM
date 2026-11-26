package grouppolicy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

const (
	gpoID  = "8f2c1b3a-5d4e-4a7b-9c1d-2e3f4a5b6c7d"
	ouDN   = "OU=Test,OU=EasyRMM,DC=corp,DC=example"
	rootDN = "DC=corp,DC=example"
	dcDN   = "OU=Domain Controllers,DC=corp,DC=example"
	siteDN = "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example"
	sid    = "S-1-5-21-1-2-3-1104"
)

func catalog(t *testing.T) *winmod.Catalog {
	t.Helper()
	c, err := winmod.NewCatalog(Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogPinsMatchScripts(t *testing.T) {
	c := catalog(t)
	entries, err := scriptFS.ReadDir("scripts")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(c.Actions()) || len(pins) != len(entries) {
		t.Errorf("%d scripts, %d actions, %d pins", len(entries), len(c.Actions()), len(pins))
	}
	for _, a := range c.Actions() {
		if got := agentproto.HashScript(a.Script); got != a.ScriptSHA256 {
			t.Errorf("%s: the script hashes to %s; run gen.sh and review pins.go", a.Name, got)
		}
	}
}

// The module's rules of ADR-0083 section 7, over every action: a read is a plain read of gpo.view; a change asks for a
// step-up and a typed reason, names the right permission, and a destructive one is confirmed by the GPO's name.
func TestCatalogLint(t *testing.T) {
	link := map[string]bool{"link_add": true, "link_remove": true, "link_order": true, "link_enabled": true, "link_enforced": true, "inheritance_block": true}
	for _, a := range catalog(t).Actions() {
		short := strings.TrimPrefix(a.Name, "group_policy.")
		if !a.Changes && a.Permission == rbac.PermGPOView {
			if !a.IsPlainRead() || a.Freshness <= 0 {
				t.Errorf("%s: a read is a plain snapshot read", a.Name)
			}
			continue
		}
		if a.Permission == rbac.PermGPOView || !a.NeedsStepUp() {
			t.Errorf("%s: a change must not be a view action and must ask for a step-up", a.Name)
		}
		if short != "gpo_restore_stage" {
			has := false
			for _, p := range a.Params {
				if p.Name == "reason" && p.Required && p.Min == 10 && p.Max == 500 {
					has = true
				}
			}
			if !has {
				t.Errorf("%s: no required reason of 10 to 500 characters", a.Name)
			}
		}
		wantPerm := rbac.PermGPOManage
		if link[short] {
			wantPerm = rbac.PermGPOLink
		}
		if a.Permission != wantPerm {
			t.Errorf("%s: permission %s, want %s", a.Name, a.Permission, wantPerm)
		}
		if a.Destructive && a.Subject != "name" {
			t.Errorf("%s: a destructive change is confirmed by the GPO's name", a.Name)
		}
		for _, p := range a.Params {
			if p.Secret {
				t.Errorf("%s: no secret is sent to a Group Policy script", a.Name)
			}
		}
	}
	for _, name := range []string{"gpo_delete", "link_remove", "sec_filter_remove", "gpo_restore"} {
		a, _ := catalog(t).Lookup("group_policy." + name)
		if !a.Destructive {
			t.Errorf("%s must be destructive (typed confirmation)", name)
		}
	}
}

func TestScriptsNeverTouchSysvolOrAttributes(t *testing.T) {
	banned := []string{"Set-ADObject", "Set-ADOrganizationalUnit", "Set-Content", "Out-File", "Add-Content", "SYSVOL\\", "Invoke-Expression", "-Credential", "gPLink", "gPCFileSysPath"}
	for _, a := range catalog(t).Actions() {
		for _, b := range banned {
			if strings.Contains(a.Script, b) {
				t.Errorf("%s: the script holds %q: EasyRMM calls only the GroupPolicy cmdlets and GPMC", a.Name, b)
			}
		}
	}
}

func TestClassifyTarget(t *testing.T) {
	for dn, want := range map[string]string{
		rootDN: "domain", dcDN: "dc_ou", siteDN: "site", ouDN: "ou",
		"OU=Domain Controllers,OU=X,DC=corp,DC=example": "ou",
		"CN=Users,DC=corp,DC=example":                   "other",
		"CN=x,CN=Sites,CN=Configuration":                "other",
		"CN=Sites,CN=Configuration,DC=corp,DC=example":  "other",
	} {
		if got := ClassifyTarget(dn); got != want {
			t.Errorf("%s: %s, want %s", dn, got, want)
		}
	}
}

func TestSensitivity(t *testing.T) {
	m := func(kv ...string) map[string]any {
		p := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			p[kv[i]] = kv[i+1]
		}
		return p
	}
	for _, c := range []struct {
		action string
		p      map[string]any
		want   string
	}{
		{"group_policy.link_add", m("id", gpoID, "target", rootDN), "sensitive_link"},
		{"group_policy.link_add", m("id", gpoID, "target", dcDN), "sensitive_link"},
		{"group_policy.link_order", m("id", gpoID, "target", siteDN), "sensitive_link"},
		{"group_policy.inheritance_block", m("target", rootDN), "sensitive_link"},
		{"group_policy.link_add", m("id", gpoID, "target", ouDN), ""},
		{"group_policy.sec_filter_add", m("id", DefaultDomainPolicyID), "default_policy"},
		{"group_policy.wmi_set", m("id", DefaultControllersPolicyID), "default_policy"},
		{"group_policy.link_add", m("id", DefaultDomainPolicyID, "target", ouDN), "default_policy"},
		{"group_policy.gpo_backup", m("id", DefaultDomainPolicyID), ""},
		{"group_policy.gpo_copy", m("id", DefaultDomainPolicyID), ""},
		{"group_policy.gpo_rename", m("id", gpoID), ""},
	} {
		if got := Sensitivity(c.action, c.p); got != c.want {
			t.Errorf("%s %v: %q, want %q", c.action, c.p, got, c.want)
		}
	}
}

func validate(t *testing.T, action, params string) error {
	t.Helper()
	a, ok := catalog(t).Lookup("group_policy." + action)
	if !ok {
		t.Fatalf("no action %s", action)
	}
	_, err := a.Validate(json.RawMessage(params))
	return err
}

func fieldHas(t *testing.T, err error, field, text string) {
	t.Helper()
	e, ok := apperr.As(err)
	if !ok || !strings.Contains(e.Fields[field], text) {
		t.Fatalf("want a %q error containing %q, got %v (%+v)", field, text, err, e)
	}
}

func TestValidation(t *testing.T) {
	why := `"reason":"Roll out the baseline"`
	// What is accepted.
	for action, params := range map[string]string{
		"gpo_create":        `{"newName":"Baseline (test)",` + why + `}`,
		"gpo_rename":        `{"id":"` + gpoID + `","newName":"Baseline 2",` + why + `,"expectComputerVersion":3,"expectUserVersion":0}`,
		"gpo_delete":        `{"id":"` + gpoID + `","name":"Baseline 2",` + why + `}`,
		"gpo_status":        `{"id":"` + gpoID + `","status":"UserSettingsDisabled",` + why + `}`,
		"sec_filter_add":    `{"id":"` + gpoID + `","trustee":"` + sid + `",` + why + `}`,
		"sec_filter_remove": `{"id":"` + gpoID + `","name":"x","trustee":"` + sid + `","keepRead":true,` + why + `}`,
		"wmi_set":           `{"id":"` + gpoID + `","filter":"",` + why + `}`,
		"link_add":          `{"id":"` + gpoID + `","target":"` + ouDN + `","enforced":false,` + why + `}`,
		"link_order":        `{"id":"` + gpoID + `","target":"` + ouDN + `","order":1,` + why + `}`,
		"inheritance_block": `{"target":"` + ouDN + `","blocked":true,` + why + `}`,
		"gpo_backup":        `{"id":"` + gpoID + `",` + why + `}`,
		"gpo_report":        `{"id":"` + gpoID + `"}`,
		"gpo_list":          `{"offset":30,"pageSize":30,"match":"base"}`,
		"link_tree":         `{}`,
	} {
		if err := validate(t, action, params); err != nil {
			t.Errorf("%s: %v", action, err)
		}
	}
	// What is refused, with the field.
	fieldHas(t, validate(t, "gpo_create", `{"newName":"x"}`), "params.reason", "required")
	fieldHas(t, validate(t, "gpo_create", `{"newName":"x","reason":"short"}`), "params.reason", "short")
	fieldHas(t, validate(t, "gpo_rename", `{"id":"not-a-guid","newName":"x",`+why+`}`), "params.id", "GUID")
	fieldHas(t, validate(t, "gpo_rename", `{"id":"`+gpoID+`","newName":"$(calc)",`+why+`}`), "params.newName", "form")
	fieldHas(t, validate(t, "gpo_rename", `{"id":"`+gpoID+`","newName":"a\u0000b",`+why+`}`), "params.newName", "character")
	fieldHas(t, validate(t, "gpo_status", `{"id":"`+gpoID+`","status":"Nope",`+why+`}`), "params.status", "one of")
	fieldHas(t, validate(t, "link_add", `{"id":"`+gpoID+`","target":"OU=a;b,DC=x",`+why+`}`), "params.target", "distinguished")
	fieldHas(t, validate(t, "link_add", `{"id":"`+gpoID+`","target":"CN=Users,DC=corp,DC=example",`+why+`}`), "params.target", "domain, an organizational unit")
	fieldHas(t, validate(t, "link_order", `{"id":"`+gpoID+`","target":"`+ouDN+`","order":0,`+why+`}`), "params.order", "range")
	fieldHas(t, validate(t, "link_order", `{"id":"`+gpoID+`","target":"`+ouDN+`","order":1000,`+why+`}`), "params.order", "range")
	fieldHas(t, validate(t, "gpo_list", `{"pageSize":500}`), "params.pageSize", "range")
	fieldHas(t, validate(t, "gpo_status", `{"id":"`+gpoID+`","status":"AllSettingsEnabled",`+why+`,"extra":1}`), "params.extra", "no parameter")
	fieldHas(t, validate(t, "sec_filter_add", `{"id":"`+gpoID+`","trustee":"Domain Users",`+why+`}`), "params.trustee", "security identifier")
	fieldHas(t, validate(t, "gpo_restore_stage", `{"backupId":"`+gpoID+`","index":6,"count":2,"chunk":"UEs="}`), "params.index", "range")
	fieldHas(t, validate(t, "gpo_restore_stage", `{"backupId":"`+gpoID+`","index":0,"count":2,"chunk":"not base64 !"}`), "params.chunk", "form")
	fieldHas(t, validate(t, "gpo_restore", `{"id":"`+gpoID+`","name":"x","backupId":"`+gpoID+`","zipSha256":"ABC","parts":1,`+why+`}`), "params.zipSha256", "form")
}

// The two Default policies (ADR-0083 section 7): never deleted, renamed, unlinked or disabled under any confirmation, and
// every other change needs the policy's name typed in full.
func TestDefaultPolicyGuard(t *testing.T) {
	why := `"reason":"Tighten the password policy"`
	for _, id := range []string{DefaultDomainPolicyID, DefaultControllersPolicyID} {
		name := DefaultPolicies[id]
		code := func(err error) string {
			e, ok := apperr.As(err)
			if !ok {
				return ""
			}
			return e.Code
		}
		for action, params := range map[string]string{
			"gpo_delete":  `{"id":"` + id + `","name":"` + name + `",` + why + `,"confirmName":"` + name + `"}`,
			"gpo_rename":  `{"id":"` + id + `","newName":"Other",` + why + `,"confirmName":"` + name + `"}`,
			"link_remove": `{"id":"` + id + `","name":"` + name + `","target":"` + ouDN + `",` + why + `,"confirmName":"` + name + `"}`,
			"gpo_status":  `{"id":"` + id + `","status":"AllSettingsDisabled",` + why + `,"confirmName":"` + name + `"}`,
		} {
			if got := code(validate(t, action, params)); got != "protected_policy" {
				t.Errorf("%s on %s: code %q, want protected_policy", action, name, got)
			}
		}
		// Another change needs the name in full, and then passes validation (two people are then required by the gate).
		for action, params := range map[string]string{
			"sec_filter_add": `{"id":"` + id + `","trustee":"` + sid + `",` + why + ``,
			"wmi_set":        `{"id":"` + id + `","filter":"",` + why + ``,
			"link_add":       `{"id":"` + id + `","target":"` + ouDN + `",` + why + ``,
			"gpo_status":     `{"id":"` + id + `","status":"AllSettingsEnabled",` + why + ``,
		} {
			fieldHas(t, validate(t, action, params+`}`), "params.confirmName", "in full")
			fieldHas(t, validate(t, action, params+`,"confirmName":"default domain"}`), "params.confirmName", "in full")
			if err := validate(t, action, params+`,"confirmName":"`+name+`"}`); err != nil {
				t.Errorf("%s with the name typed: %v", action, err)
			}
		}
		// A backup and a copy change nothing in the policy.
		if err := validate(t, "gpo_backup", `{"id":"`+id+`",`+why+`}`); err != nil {
			t.Errorf("backup of %s: %v", name, err)
		}
		if err := validate(t, "gpo_copy", `{"id":"`+id+`","newName":"Copy of it",`+why+`}`); err != nil {
			t.Errorf("copy of %s: %v", name, err)
		}
	}
	// A new GPO never takes a Default policy's name.
	fieldHas(t, validate(t, "gpo_create", `{"newName":"default domain policy",`+why+`}`), "params.newName", "Default policy")
	fieldHas(t, validate(t, "gpo_copy", `{"id":"`+gpoID+`","newName":"Default Domain Controllers Policy",`+why+`}`), "params.newName", "Default policy")
	// Inheritance is not blocked on a site.
	fieldHas(t, validate(t, "inheritance_block", `{"target":"`+siteDN+`","blocked":true,`+why+`}`), "params.target", "not on a site")
}

func TestNeedsApprovalCheck(t *testing.T) {
	for name, want := range map[string]bool{
		"group_policy.gpo_create": true, "group_policy.gpo_delete": true, "group_policy.link_add": true, "group_policy.inheritance_block": true,
		"group_policy.gpo_restore": true, "group_policy.gpo_backup": false, "group_policy.gpo_copy": false, "group_policy.gpo_restore_stage": false,
		"group_policy.gpo_list": false,
	} {
		if got := NeedsApprovalCheck(name); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
}

// A result line the scripts print for each read is read by the catalog's schema (sample outputs, written by hand from the
// cmdlets' documented properties: the real ones come with the first run on a controller).
func TestSampleOutputs(t *testing.T) {
	c := catalog(t)
	for action, data := range map[string]string{
		"status":      `{"domain":"corp.example","domainDn":"DC=corp,DC=example","controller":"dc1.corp.example","gpoCount":3,"empty":1,"unlinked":0,"targets":4}`,
		"wmi_filters": `{"filters":[{"id":"` + gpoID + `","name":"Laptops","description":"","queries":["root\\CIMv2;SELECT * FROM Win32_Battery"]}]}`,
		"link_tree": `{"domain":"corp.example","total":1,"offset":0,"next":null,"targets":[{"dn":"` + rootDN + `","name":"corp.example","kind":"domain","sensitive":true,"inheritanceBlocked":false,` +
			`"links":[{"gpoId":"` + gpoID + `","gpoName":"A","target":"` + rootDN + `","targetName":"corp.example","kind":"domain","enabled":true,"enforced":false,"order":1}]}]}`,
		"gpo_list": `{"total":1,"offset":0,"next":null,"walked":true,"items":[{"id":"` + gpoID + `","name":"A","status":"AllSettingsEnabled","description":"","owner":"CORP\\Domain Admins","created":null,"modified":"2026-01-01T00:00:00Z",` +
			`"computer":{"directory":1,"sysvol":1},"user":{"directory":0,"sysvol":0},"wmiFilter":"","default":false,"linkCount":0,"links":[]}]}`,
		"gpo_get": `{"id":"` + gpoID + `","name":"A","status":"AllSettingsEnabled","description":"","owner":"o","created":null,"modified":null,"computer":{"directory":1,"sysvol":1},"user":{"directory":0,"sysvol":0},` +
			`"wmiFilter":"","default":false,"linkCount":0,"links":[],"reportLinks":[{"name":"n","path":"corp.example","enabled":true,"enforced":false,"sensitive":true}],` +
			`"trustees":[{"name":"Authenticated Users","sid":"S-1-5-11","type":"well_known","permission":"GpoApply","inherited":false,"denied":false,"apply":true}]}`,
	} {
		a, _ := c.Lookup("group_policy." + action)
		res, err := a.ParseResult(`EASYRMM-WINMOD-RESULT-V1 {"ok":true,"version":1,"data":` + data + `,"error":null}`)
		if err != nil || !res.OK {
			t.Errorf("%s: %v", action, err)
		}
	}
	a, _ := c.Lookup("group_policy.gpo_rename")
	line := `EASYRMM-WINMOD-RESULT-V1 {"ok":true,"version":1,"data":{"summary":"Renamed","before":{"name":"a"},"after":{"name":"b"},"gpoId":"` + gpoID + `","gpoName":"b",` +
		`"backup":{"backupId":"` + gpoID + `","domain":"corp.example","gpoId":"` + gpoID + `","gpoName":"a","size":3,"sha256":"` + strings.Repeat("a", 64) + `","computer":{"directory":1,"sysvol":1},"user":{"directory":0,"sysvol":0},"zip":"UEsD"},` +
		`"versionBefore":{"computer":{"directory":1,"sysvol":1},"user":{"directory":0,"sysvol":0}},"versionAfter":null},"error":null}`
	res, err := a.ParseResult(line)
	if err != nil || !res.OK {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Data), "UEsD") {
		t.Error("the backup's zip is in the stored result: the server keeps it in its own table")
	}
	if _, err := a.ParseResult(strings.Replace(line, `"summary"`, `"surprise":1,"summary"`, 1)); err == nil {
		t.Error("a field the schema does not know was accepted")
	}
}

func TestChunks(t *testing.T) {
	for size, want := range map[int]int{1: 1, 8999: 1, 9000: 1, 9001: 2, 18000: 2, MaxBackupZip: 4} {
		if got := chunks(size); got != want {
			t.Errorf("chunks(%d) = %d, want %d", size, got, want)
		}
	}
	if chunks(MaxBackupZip) > MaxChunks {
		t.Error("the largest backup needs more chunks than a restore allows")
	}
}
