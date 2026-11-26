package defender

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

func catalog(t *testing.T) *winmod.Catalog {
	t.Helper()
	c, err := winmod.NewCatalog(Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// validate runs an action's parameter validation and returns the error code
// (and the field) it refused with, or "" when the parameters are accepted.
func validate(t *testing.T, c *winmod.Catalog, action, params string) string {
	t.Helper()
	a, ok := c.Lookup("defender." + action)
	if !ok {
		t.Fatalf("no action %s", action)
	}
	_, err := a.Validate(json.RawMessage(params))
	if err == nil {
		return ""
	}
	e, ok := apperr.As(err)
	if !ok {
		t.Fatalf("%s: %v is not an apperr", action, err)
	}
	for f := range e.Fields {
		return e.Code + ":" + f
	}
	return e.Code
}

func TestPreferenceDirectionPicksTheAction(t *testing.T) {
	c := catalog(t)
	cases := []struct {
		action, params, want string
	}{
		{"preferences_set", `{"field":"DisableRealtimeMonitoring","value":"false"}`, ""},
		{"preferences_set", `{"field":"DisableRealtimeMonitoring","value":"true"}`, "validation_failed:params.value"},
		{"preferences_weaken", `{"field":"DisableRealtimeMonitoring","value":"true"}`, ""},
		{"preferences_weaken", `{"field":"DisableRealtimeMonitoring","value":"false"}`, "validation_failed:params.value"},
		{"preferences_set", `{"field":"MAPSReporting","value":"2"}`, ""},
		{"preferences_set", `{"field":"MAPSReporting","value":"0"}`, "validation_failed:params.value"},
		{"preferences_weaken", `{"field":"MAPSReporting","value":"0"}`, ""},
		{"preferences_set", `{"field":"MAPSReporting","value":"3"}`, "validation_failed:params.value"},
		{"preferences_set", `{"field":"PUAProtection","value":"enabled"}`, ""},
		{"preferences_weaken", `{"field":"PUAProtection","value":"AuditMode"}`, ""},
		{"preferences_set", `{"field":"HighThreatDefaultAction","value":"Quarantine"}`, ""},
		{"preferences_weaken", `{"field":"HighThreatDefaultAction","value":"NoAction"}`, ""},
		{"preferences_set", `{"field":"ScanAvgCPULoadFactor","value":"3"}`, "validation_failed:params.value"},
		{"preferences_set", `{"field":"ScanAvgCPULoadFactor","value":"0"}`, ""},
		{"preferences_set", `{"field":"ScanScheduleTime","value":"1440"}`, "validation_failed:params.value"},
		{"preferences_set", `{"field":"ScanScheduleTime","value":"120"}`, ""},
		{"preferences_set", `{"field":"DisableLocalAdminMerge","value":"true"}`, "not_allowed:params.field"},
		{"preferences_set", `{"field":"ProxyServer","value":"x"}`, "not_allowed:params.field"},
		{"preferences_set", `{"field":"ExclusionPath","value":"C:\\"}`, "not_allowed:params.field"},
		{"preferences_weaken", `{"field":"DisableAutoExclusions","value":"true"}`, ""},
		{"preferences_set", `{"field":"X","value":"1","extra":"y"}`, "validation_failed:params.extra"},
	}
	for _, tc := range cases {
		if got := validate(t, c, tc.action, tc.params); got != tc.want {
			t.Errorf("%s %s: got %q, want %q", tc.action, tc.params, got, tc.want)
		}
	}
}

func TestASRAndCFAChecks(t *testing.T) {
	c := catalog(t)
	const known = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
	cases := []struct {
		action, params, want string
	}{
		{"asr_set", `{"id":"` + known + `","mode":"Enabled"}`, ""},
		{"asr_set", `{"id":"{` + strings.ToUpper(known) + `}","mode":"Warn"}`, ""},
		{"asr_set", `{"id":"` + known + `","mode":"Disabled"}`, "validation_failed:params.mode"},
		{"asr_weaken", `{"id":"` + known + `","mode":"AuditMode"}`, ""},
		{"asr_weaken", `{"id":"` + known + `","mode":"Enabled"}`, "validation_failed:params.mode"},
		{"asr_set", `{"id":"11111111-1111-1111-1111-111111111111","mode":"Enabled"}`, "not_allowed:params.id"},
		{"asr_set", `{"id":"nope","mode":"Enabled"}`, "validation_failed:params.id"},
		{"cfa_set", `{"mode":"Enabled"}`, ""},
		{"cfa_set", `{"mode":"Disabled"}`, "validation_failed:params.mode"},
		{"cfa_weaken", `{"mode":"AuditMode"}`, ""},
		{"cfa_weaken", `{"mode":"Enabled"}`, "validation_failed:params.mode"},
		{"cfa_folder_add", `{"path":"D:\\Customers"}`, ""},
		{"cfa_folder_add", `{"path":"D:\\..\\Windows"}`, "validation_failed:params.path"},
		{"cfa_app_add", `{"path":"D:\\Tools\\tool.exe"}`, ""},
		{"cfa_app_add", `{"path":"D:\\Tools\\tool.dll"}`, "validation_failed:params.path"},
		// Ours is never removed, however the path is written (case, slashes, trailing slash).
		{"cfa_app_remove", `{"path":"C:\\Program Files\\EasyRMM\\Agent\\easyrmm-agent.exe"}`, "protected_exclusion"},
		{"cfa_app_remove", `{"path":"c:/program files/easypatch agent/EasyPatch.Agent.exe"}`, "protected_exclusion"},
		{"cfa_app_remove", `{"path":"D:\\Tools\\tool.exe"}`, ""},
	}
	for _, tc := range cases {
		if got := validate(t, c, tc.action, tc.params); got != tc.want {
			t.Errorf("%s %s: got %q, want %q", tc.action, tc.params, got, tc.want)
		}
	}
}

func TestOurs(t *testing.T) {
	cases := []struct {
		kind, value string
		want        bool
	}{
		{"path", `C:\Program Files\EasyRMM\Agent`, true},
		{"path", `c:\program files\easyrmm\agent\`, true},
		{"path", `C:/ProgramData/EasyRMM/Agent`, true},
		{"path", `C:\ProgramData\EasyPatch`, true},
		{"asr_only", `C:\Program Files\EasyPatch Agent`, true},
		{"path", `C:\Program Files\EasyRMM\MeshAgent`, true},
		{"process", `C:\Program Files\EasyRMM\Agent\easyrmm-agent.exe`, true},
		{"process", `D:\Program Files\EasyRMM\MeshAgent\MESHAGENT.EXE`, true},
		{"process", `C:\Program Files\EasyPatch Agent\EasyPatch.Agent.exe`, true},
		// A parent of ours is a different value; so is a child; so is a bare name.
		{"path", `C:\Program Files\EasyRMM`, false},
		{"path", `C:\Program Files\EasyRMM\Agent\logs`, false},
		{"path", `C:\ProgramData\EasyRMM`, false},
		{"process", `easyrmm-agent.exe`, false},
		{"process", `C:\Tools\easyrmm-agent.exe`, false},
		{"extension", "exe", false},
	}
	for _, tc := range cases {
		if got := Ours(tc.kind, tc.value); got != tc.want {
			t.Errorf("Ours(%s, %s) = %v, want %v", tc.kind, tc.value, got, tc.want)
		}
	}
}

func TestExclusionRules(t *testing.T) {
	c := catalog(t)
	add := func(kind, value string) string {
		b, _ := json.Marshal(map[string]string{"kind": kind, "value": value, "reason": "a customer line of business app"})
		return validate(t, c, "exclusion_add", string(b))
	}
	remove := func(kind, value string) string {
		b, _ := json.Marshal(map[string]string{"kind": kind, "value": value})
		return validate(t, c, "exclusion_remove", string(b))
	}
	accepted := [][2]string{
		{"path", `D:\LineOfBusiness`}, {"path", `\\fileserver\share\folder`}, {"process", `D:\Apps\lob\lob.exe`}, {"extension", "xyz"},
		{"extension", ".dat"}, {"asr_only", `D:\Apps\lob`},
	}
	for _, v := range accepted {
		if got := add(v[0], v[1]); got != "" {
			t.Errorf("add %v refused: %s", v, got)
		}
	}
	tooBroadValues := [][2]string{
		{"path", `C:\`}, {"path", `D:`}, {"path", `C:\*`}, {"path", `C:\Users\*\Documents`}, {"path", `C:\Windows`}, {"path", `C:\Windows\System32`},
		{"path", `C:\Program Files`}, {"path", `C:\Users\someone`}, {"path", `\\server\share`}, {"path", `C:\Windows\`},
		{"process", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`}, {"process", `C:\Windows\System32\cmd.exe`},
		{"process", `C:\Windows\System32\mshta.exe`}, {"process", `C:\Windows\System32\msiexec.exe`},
		{"extension", "exe"}, {"extension", ".PS1"}, {"extension", "dll"}, {"extension", "py"}, {"extension", "lnk"},
	}
	for _, v := range tooBroadValues {
		if got := add(v[0], v[1]); got != "too_broad:params.value" {
			t.Errorf("add %v: got %q, want too_broad", v, got)
		}
	}
	for _, v := range [][2]string{{"process", "powershell.exe"}, {"extension", "a b"}, {"extension", "waytoolongextension"}, {"extension", `a;b`}} {
		if got := add(v[0], v[1]); got == "" {
			t.Errorf("add %v was accepted", v)
		}
	}
	// Remove: ours is protected; anything else is accepted.
	if got := remove("path", `C:\Program Files\EasyRMM\Agent`); got != "protected_exclusion" {
		t.Errorf("removing ours: %q", got)
	}
	if got := remove("asr_only", `c:\programdata\easyrmm\agent\`); got != "protected_exclusion" {
		t.Errorf("removing our ASR exclusion: %q", got)
	}
	if got := remove("process", `C:\Program Files\EasyRMM\MeshAgent\meshagent.exe`); got != "protected_exclusion" {
		t.Errorf("removing our process exclusion: %q", got)
	}
	if got := remove("path", `C:\Program Files\EasyRMM`); got != "" {
		t.Errorf("removing a parent of ours is allowed: %q", got)
	}
	if got := remove("path", `D:\LineOfBusiness`); got != "" {
		t.Errorf("removing an administrator's exclusion: %q", got)
	}
	if got := remove("nope", `D:\x`); got == "" {
		t.Error("an unknown kind was accepted")
	}
}

func TestScanPathAndQuarantineName(t *testing.T) {
	c := catalog(t)
	for _, p := range []string{`D:\Data`, `C:\Users\Public\Downloads\file.zip`, `\\server\share\folder`} {
		b, _ := json.Marshal(map[string]string{"path": p})
		if got := validate(t, c, "scan_custom", string(b)); got != "" {
			t.Errorf("scan %q refused: %s", p, got)
		}
	}
	for _, p := range []string{`C:\..\Windows`, `\\.\PhysicalDrive0`, `\\?\C:\x`, `C:\a*b`, `C:\a;b`, `C:\a"b`, `C:\a$b`, "C:\\a`b", `relative\path`, `C:\a|b`, `C:\a&b`, `C:\a%b`, `C:\a^b`, `C:\a'b`, `/etc/passwd`, `C:` + strings.Repeat(`\a`, 140)} {
		b, _ := json.Marshal(map[string]string{"path": p})
		if got := validate(t, c, "scan_custom", string(b)); got == "" {
			t.Errorf("scan %q was accepted", p)
		}
	}
	for _, n := range []string{"Virus:DOS/EICAR_Test_File", "Trojan:Win32/Wacatac.B!ml", "HackTool:Win32/Mimikatz.D"} {
		if got := validate(t, c, "quarantine_restore", `{"name":"`+n+`"}`); got != "" {
			t.Errorf("quarantine name %q refused: %s", n, got)
		}
	}
	for _, n := range []string{"-All", "--x", "a;b", `a"b`, "a|b", "a&b", "$(x)", "a`b", "a\nb"} {
		b, _ := json.Marshal(map[string]string{"name": n})
		if got := validate(t, c, "quarantine_restore", string(b)); got == "" {
			t.Errorf("quarantine name %q was accepted", n)
		}
	}
}

// What the audit records of an exclusion: the kind and the reason as they
// are, the value as its length and SHA-256 only.
func TestExclusionAuditHoldsNoValue(t *testing.T) {
	a, _ := catalog(t).Lookup("defender.exclusion_add")
	chk, err := a.Validate(json.RawMessage(`{"kind":"path","value":"D:\\Customer Acme\\Files","reason":"line of business"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(chk.Audit)
	if strings.Contains(string(b), "Acme") || !strings.Contains(string(b), "sha256") {
		t.Errorf("the audit holds the value: %s", b)
	}
	if chk.Subject != `D:\Customer Acme\Files` || a.ConfirmText(chk.Subject) != `defender.exclusion_add:D:\Customer Acme\Files` {
		t.Errorf("the confirmation subject is %q", chk.Subject)
	}
}

// ASR results are joined to the catalogue's names; an unknown GUID is
// "unrecognised".
func TestASRReadNames(t *testing.T) {
	a, _ := catalog(t).Lookup("defender.asr_read")
	out, err := a.Decode(json.RawMessage(`{"supported":true,"rules":[{"id":"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2","mode":"Enabled","managedBy":null},{"id":"00000000-0000-0000-0000-000000000000","mode":"AuditMode","managedBy":"group_policy"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var r ASRRead
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Rules) != 2 || !r.Rules[0].Known || r.Rules[0].Name == "" || r.Rules[1].Known || r.Rules[1].Name != "" {
		t.Errorf("rules: %+v", r.Rules)
	}
	if _, err := a.Decode(json.RawMessage(`{"supported":true,"rules":[],"extra":1}`)); err == nil {
		t.Error("an unknown field was accepted")
	}
}

// Result decoders: good, wrong shape.
func TestResultDecoders(t *testing.T) {
	c := catalog(t)
	good := map[string]string{
		"preferences_read":   `{"fields":[{"name":"MAPSReporting","group":"cloud","value":2,"supported":true,"managedBy":null}],"tamperProtected":true}`,
		"cfa_read":           `{"supported":true,"mode":"Enabled","managedBy":null,"protectedFolders":[{"path":"C:\\x","ours":false}],"allowedApplications":[]}`,
		"exclusions_read":    `{"path":[{"value":"D:\\x","ours":false,"managedBy":null}],"process":[],"extension":[],"asrOnly":[],"unavailable":[],"localMergeDisabled":false,"tamperProtected":false}`,
		"threats_read":       `{"threats":[{"id":2147519003,"name":"Virus:DOS/EICAR_Test_File","severity":5,"category":8,"active":true,"executed":false,"detectedAt":"2026-11-26T10:00:00Z","changedAt":null}]}`,
		"quarantine_read":    `{"items":[{"name":"Virus:DOS/EICAR_Test_File","path":"C:\\x\\eicar.txt"}]}`,
		"scan_quick":         `{"scanType":"quick","finishedAt":"2026-11-26T10:00:00Z"}`,
		"signatures_update":  `{"before":"1.1","after":"1.2","updated":true}`,
		"threats_remove":     `{"activeBefore":1,"activeAfter":0}`,
		"quarantine_restore": `{"name":"x","restored":true}`,
		"exclusion_add":      `{"applied":false,"reason":"blocked","before":false,"after":false}`,
		"preferences_set":    `{"applied":true,"reason":"","before":"1","after":"2"}`,
		"scan_cancel":        `{"cancelled":true}`,
	}
	for n, data := range good {
		a, _ := c.Lookup("defender." + n)
		if _, err := a.Decode(json.RawMessage(data)); err != nil {
			t.Errorf("%s: good data refused: %v", n, err)
		}
		if _, err := a.Decode(json.RawMessage(`{"surprise":1}`)); err == nil {
			t.Errorf("%s: unknown data accepted", n)
		}
		line := winmod.ResultPrefix + `{"ok":true,"version":1,"data":` + data + `,"error":null}`
		if _, err := a.ParseResult("noise\n" + line + "\n"); err != nil {
			t.Errorf("%s: a result line is refused: %v", n, err)
		}
		if _, err := a.ParseResult(strings.Replace(line, `"version":1`, `"version":2`, 1)); err == nil {
			t.Errorf("%s: a wrong version was accepted", n)
		}
	}
	a, _ := c.Lookup("defender.exclusion_remove")
	res, err := a.ParseResult(winmod.ResultPrefix + `{"ok":false,"version":1,"data":null,"error":{"code":"protected_exclusion","message":"no"}}`)
	if err != nil || res.OK || res.Error.Code != "protected_exclusion" {
		t.Errorf("a refusal from the script: %v %+v", err, res)
	}
}
