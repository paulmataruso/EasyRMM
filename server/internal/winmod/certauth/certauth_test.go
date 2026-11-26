package certauth

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
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

func TestCatalogLint(t *testing.T) {
	c := catalog(t)
	if got, want := len(c.Actions()), len(scriptFiles(t)); got != want {
		t.Errorf("%d actions for %d scripts", got, want)
	}
	tier3 := []string{"request_approve", "certificate_revoke", "template_publish_risky"}
	tier2 := []string{"request_deny", "certificate_unrevoke", "template_publish", "template_unpublish"}
	for _, a := range c.Actions() {
		if agentproto.HashScript(a.Script) != a.ScriptSHA256 {
			t.Errorf("%s: pin does not match", a.Name)
		}
		if a.Changes != (a.Permission == rbac.PermCAManage) || (!a.Changes && a.Permission != rbac.PermCAView) {
			t.Errorf("%s: permission %s", a.Name, a.Permission)
		}
		if (a.Destructive || a.Confirm) && (!a.SubjectIsDeviceName || a.Subject != "device") {
			t.Errorf("%s: confirmed on a name the server does not compare", a.Name)
		}
		// Whatever names requesters or subjects is sensitive.
		for _, n := range []string{"requests_pending", "requests_list", "request_get", "activity"} {
			if a.Name == "certificate_authority."+n && (!a.Sensitive || a.SensitivePermission != rbac.PermCAView || a.Keep > 15*60*1e9) {
				t.Errorf("%s: must be sensitive and short-lived", a.Name)
			}
		}
	}
	for _, n := range tier3 {
		if a, ok := c.Lookup("certificate_authority." + n); !ok || !a.Destructive || !a.NeedsStepUp() {
			t.Errorf("%s: tier 3 needs a confirmation and a step-up", n)
		}
	}
	for _, n := range tier2 {
		if a, ok := c.Lookup("certificate_authority." + n); !ok || !a.Confirm || a.NeedsStepUp() {
			t.Errorf("%s: tier 2 is confirmed, without a step-up", n)
		}
	}
	if a, _ := c.Lookup("certificate_authority.crl_publish"); a.Confirm || a.Destructive || !a.Changes {
		t.Error("crl_publish is tier 1")
	}
}

// The certutil verbs the module may use (ADR-0076 section 3). A script that names
// another fails here, before any review.
var allowedVerbs = map[string]bool{"-view": true, "-resubmit": true, "-deny": true, "-revoke": true, "-CRL": true, "-dump": true}

var callRe = regexp.MustCompile(`Invoke-Certutil\s+@\(\s*'(-[A-Za-z]+)'`)

func TestCertutilVerbAllowlist(t *testing.T) {
	for _, a := range catalog(t).Actions() {
		for _, m := range callRe.FindAllStringSubmatch(a.Script, -1) {
			if !allowedVerbs[m[1]] {
				t.Errorf("%s: certutil verb %s is not on the list", a.Name, m[1])
			}
		}
		// certutil is reached only through Invoke-Certutil, which uses the call
		// operator and an argument array.
		for _, line := range strings.Split(a.Script, "\n") {
			low := strings.ToLower(line)
			if !strings.Contains(low, "certutil") || strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			if !strings.Contains(line, "Invoke-Certutil") && !strings.Contains(line, "& certutil.exe @Arguments") {
				t.Errorf("%s: certutil is called another way: %s", a.Name, line)
			}
		}
	}
	// Invoke-Certutil's own argument arrays are all literals except the typed
	// values the actions put in: the lint above covers the verbs.
	if allowedVerbs["-backupKey"] || allowedVerbs["-getkey"] || allowedVerbs["-exportPFX"] {
		t.Error("a key verb is allowed")
	}
}

func TestNoKeyOperations(t *testing.T) {
	banned := []string{"backupKey", "-backup", "-restore", "recoverkey", "-getkey", "repairstore", "exportPFX", "deleteHelper",
		"Export-PfxCertificate", "Export-Certificate", "Install-AdcsCertificationAuthority", "Uninstall-AdcsCertificationAuthority",
		"Add-CACrlDistributionPoint", "Remove-CACrlDistributionPoint", "Add-CAAuthorityInformationAccess", "Remove-CAAuthorityInformationAccess",
		"New-CATemplate", "Set-CATemplate", "PrivateKey", "-setreg", "-SetCAAcl"}
	for _, a := range catalog(t).Actions() {
		for _, b := range banned {
			if strings.Contains(a.Script, b) {
				t.Errorf("%s: names %s", a.Name, b)
			}
		}
	}
}

// No free string reaches a -view restriction: every restriction comes from the
// three library functions, which take an [int], a validated serial, or a name
// looked up in a table.
func TestRestrictionsComeFromTypedHelpers(t *testing.T) {
	for _, a := range catalog(t).Actions() {
		for _, line := range strings.Split(a.Script, "\n") {
			if strings.Contains(line, "'-restrict'") && !strings.Contains(line, "Invoke-Certutil @('-view', '-restrict', $Restrict,") {
				t.Errorf("%s: a restriction built elsewhere: %s", a.Name, line)
			}
		}
	}
	lib := library("_common.ps1")
	for _, fn := range []string{"Get-IdRestriction([int]$Id)", "Get-SerialRestriction([string]$Serial)", "Get-DispositionRestriction([string]$Name, [int]$From)"} {
		if !strings.Contains(lib, fn) {
			t.Errorf("the library lacks %s", fn)
		}
	}
	if !strings.Contains(lib, "^[0-9A-Fa-f]{2,40}$") {
		t.Error("the serial is not checked as hexadecimal")
	}
}

func refused(t *testing.T, c *winmod.Catalog, action, params string) string {
	t.Helper()
	a, _ := c.Lookup("certificate_authority." + action)
	_, err := a.Validate(json.RawMessage(params))
	if err == nil {
		return ""
	}
	if e, ok := apperr.As(err); ok {
		return e.Code
	}
	return "other"
}

func TestParams(t *testing.T) {
	c := catalog(t)
	good := map[string]string{
		"request_approve":      `{"device":"CA1","id":12}`,
		"certificate_revoke":   `{"device":"CA1","serial":"6100000005ab","reason":"key_compromise","note":"laptop lost"}`,
		"certificate_unrevoke": `{"device":"CA1","serial":"6100000005AB"}`,
		"request_get":          `{"id":3}`,
		"requests_list":        `{"disposition":"revoked","fromId":10}`,
		"crl_publish":          `{"kind":"delta"}`,
		"template_publish":     `{"device":"CA1","name":"Web Server 2"}`,
	}
	for a, p := range good {
		if got := refused(t, c, a, p); got != "" {
			t.Errorf("%s %s: %s", a, p, got)
		}
	}
	bad := map[string][]string{
		"certificate_revoke": {`{"device":"CA1","serial":"12; 34","reason":"superseded"}`, `{"device":"CA1","serial":"xyz","reason":"superseded"}`,
			`{"device":"CA1","serial":"6100","reason":"because"}`, `{"device":"CA1","serial":"6100"}`, `{"device":"CA1","serial":"6100","reason":"removeFromCRL"}`},
		"request_approve":  {`{"device":"CA1","id":"1; calc"}`, `{"device":"CA1","id":0}`, `{"device":"CA1","id":-4}`, `{"device":"CA1","id":1.5}`},
		"request_get":      {`{}`, `{"id":1,"serial":"61"}`, `{"serial":"zz"}`},
		"requests_list":    {`{"disposition":"pending"}`, `{"disposition":"issued\" /f"}`, `{"disposition":"issued","fromId":-1}`},
		"template_publish": {`{"device":"CA1","name":"a;b"}`, `{"device":"CA1","name":"$(x)"}`, `{"device":"CA1","name":"a\"b"}`},
		"crl_publish":      {`{"kind":"full"}`},
	}
	for a, ps := range bad {
		for _, p := range ps {
			if refused(t, c, a, p) == "" {
				t.Errorf("%s %s was accepted", a, p)
			}
		}
	}
}

func TestResultsDecode(t *testing.T) {
	c := catalog(t)
	a, _ := c.Lookup("certificate_authority.status")
	line := winmod.ResultPrefix + `{"ok":true,"version":1,"data":{"caName":"Corp CA","caType":"enterprise_root","enterprise":true,"serviceState":"running","certificate":{"subject":"CN=Corp CA","thumbprint":"AB","notAfter":"2031-01-01T00:00:00Z","daysLeft":1500,"signatureAlgorithm":"sha256RSA","keyLength":4096},"crl":{"baseThisUpdate":"2026-11-01T00:00:00Z","baseNextUpdate":"2026-11-09T00:00:00Z","hoursToBaseExpiry":60,"deltaNextUpdate":null},"counts":{"pending":1,"issued":10,"revoked":2,"failed":0}},"error":null}`
	res, err := a.ParseResult(line)
	if err != nil || !res.OK {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := a.ParseResult(strings.Replace(line, `"caName"`, `"extra":1,"caName"`, 1)); err == nil {
		t.Error("an unknown field was accepted")
	}
}

func i(n int) *int { return &n }

func TestAlerts(t *testing.T) {
	m := AlertKinds()
	if len(m.Kinds) != 4 || len(m.Defaults) != 5 {
		t.Fatalf("%d kinds, %d defaults", len(m.Kinds), len(m.Defaults))
	}
	if err := monitoring.RegisterModuleAlerts(m); err != nil {
		t.Fatal(err)
	}
	eval := map[string]func(json.RawMessage, *int) (monitoring.Verdict, error){}
	for _, k := range m.Kinds {
		eval[k.Name] = k.Eval
	}
	st := `{"caName":"Corp CA","caType":"enterprise_root","enterprise":true,"serviceState":"running","certificate":{"subject":"CN=x","thumbprint":"AB","notAfter":"2027-01-01T00:00:00Z","daysLeft":10,"signatureAlgorithm":"sha256RSA","keyLength":null},"crl":{"baseThisUpdate":null,"baseNextUpdate":null,"hoursToBaseExpiry":3,"deltaNextUpdate":null},"counts":null}`
	for name, tc := range map[string]struct {
		kind  string
		th    *int
		want  bool
		isErr bool
	}{
		"90 days":      {KindCertificateExpiring, i(90), true, false},
		"5 days":       {KindCertificateExpiring, i(5), false, false},
		"crl 4 hours":  {KindCRLExpiring, i(4), true, false},
		"crl 2 hours":  {KindCRLExpiring, i(2), false, false},
		"no threshold": {KindCRLExpiring, nil, false, true},
	} {
		v, err := eval[tc.kind](json.RawMessage(st), tc.th)
		if (err != nil) != tc.isErr || v.Holds != tc.want {
			t.Errorf("%s: %+v %v", name, v, err)
		}
		if strings.Contains(v.Detail, "CN=") {
			t.Errorf("%s: the alert names a subject: %s", name, v.Detail)
		}
	}
	if v, _ := eval[KindCertificateExpiring](json.RawMessage(`{"caName":"x","caType":"","enterprise":false,"serviceState":"running","certificate":null,"crl":null,"counts":null}`), i(90)); !v.NotApplicable {
		t.Error("no certificate is not applicable")
	}
	if v, _ := eval[KindServiceStopped](json.RawMessage(strings.Replace(st, `"running"`, `"stopped"`, 1)), nil); !v.Holds {
		t.Error("a stopped service does not alert")
	}
	if v, err := eval[KindFindingsPresent](json.RawMessage(`{"caName":"Corp CA","findings":[{"id":"ESC6:Corp CA","class":"ESC6","subject":"Corp CA","evidence":"x"}],"notes":[]}`), nil); err != nil || !v.Holds || v.Value != 1 {
		t.Errorf("findings: %+v %v", v, err)
	}
}

// harness runs the library's pure checks in PowerShell (pwsh or Windows
// PowerShell), where one is installed: the findings logic needs no CA.
const harness = `
$version = 1
. $env:LIBPATH
function C($f) { return (@($f | ForEach-Object { $_.class }) -join ',') }
$low = 'S-1-5-21-1-2-3-513'
$r = [ordered]@{}
$r.lowEveryone = (Test-LowPriv 'S-1-1-0'); $r.lowUsers = (Test-LowPriv 'S-1-5-32-545'); $r.lowDomainUsers = (Test-LowPriv $low)
$r.lowDomainComputers = (Test-LowPriv 'S-1-5-21-1-2-3-515'); $r.lowAdmins = (Test-LowPriv 'S-1-5-32-544'); $r.lowDA = (Test-LowPriv 'S-1-5-21-1-2-3-512')
$esc1 = [pscustomobject]@{ name = 'T1'; nameFlag = 1; enrollFlag = 0; raSignatures = 0; ekus = @('1.3.6.1.5.5.7.3.2'); enrollSids = @($low); writeSids = @() }
$r.esc1 = C (Get-TemplateFindings $esc1)
$r.esc1Approval = C (Get-TemplateFindings ([pscustomobject]@{ name = 'T'; nameFlag = 1; enrollFlag = 2; raSignatures = 0; ekus = @('1.3.6.1.5.5.7.3.2'); enrollSids = @($low); writeSids = @() }))
$r.esc1Admins = C (Get-TemplateFindings ([pscustomobject]@{ name = 'T'; nameFlag = 1; enrollFlag = 0; raSignatures = 0; ekus = @('1.3.6.1.5.5.7.3.2'); enrollSids = @('S-1-5-21-1-2-3-512'); writeSids = @() }))
$r.noSubject = C (Get-TemplateFindings ([pscustomobject]@{ name = 'T'; nameFlag = 0; enrollFlag = 0; raSignatures = 0; ekus = @('1.3.6.1.5.5.7.3.1'); enrollSids = @($low); writeSids = @() }))
$r.esc2 = C (Get-TemplateFindings ([pscustomobject]@{ name = 'T'; nameFlag = 0; enrollFlag = 0; raSignatures = 0; ekus = @(); enrollSids = @($low); writeSids = @() }))
$r.esc3 = C (Get-TemplateFindings ([pscustomobject]@{ name = 'T'; nameFlag = 0; enrollFlag = 0; raSignatures = 0; ekus = @('1.3.6.1.4.1.311.20.2.1'); enrollSids = @('S-1-5-11'); writeSids = @() }))
$r.esc4 = C (Get-TemplateFindings ([pscustomobject]@{ name = 'T'; nameFlag = 0; enrollFlag = 0; raSignatures = 0; ekus = @('1.3.6.1.5.5.7.3.1'); enrollSids = @(); writeSids = @($low) }))
$r.risky = (Get-TemplateRisk $esc1).risky
$r.notRisky = (Get-TemplateRisk ([pscustomobject]@{ name = 'T'; nameFlag = 0; enrollFlag = 0; raSignatures = 0; ekus = @('1.3.6.1.5.5.7.3.2'); enrollSids = @($low); writeSids = @() })).risky
$r.esc6 = C (Get-EditFlagsFindings 0x40000 'CA')
$r.esc6off = C (Get-EditFlagsFindings 0x10000 'CA')
$r.esc7 = C (Get-CaAclFindings @([pscustomobject]@{ sid = 'S-1-5-11'; mask = 2; allow = $true }) 'CA')
$r.esc7enroll = C (Get-CaAclFindings @([pscustomobject]@{ sid = 'S-1-5-11'; mask = 0x100; allow = $true }) 'CA')
$r.esc7deny = C (Get-CaAclFindings @([pscustomobject]@{ sid = 'S-1-5-11'; mask = 2; allow = $false }) 'CA')
$r.restrictId = (Get-IdRestriction 42)
$r.restrictDisp = (Get-DispositionRestriction 'pending' 7)
$r.restrictSerial = (Get-SerialRestriction '61AB')
$r.reason = (Get-RevocationReasonCode 'certificate_hold')
$r.enrollRight = (Get-RightsIsEnroll 0x100 '0e10c968-78fb-11d2-90d4-00c04f79dc55')
$r.otherExtended = (Get-RightsIsEnroll 0x100 'a05b8cc2-17bc-4802-a710-e7c15ab866a2')
$r.writeProp = (Get-RightsIsWrite 0x20); $r.readOnly = (Get-RightsIsWrite 0x1)
ConvertTo-Json -InputObject $r -Compress
`

func TestFindingsLogicInPowerShell(t *testing.T) {
	exe := ""
	for _, n := range []string{"pwsh", "powershell"} {
		if p, err := exec.LookPath(n); err == nil {
			exe = p
			break
		}
	}
	if exe == "" {
		t.Skip("no PowerShell on this machine; the Windows runner and the Docker run cover it")
	}
	dir := t.TempDir()
	lib := filepath.Join(dir, "lib.ps1")
	if err := os.WriteFile(lib, []byte(library("_common.ps1")), 0o600); err != nil {
		t.Fatal(err)
	}
	h := filepath.Join(dir, "h.ps1")
	if err := os.WriteFile(h, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-NoProfile", "-NonInteractive", "-File", h) //nolint:gosec // G204: a PowerShell found on PATH runs a script this test wrote
	cmd.Env = append(os.Environ(), "LIBPATH="+lib)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var got map[string]any
	line := out[strings.LastIndex(strings.TrimSpace(string(out)), "\n")+1:]
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := map[string]any{
		"lowEveryone": true, "lowUsers": true, "lowDomainUsers": true, "lowDomainComputers": true, "lowAdmins": false, "lowDA": false,
		"esc1": "ESC1", "esc1Approval": "", "esc1Admins": "", "noSubject": "", "esc2": "ESC2", "esc3": "ESC3", "esc4": "ESC4",
		"risky": true, "notRisky": false, "esc6": "ESC6", "esc6off": "", "esc7": "ESC7", "esc7enroll": "", "esc7deny": "",
		"restrictId": "RequestID=42", "restrictDisp": "Disposition=9,RequestID>=7", "restrictSerial": "SerialNumber=61AB", "reason": "6",
		"enrollRight": true, "otherExtended": false, "writeProp": true, "readOnly": false,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %v, want %v", k, got[k], w)
		}
	}
}
