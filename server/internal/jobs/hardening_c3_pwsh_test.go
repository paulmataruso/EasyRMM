package jobs

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The evaluation of ADR-0078's C3 checks (user rights, the time source,
// application control, Office), from real-shaped output of the tools the
// script reads (secedit /export, w32tm /query /status), with the script's
// own functions run by PowerShell 7 where the test finds pwsh. The readers
// that need Windows (the registry, services, WMI) are replaced by what a
// scenario says; the Windows tests (hardening_c3_windows_test.go) run the
// real ones.

// c3Scenario is what the stand-in readers answer.
type c3Scenario struct {
	Secedit     string `json:"secedit"`
	SeceditExit int    `json:"seceditExit"`
	W32tm       string `json:"w32tm"`
	W32tmExit   int    `json:"w32tmExit"`
	// Registry maps "path|name" to its data; a missing key is absent.
	Registry map[string]string `json:"registry"`
	// Services maps a name to its status and start type; a missing one is
	// not installed.
	Services map[string][2]string `json:"services"`
	// CodeIntegrity is Win32_DeviceGuard's enforcement status; -1 where
	// Device Guard could not be read.
	CodeIntegrity int `json:"codeIntegrity"`
}

type c3Result struct {
	State, Value, Want, Note string
}

const c3Harness = `$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "the script does not parse: $($errors[0].Message)" }
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($f.Extent.Text))
}
$sc = Get-Content -Raw -LiteralPath $args[1] | ConvertFrom-Json
$env:SystemRoot = '/sys'
$ErWork = $args[2]
$ErCache = @{}
function Invoke-ErProgram {
    param([string]$Path, [string[]]$Arguments, [int]$Seconds = 60)
    if ($Path -like '*secedit*') {
        if ($sc.seceditExit -eq 0) { Set-Content -LiteralPath $Arguments[2] -Value $sc.secedit }
        return @{ ExitCode = $sc.seceditExit; Output = ''; Error = '' }
    }
    return @{ ExitCode = $sc.w32tmExit; Output = $sc.w32tm; Error = '' }
}
function Get-ErRegistryValue {
    param([string]$Path, [string]$Name)
    $k = "$Path|$Name"
    if ($sc.registry.PSObject.Properties.Name -contains $k) { return @{ Exists = $true; Data = $sc.registry.$k; Kind = 'DWord'; Error = '' } }
    return @{ Exists = $false; Data = $null; Kind = ''; Error = '' }
}
function Get-ErServiceState {
    param([string]$Name)
    if ($sc.services.PSObject.Properties.Name -contains $Name) {
        $s = @($sc.services.$Name)
        return @{ Installed = $true; Read = $true; Status = $s[0]; StartType = $s[1] }
    }
    return @{ Installed = $false; Read = $true }
}
function Get-ErDeviceGuard {
    if ($sc.codeIntegrity -lt 0) { return @{ State = $null; Error = 'no Device Guard' } }
    return @{ State = [pscustomobject]@{ CodeIntegrityPolicyEnforcementStatus = $sc.codeIntegrity }; Error = '' }
}
function Def { param($Json) return (ConvertFrom-Json $Json) }
`

// c3Run runs body (PowerShell, after the harness) for a scenario and
// decodes the JSON array it prints last.
func c3Run(t *testing.T, sc c3Scenario, body string) []c3Result {
	t.Helper()
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell 7 (pwsh) is not installed")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "script.ps1")
	harness := filepath.Join(dir, "harness.ps1")
	scenario := filepath.Join(dir, "scenario.json")
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if sc.Registry == nil {
		sc.Registry = map[string]string{}
	}
	if sc.Services == nil {
		sc.Services = map[string][2]string{}
	}
	b, _ := json.Marshal(sc)
	for f, c := range map[string]string{script: windowsHardeningScript, harness: c3Harness + body, scenario: string(b)} {
		if err := os.WriteFile(f, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", harness, script, scenario, work).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var got []c3Result
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return got
}

// A secedit user rights export as Windows writes it (Server 2025, a member
// server), but for the rights these checks read.
const c3Secedit = `[Unicode]
Unicode=yes
[Privilege Rights]
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeTcbPrivilege =
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeDebugPrivilege = *S-1-5-32-544
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeSecurityPrivilege = *S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeLoadDriverPrivilege = *S-1-5-32-544,*S-1-5-32-550
SeTakeOwnershipPrivilege = *S-1-5-32-544,*S-1-5-21-1-2-3-1105
[Version]
signature="$CHICAGO$"
Revision=1
`

func TestC3UserRights(t *testing.T) {
	right := func(id, key, allowed string) string {
		return `(Test-ErUserRight (Def '{"id":"` + id + `","key":"` + key + `","data":` + allowed + `}'))`
	}
	body := `ConvertTo-Json -Compress @(
` + strings.Join([]string{
		right("rights-debug", "SeDebugPrivilege", `["S-1-5-32-544"]`),
		right("rights-remote-logon", "SeRemoteInteractiveLogonRight", `["S-1-5-32-544","S-1-5-32-555"]`),
		right("rights-load-driver", "SeLoadDriverPrivilege", `["S-1-5-32-544"]`),
		right("rights-take-ownership", "SeTakeOwnershipPrivilege", `["S-1-5-32-544"]`),
		right("rights-act-as-os", "SeTcbPrivilege", `[]`),
		right("rights-absent", "SeCreateTokenPrivilege", `[]`),
		right("rights-audit-generate", "SeAuditPrivilege", `["S-1-5-19","S-1-5-20"]`),
	}, ",\n") + `)`
	got := c3Run(t, c3Scenario{Secedit: c3Secedit}, body)
	want := []struct{ state, value string }{
		{"in_place", "only those"}, {"in_place", "only those"}, {"not_in_place", "1 other account(s)"},
		{"not_in_place", "1 other account(s)"}, {"in_place", "no one"}, {"in_place", "no one"}, {"in_place", "only those"},
	}
	if len(got) != len(want) {
		t.Fatalf("%d results: %+v", len(got), got)
	}
	for i, w := range want {
		if got[i].State != w.state || got[i].Value != w.value {
			t.Errorf("right %d: %+v, want %s (%s)", i, got[i], w.state, w.value)
		}
	}
	// What is wanted is told in words, and no account is named in a value.
	if got[1].Want != "only Administrators, Remote Desktop Users" || got[4].Want != "no one" {
		t.Errorf("wants %q and %q", got[1].Want, got[4].Want)
	}

	// Where secedit fails, the right is unknown, never in place.
	failed := c3Run(t, c3Scenario{SeceditExit: 1}, "ConvertTo-Json -Compress @"+right("rights-debug", "SeDebugPrivilege", `["S-1-5-32-544"]`))
	if len(failed) != 1 || failed[0].State != "unknown" {
		t.Errorf("a failed secedit: %+v", failed)
	}
}

func TestC3TimeSync(t *testing.T) {
	status := func(sync string) string {
		return "Leap Indicator: 0(no warning)\nStratum: 3 (secondary reference - syncd by (S)NTP)\nPrecision: -23 (119.209ns per tick)\n" +
			"Root Delay: 0.0312500s\nRoot Dispersion: 0.0501709s\nReferenceId: 0xC0A80001 (source IP:  192.0.2.1)\n" +
			"Last Successful Sync Time: " + sync + "\nSource: time.example.test\nPoll Interval: 10 (1024s)\n"
	}
	stamp := func(ago time.Duration) string { return time.Now().Add(-ago).Format("01/02/2006 15:04:05") }
	body := `ConvertTo-Json -Compress @(Test-ErTimeSync (Def '{"id":"time-synchronized","data":24}'))`
	running := map[string][2]string{"W32Time": {"Running", "Automatic"}}
	stopped := map[string][2]string{"W32Time": {"Stopped", "Manual"}}
	for _, tc := range []struct {
		name  string
		sc    c3Scenario
		state string
	}{
		{"two hours ago", c3Scenario{W32tm: status(stamp(2 * time.Hour))}, "in_place"},
		{"two days ago", c3Scenario{W32tm: status(stamp(48 * time.Hour))}, "not_in_place"},
		{"never", c3Scenario{W32tm: status("unspecified")}, "not_in_place"},
		{"the service stopped", c3Scenario{W32tmExit: 1, W32tm: "The following error occurred: The service has not been started. (0x80070426)", Services: stopped}, "not_in_place"},
		{"w32tm failed, the service running", c3Scenario{W32tmExit: 1, Services: running}, "unknown"},
	} {
		got := c3Run(t, tc.sc, body)
		if len(got) != 1 || got[0].State != tc.state {
			t.Errorf("%s: %+v, want %s", tc.name, got, tc.state)
		}
	}
	svc := c3Run(t, c3Scenario{Services: running}, `ConvertTo-Json -Compress @(Test-ErTimeService (Def '{"id":"time-service-running"}'))`)
	if svc[0].State != "in_place" {
		t.Errorf("a running time service: %+v", svc)
	}
	svc = c3Run(t, c3Scenario{Services: map[string][2]string{"W32Time": {"Running", "Disabled"}}}, `ConvertTo-Json -Compress @(Test-ErTimeService (Def '{"id":"time-service-running"}'))`)
	if svc[0].State != "not_in_place" {
		t.Errorf("a disabled time service: %+v", svc)
	}
}

func TestC3AppControl(t *testing.T) {
	const mode = `HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe|EnforcementMode`
	body := `ConvertTo-Json -Compress @(Test-ErAppControl (Def '{"id":"app-control-enforced"}'))`
	idRunning := map[string][2]string{"AppIDSvc": {"Running", "Automatic"}}
	idStopped := map[string][2]string{"AppIDSvc": {"Stopped", "Manual"}}
	for _, tc := range []struct {
		name         string
		sc           c3Scenario
		state, value string
	}{
		{"App Control enforced", c3Scenario{CodeIntegrity: 2}, "in_place", "App Control for Business enforced"},
		{"App Control in audit mode", c3Scenario{CodeIntegrity: 1}, "not_in_place", "audit mode"},
		{"AppLocker enforced", c3Scenario{CodeIntegrity: 0, Registry: map[string]string{mode: "1"}, Services: idRunning}, "in_place", "AppLocker enforced"},
		{"AppLocker enforced, its service stopped", c3Scenario{CodeIntegrity: 0, Registry: map[string]string{mode: "1"}, Services: idStopped}, "not_in_place", "AppLocker rules set, its service is not running"},
		{"AppLocker in audit mode", c3Scenario{CodeIntegrity: 0, Registry: map[string]string{mode: "0"}, Services: idRunning}, "not_in_place", "audit mode"},
		{"no policy", c3Scenario{CodeIntegrity: 0}, "not_in_place", "no policy"},
		{"nothing could be read", c3Scenario{CodeIntegrity: -1}, "unknown", ""},
	} {
		got := c3Run(t, tc.sc, body)
		if len(got) != 1 || got[0].State != tc.state || got[0].Value != tc.value {
			t.Errorf("%s: %+v, want %s (%s)", tc.name, got, tc.state, tc.value)
		}
	}
}

func TestC3OfficeMacros(t *testing.T) {
	const (
		word  = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\WINWORD.EXE|`
		excel = `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\EXCEL.EXE|`
		wordP = `HKLM\SOFTWARE\Policies\Microsoft\Office\16.0\word\security|BlockContentExecutionFromInternet`
		xlP   = `HKLM\SOFTWARE\Policies\Microsoft\Office\16.0\excel\security|BlockContentExecutionFromInternet`
	)
	body := `ConvertTo-Json -Compress @(Test-ErOfficeMacros (Def '{"id":"office-internet-macros"}'))`
	for _, tc := range []struct {
		name         string
		reg          map[string]string
		state, value string
	}{
		{"no Office", nil, "not_applicable", ""},
		{"Word without a policy", map[string]string{word: "x"}, "not_in_place", "1 of 1 applications allow them"},
		{"Word and Excel (32-bit), one blocked", map[string]string{word: "x", excel: "x", wordP: "1"}, "not_in_place", "1 of 2 applications allow them"},
		{"Word and Excel, both blocked", map[string]string{word: "x", excel: "x", wordP: "1", xlP: "1"}, "in_place", "0 of 2 applications allow them"},
		{"Excel set to 0", map[string]string{excel: "x", xlP: "0"}, "not_in_place", "1 of 1 applications allow them"},
	} {
		got := c3Run(t, c3Scenario{Registry: tc.reg}, body)
		if len(got) != 1 || got[0].State != tc.state || got[0].Value != tc.value {
			t.Errorf("%s: %+v, want %s (%s)", tc.name, got, tc.state, tc.value)
		}
	}
}

// The comparisons the registry settings of C3 use: a limit in a range, a
// time source from a list, and a text that must not be empty.
func TestC3Wants(t *testing.T) {
	body := `$idle = Def '{"want":"range","data":1,"max":900000}'
$src = Def '{"want":"in","data":["NTP","NT5DS"]}'
$text = Def '{"want":"nonempty"}'
ConvertTo-Json -Compress @(
  @{ State = "$(Test-ErWant $idle 600000)" }, @{ State = "$(Test-ErWant $idle 0)" }, @{ State = "$(Test-ErWant $idle 900001)" },
  @{ State = "$(Test-ErWant $src 'NTP')" }, @{ State = "$(Test-ErWant $src 'AllSync')" },
  @{ State = "$(Test-ErWant $text 'Authorized use only')" }, @{ State = "$(Test-ErWant $text '  ')" },
  @{ State = (Get-ErWantText $text) })`
	got := c3Run(t, c3Scenario{}, body)
	want := []string{"True", "False", "False", "True", "False", "True", "False", "a text"}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i, w := range want {
		if got[i].State != w {
			t.Errorf("comparison %d: %q, want %q", i, got[i].State, w)
		}
	}
}
