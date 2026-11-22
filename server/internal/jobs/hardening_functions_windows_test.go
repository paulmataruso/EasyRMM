//go:build windows

package jobs

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/internal/wintest"
)

// Functions of the script a Windows hardening job carries, one by one, with
// Windows PowerShell 5.1, on what is hard to make in a whole check: CI's job
// "Agent tests on Windows" runs these (OnWindows) as the runner's
// administrator.

// hardeningFunctions defines the script's top-level functions and its
// tables ($ErSettingsJson, $ErAuditTableJson), and nothing else, in a new
// Windows PowerShell, runs body, and decodes the JSON body prints last into
// v.
func hardeningFunctions(t *testing.T, body string, v any) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "script.ps1")
	harness := filepath.Join(dir, "harness.ps1")
	if err := os.WriteFile(script, []byte(windowsHardeningScript), 0o600); err != nil {
		t.Fatal(err)
	}
	prelude := `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "the script does not parse: $($errors[0].Message)" }
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($f.Extent.Text))
}
foreach ($s in $ast.EndBlock.Statements) {
    if ($s -is [System.Management.Automation.Language.AssignmentStatementAst] -and @('$ErSettingsJson', '$ErAuditTableJson') -contains $s.Left.Extent.Text) {
        . ([scriptblock]::Create($s.Extent.Text))
    }
}
`
	if err := os.WriteFile(harness, []byte(prelude+body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(windowsPowerShell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness, script)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil || stderr.Len() > 0 {
		t.Fatalf("%v: %s %s", err, out, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if err := json.Unmarshal([]byte(strings.TrimSpace(lines[len(lines)-1])), v); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}

func TestHardeningPublicAddressOnWindows(t *testing.T) {
	in := []string{"203.0.113.9", "::ffff:203.0.113.9", "::ffff:10.0.0.1", "10.1.2.3", "172.16.5.1", "172.31.255.255",
		"172.32.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "100.128.0.1", "0.0.0.0", "224.0.0.1",
		"::1", "::", "fe80::1%12", "fd00::1", "fc00::1", "fec0::1", "ff02::1", "2001:db8::1", "-", "", "abc", " 8.8.8.8 "}
	want := []string{"203.0.113.9", "203.0.113.9", "", "", "", "", "172.32.0.1", "", "", "", "", "100.128.0.1", "", "",
		"", "", "", "", "", "", "", "2001:db8::1", "", "", "", "8.8.8.8"}
	list, _ := json.Marshal(in)
	var got []string
	hardeningFunctions(t, `$in = '`+string(list)+`' | ConvertFrom-Json
ConvertTo-Json -Compress @($in | ForEach-Object { ConvertTo-ErPublicAddress $_ })`, &got)
	for i := range in {
		if i >= len(got) || got[i] != want[i] {
			t.Errorf("%q: %q, want %q", in[i], got, want[i])
		}
	}
}

// TestHardeningServiceStateOnWindows: a service that is not installed is
// told from one that cannot be read (here, one that Administrators may not
// query the configuration of).
func TestHardeningServiceStateOnWindows(t *testing.T) {
	const name = "EasyRMMTestService"
	sc := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("sc.exe", args...).CombinedOutput(); err != nil {
			t.Fatalf("sc %q: %v %s", args, err, out)
		}
	}
	type state struct {
		Installed, Read   bool
		Status, StartType string
	}
	var states map[string]state
	read := func() {
		t.Helper()
		hardeningFunctions(t, `ConvertTo-Json -Compress @{
    missing = Get-ErServiceState 'EasyRMMNoSuchService'
    planted = Get-ErServiceState '`+name+`'
}`, &states)
	}
	// A service that is never started: cmd.exe is no service.
	sc("create", name, "binPath=", filepath.Join(os.Getenv("SystemRoot"), `System32\cmd.exe`)+" /c exit", "start=", "disabled")
	t.Cleanup(func() { _ = exec.Command("sc.exe", "delete", name).Run() })
	read()
	if m := states["missing"]; m.Installed || !m.Read {
		t.Errorf("a service that is not installed: %+v", m)
	}
	if p := states["planted"]; !p.Installed || !p.Read || p.Status != "Stopped" || p.StartType != "Disabled" {
		t.Errorf("a stopped, disabled service: %+v", p)
	}
	// Administrators may not query its configuration (CC); they may still
	// delete it (SD).
	sc("sdset", name, "D:(D;;CC;;;BA)(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;LCSWLOCRRCSDWDWO;;;BA)")
	read()
	if p := states["planted"]; !p.Installed || p.Read {
		t.Errorf("a service that cannot be read: %+v", p)
	}
}

var logonUser = windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")

// failSignIns makes n failed network sign-ins as user, which Windows records
// as event 4625 with that user name.
func failSignIns(t *testing.T, user string, n int) {
	t.Helper()
	u := windows.StringToUTF16Ptr(user)
	dot := windows.StringToUTF16Ptr(".")
	password := windows.StringToUTF16Ptr("not-the-password")
	for range n {
		var token windows.Token
		// LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT
		ok, _, _ := logonUser.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(dot)), uintptr(unsafe.Pointer(password)),
			3, 0, uintptr(unsafe.Pointer(&token)))
		if ok != 0 {
			_ = token.Close()
			t.Fatalf("%q signed in", user)
		}
	}
}

// TestHardeningExposureOnWindows: an account with 10 or more failed
// sign-ins within 15 minutes is exposed, whatever the address; names are
// cleaned as the result carries them; and where the scan stops at its
// limit, since is the oldest event it read, not 7 days ago.
func TestHardeningExposureOnWindows(t *testing.T) {
	start := time.Now().Add(-time.Second)
	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 36)
	plain := "easyrmm-burst-" + suffix
	control := "easyrmm-c1-" + suffix + "\u0085x"
	failSignIns(t, plain, 12)
	failSignIns(t, control, 12)
	failSignIns(t, "   ", 2)
	failSignIns(t, "easyrmm-few-"+suffix, 3)

	type exposure struct {
		Read, Exposed               bool
		Accounts, Addresses, Bursts []string
		Since                       time.Time
	}
	var got struct{ Limited, Full exposure }
	// Windows writes the events a moment after the sign-ins fail; the last
	// user's are the last written.
	hardeningFunctions(t, `$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
    $last = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddMinutes(-10) } -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.Properties[5].Value -eq 'easyrmm-few-`+suffix+`' })
    if ($last.Count -ge 3) { break }
    Start-Sleep -Milliseconds 500
}
ConvertTo-Json -Compress -Depth 4 @{ Limited = Get-ErExposure -Limit 5; Full = Get-ErExposure }`, &got)
	t.Logf("%+v", got)
	l, f := got.Limited, got.Full
	if !l.Read || !f.Read {
		t.Fatalf("the Security log was not read: %+v", got)
	}
	if l.Since.Before(start) {
		t.Errorf("stopped at 5 events, since %v, before the test's sign-ins at %v", l.Since, start)
	}
	if f.Since.After(start) {
		t.Errorf("since %v, after the test's sign-ins at %v", f.Since, start)
	}
	cleaned := "easyrmm-c1-" + suffix + " x"
	if !f.Exposed || !slices.Contains(f.Bursts, plain) || !slices.Contains(f.Bursts, cleaned) || slices.Contains(f.Bursts, "easyrmm-few-"+suffix) {
		t.Errorf("bursts %q, want %q and %q", f.Bursts, plain, cleaned)
	}
	for _, s := range slices.Concat(f.Bursts, f.Accounts, l.Bursts, l.Accounts) {
		if strings.TrimSpace(s) == "" || strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
			t.Errorf("account %q in the result", s)
		}
	}
}

// TestHardeningLogReachOnWindows: where the oldest record read is dated
// after the check (written while the computer's clock was wrong), how far
// back the log was read has no time, but why; a record dated before the
// check, or at the same moment, gives its time.
func TestHardeningLogReachOnWindows(t *testing.T) {
	var got []struct {
		Since       *time.Time
		SinceReason string
	}
	hardeningFunctions(t, `$now = Get-Date
ConvertTo-Json -Compress @(
    (Get-ErLogReach $now.AddHours(8) $now),
    (Get-ErLogReach $now.ToUniversalTime().AddMinutes(1) $now),
    (Get-ErLogReach $now.AddDays(-2) $now),
    (Get-ErLogReach $now $now)
)`, &got)
	t.Logf("%+v", got)
	if len(got) != 4 {
		t.Fatalf("%d answers", len(got))
	}
	for i, g := range got[:2] {
		if g.Since != nil || g.SinceReason != "The oldest record read is dated after this check: the computer's clock was wrong when it was written." {
			t.Errorf("a record dated after the check (%d): since %v, reason %q", i, g.Since, g.SinceReason)
		}
	}
	for i, g := range got[2:] {
		if g.Since == nil || g.SinceReason != "" || g.Since.After(time.Now()) {
			t.Errorf("a record dated before the check (%d): since %v, reason %q", i, g.Since, g.SinceReason)
		}
	}
	if s := got[2].Since; s != nil && time.Since(*s) < 47*time.Hour {
		t.Errorf("2 days back, since %v", s)
	}
}

// Stand-ins for a read that fails: where nothing on the computer can make
// Windows' own provider fail without breaking the computer, the cmdlet is
// sent to a computer that does not exist, and fails as a read does.
const (
	standInCim      = `$PSDefaultParameterValues['Get-CimInstance:ComputerName'] = 'easyrmm-no-such-host.invalid'` + "\n"
	standInWinEvent = `$PSDefaultParameterValues['Get-WinEvent:ComputerName'] = 'easyrmm-no-such-host.invalid'` + "\n"
	// Defender's cmdlets are CIM cmdlets: they take a session, here one to
	// that computer, made without testing it.
	standInMp = `$PSDefaultParameterValues['Get-MpComputerStatus:CimSession'] = New-CimSession -ComputerName 'easyrmm-no-such-host.invalid' -SkipTestConnection` + "\n"
)

// hardeningGlobals sets what the script sets before its modules run, on
// this computer, and Get-TestDef, a setting by its ID.
const hardeningGlobals = `$ErSettings = @((ConvertFrom-Json $ErSettingsJson).settings)
$ErAudit = ConvertFrom-Json $ErAuditTableJson
$ErCache = @{}
$ErOptions = @{}
$ErPolicy = New-ErPolicyContext ''
function Get-TestDef { param([string]$Id) return @($ErSettings | Where-Object { $_.id -eq $Id })[0] }
$m = @{ settings = @(); managed = @(); notes = @() }
`

type unreadModule struct {
	State, Reason string
	Settings      []HardeningSetting
}

// unknownWithError: a setting whose read failed, with the error.
func unknownWithError(t *testing.T, what string, s HardeningSetting) {
	t.Helper()
	if s.State != "unknown" || s.Note == "" {
		t.Errorf("%s: %+v, want unknown with the error", what, s)
	}
}

// TestHardeningUnreadableRegistryOnWindows: a registry value that cannot be
// read is neither absent nor present. Every setting read from the registry
// is unknown with the error (one that is only reported, reported without a
// value), never in place or not, whatever the kind; and a module none of
// whose settings could be read failed. The settings are read from a key no
// one may read, and the keys the script names itself are made unreadable
// to the test's account.
func TestHardeningUnreadableRegistryOnWindows(t *testing.T) {
	sid := wintest.CurrentSID(t)
	const denied = `SOFTWARE\EasyRMM-hardening-unreadable`
	wintest.Unreadable(t, denied, sid)
	for _, k := range []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer`,                   // SmartScreen's own setting
		`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, // Remote Desktop's listener
		`SOFTWARE\Policies\Microsoft\Windows\LAPS`,                             // Windows LAPS's policy
	} {
		wintest.Unreadable(t, k, sid)
	}
	var got struct {
		Modules  map[string]unreadModule
		Settings map[string]HardeningSetting
	}
	hardeningFunctions(t, hardeningGlobals+`$ErPlatform = Get-ErPlatform
$denied = 'HKLM\`+denied+`'
foreach ($d in $ErSettings) {
    if ($d.path) { $d.path = $denied }
    if ($d.localPath) { $d.localPath = $denied }
}
foreach ($r in @($ErAudit.values)) { $r.path = $denied }
$modules = @{}
foreach ($name in 'wdigest', 'ntlm', 'uac', 'winrm', 'tls', 'autoplay', 'name-resolution', 'lsa-protection', 'powershell', 'rdp', 'laps') {
    $modules[$name] = Invoke-ErModule $name
}
$one = @{}
$one['defender-smartscreen'] = Test-ErSmartScreen (Get-TestDef 'defender-smartscreen') $m
$one['defender-smartscreen-level'] = Test-ErSmartScreen (Get-TestDef 'defender-smartscreen-level') $m
$one['audit-command-lines'] = Test-ErCustomSetting (Get-TestDef 'audit-command-lines') $m
$one['audit-legacy-overridden'] = Test-ErCustomSetting (Get-TestDef 'audit-legacy-overridden') $m
# SmartScreen's own setting, where no policy sets it.
$d = (Get-TestDef 'defender-smartscreen').PSObject.Copy()
$d.path = 'HKLM\SOFTWARE\EasyRMM-hardening-no-such-key'
$one['smartscreen-own'] = Test-ErSmartScreen $d $m
# Remote Desktop's listener, where its WMI provider gives no value.
$one['rdp-listener'] = Test-ErRdpSetting (Get-TestDef 'rdp-nla') $m 'EasyRMMNoSuchProperty' 'UserAuthentication' '1'
ConvertTo-Json -Compress -Depth 8 @{ Modules = $modules; Settings = $one }`, &got)

	// The settings read from the registry, by kind or by ID.
	fromRegistry := map[string]bool{"uac-on": true, "lsa-protection-value": true, "powershell-script-block-logging": true, "laps-managed": true}
	notSet := map[string]bool{}
	for _, s := range windowsSettings {
		if s.Kind == "registry" || s.Kind == "winrm" || s.Kind == "schannel" {
			fromRegistry[s.ID] = true
		}
		notSet[s.ID] = s.Cite == "not_set"
	}
	if len(got.Modules) != 11 || len(got.Settings) != 6 {
		t.Fatalf("%d modules, %d settings", len(got.Modules), len(got.Settings))
	}
	for name, m := range got.Modules {
		t.Logf("%s: %s %s", name, m.State, m.Reason)
		read := 0
		for _, s := range m.Settings {
			switch {
			case !fromRegistry[s.ID] || s.State == "not_applicable":
				read++
			case notSet[s.ID]:
				if s.State != "reported" || s.Value != "" || !strings.Contains(s.Note, "could not be read") {
					t.Errorf("%s: %+v, want reported without a value", s.ID, s)
				}
			default:
				unknownWithError(t, s.ID, s)
			}
		}
		// A module of registry settings alone, none of which could be read.
		if read == 0 && (m.State != HardeningFailed || m.Reason != "None of its settings could be read.") {
			t.Errorf("module %s: %s (%s), want failed", name, m.State, m.Reason)
		}
	}
	for _, name := range []string{"wdigest", "ntlm", "uac", "winrm", "tls", "autoplay", "laps"} {
		if m := got.Modules[name]; m.State != HardeningFailed {
			t.Errorf("module %s: %s, want failed", name, m.State)
		}
	}
	for id, s := range got.Settings {
		unknownWithError(t, id, s)
	}
}

// TestHardeningDefenderUnreadableOnWindows: where Microsoft Defender does
// not report its status (stand-in: Get-MpComputerStatus is sent to a
// computer that does not exist; Windows PowerShell 5.1 loads Defender's
// module from its own folder whatever PSModulePath says), its modules failed
// while its service runs; they are not applicable only where it is not
// installed or not running.
func TestHardeningDefenderUnreadableOnWindows(t *testing.T) {
	type gate struct{ State, Reason string }
	var got struct {
		Defender, Asr gate
		Service       struct {
			Installed, Read bool
			Status          string
		}
	}
	hardeningFunctions(t, standInMp+hardeningGlobals+`$ErPlatform = @{ Client = $false; Build = 26100; Role = 'member_server' }
ConvertTo-Json -Compress @{
    Defender = Get-ErModuleGate 'defender' $m
    Asr = Get-ErModuleGate 'asr' $m
    Service = Get-ErServiceState 'WinDefend'
}`, &got)
	t.Logf("%+v", got)
	s := got.Service
	if !s.Read {
		t.Fatalf("Defender's service could not be read: %+v", s)
	}
	for name, g := range map[string]gate{"defender": got.Defender, "asr": got.Asr} {
		if s.Installed && s.Status == "Running" {
			if g.State != HardeningFailed || !strings.HasPrefix(g.Reason, "Microsoft Defender Antivirus did not report its status: ") {
				t.Errorf("%s: %+v, want failed with the error", name, g)
			}
		} else if g.State != "not_applicable" {
			t.Errorf("%s with Defender's service %+v: %+v, want not_applicable", name, s, g)
		}
	}
}

// TestHardeningCimUnreadableOnWindows: where Windows' WMI provider does not
// answer (stand-in: Get-CimInstance is sent to a computer that does not
// exist), the computer's role and join are unknown and the computer check
// only, with why; BitLocker's module failed, not "not installed"; and Remote
// Desktop, LSA protection, Device Guard and the shared printers are
// unknown. Then, with the MDM enrolments and the Entra join unreadable to
// the test's account, the enrolment is null and the join unknown.
func TestHardeningCimUnreadableOnWindows(t *testing.T) {
	var got struct {
		Platform  json.RawMessage
		BitLocker struct{ State, Reason string }
		Settings  map[string]HardeningSetting
	}
	hardeningFunctions(t, standInCim+hardeningGlobals+`$ErPlatform = Get-ErPlatform
$one = @{}
$one['rdp-nla'] = Test-ErRdpSetting (Get-TestDef 'rdp-nla') $m 'UserAuthenticationRequired' 'UserAuthentication' '1'
$one['lsa-protection-running'] = Test-ErLsaRunning (Get-TestDef 'lsa-protection-running')
$one['device-guard-vbs'] = Test-ErDeviceGuard (Get-TestDef 'device-guard-vbs') 'vbs'
$spooler = Get-ErServiceState 'Spooler'
if ($spooler.Installed -and -not ($spooler.Status -eq 'Stopped' -and $spooler.StartType -eq 'Disabled')) {
    $one['printing-spooler'] = Test-ErSpooler (Get-TestDef 'printing-spooler')
}
$folder = @{ Folder = 'absent'; CopySha256 = ''; Warnings = @(); SetAside = @() }
ConvertTo-Json -Compress -Depth 8 @{
    Platform = ConvertTo-ErPlatformJson $ErPlatform 'full' 'FullLanguage' (Get-ErPlatformExtra $folder)
    BitLocker = Get-ErModuleGate 'bitlocker' $m
    Settings = $one
}`, &got)
	p := parseTestPlatform(t, got.Platform)
	if w := p.Windows; w.Role != "unknown" || w.Joined != "unknown" || !slices.Contains(w.CheckOnlyReasons, "unreadable") ||
		!slices.ContainsFunc(w.Notes, func(n string) bool { return strings.Contains(n, "role") }) {
		t.Errorf("platform %+v", w)
	}
	if b := got.BitLocker; b.State != HardeningFailed || !strings.HasPrefix(b.Reason, "BitLocker's state could not be read: ") {
		t.Errorf("bitlocker: %+v, want failed with the error", b)
	}
	if len(got.Settings) < 3 {
		t.Errorf("settings %+v", got.Settings)
	}
	for id, s := range got.Settings {
		unknownWithError(t, id, s)
	}

	sid := wintest.CurrentSID(t)
	wintest.Unreadable(t, `SOFTWARE\Microsoft\Enrollments`, sid)
	wintest.Unreadable(t, `SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`, sid)
	hardeningFunctions(t, hardeningGlobals+`$ErPlatform = Get-ErPlatform
$folder = @{ Folder = 'absent'; CopySha256 = ''; Warnings = @(); SetAside = @() }
ConvertTo-Json -Compress -Depth 8 @{ Platform = ConvertTo-ErPlatformJson $ErPlatform 'full' 'FullLanguage' (Get-ErPlatformExtra $folder) }`, &got)
	p = parseTestPlatform(t, got.Platform)
	if w := p.Windows; w.MDM != nil || w.Joined != "unknown" || w.Role == "unknown" || !slices.Contains(w.CheckOnlyReasons, "unreadable") ||
		!slices.ContainsFunc(w.Notes, func(n string) bool { return strings.Contains(n, "Entra ID") }) {
		t.Errorf("platform with the enrolments and join unreadable: %+v", w)
	}
}

// parseTestPlatform parses a platform the script made as the server parses
// a result's.
func parseTestPlatform(t *testing.T, platform json.RawMessage) HardeningPlatform {
	t.Helper()
	h := Hardening{Platform: HardeningWindows, Mode: HardeningCheck, Modules: []string{"wdigest"}}
	r, err := parseHardeningResult(windowsLine(string(platform), `{"module":"wdigest","state":"not_supported","reason":"Not checked."}`), h)
	if err != nil {
		t.Fatalf("%v: %s", err, platform)
	}
	return r.Platform
}

// TestHardeningEventsUnreadableOnWindows: a log that does not exist is a
// real answer, read; where the event logs do not answer (stand-in:
// Get-WinEvent is sent to a computer that does not exist), each log's size,
// whether LSA protection started and the failed sign-ins are unknown, not
// "not in place" or "none".
func TestHardeningEventsUnreadableOnWindows(t *testing.T) {
	var got struct {
		Read, Unread []HardeningSetting
		Lsa          HardeningSetting
		Exposure     struct {
			Read  bool
			Error string
		}
	}
	hardeningFunctions(t, hardeningGlobals+`$ErPlatform = Get-ErPlatform
$ErAudit.logs = @($ErAudit.logs) + @([pscustomobject]@{ channel = 'EasyRMM-No-Such-Log'; minKB = 1024 })
$read = Test-ErAuditLogs (Get-TestDef 'audit-log-sizes') $m
`+standInWinEvent+`ConvertTo-Json -Compress -Depth 8 @{
    Read = $read
    Unread = Test-ErAuditLogs (Get-TestDef 'audit-log-sizes') $m
    Lsa = Test-ErLsaRunning (Get-TestDef 'lsa-protection-running')
    Exposure = Get-ErExposure
}`, &got)
	missing := slices.IndexFunc(got.Read, func(s HardeningSetting) bool { return s.Item == "EasyRMM-No-Such-Log" })
	if missing < 0 || got.Read[missing].State != "not_in_place" || got.Read[missing].Value != "no such log" {
		t.Errorf("a log that does not exist: %+v", got.Read)
	}
	for _, s := range got.Read {
		if s.State == "unknown" {
			t.Errorf("log %s, read: %+v", s.Item, s)
		}
	}
	if len(got.Unread) != len(got.Read) {
		t.Errorf("%d logs unread, %d read", len(got.Unread), len(got.Read))
	}
	for _, s := range got.Unread {
		unknownWithError(t, "log "+s.Item, s)
	}
	unknownWithError(t, "lsa-protection-running", got.Lsa)
	if got.Exposure.Read || got.Exposure.Error == "" {
		t.Errorf("failed sign-ins: %+v, want not read, with the error", got.Exposure)
	}
}
