//go:build windows

package winpolicy

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"
)

// The reader's functions one by one, with Windows PowerShell 5.1, on the
// inputs that are hard to make on a computer: CI's job "Agent tests on
// Windows" runs these (OnWindows) as the runner's administrator. Each
// starts a PowerShell that defines the reader's functions, and nothing
// else, and runs a body that prints its findings as JSON.

// runFunctions defines script's top-level functions in a new Windows
// PowerShell, runs body, and decodes the JSON body prints last into v.
func runFunctions(t *testing.T, script, body string, v any) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "script.ps1")
	harness := filepath.Join(dir, "harness.ps1")
	if err := os.WriteFile(file, []byte(script), 0o600); err != nil {
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
`
	if err := os.WriteFile(harness, []byte(prelude+body), 0o600); err != nil {
		t.Fatal(err)
	}
	ps := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	cmd := exec.Command(ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness, file)
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

// polEntry is one Registry.pol entry: [key;name;type;size;data] in UTF-16LE.
func polEntry(key, name string, typ uint32, data []byte) []byte {
	var b bytes.Buffer
	utf := func(s string) {
		for _, u := range utf16.Encode([]rune(s)) {
			_ = binary.Write(&b, binary.LittleEndian, u)
		}
	}
	utf("[" + key + "\x00;" + name + "\x00;")
	_ = binary.Write(&b, binary.LittleEndian, typ)
	utf(";")
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(data)))
	utf(";")
	b.Write(data)
	utf("]")
	return b.Bytes()
}

func polString(s string) []byte {
	var b bytes.Buffer
	for _, u := range utf16.Encode([]rune(s + "\x00")) {
		_ = binary.Write(&b, binary.LittleEndian, u)
	}
	return b.Bytes()
}

func polDWord(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// registryPol is a Registry.pol file holding the entries.
func registryPol(entries ...[]byte) []byte {
	b := []byte("PReg\x01\x00\x00\x00")
	for _, e := range entries {
		b = append(b, e...)
	}
	return b
}

// testPol is the local Group Policy object the tests plant: a value set, a
// value set only where absent, and each way of deleting.
func testPol(key string) []byte {
	return registryPol(
		polEntry(key, "Set", 4, polDWord(1)),
		polEntry(key, "**del.Gone", 1, polString(" ")),
		polEntry(key+`\Sub`, "**DeleteValues", 1, polString("A;B")),
		polEntry(key+`\Vals`, "**delvals.", 1, polString(" ")),
		polEntry(key, "**soft.Soft", 4, polDWord(5)),
		polEntry(key, "**DeleteKeys", 1, polString(key+`\Gone1;`+key+`\Gone2`)),
		polEntry(key, "Text", 1, polString("hello")),
	)
}

// polWant is what the reader makes of testPol: each value and its owner's
// value, "" for none.
var polWant = []struct{ key, name, value string }{
	{"", "Set", "1"}, {"", "Gone", "deleted"}, {`\Sub`, "A", "deleted"}, {`\Sub`, "B", "deleted"},
	{`\Sub`, "C", ""}, {`\Vals`, "V", "deleted"}, {`\Vals\Deeper`, "V", ""}, {"", "Soft", "5"},
	{"", "Text", "hello"}, {`\Gone1\X`, "Y", "deleted"}, {`\Gone2`, "Z", "deleted"},
}

func TestReaderFunctionsOnWindows(t *testing.T) {
	r := Reader()

	// Text from the computer: controls as spaces, format characters and
	// separators gone, cut without splitting a character.
	var texts []string
	runFunctions(t, r, `
$tests = @(
    @("a$([char]9)b$([char]13)$([char]10)c", 300),
    @("admin$([char]0x85)istrator$([char]0x202e)", 64),
    @("$([char]0x200b)$([char]0x2028)", 64),
    @("ab$([char]0xd83d)$([char]0xde00)cdef", 6),
    @("$([char]0x80)$([char]0x9f) x ", 64)
)
ConvertTo-Json -Compress @($tests | ForEach-Object { Limit-ErText $_[0] $_[1] })`, &texts)
	if want := []string{"a b c", "admin istrator", "", "ab...", "x"}; strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Errorf("Limit-ErText: %q, want %q", texts, want)
	}

	// The local Group Policy object's Registry.pol, and what Group Policy's
	// resultant set of policy records of deleted values; an entry already
	// there (another policy's) is kept.
	const key = `Software\Policies\EasyRMM-functions-test`
	pol := filepath.Join(t.TempDir(), "Registry.pol")
	if err := os.WriteFile(pol, testPol(key), 0o600); err != nil {
		t.Fatal(err)
	}
	var found []string
	q := "@("
	for _, w := range polWant {
		q += "@('HKLM\\" + key + w.key + "', '" + w.name + "'), "
	}
	runFunctions(t, r, `
$c = New-ErPolicyContext ''
Add-ErGpRegistry $c '`+key+`' 'Set' 4 ([BitConverter]::GetBytes([uint32]9)) $false 'Domain policy' $false
foreach ($e in (ConvertFrom-ErRegistryPol ([IO.File]::ReadAllBytes('`+pol+`')))) {
    Add-ErGpRegistry $c $e.Key $e.Name $e.Type $e.Data $false 'Local Group Policy' $true
}
Add-ErGpRegistry $c 'Software\Policies\Microsoft\Windows\Explorer' 'NoDriveTypeAutoRun' 4 $null $true 'GPO A'
Add-ErGpRegistry $c 'MACHINE\Software\Policies\Microsoft\Windows\Explorer' '**del.NoAutorun' 1 $null $false 'GPO B'
$out = @()
foreach ($x in `+strings.TrimSuffix(q, ", ")+`, @('HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer', 'NoDriveTypeAutoRun'), @('HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer', 'NoAutorun'))) {
    $g = Find-ErGpRegistry $c $x[0] $x[1]
    $out += $(if ($g) { "$($g.Value) $($g.Policy)" } else { '' })
}
try { $null = ConvertFrom-ErRegistryPol ([byte[]](0x50, 0x52, 0x65, 0x67, 1, 0, 0, 0, 0x5b, 0, 0x41)); $out += 'read' } catch { $out += 'refused' }
ConvertTo-Json -Compress $out`, &found)
	var want []string
	for _, w := range polWant {
		switch {
		case w.name == "Set":
			want = append(want, "9 Domain policy")
		case w.value != "":
			want = append(want, w.value+" Local Group Policy")
		default:
			want = append(want, "")
		}
	}
	want = append(want, "deleted GPO A", "deleted GPO B", "refused")
	if strings.Join(found, "|") != strings.Join(want, "|") {
		t.Errorf("registry policy:\n got %q\nwant %q", found, want)
	}

	// Legacy audit categories hold their own subcategories, named by the
	// category's policy, unless subcategories override them; one the
	// reader does not know may be held by any.
	var legacy []map[string]any
	runFunctions(t, r, `
$c = New-ErPolicyContext ''
$c.GpRecordRead = $true
$c.SubcategoriesOverride = $false
$c.GpLegacyAudit = @{ AuditLogonEvents = @{ Success = $true; Failure = $false; Policy = 'Logon GPO' }; AuditAccountLogon = @{ Success = $true; Failure = $true; Policy = 'Account GPO' } }
$out = @()
foreach ($g in '0cce9215-69ae-11d9-bed3-505054503030', '{0CCE923F-69AE-11D9-BED3-505054503030}', '0cce922b-69ae-11d9-bed3-505054503030', '0cce92ff-69ae-11d9-bed3-505054503030') {
    $out += Resolve-ErAuditOwner $c $g
}
$c.SubcategoriesOverride = $true
$out += Resolve-ErAuditOwner $c '0cce9215-69ae-11d9-bed3-505054503030'
ConvertTo-Json -Compress -Depth 4 $out`, &legacy)
	wantLegacy := []string{"owner Logon GPO success", "owner Account GPO success_failure", "none  ",
		"owner Account GPO, Logon GPO legacy categories", "none  "}
	for i, l := range legacy {
		if got := l["Result"].(string) + " " + l["Policy"].(string) + " " + l["Value"].(string); i >= len(wantLegacy) || got != wantLegacy[i] {
			t.Errorf("legacy audit %d: %v", i, l)
		}
	}

	// Subcategories override categories unless the policy says otherwise:
	// absent, as on the runner, is Enabled.
	override := true
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE); err == nil {
		v, _, err := k.GetIntegerValue("SCENoApplyLegacyAuditPolicy")
		override = err != nil || v != 0
		_ = k.Close()
	}
	var context struct{ SubcategoriesOverride bool }
	runFunctions(t, r, `ConvertTo-Json -Compress @{ SubcategoriesOverride = (Get-ErPolicyContext '').SubcategoriesOverride }`, &context)
	if context.SubcategoriesOverride != override {
		t.Errorf("subcategories override: %v, want %v", context.SubcategoriesOverride, override)
	}

	// Enrolled in an MDM: every value cannot_tell, security settings and
	// audit subcategories with their CSPs; Group Policy keeps what it holds
	// unless the MDM wins over it.
	var mdm []answer
	runFunctions(t, r, `
$c = New-ErPolicyContext ''
$c.GpRecordRead = $true
$c.Mdm = $true
$c.GpSecurity['minimumpasswordlength'] = @{ Value = '8'; Policy = 'Password policy' }
$out = @(
    (Resolve-ErSecurityOwner $c 'PasswordHistorySize'),
    (Resolve-ErSecurityOwner $c 'MinimumPasswordLength'),
    (Resolve-ErAuditOwner $c '0cce9215-69ae-11d9-bed3-505054503030'),
    (Resolve-ErRegistryOwner $c 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL')
)
$c.MdmWinsOverGp = $true
$out += Resolve-ErSecurityOwner $c 'MinimumPasswordLength'
ConvertTo-Json -Compress -Depth 4 @($out | ForEach-Object { $a = @{ result = $_.Result; owner = $_.Owner; reasons = @($_.Reasons) }; if ($_.Mdm) { $a.mdm = @{ csp = $_.Mdm.Csp } }; $a })`, &mdm)
	wantMDM := []string{"cannot_tell DeviceLock/DevicePasswordHistory", "owner ", "cannot_tell Audit/AccountLogonLogoff_AuditLogon",
		"cannot_tell ", "cannot_tell DeviceLock/MinDevicePasswordLength"}
	for i, a := range mdm {
		got := a.Result + " "
		if a.MDM != nil {
			got += a.MDM.CSP
		}
		if i >= len(wantMDM) || got != wantMDM[i] || (a.Result == ResultCannotTell && strings.Join(a.Reasons, ",") != ReasonMDM) {
			t.Errorf("MDM %d: %+v", i, a)
		}
	}

	// Another antivirus owns the values it takes over, before Group Policy;
	// Tamper Protection owns those it guards where no policy holds them;
	// where Defender's status could not be read, those are unreadable.
	var products []answer
	runFunctions(t, r, `
$c = New-ErPolicyContext ''
$c.GpRecordRead = $true
$c.Products.antivirus = @('Contoso Antivirus', 'Another Antivirus')
$c.GpRegistry[(Get-ErRegistryKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' 'PUAProtection')] = @{ Value = '1'; Policy = 'Defender policy' }
$out = @(
    (Resolve-ErRegistryOwner $c 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' 'PUAProtection' -Product antivirus),
    (Resolve-ErRegistryOwner $c 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' 'PUAProtection')
)
$c.Products.antivirus = @()
$c.TamperProtected = $true
$out += Resolve-ErRegistryOwner $c 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' -Product antivirus -Tamper
$c.TamperProtected = $false
$c.Unreadable.tamper = $true
$out += Resolve-ErRegistryOwner $c 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' -Product antivirus -Tamper
ConvertTo-Json -Compress -Depth 4 @($out | ForEach-Object { @{ result = $_.Result; owner = $_.Owner; policy = $_.Policy; value = $_.Value; reasons = @($_.Reasons) } })`, &products)
	wantProducts := []string{"owner security_product Another Antivirus, Contoso Antivirus on", "owner group_policy Defender policy 1",
		"owner tamper_protection Tamper Protection", "cannot_tell    unreadable"}
	for i, a := range products {
		if got := strings.Join([]string{a.Result, a.Owner, a.Policy, a.Value, strings.Join(a.Reasons, ",")}, " "); i >= len(wantProducts) ||
			strings.TrimSpace(got) != wantProducts[i] {
			t.Errorf("products %d: %q, want %q", i, got, wantProducts[i])
		}
	}

	// netsh's filtering platform state, with what it writes after the
	// document: only another vendor's provider with inbound filters counts.
	state := filepath.Join(t.TempDir(), "wfpstate.xml")
	if err := os.WriteFile(state, []byte(`<?xml version="1.0"?>
<wfpstate><providers>
<item><providerKey>FWPM_PROVIDER_MPSSVC_WF</providerKey><displayData><name>Microsoft Corporation</name></displayData><serviceName>mpssvc</serviceName></item>
<item><providerKey>{c3719aac-9168-45b7-825a-5f2d68be2ee5}</providerKey><displayData><name>Microsoft Corporation</name><description>Microsoft Windows edge traversal socket option authorization provider</description></displayData></item>
<item><providerKey>{308b401f-3aa1-4444-94b2-2298d7dd312f}</providerKey><displayData><name>Windows Azure Agent Provider</name></displayData></item>
<item><providerKey>{11111111-2222-3333-4444-555555555555}</providerKey><displayData><name>Contoso Firewall</name></displayData></item>
</providers><layers><item><filters>
<item><providerKey>{C3719AAC-9168-45B7-825A-5F2D68BE2EE5}</providerKey><layerKey>FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6</layerKey></item>
<item><providerKey>{308b401f-3aa1-4444-94b2-2298d7dd312f}</providerKey><layerKey>FWPM_LAYER_ALE_AUTH_CONNECT_V4</layerKey></item>
<item><providerKey>{11111111-2222-3333-4444-555555555555}</providerKey><layerKey>FWPM_LAYER_ALE_AUTH_LISTEN_V4</layerKey></item>
<item><layerKey>FWPM_LAYER_INBOUND_TRANSPORT_V4</layerKey></item>
</filters></item></layers></wfpstate>
<wfpstate/>`), 0o600); err != nil {
		t.Fatal(err)
	}
	var firewalls []string
	runFunctions(t, r, `ConvertTo-Json -Compress -InputObject (Get-ErOtherFirewalls (ConvertFrom-ErWfpState ([IO.File]::ReadAllText('`+state+`'))))`, &firewalls)
	if strings.Join(firewalls, "|") != "Contoso Firewall" {
		t.Errorf("other firewalls: %q", firewalls)
	}

	// CREATOR OWNER's entries give no one rights on the folder itself;
	// Users' modify right does.
	var writers struct{ Creator, Users []string }
	runFunctions(t, r, `ConvertTo-Json -Compress @{
    Creator = (Get-ErWriters 'O:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;0x1200a9;;;BU)(A;OICI;FA;;;SY)' $true)
    Users = (Get-ErWriters 'O:SYD:PAI(A;OICI;0x1301bf;;;BU)(A;OICI;FA;;;SY)' $true)
}`, &writers)
	if len(writers.Creator) != 0 || strings.Join(writers.Users, ",") != "S-1-5-32-545" {
		t.Errorf("writers %+v", writers)
	}
}

// unreadRecord is what the reader keeps of the records it could not read.
type unreadRecord struct {
	Unreadable map[string]bool
	Notes      []string
}

// hasNote: whether a note contains the text.
func (u unreadRecord) hasNote(text string) bool {
	return slices.ContainsFunc(u.Notes, func(n string) bool { return strings.Contains(n, text) })
}

// TestReaderUnreadableOnWindows: an MDM's setting wins over Group
// Policy's only where MDMWinsOverGP is set or cannot be read, never for
// attack surface reduction rules, which it does not cover; and records the
// reader could not read make the values they concern cannot_tell
// (unreadable), with why: Security Center's products, the filtering
// platform's state, Defender's status.
func TestReaderUnreadableOnWindows(t *testing.T) {
	r := Reader()
	var wins []bool
	runFunctions(t, r, `
$c = New-ErPolicyContext ''
$c.Mdm = $true
$out = @((Test-ErMdmWins $c 'Defender/AllowRealtimeMonitoring'))
$c.MdmWinsOverGp = $true
$out += Test-ErMdmWins $c 'Defender/AllowRealtimeMonitoring'
$out += Test-ErMdmWins $c 'Defender/AttackSurfaceReductionRules'
$out += Test-ErMdmWins $c ''
$c.MdmWinsOverGp = $false
$c.Unreadable.mdmWins = $true
$out += Test-ErMdmWins $c 'Defender/AllowRealtimeMonitoring'
$c.Mdm = $false
$out += Test-ErMdmWins $c 'Defender/AllowRealtimeMonitoring'
ConvertTo-Json -Compress $out`, &wins)
	if want := []bool{false, true, false, false, true, false}; !slices.Equal(wins, want) {
		t.Errorf("Test-ErMdmWins: %v, want %v", wins, want)
	}
	// Under MDMWinsOverGP, Group Policy keeps its attack surface reduction
	// rule; the MDM may hold another Defender policy.
	var asr []answer
	runFunctions(t, r, `
$c = New-ErPolicyContext ''
$c.GpRecordRead = $true
$c.Mdm = $true
$c.MdmWinsOverGp = $true
$rules = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
$rule = '56a863a9-875e-4185-98a7-b882c64b5ce5'
$defender = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'
$c.GpRegistry[(Get-ErRegistryKey $rules $rule)] = @{ Value = '1'; Policy = 'ASR policy' }
$c.GpRegistry[(Get-ErRegistryKey $defender 'PUAProtection')] = @{ Value = '1'; Policy = 'Defender policy' }
$out = @(
    (Resolve-ErRegistryOwner $c $rules $rule 'Defender/AttackSurfaceReductionRules' -Defender -Product antivirus),
    (Resolve-ErRegistryOwner $c $defender 'PUAProtection' 'Defender/PUAProtection' -Defender -Product antivirus)
)
ConvertTo-Json -Compress -Depth 4 @($out | ForEach-Object { @{ result = $_.Result; owner = $_.Owner; policy = $_.Policy; reasons = @($_.Reasons) } })`, &asr)
	if len(asr) != 2 || asr[0].Result != ResultOwner || asr[0].Owner != OwnerGroupPolicy || asr[0].Policy != "ASR policy" ||
		asr[1].Result != ResultCannotTell || !slices.Contains(asr[1].Reasons, ReasonMDM) {
		t.Errorf("under MDMWinsOverGP: %+v, want Group Policy's rule and the MDM's Defender policy", asr)
	}

	// Security Center's products: on a server, where Windows has no
	// Security Center, a real failure; on a workstation, the stand-in sends
	// Get-CimInstance to a computer that does not exist.
	var products unreadRecord
	runFunctions(t, r, `$c = New-ErPolicyContext ''
if ((Get-ErRegistryValue 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'InstallationType').Data -eq 'Client') {
    $PSDefaultParameterValues['Get-CimInstance:ComputerName'] = 'easyrmm-no-such-host.invalid'
}
Read-ErSecurityProducts $c
ConvertTo-Json -Compress @{ Unreadable = $c.Unreadable; Notes = @($c.Notes) }`, &products)
	if !products.Unreadable["antivirus"] || !products.Unreadable["firewall"] || !products.hasNote("Security Center did not list") {
		t.Errorf("Security Center unread: %+v", products)
	}

	// The filtering platform's state, without a work folder and with one
	// that does not exist (netsh cannot write there): firewall values
	// cannot_tell (unreadable).
	var wfp []struct {
		unreadRecord
		Reasons []string
	}
	runFunctions(t, r, `$out = @()
foreach ($folder in '', '`+filepath.Join(t.TempDir(), "missing")+`') {
    $c = New-ErPolicyContext $folder
    $c.GpRecordRead = $true
    $reasons = Get-ErReasons $c 'registry' -Defender -Product firewall
    $out += @{ Unreadable = $c.Unreadable; Notes = @($c.Notes); Reasons = @($reasons) }
}
ConvertTo-Json -Compress -Depth 4 $out`, &wfp)
	if len(wfp) != 2 {
		t.Fatalf("filtering platform: %+v", wfp)
	}
	for i, w := range wfp {
		if !w.Unreadable["firewall"] || !slices.Equal(w.Reasons, []string{ReasonUnreadable}) || !w.hasNote("filtering platform") {
			t.Errorf("filtering platform %d: %+v", i, w)
		}
	}

	// Defender's status, where its module cannot be loaded (the PowerShell
	// modules limited to an empty folder): whether Tamper Protection is on
	// is not known, so real-time protection is cannot_tell (unreadable).
	var tamper struct {
		unreadRecord
		Realtime answer
	}
	runFunctions(t, r, `foreach ($n in 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility', 'CimCmdlets') { Import-Module $n }
$env:PSModulePath = '`+t.TempDir()+`'
$c = Get-ErPolicyContext ''
$a = Resolve-ErRegistryOwner $c 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' 'Defender/AllowRealtimeMonitoring' -Defender -Product antivirus -Tamper
ConvertTo-Json -Compress -Depth 4 @{ Unreadable = $c.Unreadable; Notes = @($c.Notes); Realtime = @{ result = $a.Result; reasons = @($a.Reasons) } }`, &tamper)
	if !tamper.Unreadable["tamper"] || !tamper.hasNote("Tamper Protection") || tamper.Realtime.Result != ResultCannotTell ||
		!slices.Contains(tamper.Realtime.Reasons, ReasonUnreadable) {
		t.Errorf("Defender's status unread: %+v", tamper)
	}
}
