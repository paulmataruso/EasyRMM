package jobs

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The evaluation of ADR-0078's C4 checks (the domain controller module),
// from real-shaped answers of the directory, repadmin and the registry, with
// the script's own functions run by PowerShell 7 where the test finds pwsh.
// The readers that need a domain controller (the LDAP search, the
// replication neighbors, the shares, the PDC emulator, repadmin) are
// replaced by what a case says; the Windows test
// (hardening_c4_windows_test.go) runs the real ones on a domain controller.

const c4Fakes = `
function Invoke-ErSearch {
    param([string]$BaseDn, [string]$Scope, [string]$Filter, [string[]]$Properties, [int]$Limit = 0)
    foreach ($e in @($c4.search)) {
        if ($e.props -ne $Properties[0]) { continue }
        if ($e.base -and $e.base -ne $BaseDn) { continue }
        if ($e.contains -and -not $Filter.Contains($e.contains)) { continue }
        if ($e.error) { return @{ Read = $false; Error = $e.error; Rows = @(); Truncated = $false } }
        $rows = @()
        foreach ($r in @($e.rows)) { $h = @{}; foreach ($p in $r.PSObject.Properties) { $h[$p.Name] = $p.Value }; $rows += $h }
        return @{ Read = $true; Error = ''; Rows = $rows; Truncated = [bool]$e.truncated }
    }
    return @{ Read = $true; Error = ''; Rows = @(); Truncated = $false }
}
function Get-ErRootDse { return @{ DomainDn = 'DC=corp,DC=example,DC=test'; ForestDn = 'DC=corp,DC=example,DC=test' } }
function Resolve-ErRegistryOwner { return $null }
function Get-ErRegistryValue {
    param([string]$Path, [string]$Name)
    $k = "$Path|$Name"
    if ($c4.registryError -eq $k) { return @{ Exists = $false; Data = $null; Kind = ''; Error = 'access denied' } }
    if ($c4.registry -and $c4.registry.PSObject.Properties.Name -contains $k) { return @{ Exists = $true; Data = $c4.registry.$k; Kind = 'DWord'; Error = '' } }
    return @{ Exists = $false; Data = $null; Kind = ''; Error = '' }
}
function Get-ErServiceState {
    param([string]$Name)
    if ($c4.services -and $c4.services.PSObject.Properties.Name -contains $Name) {
        $s = @($c4.services.$Name)
        return @{ Installed = $true; Read = $true; Status = $s[0]; StartType = $s[1] }
    }
    return @{ Installed = $false; Read = $true }
}
function Get-ErReplicationNeighbors {
    if ($c4.neighborsError) { return @{ Read = $false; Error = $c4.neighborsError; Neighbors = @() } }
    $list = @()
    foreach ($n in @($c4.neighbors)) { $list += @{ Failures = [int]$n.failures; LastSuccess = $n.lastSuccess; Result = [int]$n.result } }
    return @{ Read = $true; Error = ''; Neighbors = $list }
}
function Get-ErShareNames {
    if ($c4.sharesError) { return @{ Read = $false; Error = $c4.sharesError; Names = @() } }
    return @{ Read = $true; Error = ''; Names = @($c4.shares) }
}
function Get-ErPdcRole {
    if ($c4.pdcError) { return @{ Read = $false; Error = $c4.pdcError; IsPdc = $false } }
    return @{ Read = $true; Error = ''; IsPdc = [bool]$c4.isPdc }
}
function Invoke-ErProgram {
    param([string]$Path, [string[]]$Arguments, [int]$Seconds = 60)
    return @{ ExitCode = [int]$c4.repadmin.exit; Output = [string]$c4.repadmin.out; Error = '' }
}
`

// c4Case is one case: the PowerShell it evaluates (run), and what the
// stand-in readers answer.
type c4Case map[string]any

func c4Def(fn, id string, extra string) string {
	return fn + ` (Def '{"id":"` + id + `"` + extra + `}')`
}

// c4Run evaluates each case's run, with a fresh cache, in one PowerShell,
// and decodes the results in the order of the cases.
func c4Run(t *testing.T, cases []c4Case) []c3Result {
	t.Helper()
	b, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	body := c4Fakes + "\n$Module = @{ managed = @(); notes = @() }\n$ErPolicy = $null\n$cases = ConvertFrom-Json @'\n" + string(b) + "\n'@\n" +
		"$out = @()\nforeach ($c in $cases) { $c4 = $c; $ErCache = @{}; $out += @(& ([scriptblock]::Create($c.run))) }\nConvertTo-Json -Compress @($out)"
	got := c3Run(t, c3Scenario{}, body)
	if len(got) != len(cases) {
		t.Fatalf("%d results for %d cases: %+v", len(got), len(cases), got)
	}
	return got
}

// c4Want is the state a case ends in and a text its value or note holds.
type c4Want struct{ state, text string }

func c4Check(t *testing.T, name string, got []c3Result, want []c4Want) {
	t.Helper()
	for i, w := range want {
		if got[i].State != w.state || !strings.Contains(got[i].Value+" | "+got[i].Note, w.text) {
			t.Errorf("%s %d: %+v, want %s (%s)", name, i, got[i], w.state, w.text)
		}
	}
}

const (
	c4DomainDn  = "DC=corp,DC=example,DC=test"
	c4DomainSid = "S-1-5-21-1111111111-2222222222-3333333333"
)

// The directory's answer for the domain and the forest root, which is the
// same domain here.
func c4Search(run string, extra ...map[string]any) c4Case {
	root := map[string]any{"objectsid": c4DomainSid}
	return c4Case{"run": run, "search": append([]map[string]any{{"props": "objectsid", "rows": []any{root}}}, extra...)}
}

func c4Filetime(ago time.Duration) int64 {
	return (time.Now().Add(-ago).Unix() + 11644473600) * 10000000
}

func TestC4DomainPolicy(t *testing.T) {
	policy := func(length, props, history, threshold, duration int64) map[string]any {
		return map[string]any{"props": "minpwdlength", "rows": []any{map[string]any{
			"minpwdlength": length, "pwdproperties": props, "pwdhistorylength": history, "lockoutthreshold": threshold, "lockoutduration": duration}}}
	}
	all := func(p map[string]any) []c4Case {
		var cs []c4Case
		for _, d := range [][2]string{{"dc-password-length", `,"data":14`}, {"dc-password-complexity", ""}, {"dc-password-history", `,"data":24`},
			{"dc-lockout-threshold", `,"data":10`}, {"dc-lockout-duration", `,"data":15`}} {
			cs = append(cs, c4Search(c4Def("Test-ErDomainPolicy", d[0], d[1]), p))
		}
		return cs
	}
	// Lockout durations are negative counts of 100-nanosecond intervals:
	// 15 minutes is -9000000000.
	var cases []c4Case
	cases = append(cases, all(policy(14, 1, 24, 5, -9000000000))...)
	cases = append(cases, all(policy(7, 0, 0, 0, -3000000000))...)
	cases = append(cases, all(policy(24, 9, 24, 10, 0))...)
	cases = append(cases, all(map[string]any{"props": "minpwdlength", "error": "The directory could not be searched: the server is not operational"})...)
	cases = append(cases, c4Case{"run": c4Def("Test-ErDomainPolicy", "dc-password-length", `,"data":14`),
		"search": []any{map[string]any{"props": "objectsid", "error": "The directory could not be searched: no domain"}}})
	got := c4Run(t, cases)
	c4Check(t, "policy", got, []c4Want{
		{"in_place", "14 characters"}, {"in_place", "on"}, {"in_place", "24 passwords"}, {"in_place", "5 failed"}, {"in_place", "15 minutes"},
		{"not_in_place", "7 characters"}, {"not_in_place", "off"}, {"not_in_place", "0 passwords"}, {"not_in_place", "never locks out"}, {"not_in_place", "5 minutes"},
		{"in_place", "24 characters"}, {"in_place", "on"}, {"in_place", "24 passwords"}, {"in_place", "10 failed"}, {"in_place", "until an administrator unlocks"},
		{"unknown", "not operational"}, {"unknown", "not operational"}, {"unknown", "not operational"}, {"unknown", "not operational"}, {"unknown", "not operational"},
		{"unknown", "no domain"},
	})
}

func TestC4KrbtgtAge(t *testing.T) {
	run := c4Def("Test-ErKrbtgtAge", "dc-krbtgt-age", `,"data":180`)
	row := func(ago time.Duration) map[string]any {
		return map[string]any{"props": "pwdlastset", "rows": []any{map[string]any{"pwdlastset": c4Filetime(ago)}}}
	}
	day := 24 * time.Hour
	got := c4Run(t, []c4Case{
		c4Search(run, row(100*day)),
		c4Search(run, row(400*day)),
		c4Search(run, map[string]any{"props": "pwdlastset", "rows": []any{}}),
		c4Search(run, map[string]any{"props": "pwdlastset", "rows": []any{map[string]any{"pwdlastset": 0}}}),
		c4Search(run, map[string]any{"props": "pwdlastset", "error": "insufficient access"}),
	})
	c4Check(t, "krbtgt", got, []c4Want{{"in_place", "100 days"}, {"not_in_place", "400 days"}, {"unknown", "did not report"}, {"unknown", "did not report"}, {"unknown", "insufficient access"}})
}

func TestC4PrivilegedGroups(t *testing.T) {
	grp := func(sid string, n int, more bool) map[string]any {
		r := map[string]any{"member": n}
		if more {
			r["memberMore"] = true
		}
		return map[string]any{"props": "member", "contains": sid, "rows": []any{r}}
	}
	da := c4Def("Test-ErPrivilegedGroup", "dc-domain-admins", `,"key":"domain-admins","data":5`)
	ea := c4Def("Test-ErPrivilegedGroup", "dc-enterprise-admins", `,"key":"enterprise-admins","data":1`)
	sa := c4Def("Test-ErPrivilegedGroup", "dc-schema-admins", `,"key":"schema-admins","data":0`)
	ad := c4Def("Test-ErPrivilegedGroup", "dc-administrators", `,"key":"administrators","data":5`)
	got := c4Run(t, []c4Case{
		c4Search(da, grp(c4DomainSid+"-512", 3, false)),
		c4Search(da, grp(c4DomainSid+"-512", 9, false)),
		c4Search(ea, grp(c4DomainSid+"-519", 1, false)),
		c4Search(ea, grp(c4DomainSid+"-519", 2, false)),
		c4Search(sa, grp(c4DomainSid+"-518", 0, false)),
		c4Search(sa, grp(c4DomainSid+"-518", 1, false)),
		c4Search(ad, grp("S-1-5-32-544", 4, false)),
		c4Search(ad, grp("S-1-5-32-544", 1500, true)),
		c4Search(da, map[string]any{"props": "member", "rows": []any{}}),
		c4Search(da, map[string]any{"props": "member", "error": "the server is busy"}),
	})
	c4Check(t, "groups", got, []c4Want{
		{"in_place", "3 member(s)"}, {"not_in_place", "9 member(s)"}, {"in_place", "1 member(s)"}, {"not_in_place", "2 member(s)"},
		{"in_place", "0 member(s)"}, {"not_in_place", "1 member(s)"}, {"in_place", "4 member(s)"}, {"not_in_place", "1500 or more"},
		{"unknown", "did not return"}, {"unknown", "busy"},
	})
	// The want is told in words, and no member is named anywhere.
	if got[4].Want != "no members" || got[0].Want != "at most 5 members" {
		t.Errorf("wants %q and %q", got[4].Want, got[0].Want)
	}
}

func TestC4AccountHygiene(t *testing.T) {
	stale := c4Def("Test-ErAccountHygiene", "dc-stale-accounts", `,"data":90`) + " 'stale'"
	never := c4Def("Test-ErAccountHygiene", "dc-password-never-expires", "") + " 'never-expires'"
	// The script asks for the two kinds by their filters.
	rows := func(n int, contains string, truncated bool) map[string]any {
		r := make([]any, n)
		for i := range r {
			r[i] = map[string]any{"distinguishedname": "CN=u" + strconv.Itoa(i) + "," + c4DomainDn}
		}
		return map[string]any{"props": "distinguishedname", "contains": contains, "rows": r, "truncated": truncated}
	}
	got := c4Run(t, []c4Case{
		c4Search(stale, rows(0, "lastLogonTimestamp<=", false)),
		c4Search(stale, rows(4, "lastLogonTimestamp<=", false)),
		c4Search(stale, rows(20000, "lastLogonTimestamp<=", true)),
		c4Search(never, rows(0, "=65536", false)),
		c4Search(never, rows(2, "=65536", false)),
		c4Search(never, map[string]any{"props": "distinguishedname", "error": "size limit exceeded"}),
	})
	c4Check(t, "accounts", got, []c4Want{
		{"in_place", "0 enabled"}, {"not_in_place", "4 enabled account(s) with no sign-in"}, {"not_in_place", "20000 or more"},
		{"in_place", "0 enabled"}, {"not_in_place", "2 enabled account(s) whose password never expires"}, {"unknown", "size limit"},
	})
	for _, g := range got {
		if strings.Contains(g.Value, "CN=") {
			t.Errorf("a name in a value: %+v", g)
		}
	}
}

func TestC4Replication(t *testing.T) {
	run := c4Def("Test-ErReplication", "dc-replication", `,"data":24`)
	at := func(ago time.Duration) string { return time.Now().Add(-ago).UTC().Format(time.RFC3339) }
	nb := func(failures, result int, ago time.Duration) map[string]any {
		return map[string]any{"failures": failures, "result": result, "lastSuccess": at(ago)}
	}
	got := c4Run(t, []c4Case{
		{"run": run, "neighbors": []any{nb(0, 0, time.Minute), nb(0, 0, 3*time.Hour)}},
		{"run": run, "neighbors": []any{nb(0, 0, time.Minute), nb(3, 1722, 2*time.Hour)}},
		{"run": run, "neighbors": []any{nb(0, 0, 30*time.Hour)}},
		{"run": run, "neighbors": []any{}},
		{"run": run, "neighborsError": "Replication could not be read: the server is not operational"},
	})
	c4Check(t, "replication", got, []c4Want{
		{"in_place", "2 partner link(s) succeeding"}, {"not_in_place", "1 of 2 partner link(s) failing"}, {"not_in_place", "not synchronized within 24 hours"},
		{"not_applicable", "no replication partners"}, {"unknown", "not operational"},
	})
}

func TestC4Sysvol(t *testing.T) {
	run := c4Def("Test-ErSysvol", "dc-sysvol", "")
	running := map[string][2]string{"DFSR": {"Running", "Automatic"}}
	got := c4Run(t, []c4Case{
		{"run": run, "shares": []string{"ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL"}, "services": running},
		{"run": run, "shares": []string{"ADMIN$", "C$", "IPC$", "NETLOGON"}, "services": running},
		{"run": run, "shares": []string{"NETLOGON", "SYSVOL"}, "services": map[string][2]string{"DFSR": {"Stopped", "Automatic"}}},
		{"run": run, "shares": []string{"NETLOGON", "SYSVOL"}, "services": map[string][2]string{"NtFrs": {"Running", "Automatic"}}},
		{"run": run, "sharesError": "The shares could not be read: access denied"},
	})
	c4Check(t, "sysvol", got, []c4Want{
		{"in_place", "replication running"}, {"not_in_place", "not shared: SYSVOL"}, {"not_in_place", "neither DFS Replication"},
		{"in_place", "replication running"}, {"unknown", "access denied"},
	})
}

// repadmin /showbackup, as a controller that was backed up writes it (the
// form is recorded from documentation, not from a real run: see the notes).
func c4Showbackup(when string) string {
	return "Repadmin: running command /showbackup against full DC dc01.corp.example.test\n\n" + c4DomainDn + "\n" +
		"    Last backup date            : " + when + "\n" +
		"    dSASignature GUID           : 7c3f1a52-0000-0000-0000-000000000000\n"
}

func TestC4AdBackup(t *testing.T) {
	run := c4Def("Test-ErAdBackup", "dc-backup", `,"data":7`)
	at := func(ago time.Duration) string { return time.Now().Add(-ago).Format("2006-01-02 15:04:05") }
	day := 24 * time.Hour
	rep := func(exit int, out string) c4Case {
		return c4Case{"run": run, "repadmin": map[string]any{"exit": exit, "out": out}}
	}
	got := c4Run(t, []c4Case{
		rep(0, c4Showbackup(at(2*day))),
		rep(0, c4Showbackup(at(20*day))),
		rep(0, c4Showbackup("1601-01-01 00:00:00")),
		rep(0, "Repadmin: running command /showbackup against full DC dc01\n\nNo backup information.\n"),
		rep(5, "Access is denied."),
	})
	c4Check(t, "backup", got, []c4Want{
		{"in_place", "2 days ago"}, {"not_in_place", "20 days ago"}, {"not_in_place", "never backed up"}, {"unknown", "no backup date"}, {"unknown", "exit 5"},
	})
}

func TestC4TimeHierarchy(t *testing.T) {
	run := c4Def("Test-ErTimeHierarchy", "dc-time-hierarchy", "")
	const p = `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters|`
	reg := func(kind, server string) map[string]string {
		m := map[string]string{}
		if kind != "" {
			m[p+"Type"] = kind
		}
		if server != "" {
			m[p+"NtpServer"] = server
		}
		return m
	}
	got := c4Run(t, []c4Case{
		{"run": run, "isPdc": true, "registry": reg("NTP", "time.example.test,0x9")},
		{"run": run, "isPdc": true, "registry": reg("NT5DS", "")},
		{"run": run, "isPdc": true, "registry": reg("NTP", "")},
		{"run": run, "isPdc": false, "registry": reg("NT5DS", "")},
		{"run": run, "isPdc": false, "registry": reg("", "")},
		{"run": run, "isPdc": false, "registry": reg("NTP", "time.example.test,0x9")},
		{"run": run, "pdcError": "The PDC emulator could not be found: no domain"},
		{"run": run, "isPdc": false, "registryError": p + "Type"},
	})
	c4Check(t, "time", got, []c4Want{
		{"in_place", "PDC emulator, source type NTP"}, {"not_in_place", "PDC emulator, source type NT5DS"}, {"not_in_place", "PDC emulator"},
		{"in_place", "not the PDC emulator"}, {"in_place", "NT5DS"}, {"not_in_place", "source type NTP"}, {"unknown", "no domain"}, {"unknown", "access denied"},
	})
}

func TestC4KerberosTypes(t *testing.T) {
	const pol = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters|SupportedEncryptionTypes`
	const kdc = `HKLM\SYSTEM\CurrentControlSet\Services\KDC|DefaultDomainSupportedEncTypes`
	policy := c4Def("Test-ErKerberosTypes", "dc-kerberos-types", `,"path":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters","name":"SupportedEncryptionTypes"`) + " $Module"
	def := c4Def("Test-ErKerberosTypes", "dc-kdc-default-types", `,"path":"HKLM\\SYSTEM\\CurrentControlSet\\Services\\KDC","name":"DefaultDomainSupportedEncTypes"`) + " $Module"
	got := c4Run(t, []c4Case{
		{"run": policy, "registry": map[string]string{pol: "24"}},
		{"run": policy, "registry": map[string]string{pol: "28"}},
		{"run": policy, "registry": map[string]string{pol: "4"}},
		{"run": policy, "registry": map[string]string{pol: "31"}},
		{"run": policy, "registry": map[string]string{}},
		{"run": policy, "registryError": pol},
		{"run": def, "registry": map[string]string{kdc: "24"}},
		{"run": def, "registry": map[string]string{kdc: "20"}},
	})
	c4Check(t, "kerberos", got, []c4Want{
		{"in_place", "24: AES128, AES256"}, {"not_in_place", "28: RC4, AES128, AES256"}, {"not_in_place", "4: RC4"}, {"not_in_place", "DES-CRC, DES-MD5, RC4"},
		{"not_in_place", "not set"}, {"unknown", "access denied"}, {"in_place", "24: AES128, AES256"}, {"not_in_place", "20: RC4, AES256"},
	})
}

// Settings for domain controllers only are not applicable elsewhere, and
// unknown where Windows did not report the role, never taken as either.
func TestC4SettingsApplyToDomainControllersOnly(t *testing.T) {
	var cases []c4Case
	for _, role := range []string{"domain_controller", "member_server", "workstation", "standalone_server", "unknown"} {
		cases = append(cases, c4Case{"run": `$ErPlatform = @{ Role = '` + role + `'; Client = $false; Build = 26100 }; @{ state = (Get-ErApplies (Def '{"id":"dc-krbtgt-age","only":{"roles":["domain_controller"]}}')) }`})
	}
	got := c4Run(t, cases)
	for i, w := range []string{"", "not_applicable", "not_applicable", "not_applicable", "unknown"} {
		if got[i].State != w {
			t.Errorf("case %d: %q, want %q", i, got[i].State, w)
		}
	}
}
