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
)

// Functions of the script a Windows hardening job carries, one by one, with
// Windows PowerShell 5.1, on what is hard to make in a whole check: CI's job
// "Agent tests on Windows" runs these (OnWindows) as the runner's
// administrator.

// hardeningFunctions defines the script's top-level functions, and nothing
// else, in a new Windows PowerShell, runs body, and decodes the JSON body
// prints last into v.
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
	hardeningFunctions(t, `ConvertTo-Json -Compress -Depth 4 @{ Limited = Get-ErExposure -Limit 5; Full = Get-ErExposure }`, &got)
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
