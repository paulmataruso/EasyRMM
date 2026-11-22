//go:build windows

package winpolicy

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/paulmataruso/easyrmm/internal/wintest"
)

// The reader started on its own, as the agent is to start it: Windows
// PowerShell 5.1 as LocalSystem. CI's job "Windows hardening as
// LocalSystem" starts these tests through a scheduled task with
// EASYRMM_TEST_SYSTEM set; they write values under HKLM and files under
// Program Files and System32, so they run only on computers made for the
// job.

func systemTest(t *testing.T) {
	t.Helper()
	if os.Getenv("EASYRMM_TEST_SYSTEM") == "" {
		t.Skip("runs as LocalSystem on a computer made for it; CI's job sets EASYRMM_TEST_SYSTEM")
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatalf("not running as LocalSystem (%v)", err)
	}
}

// runnerTest: a systemTest that expects no domain's Group Policy to hold
// what it asks about, as on GitHub's runners. On a member of a domain or
// its controller the domain's policies hold those values and its
// preference items make the rest cannot_tell; TestQueryDomainAsSystem
// checks the answers there.
func runnerTest(t *testing.T) {
	t.Helper()
	systemTest(t)
	var name *uint16
	var status uint32
	if err := windows.NetGetJoinInformation(nil, &name, &status); err != nil {
		t.Fatal(err)
	}
	_ = windows.NetApiBufferFree((*byte)(unsafe.Pointer(name)))
	if status == windows.NetSetupDomainName {
		t.Skip("expects no domain's Group Policy; this computer is in a domain, where TestQueryDomainAsSystem runs")
	}
}

type answer struct {
	Result  string   `json:"result"`
	Owner   string   `json:"owner"`
	Policy  string   `json:"policy"`
	Value   string   `json:"value"`
	Reasons []string `json:"reasons"`
	MDM     *struct {
		CSP string `json:"csp"`
	} `json:"mdm"`
}

func (a answer) String() string {
	b, _ := json.Marshal(a)
	return string(b)
}

type answers struct {
	Registry []answer `json:"registry"`
	Security []answer `json:"security"`
	Audit    []answer `json:"audit"`
	Notes    []string `json:"notes"`
}

func (a *answers) all() []answer {
	return slices.Concat(a.Registry, a.Security, a.Audit)
}

// ask starts the reader with a request and returns its exit code and the
// answers it printed.
func ask(t *testing.T, request string) (int, *answers) {
	t.Helper()
	return askWith(t, request, nil)
}

// askWith is ask with more environment variables for the reader.
func askWith(t *testing.T, request string, env []string) (int, *answers) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "easyrmm-winpolicy.ps1")
	file := filepath.Join(dir, "request.json")
	if err := os.WriteFile(script, []byte(Query()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(request), 0o600); err != nil {
		t.Fatal(err)
	}
	ps := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	cmd := exec.Command(ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, file)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	if stderr.Len() > 0 {
		t.Logf("stderr: %s", stderr.String())
	}
	code := cmd.ProcessState.ExitCode()
	if code != 0 {
		return code, nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if len(lines) != 1 || !strings.HasPrefix(last, QueryResultPrefix) {
		t.Fatalf("output %q", out)
	}
	var a answers
	if err := json.Unmarshal([]byte(strings.TrimPrefix(last, QueryResultPrefix)), &a); err != nil {
		t.Fatalf("%v: %s", err, last)
	}
	for i, x := range a.all() {
		checkAnswer(t, "answer "+strconv.Itoa(i), x)
	}
	return code, &a
}

func checkAnswer(t *testing.T, what string, a answer) {
	t.Helper()
	ok := false
	switch a.Result {
	case ResultOwner:
		ok = slices.Contains(Owners, a.Owner) && len(a.Reasons) == 0
	case ResultNone:
		ok = a.Owner == "" && len(a.Reasons) == 0
	case ResultCannotTell:
		ok = a.Owner == "" && len(a.Reasons) > 0
		for _, r := range a.Reasons {
			ok = ok && slices.Contains(Reasons, r)
		}
	}
	if !ok {
		t.Errorf("%s: %+v", what, a)
	}
}

// powershell runs a command with Windows PowerShell and returns its output.
func powershell(t *testing.T, command string) string {
	t.Helper()
	ps := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	out, err := exec.Command(ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command).Output()
	if err != nil {
		t.Fatalf("%s: %v", command, err)
	}
	return strings.TrimSpace(string(out))
}

// valueExists: whether a value exists under HKLM.
func valueExists(path, name string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetValue(name, nil)
	return err == nil
}

// The request TestQueryAsSystem and the planted owners ask.
const (
	plantedKey = `SOFTWARE\Policies\EasyRMM-winpolicy-test`
	realtime   = `SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
	logonGUID  = "0cce9215-69ae-11d9-bed3-505054503030"
)

var baseRequest = `{"registry": [
	{"path": "HKLM\\` + strings.ReplaceAll(plantedKey, `\`, `\\`) + `", "name": "Planted"},
	{"path": "HKLM\\` + strings.ReplaceAll(realtime, `\`, `\\`) + `", "name": "DisableRealtimeMonitoring", "csp": "Defender/AllowRealtimeMonitoring", "defender": true, "product": "antivirus", "tamper": true},
	{"path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "name": "UseLogonCredential"}],
 "security": ["MinimumPasswordLength", "LockoutBadCount"],
 "audit": ["` + logonGUID + `", "{0CCE922B-69AE-11D9-BED3-505054503030}"]}`

// TestQueryAsSystem: on a runner, which no Group Policy object, MDM or
// other owner manages (GitHub's images are not enrolled, carry no
// preference items, Configuration Manager, DSC configuration or OSConfig
// baseline), each answer is the one Windows' own state gives.
func TestQueryAsSystem(t *testing.T) {
	runnerTest(t)
	// A value under Policies that no owner the reader knows explains.
	wintest.Plant(t, plantedKey, map[string]any{"Planted": uint32(1)})

	code, a := ask(t, baseRequest)
	if code != 0 || len(a.Registry) != 3 || len(a.Security) != 2 || len(a.Audit) != 2 {
		t.Fatalf("exit code %d, answers %+v", code, a)
	}
	t.Logf("answers %+v", a)
	// The answers keep the request's order.
	if r := a.Registry[0]; r.Result != ResultCannotTell || strings.Join(r.Reasons, ",") != ReasonUnexplainedPolicy {
		t.Errorf("a value under Policies no one explains: %v", r)
	}
	// Real-time protection: Tamper Protection's where it is on (the
	// Windows 11 runner); otherwise unexplained where the image set a
	// policy value, none where it did not.
	tamper := powershell(t, `(Get-MpComputerStatus).IsTamperProtected`) == "True"
	r := a.Registry[1]
	switch {
	case tamper:
		if r.Result != ResultOwner || r.Owner != OwnerTamperProtection || r.Policy != "Tamper Protection" {
			t.Errorf("real-time protection with Tamper Protection on: %v", r)
		}
	case valueExists(realtime, "DisableRealtimeMonitoring"):
		if r.Result != ResultCannotTell || strings.Join(r.Reasons, ",") != ReasonUnexplainedPolicy {
			t.Errorf("real-time protection's policy value: %v", r)
		}
	case r.Result != ResultNone:
		t.Errorf("real-time protection: %v", r)
	}
	// A value outside Policies, security settings and audit subcategories
	// no one holds.
	for i, x := range append([]answer{a.Registry[2]}, slices.Concat(a.Security, a.Audit)...) {
		if x.Result != ResultNone {
			t.Errorf("unowned %d: %v", i, x)
		}
	}

	// A value under Policies that cannot be read is neither absent nor
	// unexplained: cannot_tell (unreadable), with the error in the notes.
	wintest.DenyKeyRead(t, plantedKey)
	if code, a = ask(t, baseRequest); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if r := a.Registry[0]; r.Result != ResultCannotTell || strings.Join(r.Reasons, ",") != ReasonUnreadable {
		t.Errorf("a value under Policies that cannot be read: %v", r)
	}
	if !slices.ContainsFunc(a.Notes, func(n string) bool { return strings.Contains(n, "EasyRMM-winpolicy-test") }) {
		t.Errorf("notes %q do not name the value", a.Notes)
	}

	badRequests(t)
}

// TestQueryDomainAsSystem runs on a member of a test domain whose
// controller ran testdata/domain-gpos.ps1 (docs/development/machine-tests.md),
// with EASYRMM_TEST_DOMAIN set as well. It checks the owners the reader
// names against the policies the script made, or, with EasyRMM-W1-RSoPOff
// linked, that Group Policy's record being off makes them cannot_tell.
func TestQueryDomainAsSystem(t *testing.T) {
	systemTest(t)
	if os.Getenv("EASYRMM_TEST_DOMAIN") == "" {
		t.Skip("runs on a member of a test domain made with testdata/domain-gpos.ps1")
	}
	code, a := ask(t, `{"registry": [
		{"path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "name": "EnableMulticast"},
		{"path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "name": "LmCompatibilityLevel"},
		{"path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "name": "UseLogonCredential"}],
	 "security": ["MinimumPasswordLength", "LockoutBadCount", "PasswordHistorySize"],
	 "audit": ["{0CCE922B-69AE-11D9-BED3-505054503030}", "0cce923f-69ae-11d9-bed3-505054503030", "0cce9215-69ae-11d9-bed3-505054503030"]}`)
	if code != 0 || len(a.Registry) != 3 || len(a.Security) != 3 || len(a.Audit) != 3 {
		t.Fatalf("exit code %d, answers %+v", code, a)
	}
	t.Logf("answers %+v", a)

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\System`, registry.QUERY_VALUE)
	recordOff := false
	if err == nil {
		v, _, err := k.GetIntegerValue("RSoPLogging")
		recordOff = err == nil && v == 0
		_ = k.Close()
	}
	owner := func(what string, got answer, policy, value string) {
		t.Helper()
		if got.Result != ResultOwner || got.Owner != OwnerGroupPolicy || got.Policy != policy || got.Value != value {
			t.Errorf("%s: %+v, want Group Policy's %s with %s", what, got, policy, value)
		}
	}
	cannotTell := func(what string, got answer, reason string) {
		t.Helper()
		if got.Result != ResultCannotTell || !slices.Contains(got.Reasons, reason) {
			t.Errorf("%s: %+v, want cannot_tell with %s", what, got, reason)
		}
	}
	// Preference items say nothing of which values they set.
	cannotTell("WDigest, set by a preference item", a.Registry[2], ReasonGroupPolicyPreferences)
	if recordOff {
		t.Log("Group Policy's record is off")
		cannotTell("LLMNR", a.Registry[0], ReasonGroupPolicyRecordOff)
		cannotTell("LmCompatibilityLevel", a.Registry[1], ReasonGroupPolicyRecordOff)
		for i, s := range a.Security {
			cannotTell("security "+strconv.Itoa(i), s, ReasonGroupPolicyRecordOff)
		}
	} else {
		owner("LLMNR", a.Registry[0], "EasyRMM-W1-Registry", "0")
		owner("LmCompatibilityLevel", a.Registry[1], "EasyRMM-W1-Security", "3")
		owner("minimum password length", a.Security[0], "EasyRMM-W1-Security", "8")
		owner("lockout threshold", a.Security[1], "EasyRMM-W1-Security", "5")
		// Default Domain Policy sets the password history.
		owner("password history", a.Security[2], "Default Domain Policy", "24")
	}
	// The audit policy extension's own record does not depend on Group
	// Policy's record.
	owner("Process Creation", a.Audit[0], "EasyRMM-W1-Audit", "success")
	owner("Credential Validation", a.Audit[1], "EasyRMM-W1-Audit", "success_failure")
	if l := a.Audit[2]; recordOff {
		cannotTell("Logon", l, ReasonGroupPolicyRecordOff)
	} else if l.Result != ResultNone {
		t.Errorf("Logon, which no policy sets: %+v", l)
	}
}

// badRequests: requests the reader refuses, with exit code 2.
func badRequests(t *testing.T) {
	t.Helper()
	for _, bad := range []string{
		``, `[]`, `{"other": []}`, `{"registry": [{"path": "HKCU\\x", "name": "y"}]}`,
		`{"registry": [{"path": "HKLM\\x"}]}`, `{"registry": [{"path": "HKLM\\x", "name": "y", "csp": "no slash"}]}`,
		`{"registry": [{"path": "HKLM\\x", "name": "y", "defender": "yes"}]}`,
		`{"registry": [{"path": "HKLM\\x", "name": "y", "tamper": 1}]}`,
		`{"registry": [{"path": "HKLM\\x", "name": "y", "product": "edr"}]}`,
		`{"registry": [{"path": "HKLM\\x", "name": "y", "products": "firewall"}]}`,
		`{"security": ["Minimum Password"]}`, `{"audit": ["Logon"]}`,
	} {
		if code, _ := ask(t, bad); code != 2 {
			t.Errorf("request %q: exit code %d, want 2", bad, code)
		}
	}
}
