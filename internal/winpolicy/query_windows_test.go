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

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The reader started on its own, as the agent is to start it: Windows
// PowerShell 5.1 as LocalSystem. CI's job "Windows hardening as
// LocalSystem" starts these tests through a scheduled task with
// EASYRMM_TEST_SYSTEM set; they write a value under HKLM\SOFTWARE\Policies,
// so they run only on computers made for the job.

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

type answers struct {
	Registry []answer `json:"registry"`
	Security []answer `json:"security"`
	Audit    []answer `json:"audit"`
	Notes    []string `json:"notes"`
}

// ask starts the reader with a request and returns its exit code and the
// answers it printed.
func ask(t *testing.T, request string) (int, *answers) {
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
	return code, &a
}

// enrolledInMDM reads the enrolments as the reader's rule does: enrolled,
// and found through a discovery service.
func enrolledInMDM(t *testing.T) bool {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Enrollments`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		e, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		state, _, _ := e.GetIntegerValue("EnrollmentState")
		url, _, _ := e.GetStringValue("DiscoveryServiceFullURL")
		_ = e.Close()
		if state == 1 && url != "" {
			return true
		}
	}
	return false
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

func TestQueryAsSystem(t *testing.T) {
	systemTest(t)
	// A value under Policies that no owner the reader knows explains.
	const key = `SOFTWARE\Policies\EasyRMM-winpolicy-test`
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.DeleteKey(registry.LOCAL_MACHINE, key) })
	if err := k.SetDWordValue("Planted", 1); err != nil {
		t.Fatal(err)
	}
	_ = k.Close()

	request := `{"registry": [
		{"path": "HKLM\\` + strings.ReplaceAll(key, `\`, `\\`) + `", "name": "Planted"},
		{"path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "name": "DisableRealtimeMonitoring", "csp": "Defender/AllowRealtimeMonitoring", "defender": true},
		{"path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "name": "UseLogonCredential"}],
	 "security": ["MinimumPasswordLength", "LockoutBadCount"],
	 "audit": ["0cce9215-69ae-11d9-bed3-505054503030", "{0CCE922B-69AE-11D9-BED3-505054503030}"]}`
	code, a := ask(t, request)
	if code != 0 || len(a.Registry) != 3 || len(a.Security) != 2 || len(a.Audit) != 2 {
		t.Fatalf("exit code %d, answers %+v", code, a)
	}
	b, _ := json.Marshal(a)
	t.Logf("answers %s", b)
	for i, x := range a.Registry {
		checkAnswer(t, "registry "+strconv.Itoa(i), x)
	}
	for i, x := range a.Security {
		checkAnswer(t, "security "+strconv.Itoa(i), x)
	}
	for i, x := range a.Audit {
		checkAnswer(t, "audit "+strconv.Itoa(i), x)
	}
	// The planted value is never "none": unexplained, or another reason
	// that holds for the whole computer. The answers keep the request's
	// order: a value outside Policies is never unexplained.
	if a.Registry[0].Result != ResultCannotTell {
		t.Errorf("a value under Policies no one explains: %+v", a.Registry[0])
	}
	if slices.Contains(a.Registry[2].Reasons, ReasonUnexplainedPolicy) {
		t.Errorf("a value outside Policies: %+v", a.Registry[2])
	}
	if p := a.Registry[1]; slices.Contains(p.Reasons, ReasonMDM) && (p.MDM == nil || p.MDM.CSP != "Defender/AllowRealtimeMonitoring") {
		t.Errorf("an MDM reason without what the MDM reader read: %+v", p)
	}
	// Windows' own enrolments, on every computer, are not an MDM.
	if !enrolledInMDM(t) {
		for i, x := range a.Registry {
			if slices.Contains(x.Reasons, ReasonMDM) {
				t.Errorf("registry %d: an MDM reason on a computer no MDM enrolled: %+v", i, x)
			}
		}
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
	b, _ := json.Marshal(a)
	t.Logf("answers %s", b)

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
		`{"security": ["Minimum Password"]}`, `{"audit": ["Logon"]}`,
	} {
		if code, _ := ask(t, bad); code != 2 {
			t.Errorf("request %q: exit code %d, want 2", bad, code)
		}
	}
}
