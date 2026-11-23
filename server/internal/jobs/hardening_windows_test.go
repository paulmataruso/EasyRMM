//go:build windows

package jobs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/paulmataruso/easyrmm/internal/winpolicy"
	"github.com/paulmataruso/easyrmm/internal/wintest"
)

// Windows hardening's check (ADR-0054, W1) on a real Windows, as the
// agent's service runs jobs: as LocalSystem, with Windows PowerShell 5.1.
// CI's job "Windows hardening as LocalSystem" starts these tests through a
// scheduled task (scripts/ci/run-as-system.ps1) with EASYRMM_TEST_SYSTEM
// set. They plant and remove %ProgramData%\EasyRMM\Hardening, so they run
// only on computers made for the job.

// hardeningSystemTest skips a test unless it may run, and fails one that
// is not running as LocalSystem.
func hardeningSystemTest(t *testing.T) {
	t.Helper()
	if os.Getenv("EASYRMM_TEST_SYSTEM") == "" {
		t.Skip("runs as LocalSystem on a computer made for it; CI's job sets EASYRMM_TEST_SYSTEM")
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatalf("not running as LocalSystem (%v)", err)
	}
}

func windowsPowerShell() string {
	return filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
}

// checkAll runs the script a Windows job carries, with the agent's
// arguments (agent/jobs), to check every module, and parses its result as
// the server does.
func checkAll(t *testing.T) *hardeningResult {
	t.Helper()
	script := filepath.Join(t.TempDir(), "easyrmm-hardening.ps1")
	if err := os.WriteFile(script, []byte(windowsHardeningScript), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(windowsPowerShell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", script, "check", "all")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if stderr.Len() > 0 {
		t.Logf("stderr: %s", stderr.String())
	}
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	h := Hardening{Platform: HardeningWindows, Mode: HardeningCheck, Modules: slices.Clone(WindowsHardeningModules)}
	r, err := parseHardeningResult(string(out), h)
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return r
}

func setting(r *hardeningResult, module, id string) *HardeningSetting {
	for _, m := range r.Modules {
		if m.Module != module {
			continue
		}
		for i := range m.Settings {
			if m.Settings[i].ID == id {
				return &m.Settings[i]
			}
		}
	}
	return nil
}

// powershellValue reads one value with a PowerShell of its own.
func powershellValue(t *testing.T, command string) string {
	t.Helper()
	out, err := exec.Command(windowsPowerShell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command).Output()
	if err != nil {
		t.Fatalf("%s: %v", command, err)
	}
	return strings.TrimSpace(string(out))
}

// checkedKeys are the keys under HKLM whose values check reads: the
// settings' policy and local keys, the attack surface reduction rules' and
// the audit table's.
func checkedKeys(t *testing.T) []string {
	t.Helper()
	var a winpolicy.AuditTable
	if err := json.Unmarshal([]byte(winpolicy.AuditJSON()), &a); err != nil {
		t.Fatal(err)
	}
	paths := []string{`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`}
	for _, s := range windowsSettings {
		paths = append(paths, s.Path, s.LocalPath)
	}
	for _, v := range a.Values {
		paths = append(paths, v.Path)
	}
	var keys []string
	for _, p := range paths {
		if k, ok := strings.CutPrefix(p, `HKLM\`); ok && !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	return keys
}

// registrySnapshot: every value of the keys, as its type and data, or the
// key's absence.
func registrySnapshot(t *testing.T, keys []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, path := range keys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			out[path] = "not opened: " + err.Error()
			continue
		}
		names, err := k.ReadValueNames(-1)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, n := range names {
			size, _, err := k.GetValue(n, nil)
			if err != nil {
				t.Fatalf(`%s\%s: %v`, path, n, err)
			}
			buf := make([]byte, size)
			size, typ, err := k.GetValue(n, buf)
			if err != nil {
				t.Fatalf(`%s\%s: %v`, path, n, err)
			}
			out[path+`\`+n] = fmt.Sprintf("%d %x", typ, buf[:size])
		}
		_ = k.Close()
	}
	return out
}

// policyExports: the security policy (secedit /export) and audit policy
// (auditpol /backup) as Windows' own tools write them.
func policyExports(t *testing.T) [2][]byte {
	t.Helper()
	dir := t.TempDir()
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	security := filepath.Join(dir, "security.inf")
	audit := filepath.Join(dir, "audit.csv")
	if out, err := exec.Command(filepath.Join(sys, "secedit.exe"), "/export", "/cfg", security, "/areas", "SECURITYPOLICY", "/quiet").CombinedOutput(); err != nil {
		t.Fatalf("secedit: %v %s", err, out)
	}
	if out, err := exec.Command(filepath.Join(sys, "auditpol.exe"), "/backup", "/file:"+audit).CombinedOutput(); err != nil {
		t.Fatalf("auditpol: %v %s", err, out)
	}
	var out [2][]byte
	for i, f := range []string{security, audit} {
		b, err := os.ReadFile(f)
		if err != nil || len(b) == 0 {
			t.Fatalf("%s: %v", f, err)
		}
		out[i] = b
	}
	return out
}

func TestWindowsHardeningCheckAsSystem(t *testing.T) {
	hardeningSystemTest(t)
	hardening := filepath.Join(os.Getenv("ProgramData"), "EasyRMM", "Hardening")
	if err := os.RemoveAll(hardening); err != nil {
		t.Fatal(err)
	}
	// What check reads, before and after: it changes none of it (ADR-0054,
	// check mode).
	keys := checkedKeys(t)
	values := registrySnapshot(t, keys)
	exports := policyExports(t)
	r := checkAll(t)
	after := registrySnapshot(t, keys)
	// Windows itself writes these while the check runs: LSA turns its own
	// protection on (Windows 11 24H2 and Server 2025 evaluate it after boot),
	// so a runner's first minutes can see them appear.
	for _, k := range []string{`SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`, `SYSTEM\CurrentControlSet\Control\Lsa\IsPplAutoEnabled`} {
		if values[k] != after[k] {
			t.Logf("Windows changed %s: %q, then %q", k, values[k], after[k])
		}
		delete(values, k)
		delete(after, k)
	}
	if !maps.Equal(values, after) {
		for k, v := range after {
			if values[k] != v {
				t.Errorf("check changed %s: %q, then %q", k, values[k], v)
			}
		}
		for k, v := range values {
			if _, ok := after[k]; !ok {
				t.Errorf("check removed %s (%q)", k, v)
			}
		}
	}
	if after := policyExports(t); !bytes.Equal(exports[0], after[0]) || !bytes.Equal(exports[1], after[1]) {
		t.Errorf("check changed the security or audit policy:\n%s\n%s\nthen\n%s\n%s", exports[0], exports[1], after[0], after[1])
	}
	t.Logf("%d values in %d keys unchanged", len(values), len(keys))
	w := r.Platform.Windows
	b, _ := json.Marshal(r.Platform)
	t.Logf("platform %s", b)
	if w.LanguageMode != "FullLanguage" || w.Hardening == nil || w.Hardening.Folder != "absent" || w.Owners == nil {
		t.Errorf("platform %s", b)
	}
	wantSupport := "full"
	if runtime.GOARCH == "arm64" {
		wantSupport = "check_only" // ADR-0054, Platforms: ARM64 waits
	}
	if r.Platform.Support != wantSupport {
		t.Errorf("support %s, want %s", r.Platform.Support, wantSupport)
	}
	for _, m := range r.Modules {
		t.Logf("%s: %s %s", m.Module, m.State, m.Reason)
		if m.State == HardeningFailed || m.State == HardeningNotSupported {
			t.Errorf("module %s: %s (%s)", m.Module, m.State, m.Reason)
		}
		for _, s := range m.Settings {
			if s.State == "unknown" && m.Module != "tls" && m.Module != "device-guard" {
				t.Errorf("setting %s could not be read: %s", s.ID, s.Note)
			}
		}
	}
	// A check makes nothing where the folder is absent.
	if _, err := os.Stat(hardening); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the check made %s: %v", hardening, err)
	}

	// What the runner image turned off is reported as it is (ADR-0054,
	// Testing: Defender's real-time protection, UAC's prompt).
	if s := setting(r, "uac", "uac-consent-admin"); s != nil {
		want := powershellValue(t, `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').ConsentPromptBehaviorAdmin`)
		if s.Value != want || (want == "0" && s.State == "in_place") {
			t.Errorf("uac-consent-admin %+v, registry %s", s, want)
		}
	}
	if s := setting(r, "defender", "defender-realtime"); s != nil {
		want := powershellValue(t, `(Get-MpPreference).DisableRealtimeMonitoring`)
		if s.Value != want || (want == "True" && s.State == "in_place") {
			t.Errorf("defender-realtime %+v, Get-MpPreference %s", s, want)
		}
	}
	if s := setting(r, "audit", "audit-subcategories"); s == nil {
		t.Error("no audit subcategories")
	}
}

// TestWindowsHardeningUnreadableAsSystem: keys LocalSystem may not read
// (WDigest's and SCHANNEL's own, denied to it alone; policy keys planted
// and denied to everyone where they are absent) make each setting read
// from them unknown, with the error: never "not set (Windows default)" and
// in place, or not in place. WDigest's module, which has nothing else to
// read, failed.
func TestWindowsHardeningUnreadableAsSystem(t *testing.T) {
	hardeningSystemTest(t)
	keys := map[string][]string{
		`SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`:                           {"wdigest-logon-credential"},
		`SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client`: {"tls-ssl2-client"},
		`SOFTWARE\Policies\Microsoft\Windows\Installer`:                                        {"uac-installer-elevated"},
		`SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint`:                        {"printing-driver-admins"},
		`SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`:                                    {"winrm-service-basic", "winrm-service-unencrypted", "winrm-service-runas"},
		`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`:                                     {"name-resolution-llmnr"},
	}
	for k := range keys {
		wintest.Unreadable(t, k, wintest.SystemSID)
	}
	r := checkAll(t)
	for k, ids := range keys {
		for _, id := range ids {
			// UAC's module does not apply on Server Core, and reads nothing
			// there; every other module reads its keys.
			module := windowsSettings[slices.IndexFunc(windowsSettings, func(s windowsSetting) bool { return s.ID == id })].Module
			if module == "uac" && r.Platform.Windows != nil && r.Platform.Windows.InstallationType == "Server Core" {
				if i := slices.IndexFunc(r.Modules, func(m HardeningModuleResult) bool { return m.Module == module }); i >= 0 && r.Modules[i].State == "not_applicable" {
					t.Logf("%s: UAC's module is not applicable on Server Core (%s)", id, r.Modules[i].Reason)
					continue
				}
			}
			if s := setting(r, module, id); s == nil || s.State != "unknown" || !strings.Contains(s.Note, "could not be read") {
				t.Errorf(`%s, with HKLM\%s unreadable: %+v, want unknown with the error`, id, k, s)
			}
		}
	}
	for _, m := range r.Modules {
		if m.Module == "wdigest" && (m.State != HardeningFailed || m.Reason != "None of its settings could be read.") {
			t.Errorf("wdigest: %s (%s), want failed", m.State, m.Reason)
		}
	}
}

// The Hardening folder's check (ADR-0054, Backups, undo and interruptions),
// in check mode.
func TestWindowsHardeningFolderAsSystem(t *testing.T) {
	hardeningSystemTest(t)
	hardening := filepath.Join(os.Getenv("ProgramData"), "EasyRMM", "Hardening")
	icacls := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
			t.Fatalf("icacls %q: %v %s", args, err, out)
		}
	}
	fresh := func() {
		t.Helper()
		if err := os.RemoveAll(hardening); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(hardening, 0o700); err != nil {
			t.Fatal(err)
		}
		icacls(hardening, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
	}
	t.Cleanup(func() { _ = os.RemoveAll(hardening) })
	notSupported := func(r *hardeningResult) bool {
		for _, m := range r.Modules {
			if m.State != HardeningNotSupported {
				return false
			}
		}
		return true
	}

	// A folder users may write to is refused and left where it is.
	fresh()
	icacls(hardening, "/grant", "*S-1-5-32-545:(OI)(CI)M")
	r := checkAll(t)
	if f := r.Platform.Windows.Hardening; f.Folder != "refused" || !notSupported(r) {
		t.Errorf("a folder users may write to: %+v", f)
	}
	if _, err := os.Stat(hardening); err != nil {
		t.Errorf("the refused folder was moved: %v", err)
	}

	// A read-only grant is set back, with a warning, and the run goes on;
	// the lock file is made.
	fresh()
	icacls(hardening, "/grant", "*S-1-5-32-545:(OI)(CI)RX")
	r = checkAll(t)
	if f := r.Platform.Windows.Hardening; f.Folder != "present" || len(f.Warnings) != 1 || notSupported(r) {
		t.Errorf("a read-only grant: %+v", f)
	}
	if _, err := os.Stat(filepath.Join(hardening, "lock")); err != nil {
		t.Errorf("no lock file: %v", err)
	}

	// A hard-linked manifest is moved aside within the folder and the run
	// refused, naming its new path.
	fresh()
	manifest := filepath.Join(hardening, "manifest.json")
	if err := os.WriteFile(manifest, []byte(`{"formatVersion":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(manifest, filepath.Join(hardening, "second-name")); err != nil {
		t.Fatal(err)
	}
	r = checkAll(t)
	if f := r.Platform.Windows.Hardening; len(f.SetAside) != 1 || !strings.HasPrefix(f.SetAside[0], manifest+".set-aside-") || !notSupported(r) {
		t.Errorf("a hard-linked manifest: %+v", f)
	}

	// A module begun and not finished is half applied.
	fresh()
	if err := os.WriteFile(manifest, []byte(`{"formatVersion":1,"modules":{"wdigest":{"intent":"2026-11-22T00:00:00Z"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r = checkAll(t)
	if f := r.Platform.Windows.Hardening; f.Folder != "present" || len(f.Warnings) != 0 {
		t.Errorf("a manifest with the access list it inherits: %+v", f)
	}
	for _, m := range r.Modules {
		if (m.Module == "wdigest") != (m.State == HardeningHalfApplied) {
			t.Errorf("module %s: %s (%s); folder %+v", m.Module, m.State, m.Reason, r.Platform.Windows.Hardening)
		}
	}

	// A junction in the path is refused.
	if err := os.RemoveAll(hardening); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", hardening, t.TempDir()).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	r = checkAll(t)
	if f := r.Platform.Windows.Hardening; f.Folder != "refused" || !notSupported(r) {
		t.Errorf("a junction: %+v", f)
	}
}
