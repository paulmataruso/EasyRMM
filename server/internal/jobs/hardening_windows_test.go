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
	"time"

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
			if s.State == "unknown" && m.Module != "tls" && m.Module != "device-guard" && m.Module != "time" && m.Module != "app-control" {
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

// runHardening runs the script a Windows job carries, with the agent's
// arguments, and parses its result as the server does for a job of that
// mode and modules.
func runHardening(t *testing.T, h Hardening, args ...string) *hardeningResult {
	t.Helper()
	script := filepath.Join(t.TempDir(), "easyrmm-hardening.ps1")
	if err := os.WriteFile(script, []byte(windowsHardeningScript), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(windowsPowerShell(), append([]string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}, args...)...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if stderr.Len() > 0 {
		t.Logf("stderr: %s", stderr.String())
	}
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	r, err := parseHardeningResult(string(out), h)
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return r
}

// regValue is a value as its type and data, or "absent".
func regValue(t *testing.T, path, name string) string {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, strings.TrimPrefix(path, `HKLM\`), registry.QUERY_VALUE)
	if err != nil {
		return "absent"
	}
	defer func() { _ = k.Close() }()
	if n, _, err := k.GetIntegerValue(name); err == nil {
		return fmt.Sprintf("dword:%d", n)
	}
	if s, _, err := k.GetStringValue(name); err == nil {
		return "string:" + s
	}
	return "absent"
}

// Apply, then undo, as LocalSystem on a real Windows (ADR-0054, W2): the
// autoplay module's values are written and read back, a second apply
// changes nothing, the guard's task is armed and a confirm ends it, undo
// returns every value to what the computer had before (present with its
// type, or absent), and the guard's own timer undoes a change that no one
// confirms. These tests change the computer's registry and
// %ProgramData%\EasyRMM\Hardening, so they run only on runners made for
// the job, like the others of the AsSystem job.
func TestWindowsHardeningApplyUndoAsSystem(t *testing.T) {
	hardeningSystemTest(t)
	hardening := filepath.Join(os.Getenv("ProgramData"), "EasyRMM", "Hardening")
	type value struct{ path, name string }
	var values []value
	for _, s := range windowsSettings {
		if s.Module == "autoplay" {
			values = append(values, value{s.Path, s.Name})
		}
	}
	if len(values) != 3 {
		t.Fatalf("autoplay has %d registry settings", len(values))
	}
	snap := func() map[value]string {
		m := map[value]string{}
		for _, v := range values {
			m[v] = regValue(t, v.path, v.name)
		}
		return m
	}
	before := snap()
	task := func() bool {
		return exec.Command("schtasks", "/Query", "/TN", `\EasyRMM\EasyRMM Hardening Rollback`).Run() == nil
	}
	restore := func() {
		for v, was := range before {
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, strings.TrimPrefix(v.path, `HKLM\`), registry.SET_VALUE)
			if err != nil {
				continue
			}
			if was == "absent" {
				_ = k.DeleteValue(v.name)
			} else if n, ok := strings.CutPrefix(was, "dword:"); ok {
				var d uint32
				_, _ = fmt.Sscan(n, &d)
				_ = k.SetDWordValue(v.name, d)
			}
			_ = k.Close()
		}
	}
	t.Cleanup(func() {
		_ = exec.Command("schtasks", "/Delete", "/TN", `\EasyRMM\EasyRMM Hardening Rollback`, "/F").Run()
		_ = os.RemoveAll(hardening)
		restore()
	})
	if err := os.RemoveAll(hardening); err != nil {
		t.Fatal(err)
	}
	autoplay := []string{"autoplay"}
	hApply := Hardening{Platform: HardeningWindows, Mode: HardeningApply, Modules: autoplay}
	hUndo := Hardening{Platform: HardeningWindows, Mode: HardeningUndo, Modules: autoplay}

	r := runHardening(t, hApply, "apply", "autoplay", "guard-minutes=30")
	m := r.Modules[0]
	if m.Outcome == HardeningRefused {
		t.Skipf("apply is refused on this computer, which is correct there: %s", m.OutcomeReason)
	}
	want := map[string]string{"autoplay-non-volume": "dword:1", "autoplay-autorun": "dword:1", "autoplay-all-drives": "dword:255"}
	byID := map[string]value{}
	for _, s := range windowsSettings {
		if s.Module == "autoplay" {
			byID[s.ID] = value{s.Path, s.Name}
		}
	}
	if m.Outcome != HardeningApplied && m.Outcome != HardeningUnchanged {
		t.Fatalf("apply: %s %s", m.Outcome, m.OutcomeReason)
	}
	for id, w := range want {
		if got := regValue(t, byID[id].path, byID[id].name); got != w {
			t.Errorf("%s after apply: %s, want %s", id, got, w)
		}
		if st := setting(r, "autoplay", id); st == nil || st.State != "in_place" {
			t.Errorf("%s read back: %+v", id, st)
		}
	}
	changed := m.Outcome == HardeningApplied
	if changed && !task() {
		t.Error("the guard's task was not armed")
	}
	for _, f := range []string{"manifest.json", "easyrmm-hardening.ps1"} {
		if _, err := os.Stat(filepath.Join(hardening, f)); changed && err != nil {
			t.Errorf("no %s after apply: %v", f, err)
		}
	}

	// A second apply changes nothing.
	if r = runHardening(t, hApply, "apply", "autoplay"); r.Modules[0].Outcome != HardeningUnchanged {
		t.Errorf("second apply: %s %s", r.Modules[0].Outcome, r.Modules[0].OutcomeReason)
	}

	// The confirm job's script ends the guard.
	cmd := exec.Command(windowsPowerShell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
		filepath.Join(hardening, "easyrmm-hardening.ps1"), "confirm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("confirm: %v %s", err, out)
	}
	if task() {
		t.Error("the guard's task is still there after confirm")
	}

	// Undo, from the copy on the computer itself, as the guide says.
	cmd = exec.Command(windowsPowerShell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
		filepath.Join(hardening, "easyrmm-hardening.ps1"), "undo", "all")
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), HardeningResultPrefix) {
		t.Fatalf("undo from the copy: %v %s", err, out)
	}
	for v, was := range before {
		if got := regValue(t, v.path, v.name); got != was {
			t.Errorf("%s\\%s after undo: %s, was %s", v.path, v.name, got, was)
		}
	}
	// The same through the job's script: nothing is left to undo.
	if r = runHardening(t, hUndo, "undo", "autoplay"); r.Modules[0].Outcome != HardeningNothingToUndo {
		t.Errorf("undo with no record: %s", r.Modules[0].Outcome)
	}

	// Undo of a value an administrator changed afterwards leaves it.
	runHardening(t, hApply, "apply", "autoplay")
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, strings.TrimPrefix(byID["autoplay-autorun"].path, `HKLM\`), registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	_ = k.SetDWordValue(byID["autoplay-autorun"].name, 7)
	_ = k.Close()
	r = runHardening(t, hUndo, "undo", "autoplay")
	if o := r.Modules[0].Outcome; o != HardeningPartlyUndone {
		t.Errorf("undo of a changed value: %s", o)
	}
	if got := regValue(t, byID["autoplay-autorun"].path, byID["autoplay-autorun"].name); got != "dword:7" {
		t.Errorf("the changed value was not left: %s", got)
	}
	_ = os.RemoveAll(hardening)
	restore()

	// An unconfirmed change is undone by the computer's own timer.
	runHardening(t, hApply, "apply", "--settings", "autoplay-autorun", "guard-minutes=1")
	deadline := time.Now().Add(5 * time.Minute)
	for regValue(t, byID["autoplay-autorun"].path, byID["autoplay-autorun"].name) != before[byID["autoplay-autorun"]] {
		if time.Now().After(deadline) {
			t.Fatal("the guard did not undo the change within five minutes")
		}
		time.Sleep(10 * time.Second)
	}
	if task() {
		t.Error("the task is still there after it undid the change")
	}
	if b, err := os.ReadFile(filepath.Join(hardening, "last-rollback.json")); err != nil || !strings.Contains(string(b), "autoplay-autorun") {
		t.Errorf("no note of the rollback: %v %s", err, b)
	}
}

// The apply and undo logic of the script on Windows PowerShell 5.1, which
// the agent runs it with, against a registry that is a hashtable (the same
// harness and expected output as the PowerShell 7 test).
func TestWindowsApplyUndoFlowOnWindows(t *testing.T) {
	dir, _ := filepath.Abs("hardening")
	harness, _ := filepath.Abs(filepath.Join("testdata", "windows-flow-harness.ps1"))
	out, err := exec.Command(windowsPowerShell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", harness,
		"-Script", filepath.Join(dir, "windows.ps1"), "-Settings", filepath.Join(dir, "windows-settings.json")).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "windows-flow-expected.txt"))
	if err != nil {
		t.Fatal(err)
	}
	norm := func(b []byte) string { return strings.ReplaceAll(strings.TrimSpace(string(b)), "\r\n", "\n") }
	if norm(out) != norm(want) {
		t.Errorf("the flow printed\n%s\nwant\n%s", out, want)
	}
}
