//go:build windows

package jobs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestAdminOnlyOnWindows runs the Windows software scripts' Test-AdminOnly
// against real files: the agent must not run, as LocalSystem, a choco.exe
// or winget.exe that a standard user could have planted or replaced.
func TestAdminOnlyOnWindows(t *testing.T) {
	ps := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	script := filepath.Join(t.TempDir(), "check.ps1")
	body := adminOnlyScript + "\nif (Test-AdminOnly $args[0] $args[1]) { 'yes' } else { 'no' }\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(path, top string) string {
		t.Helper()
		out, err := exec.Command(ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, path, top).CombinedOutput()
		if err != nil {
			t.Fatalf("powershell: %v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}

	// Windows' own programs: only TrustedInstaller and administrators.
	system := os.Getenv("SystemRoot")
	if got := check(filepath.Join(system, `System32\cmd.exe`), system); got != "yes" {
		t.Errorf("cmd.exe: %s", got)
	}

	// A program in a folder its user may write to (a temporary folder
	// grants its user full control).
	dir := filepath.Join(t.TempDir(), "chocolatey")
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(bin, "choco.exe")
	cmd, err := os.ReadFile(filepath.Join(system, `System32\cmd.exe`))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, cmd, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := check(exe, dir); got != "no" {
		t.Errorf("a user's folder: %s", got)
	}

	// Locked to SYSTEM and Administrators, and owned by Administrators, as
	// Chocolatey's installer leaves its folder.
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, bin, exe} {
		if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
			t.Skipf("cannot make Administrators the owner here: %v", err)
		}
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if got := check(exe, dir); got != "yes" {
		t.Errorf("an administrators-only folder: %s", got)
	}

	// Not below the folder it should be in, or missing.
	if got := check(exe, filepath.Join(system, "System32")); got != "no" {
		t.Errorf("outside its folder: %s", got)
	}
	if got := check(filepath.Join(bin, "missing.exe"), dir); got != "no" {
		t.Errorf("a missing program: %s", got)
	}
}
