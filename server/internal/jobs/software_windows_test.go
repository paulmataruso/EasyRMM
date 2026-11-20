//go:build windows

package jobs

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// runSoftwareScript runs a Windows software script as the agent would, with
// extra environment, and returns its exit code and output.
func runSoftwareScript(t *testing.T, body string, env []string, args ...string) (int, string) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "software.ps1")
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ps := filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	cmd := exec.Command(ps, append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatalf("powershell: %v %s", err, out)
	}
	return cmd.ProcessState.ExitCode(), string(out)
}

// TestWingetScriptOnWindows runs the winget script against a stand-in
// winget.exe in App Installer's folder that exits with winget's own codes:
// removing what is not installed succeeds, updating it fails with 3, as on
// Linux.
func TestWingetScriptOnWindows(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte(`package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	fmt.Println("winget", os.Args[1:])
	code, _ := strconv.ParseInt(os.Getenv("FAKE_WINGET_EXIT"), 10, 32)
	os.Exit(int(int32(code)))
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	programFiles := filepath.Join(dir, "pf")
	app := filepath.Join(programFiles, "WindowsApps", "Microsoft.DesktopAppInstaller_1.2.3.0_x64__8wekyb3d8bbwe")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", filepath.Join(app, "winget.exe"), src)
	build.Dir = dir
	build.Env = append(os.Environ(), "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v %s", err, out)
	}

	for _, c := range []struct {
		action, wingetExit string
		want               int
		says               string
	}{
		{"install", "0", 0, "--scope machine"},
		{"install", "-1978335135", 0, "already installed"},      // 0x8A150061
		{"install", "-1978335212", 1, "has no package"},         // 0x8A150014
		{"upgrade", "-1978335189", 0, "No newer version"},       // 0x8A15002B
		{"upgrade", "-1978335212", 3, "cannot be updated"},      // 0x8A150014
		{"uninstall", "-1978335212", 0, "is not installed"},     // 0x8A150014
		{"uninstall", "-1978334967", 0, "Restart the computer"}, // 0x8A150109
		{"uninstall", "5", 1, "exit code 0x00000005"},
	} {
		code, out := runSoftwareScript(t, adminOnlyScript+wingetScript,
			[]string{"ProgramFiles=" + programFiles, "FAKE_WINGET_EXIT=" + c.wingetExit}, c.action, "Example.Package")
		if code != c.want || !strings.Contains(out, c.says) {
			t.Errorf("%s, winget exits %s: exit %d, want %d with %q:\n%s", c.action, c.wingetExit, code, c.want, c.says, out)
		}
	}
}

// TestChocolateyScriptOnWindows asks the Chocolatey script to remove and to
// update a package that Chocolatey does not have: the first succeeds and the
// second fails with 3, as on Linux, and choco itself never runs.
func TestChocolateyScriptOnWindows(t *testing.T) {
	root := os.Getenv("ChocolateyInstall")
	if root == "" {
		root = filepath.Join(os.Getenv("ProgramData"), "chocolatey")
	}
	if _, err := os.Stat(filepath.Join(root, "bin", "choco.exe")); err != nil {
		t.Skipf("Chocolatey is not installed here: %v", err)
	}
	const id = "easyrmm-test-not-a-package"
	for _, c := range []struct {
		action string
		want   int
		says   string
	}{
		{"uninstall", 0, id + " is not installed."},
		{"upgrade", 3, id + " is not installed, so it cannot be updated."},
	} {
		code, out := runSoftwareScript(t, adminOnlyScript+chocolateyScript, nil, c.action, id)
		if code == 2 && strings.Contains(out, "accounts other than administrators") {
			t.Skipf("this computer's Chocolatey folder is not administrators-only: %s", out)
		}
		if code != c.want || !strings.Contains(out, c.says) || strings.Contains(out, "+ choco") {
			t.Errorf("%s: exit %d, want %d with %q and no choco run:\n%s", c.action, code, c.want, c.says, out)
		}
	}
}

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
