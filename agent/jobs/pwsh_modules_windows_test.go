//go:build windows

package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/paulmataruso/easyrmm/agent/powershell"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// grantUsers gives BUILTIN\Users the right to change p and what it holds.
func grantUsers(t *testing.T, p string) {
	t.Helper()
	out, err := exec.Command(filepath.Join(systemRoot(), `System32\icacls.exe`), p, "/grant", "*S-1-5-32-545:(OI)(CI)(M)").CombinedOutput() //nolint:gosec // the test's own folder
	if err != nil {
		t.Fatalf("icacls: %v\n%s", err, out)
	}
}

// TestPwshBlockedAsSystem: a module folder that Users may change, in
// Windows PowerShell's folder in Program Files or in PowerShell 7's shared
// one, stops a pwsh run before anything starts, and a script that allows
// Windows PowerShell does not run there instead: Windows PowerShell loads
// from its own folder too (ADR-0064).
func TestPwshBlockedAsSystem(t *testing.T) {
	systemTest(t)
	roots, err := powershell.Roots()
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	for _, folder := range []string{
		filepath.Join(roots[0], `WindowsPowerShell\Modules`),
		filepath.Join(roots[0], `PowerShell\Modules`),
	} {
		_, statErr := os.Stat(folder)
		planted := filepath.Join(folder, "EasyRMM open "+hex.EncodeToString(b))
		if err := os.MkdirAll(planted, 0o755); err != nil {
			t.Fatal(err)
		}
		grantUsers(t, planted)
		p := winPayload(agentproto.ShellPwsh, "Write-Output ran\n")
		p.PwshFallback = true
		res := Execute(context.Background(), p, t.TempDir())
		want := "PowerShell 7 would load modules from " + folder + ", and " + planted + ` can be changed by BUILTIN\Users; the script was not run.`
		if res.Status != agentproto.RunFailed || res.Error != want || res.Interpreter != nil || res.ExitCode != nil || res.Stdout != "" {
			t.Errorf("with %s open to Users: %+v\nwant the error %q", planted, res, want)
		}
		for _, i := range powershell.Discover(roots) {
			if i.Edition == agentproto.EditionCore && (i.Usable || (!i.Store && i.Arch != agentproto.ArchX86 && !i.Blocked)) {
				t.Errorf("an install with %s open to Users: %+v", planted, i)
			}
		}
		if err := os.RemoveAll(planted); err != nil {
			t.Fatal(err)
		}
		if errors.Is(statErr, os.ErrNotExist) {
			_ = os.Remove(folder)
		}
	}
	// Closed again, the same script runs in PowerShell 7.
	res := Execute(context.Background(), winPayload(agentproto.ShellPwsh, "Write-Output \"edition:$($PSVersionTable.PSEdition)\"\n"), t.TempDir())
	if line(res.Stdout, "edition:") != "Core" {
		t.Errorf("closed again: %+v", res)
	}
}

// TestPwshCompatibilitySessionAsSystem: a module that only Windows
// PowerShell can load is loaded by PowerShell 7 in a Windows PowerShell
// process of its own (implicit compatibility, kept: scripts rely on it).
// That process's module path is the run's two Windows PowerShell folders,
// which the run checked, and nothing else: not the folders the computer's
// or the system account's PSModulePath names, planted here (ADR-0064).
func TestPwshCompatibilitySessionAsSystem(t *testing.T) {
	systemTest(t)
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	machineFolder := filepath.Join(os.Getenv("SystemDrive")+`\`, "EasyRMM machine "+hex.EncodeToString(b))
	userFolder := filepath.Join(os.Getenv("SystemDrive")+`\`, "EasyRMM system user "+hex.EncodeToString(b))
	for _, f := range []string{machineFolder, userFolder} {
		if err := os.Mkdir(f, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(f) })
	}
	addToPath(t, registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, machineFolder)
	addToPath(t, registry.CURRENT_USER, `Environment`, userFolder)

	roots, _ := powershell.Roots()
	run, err := powershell.ForRun(roots)
	if err != nil {
		t.Fatal(err)
	}
	run.Release()
	res := Execute(context.Background(), winPayload(agentproto.ShellPwsh,
		compatScript+
			"$s = Get-PSSession -Name WinPSCompatSession -ErrorAction SilentlyContinue\n"+
			"if ($s) { 'compat:' + (Invoke-Command -Session $s { $env:PSModulePath }); 'compat edition:' + (Invoke-Command -Session $s { $PSVersionTable.PSEdition }) } else { 'compat:none' }\n"),
		t.TempDir())
	t.Logf("stdout:\n%s\nstderr:\n%s", res.Stdout, res.Stderr)
	if line(res.Stdout, "imported:") == "(no line imported:)" || line(res.Stdout, "compat edition:") != "Desktop" {
		t.Fatalf("no module was loaded in a compatibility session: %+v", res)
	}
	want, _ := strings.CutPrefix(run.Env[0], "PSModulePath=")
	if got := line(res.Stdout, "compat:"); !strings.EqualFold(got, want) {
		t.Errorf("the compatibility session's module path %q, want the run's Windows PowerShell folders %q", got, want)
	}
}

// copyInstall copies the runner's PowerShell 7 into a Program Files of the
// test's own, which has Program Files' access list, and points pwsh runs
// at it until the test ends. It returns the copy's folder.
func copyInstall(t *testing.T) string {
	t.Helper()
	roots, err := powershell.Roots()
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	root := filepath.Join(roots[0], "EasyRMM test "+hex.EncodeToString(b))
	install := filepath.Join(root, `PowerShell\7`)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	copyTree(t, filepath.Join(roots[0], `PowerShell\7`), install)
	old := pwshRoots
	pwshRoots = func() ([]string, error) { return []string{root}, nil }
	t.Cleanup(func() { pwshRoots = old })
	return install
}

// copyTree copies the folder from, and what it holds, to the folder to.
func copyTree(t *testing.T, from, to string) {
	t.Helper()
	if err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o755)
		}
		copyFile(t, p, filepath.Join(to, rel))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// hold opens p, a file or a folder, to read it and shares it with no one,
// as any user who may read it could, until the function it returns is
// called or the test ends.
func hold(t *testing.T, p string) func() {
	t.Helper()
	name, _ := windows.UTF16PtrFromString(p)
	h, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("holding %s: %v", p, err)
	}
	var once sync.Once
	let := func() { once.Do(func() { _ = windows.CloseHandle(h) }) }
	t.Cleanup(let)
	return let
}

// blockedWhileHeld checks that a pwsh script that allows Windows
// PowerShell fails, and does not run there instead, with an error that
// starts with want, and that the inventory lists listed as blocked, could
// not be checked, and no PowerShell 7 as usable (ADR-0064).
func blockedWhileHeld(t *testing.T, listed, want string) {
	t.Helper()
	p := winPayload(agentproto.ShellPwsh, "Write-Output ran\n")
	p.PwshFallback = true
	res := Execute(context.Background(), p, t.TempDir())
	if res.Status != agentproto.RunFailed || !strings.HasPrefix(strings.ToLower(res.Error), strings.ToLower(want)) || !strings.HasSuffix(res.Error, "; the script was not run.") ||
		res.Interpreter != nil || res.ExitCode != nil || res.Stdout != "" {
		t.Errorf("held: %+v, program %+v\nwant an error that starts %q", res, res.Interpreter, want)
	}
	roots, _ := pwshRoots()
	found := false
	for _, i := range powershell.Discover(roots) {
		t.Logf("the inventory lists %+v", i)
		if i.Edition == agentproto.EditionCore && i.Usable {
			t.Errorf("usable while held: %+v", i)
		}
		if strings.EqualFold(i.Path, listed) {
			found = true
			if !i.Blocked || !strings.HasPrefix(i.Reason, "Could not be checked: ") || !strings.HasSuffix(i.Reason, "Scripts that allow Windows PowerShell 5.1 do not run in it instead.") {
				t.Errorf("held, the inventory lists %+v", i)
			}
		}
	}
	if !found {
		t.Errorf("held, the inventory does not list %s", listed)
	}
}

// usedAgain checks that a pwsh run uses the copy at install.
func usedAgain(t *testing.T, install string) {
	t.Helper()
	res := Execute(context.Background(), winPayload(agentproto.ShellPwsh, "Write-Output \"edition:$($PSVersionTable.PSEdition)\"\n"), t.TempDir())
	if line(res.Stdout, "edition:") != "Core" || res.Interpreter == nil || !strings.EqualFold(res.Interpreter.Path, filepath.Join(install, "pwsh.exe")) {
		t.Errorf("let go: %+v", res)
	}
}

// TestPwshUnlistedAsSystem: the folder PowerShell 7's installs are in,
// opened and shared with no one, as any user who may list it could, so
// that the agent cannot list it, stops a pwsh run, and a script that
// allows Windows PowerShell does not run there instead; the inventory lists
// the folder as could not be checked, not PowerShell 7 as not installed
// (ADR-0064). A stand-in: the test's own process holds the folder, which
// is a copy's in a Program Files of the test's own; what the agent meets
// is the share mode, not who holds it.
func TestPwshUnlistedAsSystem(t *testing.T) {
	systemTest(t)
	install := copyInstall(t)
	folder := filepath.Dir(install)
	let := hold(t, folder)
	blockedWhileHeld(t, folder, folder+" could not be checked: open "+folder+": ")
	let()
	usedAgain(t, install)
}

// TestPwshUnreadProgramAsSystem: an install's pwsh.exe opened and shared
// with no one, or with its header locked, as any user who may read it
// could, so that the agent cannot read its version or architecture, stops
// a pwsh run, and a script that allows Windows PowerShell does not run
// there instead; the inventory lists the install as could not be checked
// (ADR-0064). A stand-in: the test's own process holds the copy's
// pwsh.exe; what the agent meets is the share mode and the lock, not who
// holds them.
func TestPwshUnreadProgramAsSystem(t *testing.T) {
	systemTest(t)
	install := copyInstall(t)
	pwsh := filepath.Join(install, "pwsh.exe")
	let := hold(t, pwsh)
	blockedWhileHeld(t, pwsh, pwsh+" could not be checked: ")
	let()
	usedAgain(t, install)

	f, err := os.Open(pwsh) //nolint:gosec // the test's own copy
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	var o windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 4096, 0, &o); err != nil {
		t.Fatal(err)
	}
	blockedWhileHeld(t, pwsh, pwsh+" could not be checked: ")
	if err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 4096, 0, &o); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	usedAgain(t, install)
}

// TestPwshUncheckedFolderAsSystem: a folder in an install opened and shared
// with no one, as any user who may read it could, so that the agent cannot
// check what it holds, stops a pwsh run, and a script that allows Windows
// PowerShell does not run there instead; the inventory lists the install
// as could not be checked (ADR-0064). A stand-in: the test's own process
// holds the copy's Modules folder; what the agent meets is the share mode,
// not who holds it.
func TestPwshUncheckedFolderAsSystem(t *testing.T) {
	systemTest(t)
	install := copyInstall(t)
	folder := filepath.Join(install, "Modules")
	let := hold(t, folder)
	pwsh := filepath.Join(install, "pwsh.exe")
	blockedWhileHeld(t, pwsh, pwsh+" could not be checked: open "+folder+": ")
	let()
	usedAgain(t, install)
}

// TestPwshBusyAsSystem: a file of the install that another program holds
// open, here pwsh.dll opened to read and shared with no one, as any user who
// may read it could, stops a pwsh run, and a script that allows Windows
// PowerShell does not run there instead: otherwise anyone could send
// scripts to it (ADR-0064). The test's own process holds the file, standing
// in for a user's: what the check meets is the share mode, not who holds it.
func TestPwshBusyAsSystem(t *testing.T) {
	systemTest(t)
	install := copyInstall(t)
	dll := filepath.Join(install, "pwsh.dll")
	name, _ := windows.UTF16PtrFromString(dll)
	h, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := winPayload(agentproto.ShellPwsh, "Write-Output ran\n")
	p.PwshFallback = true
	res := Execute(context.Background(), p, t.TempDir())
	want := dll + " is open in another program that may write to it; the script was not run."
	if res.Status != agentproto.RunFailed || !strings.EqualFold(res.Error, want) || res.Interpreter != nil || res.ExitCode != nil || res.Stdout != "" {
		t.Errorf("with pwsh.dll held: %+v\nwant the error %q", res, want)
	}
	roots, _ := pwshRoots()
	for _, i := range powershell.Discover(roots) {
		if strings.EqualFold(i.Path, filepath.Join(install, "pwsh.exe")) && (i.Usable || !i.Blocked || !strings.HasPrefix(strings.ToLower(i.Reason), strings.ToLower(dll)+" is open in another program")) {
			t.Errorf("the copy with pwsh.dll held: %+v", i)
		}
	}
	_ = windows.CloseHandle(h)
	usedAgain(t, install)

	// With a second install that passes every check, a run held off the
	// first uses the second, never Windows PowerShell: the one it moves to
	// is changeable by administrators only, as the first is (ADR-0064).
	second := filepath.Join(filepath.Dir(install), "8")
	copyTree(t, install, second)
	let := hold(t, dll)
	res = Execute(context.Background(), p, t.TempDir())
	if res.Status != agentproto.RunSucceeded || res.Interpreter == nil || res.Interpreter.Fallback || !strings.EqualFold(res.Interpreter.Path, filepath.Join(second, "pwsh.exe")) {
		t.Errorf("with pwsh.dll held and a second install: %+v", res)
	}
	let()
	usedAgain(t, install)
}

// TestPwshHardLinkAsSystem: a file of the install with a second hard link,
// here pwsh.dll, stops a pwsh run, and a script that allows Windows
// PowerShell does not run there instead: which Windows builds let a user
// link to a file they may only read is not confirmed, and one who could
// would otherwise choose where scripts run (ADR-0064). A stand-in: the test,
// as SYSTEM, makes the link, beside the copy in a Program Files of the
// test's own; what the check meets is the file's count of links, not who
// made the link.
func TestPwshHardLinkAsSystem(t *testing.T) {
	systemTest(t)
	install := copyInstall(t)
	dll := filepath.Join(install, "pwsh.dll")
	link := filepath.Join(filepath.Dir(filepath.Dir(install)), "pwsh.dll link")
	if err := os.Link(dll, link); err != nil {
		t.Fatal(err)
	}
	p := winPayload(agentproto.ShellPwsh, "Write-Output ran\n")
	p.PwshFallback = true
	res := Execute(context.Background(), p, t.TempDir())
	want := dll + " has 2 hard links; the script was not run."
	if res.Status != agentproto.RunFailed || !strings.EqualFold(res.Error, want) || res.Interpreter != nil || res.ExitCode != nil || res.Stdout != "" {
		t.Errorf("with a second link to pwsh.dll: %+v, program %+v\nwant the error %q", res, res.Interpreter, want)
	}
	roots, _ := pwshRoots()
	listed := false
	for _, i := range powershell.Discover(roots) {
		t.Logf("the inventory lists %+v", i)
		if !strings.EqualFold(i.Path, filepath.Join(install, "pwsh.exe")) {
			continue
		}
		listed = true
		if i.Usable || !i.Blocked || !strings.HasPrefix(strings.ToLower(i.Reason), strings.ToLower(dll)+" has 2 hard links: not used while it has") {
			t.Errorf("the copy with a second link to pwsh.dll: %+v", i)
		}
	}
	if !listed {
		t.Error("the inventory does not list the copy")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	usedAgain(t, install)
}

// TestPwshFallbackModulesAsSystem: a pwsh script that falls back to Windows
// PowerShell runs with a module path of the folders the agent checked, not
// the agent's own, which names the computer's PSModulePath, and so does
// PowerShell 7's compatibility session. With the computer's PSModulePath as
// the runner has it; as Windows sets it on a new computer, which Windows
// PowerShell 5.1 compares a given path with: one equal to it gets the
// system account's own module folder in front, a relative path where that
// account has no Documents folder; and with a PSModulePath of the system
// account's, which one equal to the computer's would get instead. A folder
// Users may change in Windows PowerShell's folder in Program Files stops
// the script (ADR-0064).
func TestPwshFallbackModulesAsSystem(t *testing.T) {
	systemTest(t)
	empty := t.TempDir()
	old := pwshRoots
	pwshRoots = func() ([]string, error) { return []string{empty}, nil }
	t.Cleanup(func() { pwshRoots = old })
	roots, err := powershell.Roots()
	if err != nil {
		t.Fatal(err)
	}
	f, err := powershell.ForFallback()
	if err != nil {
		t.Fatal(err)
	}
	// What the agent checks: the system account's own folder, then the two
	// the PSModulePath it gives Windows PowerShell names.
	docs, err := windows.KnownFolderPath(windows.FOLDERID_Documents, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		t.Fatal(err)
	}
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	checked := []string{filepath.Join(docs, `WindowsPowerShell\Modules`), filepath.Join(roots[0], `WindowsPowerShell\Modules`), filepath.Join(system32, `WindowsPowerShell\v1.0\Modules`)}
	if len(f.Env) != 1 || !sameFolders(f.Env[0], checked[1:]) {
		t.Fatalf("the fallback %+v", f)
	}
	script := "'path:' + $env:PSModulePath\n"
	ps7 := script + compatScript +
		"$s = Get-PSSession -Name WinPSCompatSession -ErrorAction SilentlyContinue\n" +
		"if ($s) { 'compat:' + (Invoke-Command -Session $s { $env:PSModulePath }) } else { 'compat:none' }\n"
	checkedOnly := func(what, got string, checked []string) {
		t.Helper()
		t.Logf("%s: %s", what, got)
		for _, e := range strings.Split(got, ";") {
			if e != "" && !slices.ContainsFunc(checked, func(c string) bool { return strings.EqualFold(filepath.Clean(e), filepath.Clean(c)) }) {
				t.Errorf("%s: %s is not a folder the agent checked (%q)", what, e, checked)
			}
		}
		for _, c := range checked[1:] {
			if !slices.ContainsFunc(strings.Split(got, ";"), func(e string) bool { return strings.EqualFold(filepath.Clean(e), filepath.Clean(c)) }) {
				t.Errorf("%s: %s is missing", what, c)
			}
		}
	}
	fallback := func(what string) {
		t.Helper()
		p := winPayload(agentproto.ShellPwsh, script)
		p.PwshFallback = true
		res := Execute(context.Background(), p, t.TempDir())
		if res.Interpreter == nil || !res.Interpreter.Fallback {
			t.Fatalf("%s: not the fallback: %+v", what, res)
		}
		checkedOnly(what+", the fallback's module path", line(res.Stdout, "path:"), checked)
	}
	// compat runs PowerShell 7, whose own module path must end with the path
	// the run gives, spelled exactly as given, which it returns.
	compat := func(what string) string {
		t.Helper()
		pwshRoots = func() ([]string, error) { return roots, nil }
		defer func() { pwshRoots = func() ([]string, error) { return []string{empty}, nil } }()
		run, err := powershell.ForRun(roots)
		if err != nil {
			t.Fatal(err)
		}
		run.Release()
		given, _ := strings.CutPrefix(run.Env[0], "PSModulePath=")
		res := Execute(context.Background(), winPayload(agentproto.ShellPwsh, ps7), t.TempDir())
		if own := line(res.Stdout, "path:"); !strings.HasSuffix(own, ";"+given) {
			t.Errorf("%s: PowerShell 7's own module path %q does not end with the path the run gave, %q, as given", what, own, given)
		}
		got := line(res.Stdout, "compat:")
		if got == "none" {
			t.Fatalf("%s: no compatibility session: %+v", what, res)
		}
		checkedOnly(what+", the compatibility session's module path", got, checked)
		return given
	}

	fallback("the runner's PSModulePath")
	compat("the runner's PSModulePath")

	// Windows' own PSModulePath, as on a computer no installer changed, and
	// none for the system account: the path given is spelled unlike it.
	machine := `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	def := `%ProgramFiles%\WindowsPowerShell\Modules;%SystemRoot%\system32\WindowsPowerShell\v1.0\Modules`
	setPath(t, registry.LOCAL_MACHINE, machine, def)
	setPath(t, registry.CURRENT_USER, `Environment`, "")
	expanded, err := registry.ExpandString(def)
	if err != nil {
		t.Fatal(err)
	}
	g, err := powershell.ForFallback()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("given %s where the computer's PSModulePath is %s", g.Env[0], expanded)
	if !sameFolders(g.Env[0], checked[1:]) || strings.EqualFold(g.Env[0], "PSModulePath="+expanded) {
		t.Errorf("given %q where the computer's PSModulePath is %q", g.Env[0], expanded)
	}
	fallback("Windows' default PSModulePath")
	// PowerShell 7 keeps the path given with its trailing backslash, and so
	// passes it on to its compatibility session as spelled.
	if given := compat("Windows' default PSModulePath"); given != strings.TrimPrefix(g.Env[0], "PSModulePath=") || !strings.Contains(given+";", `\;`) {
		t.Errorf("a run given %q, the fallback %q, where the computer's PSModulePath is %q", given, g.Env[0], expanded)
	}

	// And a PSModulePath of the system account's own.
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	setPath(t, registry.CURRENT_USER, `Environment`, filepath.Join(os.Getenv("SystemDrive")+`\`, "EasyRMM system account "+hex.EncodeToString(b)))
	fallback("Windows' default PSModulePath and the system account's")
	compat("Windows' default PSModulePath and the system account's")

	// A folder Users may change in Windows PowerShell's folder in Program
	// Files stops the fallback.
	folder := filepath.Join(roots[0], `WindowsPowerShell\Modules`)
	planted := filepath.Join(folder, "EasyRMM open "+hex.EncodeToString(b))
	if err := os.MkdirAll(planted, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(planted) })
	grantUsers(t, planted)
	p := winPayload(agentproto.ShellPwsh, "Write-Output ran\n")
	p.PwshFallback = true
	res := Execute(context.Background(), p, t.TempDir())
	want := "Windows PowerShell would load modules from " + folder + ", and " + planted + ` can be changed by BUILTIN\Users; the script was not run.`
	if res.Status != agentproto.RunFailed || res.Error != want || res.Interpreter != nil || res.Stdout != "" {
		t.Errorf("the fallback with %s open to Users: %+v\nwant the error %q", planted, res, want)
	}
}

// sameFolders reports whether env, PSModulePath=…, names folders, in order,
// as Windows reads them: ignoring case and a trailing backslash.
func sameFolders(env string, folders []string) bool {
	v, ok := strings.CutPrefix(env, "PSModulePath=")
	got := strings.Split(v, ";")
	return ok && slices.EqualFunc(got, folders, func(a, b string) bool { return strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) })
}

// setPath sets the PSModulePath a registry key holds, or removes it for "",
// until the test ends.
func setPath(t *testing.T, root registry.Key, path, value string) {
	t.Helper()
	k, _, err := registry.CreateKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	old, typ, err := k.GetStringValue("PSModulePath")
	had := err == nil
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		switch {
		case !had:
			_ = k.DeleteValue("PSModulePath")
		case typ == registry.EXPAND_SZ:
			_ = k.SetExpandStringValue("PSModulePath", old)
		default:
			_ = k.SetStringValue("PSModulePath", old)
		}
		_ = k.Close()
	})
	switch {
	case value != "":
		err = k.SetExpandStringValue("PSModulePath", value)
	case had:
		err = k.DeleteValue("PSModulePath")
	default:
		return // none to remove
	}
	if err != nil {
		t.Fatal(err)
	}
}

// compatScript imports the first module PowerShell 7 can load only in a
// Windows PowerShell compatibility session, and prints its name.
const compatScript = "$only = Get-Module -ListAvailable -SkipEditionCheck | Where-Object { $_.CompatiblePSEditions -notcontains 'Core' } | Sort-Object Name -Unique\n" +
	"$names = @('ServerManager') + @($only | ForEach-Object Name) | Where-Object { $_ -notin 'PSScheduledJob', 'BestPractices', 'UpdateServices', 'PSDiagnostics' }\n" +
	"foreach ($n in $names) { try { Import-Module $n -ErrorAction Stop -WarningAction SilentlyContinue; \"imported:$n\"; break } catch { } }\n"

// addToPath adds folder to the PSModulePath a registry key holds, as an
// installer would, until the test ends.
func addToPath(t *testing.T, root registry.Key, path, folder string) {
	t.Helper()
	k, _, err := registry.CreateKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	old, typ, err := k.GetStringValue("PSModulePath")
	switch {
	case errors.Is(err, registry.ErrNotExist):
		t.Cleanup(func() { _ = k.DeleteValue("PSModulePath"); _ = k.Close() })
		err = k.SetExpandStringValue("PSModulePath", folder)
	case err != nil:
		t.Fatal(err)
	default:
		t.Cleanup(func() {
			if typ == registry.EXPAND_SZ {
				_ = k.SetExpandStringValue("PSModulePath", old)
			} else {
				_ = k.SetStringValue("PSModulePath", old)
			}
			_ = k.Close()
		})
		err = k.SetExpandStringValue("PSModulePath", old+";"+folder)
	}
	if err != nil {
		t.Fatal(err)
	}
}
