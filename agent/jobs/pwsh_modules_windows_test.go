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
		list, _ := powershell.Discover(roots)
		for _, i := range list {
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
	want := strings.Join(run.Modules[3:], ";")
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
	from := filepath.Join(roots[0], `PowerShell\7`)
	install := filepath.Join(root, `PowerShell\7`)
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(install, rel), 0o755)
		}
		copyFile(t, p, filepath.Join(install, rel))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	old := pwshRoots
	pwshRoots = func() ([]string, error) { return []string{root}, nil }
	t.Cleanup(func() { pwshRoots = old })
	return install
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
	list, _ := powershell.Discover(roots)
	for _, i := range list {
		if strings.EqualFold(i.Path, filepath.Join(install, "pwsh.exe")) && (i.Usable || !i.Blocked || !strings.HasPrefix(strings.ToLower(i.Reason), strings.ToLower(dll)+" is open in another program")) {
			t.Errorf("the copy with pwsh.dll held: %+v", i)
		}
	}
	_ = windows.CloseHandle(h)
	res = Execute(context.Background(), winPayload(agentproto.ShellPwsh, "Write-Output \"edition:$($PSVersionTable.PSEdition)\"\n"), t.TempDir())
	if line(res.Stdout, "edition:") != "Core" || res.Interpreter == nil || !strings.EqualFold(res.Interpreter.Path, filepath.Join(install, "pwsh.exe")) {
		t.Errorf("let go: %+v", res)
	}
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
	if len(f.Modules) != 3 || len(f.Env) != 1 || !sameFolders(f.Env[0], f.Modules[1:]) {
		t.Fatalf("the fallback %+v", f)
	}
	script := "'path:' + $env:PSModulePath\n"
	ps7 := compatScript +
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
		checkedOnly(what+", the fallback's module path", line(res.Stdout, "path:"), f.Modules)
	}
	compat := func(what string) {
		t.Helper()
		pwshRoots = func() ([]string, error) { return roots, nil }
		defer func() { pwshRoots = func() ([]string, error) { return []string{empty}, nil } }()
		run, err := powershell.ForRun(roots)
		if err != nil {
			t.Fatal(err)
		}
		run.Release()
		res := Execute(context.Background(), winPayload(agentproto.ShellPwsh, ps7), t.TempDir())
		got := line(res.Stdout, "compat:")
		if got == "none" {
			t.Fatalf("%s: no compatibility session: %+v", what, res)
		}
		checkedOnly(what+", the compatibility session's module path", got, f.Modules)
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
	if !sameFolders(g.Env[0], f.Modules[1:]) || strings.EqualFold(g.Env[0], "PSModulePath="+expanded) {
		t.Errorf("given %q where the computer's PSModulePath is %q", g.Env[0], expanded)
	}
	fallback("Windows' default PSModulePath")
	compat("Windows' default PSModulePath")

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
