//go:build windows

package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
		"$only = Get-Module -ListAvailable -SkipEditionCheck | Where-Object { $_.CompatiblePSEditions -notcontains 'Core' } | Sort-Object Name -Unique\n"+
			"$names = @('ServerManager') + @($only | ForEach-Object Name) | Where-Object { $_ -notin 'PSScheduledJob', 'BestPractices', 'UpdateServices', 'PSDiagnostics' }\n"+
			"foreach ($n in $names) { try { Import-Module $n -ErrorAction Stop -WarningAction SilentlyContinue; \"imported:$n\"; break } catch { } }\n"+
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
