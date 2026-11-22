//go:build windows

package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/agent/powershell"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// pwsh runs (ADR-0064) as the agent's service runs them: as LocalSystem.
// CI's job "PowerShell 7 as LocalSystem" starts these tests through a
// scheduled task with EASYRMM_TEST_SYSTEM set, on a runner with PowerShell
// 7 installed from Microsoft's MSI.

// systemTest skips a test unless it may run, and fails one that is not
// running as LocalSystem.
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

// printed starts a PowerShell and returns what it prints for command.
func printed(t *testing.T, exe, command string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command).CombinedOutput() //nolint:gosec // a test's PowerShell
	if err != nil {
		t.Fatalf("%s: %v\n%s", exe, err, out)
	}
	return strings.TrimSpace(string(out))
}

// runnerPwsh is the runner's PowerShell 7 as a run's result should name it,
// read from what it prints of itself.
func runnerPwsh(t *testing.T) agentproto.Interpreter {
	t.Helper()
	roots, err := powershell.Roots()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(roots[0], `PowerShell\7\pwsh.exe`)
	arch := map[string]string{"AMD64": agentproto.ArchX64, "ARM64": agentproto.ArchARM64}[printed(t, path, "$env:PROCESSOR_ARCHITECTURE")]
	return agentproto.Interpreter{Edition: agentproto.EditionCore, Version: printed(t, path, "$PSVersionTable.PSVersion.ToString()"), Arch: arch, Path: path}
}

// line is the text after prefix on the line of out that starts with it.
func line(out, prefix string) string {
	for l := range strings.SplitSeq(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimRight(l, "\r"), prefix); ok {
			return rest
		}
	}
	return "(no line " + prefix + ")"
}

// TestPwshAsSystem: a pwsh run starts the runner's PowerShell 7, never a
// pwsh.exe on the PATH; it gets its arguments, the run's environment and a
// module path of the five checked folders, without the folders the agent's
// own PSModulePath adds; its result names what ran.
func TestPwshAsSystem(t *testing.T) {
	systemTest(t)
	want := runnerPwsh(t)
	roots, _ := powershell.Roots()
	run, err := powershell.ForRun(roots)
	if err != nil {
		t.Fatal(err)
	}
	run.Release()
	t.Logf("choosing PowerShell 7 and checking it and its module folders took %s; module folders %q", run.Took, run.Modules)

	// A pwsh.exe on the PATH, in a folder of the system drive's root, which
	// users may write to: a copy of cmd.exe, which never prints the lines
	// checked below.
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	planted := filepath.Join(os.Getenv("SystemDrive")+`\`, "EasyRMM planted "+hex.EncodeToString(b))
	if err := os.Mkdir(planted, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(planted) })
	copyFile(t, filepath.Join(systemRoot(), `System32\cmd.exe`), filepath.Join(planted, "pwsh.exe"))
	t.Setenv("PATH", planted+";"+os.Getenv("PATH"))

	// A module in a folder added to the agent's own PSModulePath.
	mods := t.TempDir()
	if err := os.MkdirAll(filepath.Join(mods, "EasyRMMPlanted"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mods, "EasyRMMPlanted", "EasyRMMPlanted.psm1"), []byte("function Get-EasyRMMPlanted { 'planted' }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PSModulePath", os.Getenv("PSModulePath")+";"+mods)
	const probe = "if (Get-Module -ListAvailable -Name EasyRMMPlanted) { 'planted:found' } else { 'planted:not found' }\n"

	root := t.TempDir()
	res := Execute(context.Background(), winPayload(agentproto.ShellPwsh,
		"param($First, $Second)\n"+
			"Write-Output \"out:$First|$Second|$env:EASYRMM_RUN_ID\"\n"+
			"Write-Output 'Grüße'\n"+
			"Write-Output \"telemetry:$env:POWERSHELL_TELEMETRY_OPTOUT|$env:POWERSHELL_UPDATECHECK\"\n"+
			"Write-Output \"edition:$($PSVersionTable.PSEdition)\"\n"+
			"Write-Output \"process:$((Get-Process -Id $PID).Path)\"\n"+
			"Write-Output \"modules:$env:PSModulePath\"\n"+
			probe+
			"[Console]::Error.WriteLine('to stderr')\n"+
			"exit 4\n",
		"one", "two words"), root)
	t.Logf("stdout:\n%s\nstderr:\n%s", res.Stdout, res.Stderr)
	if res.Status != agentproto.RunFailed || res.ExitCode == nil || *res.ExitCode != 4 || !strings.Contains(res.Stderr, "to stderr") {
		t.Fatalf("result %+v", res)
	}
	for prefix, v := range map[string]string{
		"out:": "one|two words|run-1", "telemetry:": "1|Off", "edition:": "Core", "planted:": "not found",
	} {
		if got := line(res.Stdout, prefix); got != v {
			t.Errorf("%s %q, want %q", prefix, got, v)
		}
	}
	if !strings.Contains(res.Stdout, "Grüße") {
		t.Error("non-ASCII output was lost")
	}
	if got := line(res.Stdout, "process:"); !strings.EqualFold(got, want.Path) {
		t.Errorf("ran %q, want %q", got, want.Path)
	}
	seen := strings.Split(line(res.Stdout, "modules:"), ";")
	if len(seen) != 5 || len(run.Modules) != 5 {
		t.Errorf("module path %q, checked %q", seen, run.Modules)
	} else {
		for i := range seen {
			if !strings.EqualFold(filepath.Clean(seen[i]), filepath.Clean(run.Modules[i])) {
				t.Errorf("module folder %d: %q, checked %q", i, seen[i], run.Modules[i])
			}
		}
	}
	if res.Interpreter == nil || *res.Interpreter != want {
		t.Errorf("program %+v, want %+v", res.Interpreter, want)
	}

	// Windows PowerShell, which keeps the agent's environment, finds the
	// planted module: the plant works.
	res = Execute(context.Background(), winPayload(agentproto.ShellPowerShell, probe), root)
	if got := line(res.Stdout, "planted:"); got != "found" {
		t.Errorf("Windows PowerShell: planted %q (%+v)", got, res)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	in, err := os.Open(from) //nolint:gosec // the test's own files
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(to) //nolint:gosec // as above
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestPwshExitCodesAsSystem: exit codes are those of Windows PowerShell for
// the same script.
func TestPwshExitCodesAsSystem(t *testing.T) {
	systemTest(t)
	root := t.TempDir()
	for script, code := range map[string]int{
		"exit 7":                            7,
		"cmd /c exit 3\nexit $LASTEXITCODE": 3,
		"throw 'broken'":                    1,
		"cmd /c exit 3":                     -1, // a failing native command last: whatever Windows PowerShell gives
	} {
		ps := Execute(context.Background(), winPayload(agentproto.ShellPowerShell, script), root)
		pw := Execute(context.Background(), winPayload(agentproto.ShellPwsh, script), root)
		if ps.ExitCode == nil || pw.ExitCode == nil {
			t.Errorf("%q: Windows PowerShell %+v, PowerShell 7 %+v", script, ps, pw)
			continue
		}
		t.Logf("%q: Windows PowerShell %s %d, PowerShell 7 %s %d", script, ps.Status, *ps.ExitCode, pw.Status, *pw.ExitCode)
		if ps.Status != pw.Status || *ps.ExitCode != *pw.ExitCode || (code >= 0 && *pw.ExitCode != code) {
			t.Errorf("%q: Windows PowerShell %s %d, PowerShell 7 %s %d, want %d", script, ps.Status, *ps.ExitCode, pw.Status, *pw.ExitCode, code)
		}
	}
}

// TestPwshStopsWhatItStartedAsSystem: a pwsh run's timeout stops what the
// script started, as for the other shells.
func TestPwshStopsWhatItStartedAsSystem(t *testing.T) {
	systemTest(t)
	before := running("ping.exe")
	p := winPayload(agentproto.ShellPwsh, "Start-Process -NoNewWindow -FilePath ping.exe -ArgumentList '-n','300','127.0.0.1'\n"+
		"Write-Output started\nping.exe -n 300 127.0.0.1 | Out-Null\n")
	p.TimeoutSeconds = 20
	res := Execute(context.Background(), p, t.TempDir())
	if res.Status != agentproto.RunTimedOut || !strings.Contains(res.Stdout, "started") {
		t.Fatalf("result %+v", res)
	}
	time.Sleep(time.Second)
	if n := running("ping.exe"); n > before {
		t.Errorf("%d ping.exe still running", n-before)
	}
}

// TestPwshMissingAsSystem: without PowerShell 7 where the agent looks, a
// pwsh run fails with the reason, or runs in Windows PowerShell where the
// script allows it, and says so.
func TestPwshMissingAsSystem(t *testing.T) {
	systemTest(t)
	empty := t.TempDir()
	old := pwshRoots
	pwshRoots = func() ([]string, error) { return []string{empty}, nil }
	t.Cleanup(func() { pwshRoots = old })
	root := t.TempDir()

	res := Execute(context.Background(), winPayload(agentproto.ShellPwsh, "Write-Output ran"), root)
	want := "PowerShell 7 is not installed on this device (looked in " + filepath.Join(empty, "PowerShell") + "). The script was not run."
	if res.Status != agentproto.RunFailed || res.ExitCode != nil || res.Error != want || res.Interpreter != nil || res.Stdout != "" {
		t.Errorf("without the fallback: %+v", res)
	}

	p := winPayload(agentproto.ShellPwsh, "Write-Output \"edition:$($PSVersionTable.PSEdition)\"\nexit 5\n")
	p.PwshFallback = true
	res = Execute(context.Background(), p, root)
	if res.Status != agentproto.RunFailed || res.ExitCode == nil || *res.ExitCode != 5 || line(res.Stdout, "edition:") != "Desktop" {
		t.Errorf("with the fallback: %+v", res)
	}
	desktop := powershell.DesktopInterpreter()
	desktop.Fallback = true
	if res.Interpreter == nil || *res.Interpreter != desktop {
		t.Errorf("program %+v, want %+v", res.Interpreter, desktop)
	}
}
