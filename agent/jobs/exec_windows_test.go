//go:build windows

package jobs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func winPayload(shell, script string, args ...string) agentproto.JobPayload {
	return agentproto.JobPayload{V: 1, RunID: "run-1", JobID: "job-1", Shell: shell, Script: script, Args: args, TimeoutSeconds: 60}
}

func TestPowerShell(t *testing.T) {
	root := t.TempDir()
	res := Execute(context.Background(), winPayload(agentproto.ShellPowerShell,
		"param($First, $Second)\nWrite-Output \"out:$First|$Second|$env:EASYRMM_RUN_ID\"\nWrite-Output 'Grüße'\n[Console]::Error.WriteLine('to stderr')\nexit 4\n",
		"one", "two words"), root)
	if res.Status != agentproto.RunFailed || res.ExitCode == nil || *res.ExitCode != 4 {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(res.Stdout, "out:one|two words|run-1") || !strings.Contains(res.Stdout, "Grüße") || !strings.Contains(res.Stderr, "to stderr") {
		t.Errorf("stdout %q, stderr %q", res.Stdout, res.Stderr)
	}
	res = Execute(context.Background(), winPayload(agentproto.ShellPowerShell, "throw 'broken'"), root)
	if res.Status != agentproto.RunFailed || res.ExitCode == nil || *res.ExitCode != 1 || !strings.Contains(res.Stderr, "broken") {
		t.Errorf("a thrown error: %+v", res)
	}
	res = Execute(context.Background(), winPayload(agentproto.ShellPowerShell, "Write-Output ok"), root)
	if res.Status != agentproto.RunSucceeded || strings.TrimSpace(res.Stdout) != "ok" {
		t.Errorf("success: %+v", res)
	}
}

func TestCmd(t *testing.T) {
	root := t.TempDir()
	res := Execute(context.Background(), winPayload(agentproto.ShellCmd, "@echo off\necho out:%~1^|%~2\necho err 1>&2\nexit /b 2\n", "one", "two words"), root)
	if res.Status != agentproto.RunFailed || res.ExitCode == nil || *res.ExitCode != 2 {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(res.Stdout, "out:one|two words") || !strings.Contains(res.Stderr, "err") {
		t.Errorf("stdout %q, stderr %q", res.Stdout, res.Stderr)
	}
	res = Execute(context.Background(), winPayload(agentproto.ShellCmd, "echo x", `a"b`), root)
	if res.Status != agentproto.RunFailed || !strings.Contains(res.Error, "double quotes") {
		t.Errorf("a quote in an argument: %+v", res)
	}
	// %CMDCMDLINE:~-1% expands to a double quote even inside quotes, which
	// would end the argument and run what follows.
	marker := filepath.Join(root, "escaped")
	res = Execute(context.Background(), winPayload(agentproto.ShellCmd, "echo x", `%CMDCMDLINE:~-1% & echo>`+marker+` & rem `), root)
	if res.Status != agentproto.RunFailed || !strings.Contains(res.Error, "%") {
		t.Errorf("a %% in an argument: %+v", res)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("an argument ran a command of its own")
	}
	res = Execute(context.Background(), winPayload(agentproto.ShellBash, "echo x"), root)
	if res.Status != agentproto.RunFailed || !strings.Contains(res.Error, "do not run on Windows") {
		t.Errorf("bash on Windows: %+v", res)
	}
}

// TestTimeoutStopsChildren checks that a timeout stops what the script
// started, not only the script: both ping.exe processes go with the job.
func TestTimeoutStopsChildren(t *testing.T) {
	root := t.TempDir()
	before := running("ping.exe")
	p := winPayload(agentproto.ShellCmd, "@echo off\nstart \"\" /b ping -n 300 127.0.0.1 >nul\nping -n 300 127.0.0.1 >nul\n")
	p.TimeoutSeconds = 3
	started := time.Now()
	res := Execute(context.Background(), p, root)
	if res.Status != agentproto.RunTimedOut || time.Since(started) > 30*time.Second {
		t.Fatalf("result = %+v after %v", res, time.Since(started))
	}
	time.Sleep(time.Second)
	if n := running("ping.exe"); n > before {
		t.Errorf("%d ping.exe still running", n-before)
	}
}

// running counts the processes with an executable's name.
func running(exe string) int {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	e := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	n := 0
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), exe) {
			n++
		}
	}
	return n
}
