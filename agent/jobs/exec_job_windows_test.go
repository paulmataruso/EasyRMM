//go:build windows

package jobs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// ADR-0060 slice 0: every process of a run starts inside its job object, in
// four ordered steps, and a run is refused where one fails.

var procIsProcessInJob = kernel32.NewProc("IsProcessInJob")

func cmdExe() string { return filepath.Join(systemRoot(), `System32\cmd.exe`) }

// inJob reports whether a process is in a job object.
func inJob(t *testing.T, pid uint32, job windows.Handle) bool {
	t.Helper()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		t.Fatalf("open process %d: %v", pid, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var result int32
	if r, _, err := procIsProcessInJob.Call(uintptr(h), uintptr(job), uintptr(unsafe.Pointer(&result))); r == 0 {
		t.Fatalf("IsProcessInJob: %v", err)
	}
	return result != 0
}

// childOf waits for a process whose parent is pid.
func childOf(t *testing.T, pid uint32) uint32 {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0); err == nil {
			e := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
			for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
				if e.ParentProcessID == pid {
					_ = windows.CloseHandle(snap)
					return e.ProcessID
				}
			}
			_ = windows.CloseHandle(snap)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("process %d started no child", pid)
	return 0
}

func holds(g *group, pid uint32) bool {
	for _, p := range g.processes() {
		if p == pid {
			return true
		}
	}
	return false
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// swap replaces a hook for one test.
func swap[T any](t *testing.T, hook *T, with T) {
	t.Helper()
	old := *hook
	*hook = with
	t.Cleanup(func() { *hook = old })
}

func TestAChildOfARunIsInItsJobObject(t *testing.T) {
	cmd := exec.Command(cmdExe(), "/D", "/C", "ping -n 30 127.0.0.1 >nul") //nolint:gosec,noctx // a test
	g, err := start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { g.kill(); _ = cmd.Wait(); g.release() }()
	pid := uint32(cmd.Process.Pid) //nolint:gosec // a process id
	child := childOf(t, pid)
	if !inJob(t, pid, g.job) || !inJob(t, child, g.job) {
		t.Errorf("the process or its child is not in the job object")
	}
	eventually(t, "the job to report its processes", func() bool { return holds(g, pid) && holds(g, child) })
	// Stopping the job stops what the process started.
	g.kill()
	eventually(t, "the child to stop", func() bool { return !alive(child) })
}

func alive(pid uint32) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	ev, _ := windows.WaitForSingleObject(h, 0)
	return ev == uint32(windows.WAIT_TIMEOUT)
}

// A child that ends at once is in the job too: the port reports it.
func TestAShortLivedChildIsReportedOnTheCompletionPort(t *testing.T) {
	cmd := exec.Command(cmdExe(), "/D", "/C", "ver >nul & cmd /D /C exit 0 & cmd /D /C exit 0") //nolint:gosec,noctx // a test
	g, err := start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer g.release()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the run and its two children reported", func() bool {
		return holds(g, uint32(cmd.Process.Pid)) && len(g.processes()) >= 3 //nolint:gosec // a process id
	})
}

// The process has not run when it is assigned, and the job object is the
// first thing it is in.
func TestTheProcessIsAssignedBeforeItRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	checked := false
	swap(t, &assignToJob, func(job, process windows.Handle) error {
		for range 6 {
			if _, err := os.Stat(marker); err == nil {
				t.Error("the process ran before it was assigned to the job object")
			}
			time.Sleep(100 * time.Millisecond)
		}
		checked = true
		return windows.AssignProcessToJobObject(job, process)
	})
	cmd := exec.Command(cmdExe(), "/D", "/C", "echo x>"+marker) //nolint:gosec,noctx // a test
	g, err := start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer g.release()
	if err := cmd.Wait(); err != nil || !checked {
		t.Fatalf("wait: %v, checked %v", err, checked)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the process did not run after it was resumed: %v", err)
	}
}

func TestARunIsRefusedWhenTheJobObjectCannotBeMadeOrAttached(t *testing.T) {
	boom := errors.New("injected")
	cases := map[string]func(*testing.T){
		"make": func(t *testing.T) {
			swap(t, &createJobObject, func() (windows.Handle, error) { return 0, boom })
		},
		"attach": func(t *testing.T) {
			swap(t, &associatePort, func(_, _ windows.Handle) error { return boom })
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			setup(t)
			cmd := exec.Command(cmdExe(), "/D", "/C", "exit 0") //nolint:gosec,noctx // a test
			g, err := start(cmd)
			if g != nil || err == nil || !errors.Is(err, boom) || !strings.Contains(err.Error(), "job object") {
				t.Fatalf("group %v, error %v", g, err)
			}
			if cmd.Process != nil {
				t.Error("a process was started")
			}
		})
	}
}

func TestARunIsRefusedAndItsProcessStoppedWhenItCannotBeAssigned(t *testing.T) {
	boom := errors.New("injected")
	marker := filepath.Join(t.TempDir(), "ran")
	var pid uint32
	swap(t, &assignToJob, func(_, process windows.Handle) error {
		pid, _ = windows.GetProcessId(process)
		return boom
	})
	cmd := exec.Command(cmdExe(), "/D", "/C", "echo x>"+marker) //nolint:gosec,noctx // a test
	g, err := start(cmd)
	if g != nil || !errors.Is(err, boom) || !strings.Contains(err.Error(), "put the process in the job object") {
		t.Fatalf("group %v, error %v", g, err)
	}
	if pid == 0 || cmd.ProcessState == nil || alive(pid) {
		t.Errorf("the suspended process %d was not stopped (state %v)", pid, cmd.ProcessState)
	}
	time.Sleep(time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Error("the refused process ran")
	}
}

func TestResumingAProcessWithNoThreadIsAnError(t *testing.T) {
	if err := resumeThreads(0xFFFFFFF0); err == nil || !strings.Contains(err.Error(), "no thread") {
		t.Errorf("error %v", err)
	}
}

// Execute reports a refusal with its reason, and the script never runs.
func TestExecuteRefusesARunWithoutAJobObject(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "ran")
	swap(t, &createJobObject, func() (windows.Handle, error) { return 0, syscall.EACCES })
	for _, shell := range []string{agentproto.ShellPowerShell, agentproto.ShellCmd} {
		script := "echo x>" + marker
		if shell == agentproto.ShellPowerShell {
			script = "'x' | Out-File '" + marker + "'"
		}
		res := Execute(context.Background(), winPayload(shell, script), root)
		if res.Status != agentproto.RunFailed || !strings.Contains(res.Error, "could not make the job object") {
			t.Errorf("%s: %+v", shell, res)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("%s: the script ran", shell)
		}
	}
}

// Exit codes and arguments are as they were without the job object's
// suspended start.
func TestExitCodesAndArgumentsAreUnchangedByTheSuspendedStart(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name, shell, script string
		args                []string
		status              string
		code                int
		out                 string
	}{
		{"powershell exit", agentproto.ShellPowerShell, "param($a,$b)\nWrite-Output \"$a|$b\"\nexit 7", []string{"x y", "z"}, agentproto.RunFailed, 7, "x y|z"},
		{"powershell failing native command at the end", agentproto.ShellPowerShell, "cmd /c exit 5", nil, agentproto.RunSucceeded, 0, ""},
		{"powershell thrown", agentproto.ShellPowerShell, "throw 'x'", nil, agentproto.RunFailed, 1, ""},
		{"cmd exit", agentproto.ShellCmd, "@echo off\necho %~1\nexit /b 3", []string{"a b"}, agentproto.RunFailed, 3, "a b"},
		{"cmd success", agentproto.ShellCmd, "@echo off\nexit /b 0", nil, agentproto.RunSucceeded, 0, ""},
	}
	for _, c := range cases {
		res := Execute(context.Background(), winPayload(c.shell, c.script, c.args...), root)
		if res.Status != c.status || res.ExitCode == nil || *res.ExitCode != c.code || !strings.Contains(res.Stdout, c.out) {
			t.Errorf("%s: %+v", c.name, res)
		}
	}
}
