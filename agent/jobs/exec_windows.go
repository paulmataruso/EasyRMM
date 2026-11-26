//go:build windows

package jobs

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/agent/powershell"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procWideCharToMultiByte = kernel32.NewProc("WideCharToMultiByte")
)

// cpOEM is the system's OEM code page, the one console programs read and
// write.
const cpOEM = 1

func systemRoot() string { return cmp.Or(os.Getenv("SystemRoot"), `C:\Windows`) }

// Accepts lists the job capabilities this build takes, for its polls
// (agentproto.PollRequest.Accepts): pwsh jobs, their fallback and the
// program a result reports.
func Accepts() []string { return []string{agentproto.CapJobPwsh, agentproto.CapJobParams} }

// pwshRoots are where a pwsh run looks for PowerShell 7: Program Files and
// Program Files (x86). Tests point them at folders of their own, since the
// runner's PowerShell 7 cannot be removed while a test runs in it.
var pwshRoots = powershell.Roots

// interpreter finds a shell's program: Windows PowerShell 5.1 and cmd.exe,
// both part of Windows, or for pwsh the PowerShell 7 chosen at this moment:
// the first, in the order a run prefers them, that passes every check of
// its install and module folders, its program and libraries held open until
// the run's process is created (ADR-0064). A blocked install is passed over
// for the next one that passes, which only administrators can change, as
// any install a run uses: one that could not be listed or read, whose
// version is not one, with a file open in another program or with a second
// hard link, or whose own files pass but what it would load fails. Where
// none passes and one is blocked, the script fails, naming the blocked one
// the inventory lists first, whatever it allows. Where none is blocked
// either, a pwsh script runs in Windows PowerShell 5.1 if it allows that,
// recorded as a fallback, with a module path of checked folders only
// (fallback), and fails if not.
func interpreter(p agentproto.JobPayload) (program, error) {
	switch p.Shell {
	case agentproto.ShellPowerShell:
		return desktop()
	case agentproto.ShellCmd:
		path := filepath.Join(systemRoot(), `System32\cmd.exe`)
		if _, err := os.Stat(path); err != nil {
			return program{}, errors.New("cmd is not installed on this device")
		}
		return program{path: path, info: agentproto.Interpreter{Path: path}}, nil
	case agentproto.ShellPwsh:
		roots, err := pwshRoots()
		if err != nil {
			return program{}, err
		}
		run, err := powershell.ForRun(roots)
		var missing *powershell.NotFound
		if errors.As(err, &missing) && p.PwshFallback {
			return fallback()
		}
		if err != nil {
			return program{}, err
		}
		return program{path: run.Interpreter.Path, info: run.Interpreter, env: run.Env, release: run.Release}, nil
	}
	return program{}, fmt.Errorf("%s scripts do not run on Windows", p.Shell)
}

// fallback is Windows PowerShell 5.1 for a pwsh script that allows it, its
// module folders checked as a pwsh run's are and its PSModulePath set to
// them (powershell.ForFallback): the agent's own, which names the system
// environment's folders, is not what a pwsh script was checked to load.
func fallback() (program, error) {
	prog, err := desktop()
	if err != nil {
		return program{}, err
	}
	f, err := powershell.ForFallback()
	if err != nil {
		return program{}, fmt.Errorf("%w; the script was not run", err)
	}
	prog.info.Fallback = true
	prog.env = f.Env
	return prog, nil
}

// desktop is Windows PowerShell 5.1.
func desktop() (program, error) {
	info := powershell.DesktopInterpreter()
	if _, err := os.Stat(info.Path); err != nil {
		return program{}, errors.New("Windows PowerShell is not installed on this device") //nolint:staticcheck // ST1005: a name
	}
	return program{path: info.Path, info: info}, nil
}

// environment is the agent's own environment, which as a service is
// Windows' system environment, without EasyRMM's settings, with TEMP in
// the run's directory and the job's ids: what powershell.PerRun names is
// set for each run.
func environment(p agentproto.JobPayload, home string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); k == "" || powershell.PerRun(k) {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "TEMP="+home, "TMP="+home, "EASYRMM_JOB_ID="+p.JobID, "EASYRMM_RUN_ID="+p.RunID)
}

// scriptBody is the script as the shell reads it. A PowerShell script that
// takes parameters (a Windows module's, ADR-0073) gets agentproto.ParamsPrologue,
// so its standard input and output are UTF-8; the signature was checked on the
// script as sent, and nothing else about it changes.
func scriptBody(p agentproto.JobPayload) string {
	if len(p.Params) > 0 && (p.Shell == agentproto.ShellPowerShell || p.Shell == agentproto.ShellPwsh) {
		return agentproto.ParamsPrologue + p.Script
	}
	return p.Script
}

// writeScript writes the script as the shell reads it: PowerShell scripts as
// UTF-8 with a byte order mark (Windows PowerShell reads a script without
// one in the ANSI code page), batch files with CRLF line ends in the OEM
// code page.
func writeScript(dir, shell, body string) (string, error) {
	if shell == agentproto.ShellCmd {
		path := filepath.Join(dir, "script.cmd")
		body = strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
		return path, os.WriteFile(path, toOEM(body), 0o600)
	}
	path := filepath.Join(dir, "script.ps1")
	return path, os.WriteFile(path, append([]byte("\xef\xbb\xbf"), body...), 0o600)
}

// command runs the script. PowerShell gets -File, so the script's exit
// sets the exit code; cmd gets a command line of its own, as cmd parses
// quotes its own way.
func command(prog, shell, script string, args []string) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	if shell == agentproto.ShellCmd {
		line := `"` + script + `"`
		for _, a := range args {
			// cmd expands %variables% even inside quotes: %CMDCMDLINE:~-1%
			// is a double quote, which would end the argument's quotes.
			if strings.ContainsAny(a, "%\"\r\n") {
				return nil, errors.New("A cmd script's arguments cannot contain %, double quotes or line breaks.") //nolint:staticcheck // ST1005: shown to people as the run's error
			}
			line += ` "` + a + `"`
		}
		cmd = exec.Command(prog) //nolint:gosec,noctx // a signed job; stopped by its job object
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: syscall.EscapeArg(prog) + ` /D /E:ON /V:OFF /S /C "` + line + `"`}
	} else {
		cmd = exec.Command(prog, append([]string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}, args...)...) //nolint:gosec,noctx // as above
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// A console of its own, without a window: the script never shares the
	// agent's console and its Ctrl+C.
	cmd.SysProcAttr.CreationFlags = windows.CREATE_NO_WINDOW
	return cmd, nil
}

// group is a started script in a job object: stopping the job stops
// everything the script started.
type group struct {
	cmd *exec.Cmd
	job windows.Handle
}

func start(cmd *exec.Cmd) (*group, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	g := &group{cmd: cmd}
	// Without a job, stopping ends the script's own process only.
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return g, nil //nolint:nilerr // see above
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)) //nolint:gosec // a process id
	if err != nil {
		_ = windows.CloseHandle(job)
		return g, nil //nolint:nilerr // see above
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		_ = windows.CloseHandle(job)
		return g, nil //nolint:nilerr // see above
	}
	g.job = job
	return g, nil
}

// terminate stops the script at once: a console program in a console of
// its own cannot be asked to stop.
func (g *group) terminate() { g.kill() }

func (g *group) kill() {
	if g.job != 0 {
		_ = windows.TerminateJobObject(g.job, 1)
		return
	}
	_ = g.cmd.Process.Kill()
}

// release lets go of the job; what the script left running keeps running.
func (g *group) release() {
	if g.job != 0 {
		_ = windows.CloseHandle(g.job)
	}
}

// decodeOutput turns a script's output into text. Console programs,
// PowerShell included, write in the OEM code page when their output is
// redirected; programs that write UTF-8 are kept as they are.
func decodeOutput(b []byte) string {
	if len(b) == 0 || utf8.Valid(b) {
		return string(b)
	}
	n, err := windows.MultiByteToWideChar(cpOEM, 0, &b[0], int32(len(b)), nil, 0) //nolint:gosec // output is at most a few hundred kB
	if err != nil || n == 0 {
		return string(b)
	}
	u := make([]uint16, n)
	if _, err := windows.MultiByteToWideChar(cpOEM, 0, &b[0], int32(len(b)), &u[0], n); err != nil { //nolint:gosec // as above
		return string(b)
	}
	return windows.UTF16ToString(u)
}

// toOEM converts a batch file to the OEM code page; characters it lacks
// become question marks.
func toOEM(s string) []byte {
	if s == "" {
		return nil
	}
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return []byte(s)
	}
	u = u[:len(u)-1] // no terminating NUL
	n, _, _ := procWideCharToMultiByte.Call(cpOEM, 0, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)), 0, 0, 0, 0)
	if n == 0 {
		return []byte(s)
	}
	out := make([]byte, n)
	if r, _, _ := procWideCharToMultiByte.Call(cpOEM, 0, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)), uintptr(unsafe.Pointer(&out[0])), n, 0, 0); r == 0 {
		return []byte(s)
	}
	return out
}
