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

// interpreter finds a shell's program: Windows PowerShell 5.1 and cmd.exe,
// both part of Windows.
func interpreter(shell string) (string, error) {
	var p string
	switch shell {
	case agentproto.ShellPowerShell:
		p = filepath.Join(systemRoot(), `System32\WindowsPowerShell\v1.0\powershell.exe`)
	case agentproto.ShellCmd:
		p = filepath.Join(systemRoot(), `System32\cmd.exe`)
	default:
		return "", fmt.Errorf("%s scripts do not run on Windows", shell)
	}
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("%s is not installed on this device", shell)
	}
	return p, nil
}

// environment is the agent's own environment, which as a service is
// Windows' system environment, without EasyRMM's settings, with TEMP in
// the run's directory and the job's ids.
func environment(p agentproto.JobPayload, home string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch u := strings.ToUpper(k); {
		case k == "", u == "TEMP", u == "TMP", strings.HasPrefix(u, "EASYRMM_"):
			continue
		}
		env = append(env, kv)
	}
	return append(env, "TEMP="+home, "TMP="+home, "EASYRMM_JOB_ID="+p.JobID, "EASYRMM_RUN_ID="+p.RunID)
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
