//go:build unix

package jobs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// searchPath is where interpreters are looked up and what scripts get as
// PATH: the system directories, never the agent's own environment.
var searchPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// Accepts lists the job capabilities this build takes, for its polls
// (agentproto.PollRequest.Accepts): none on Linux, where pwsh does not run.
func Accepts() []string { return []string{} }

// interpreter finds a shell's program; the result reports its path.
func interpreter(p agentproto.JobPayload) (program, error) {
	shell := p.Shell
	if !agentproto.ValidShell(shell) || agentproto.ShellPlatforms(shell)[0] != "linux" {
		return program{}, fmt.Errorf("%s scripts do not run on this device", shell)
	}
	for _, dir := range searchPath {
		path := filepath.Join(dir, shell)
		if st, err := os.Stat(path); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return program{path: path, info: agentproto.Interpreter{Path: path}}, nil
		}
	}
	return program{}, fmt.Errorf("%s is not installed on this device", shell)
}

// environment is a script's whole environment.
func environment(p agentproto.JobPayload, home string) []string {
	return []string{
		"PATH=" + strings.Join(searchPath, ":"),
		"HOME=" + home,
		"LANG=C.UTF-8",
		"EASYRMM_JOB_ID=" + p.JobID,
		"EASYRMM_RUN_ID=" + p.RunID,
	}
}

// writeScript writes the script for the interpreter to read.
func writeScript(dir, _ string, body string) (string, error) {
	path := filepath.Join(dir, "script")
	return path, os.WriteFile(path, []byte(body), 0o600)
}

// command runs the script with its arguments.
func command(prog, _ string, script string, args []string) (*exec.Cmd, error) {
	return exec.Command(prog, append([]string{script}, args...)...), nil //nolint:gosec,noctx // a signed job; stopped by its group
}

// group is a started script's process group: stopping it stops everything
// the script started.
type group struct{ cmd *exec.Cmd }

func start(cmd *exec.Cmd) (group, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return group{cmd}, cmd.Start()
}

func (g group) terminate() { _ = syscall.Kill(-g.cmd.Process.Pid, syscall.SIGTERM) }

func (g group) kill() { _ = syscall.Kill(-g.cmd.Process.Pid, syscall.SIGKILL) }

func (g group) release() {}

// decodeOutput turns a script's output into text; Unix programs write
// UTF-8.
func decodeOutput(b []byte) string { return string(b) }
