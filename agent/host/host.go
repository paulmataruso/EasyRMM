// Package host describes the machine the agent runs on and manages its
// files and services: systemd units on Linux, Windows services on Windows.
package host

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Paths are where the agent keeps its files. Root prefixes all of them; ""
// or "/" is a real installation. OS is runtime.GOOS unless a test sets it.
type Paths struct {
	Root string
	OS   string
}

// Windows reports whether the paths follow the Windows layout.
func (p Paths) Windows() bool { return cmp.Or(p.OS, runtime.GOOS) == "windows" }

// real reports whether the paths are the machine's own, not a test root.
func (p Paths) real() bool { return p.Root == "" || p.Root == "/" }

func (p Paths) unix(rel string) string { return filepath.Join(cmp.Or(p.Root, "/"), rel) }

// programData is C:\ProgramData on a real Windows installation.
func (p Paths) programData() string {
	if p.real() {
		return cmp.Or(os.Getenv("ProgramData"), `C:\ProgramData`)
	}
	return filepath.Join(p.Root, "ProgramData")
}

// programFiles is C:\Program Files on a real Windows installation.
func (p Paths) programFiles() string {
	if p.real() {
		return cmp.Or(os.Getenv("ProgramFiles"), `C:\Program Files`)
	}
	return filepath.Join(p.Root, "Program Files")
}

// State is the directory with the enrollment and key.
func (p Paths) State() string {
	if p.Windows() {
		return filepath.Join(p.programData(), "EasyRMM", "Agent")
	}
	return p.unix("var/lib/easyrmm-agent")
}

// MeshAgent is the directory MeshAgent is installed in.
func (p Paths) MeshAgent() string {
	if p.Windows() {
		return filepath.Join(p.programFiles(), "EasyRMM", "MeshAgent")
	}
	return p.unix("usr/local/lib/easyrmm-agent/meshagent")
}

// Binary is where the agent's own executable is installed.
func (p Paths) Binary() string {
	if p.Windows() {
		return filepath.Join(p.programFiles(), "EasyRMM", "Agent", "easyrmm-agent.exe")
	}
	return p.unix("usr/local/bin/easyrmm-agent")
}

// Units is the systemd unit directory.
func (p Paths) Units() string { return p.unix("etc/systemd/system") }

// Logs is where the agent writes its log on Windows; on Linux the journal
// keeps it.
func (p Paths) Logs() string { return filepath.Join(p.State(), "logs") }

// CheckState makes the state folder safe to read, before anything in it is
// read or written. On Windows, where any user may create folders under
// ProgramData, it moves aside what the agent cannot trust (see checkState);
// elsewhere only root reaches the folder, and it does nothing. entries are
// what the agent reads and writes in the folder: groups of names relative
// to it, the last element of each possibly a pattern. It returns where it
// moved what it set aside.
func (p Paths) CheckState(entries [][]string) (aside []string, err error) {
	return checkState(p.State(), p.programData(), entries)
}

// Facts describes this machine.
func Facts(version string) agentproto.Facts {
	name, _ := os.Hostname()
	return agentproto.Facts{
		Hostname:     name,
		OS:           cmp.Or(systemDescription(), runtime.GOOS),
		Platform:     platform(),
		Arch:         runtime.GOARCH,
		AgentVersion: version,
	}
}

func platform() string {
	switch runtime.GOOS {
	case "windows", "linux":
		return runtime.GOOS
	case "darwin":
		return "macos"
	}
	return "other"
}

// linuxDescription is the distribution's PRETTY_NAME.
func linuxDescription(root string) string {
	for _, f := range []string{"etc/os-release", "usr/lib/os-release"} {
		if b, err := os.ReadFile(filepath.Join(root, f)); err == nil { //nolint:gosec // fixed os-release paths
			if name := prettyName(b); name != "" {
				return name
			}
		}
	}
	return "Linux"
}

// prettyName reads PRETTY_NAME (or NAME) from os-release content.
func prettyName(b []byte) string {
	values := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		values[k] = v
	}
	if v := values["PRETTY_NAME"]; v != "" {
		return v
	}
	return values["NAME"]
}

// Runner runs a command and returns its combined output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Exec runs commands for real.
func Exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // callers pass fixed commands
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return out, nil
}
