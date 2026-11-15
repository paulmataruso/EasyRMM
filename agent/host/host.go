// Package host describes the machine the agent runs on and manages its
// services.
package host

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Paths are where the agent keeps its files. Root prefixes all of them,
// "/" on a real installation.
type Paths struct {
	Root string
}

// State is the directory with the enrollment and key.
func (p Paths) State() string { return filepath.Join(p.Root, "var/lib/easyrmm-agent") }

// MeshAgent is the directory MeshAgent is installed in.
func (p Paths) MeshAgent() string {
	return filepath.Join(p.Root, "usr/local/lib/easyrmm-agent/meshagent")
}

// Binary is where the agent's own executable is installed.
func (p Paths) Binary() string { return filepath.Join(p.Root, "usr/local/bin/easyrmm-agent") }

// Units is the systemd unit directory.
func (p Paths) Units() string { return filepath.Join(p.Root, "etc/systemd/system") }

// Facts describes this machine.
func Facts(version string) agentproto.Facts {
	name, _ := os.Hostname()
	return agentproto.Facts{
		Hostname:     name,
		OS:           osDescription(),
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

func osDescription() string {
	if runtime.GOOS == "linux" {
		for _, f := range []string{"/etc/os-release", "/usr/lib/os-release"} {
			if b, err := os.ReadFile(f); err == nil { //nolint:gosec // fixed os-release paths
				if name := prettyName(b); name != "" {
					return name
				}
			}
		}
		return "Linux"
	}
	return runtime.GOOS
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

// Systemd installs and removes systemd units.
type Systemd struct {
	Dir string // unit directory
	Run Runner
}

// Available reports whether systemd manages this machine.
func Available() bool {
	st, err := os.Stat("/run/systemd/system")
	return err == nil && st.IsDir()
}

// Install writes a unit, then enables and starts it.
func (s Systemd) Install(ctx context.Context, name, content string) error {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil { //nolint:gosec // the system unit directory
		return err
	}
	if err := os.WriteFile(filepath.Join(s.Dir, name), []byte(content), 0o644); err != nil { //nolint:gosec // units are world-readable
		return err
	}
	if _, err := s.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err := s.Run(ctx, "systemctl", "enable", "--now", name)
	return err
}

// Remove stops, disables and deletes a unit. A missing unit is not an
// error.
func (s Systemd) Remove(ctx context.Context, name string) error {
	path := filepath.Join(s.Dir, name)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	_, _ = s.Run(ctx, "systemctl", "disable", "--now", name)
	if err := os.Remove(path); err != nil {
		return err
	}
	_, err := s.Run(ctx, "systemctl", "daemon-reload")
	return err
}

// State returns `systemctl is-active` for a unit.
func (s Systemd) State(ctx context.Context, name string) string {
	out, _ := s.Run(ctx, "systemctl", "is-active", name)
	if st := strings.TrimSpace(string(out)); st != "" {
		return strings.SplitN(st, "\n", 2)[0]
	}
	return "unknown"
}

// AgentUnit is the systemd unit of the EasyRMM agent.
const AgentUnit = "easyrmm-agent.service"

// AgentUnitContent runs the agent from binary.
func AgentUnitContent(binary string) string {
	return `[Unit]
Description=EasyRMM agent
Documentation=https://github.com/paulmataruso/easyrmm
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + binary + ` run
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`
}
