// Package meshagent installs and runs MeshAgent, MeshCentral's agent, for
// EasyRMM remote access (ADR-0015). The binary and its settings come from
// the EasyRMM server.
//
// MeshAgent runs either as its own systemd unit or, where systemd is not
// available, as a child process the EasyRMM agent supervises.
package meshagent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Unit is MeshAgent's systemd unit.
const Unit = "easyrmm-meshagent.service"

// Mode is how MeshAgent is run.
type Mode string

// Modes.
const (
	ModeSystemd Mode = "systemd"
	ModeChild   Mode = "child"
)

// Manager installs and runs MeshAgent in one directory.
type Manager struct {
	Dir     string
	Mode    Mode
	Systemd host.Systemd
	Log     *slog.Logger
	// RestartDelay is the pause before restarting a child MeshAgent that
	// exited (5 s).
	RestartDelay time.Duration

	mu    sync.Mutex
	child *exec.Cmd
}

func (m *Manager) binary() string   { return filepath.Join(m.Dir, "meshagent") }
func (m *Manager) settings() string { return filepath.Join(m.Dir, "meshagent.msh") }

// Installed reports whether MeshAgent's files are in place.
func (m *Manager) Installed() bool {
	for _, f := range []string{m.binary(), m.settings()} {
		if _, err := os.Stat(f); err != nil {
			return false
		}
	}
	return true
}

// Install writes MeshAgent and its settings and starts it. download writes
// the binary.
func (m *Manager) Install(ctx context.Context, download func(io.Writer) error, settings []byte) error {
	if err := os.MkdirAll(m.Dir, 0o755); err != nil { //nolint:gosec // MeshAgent's directory, like MeshCentral's own installer
		return err
	}
	tmp, err := os.CreateTemp(m.Dir, ".meshagent-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := download(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(m.settings(), settings, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), m.binary()); err != nil {
		return err
	}
	return m.Start(ctx)
}

// Start runs an installed MeshAgent.
func (m *Manager) Start(ctx context.Context) error {
	if !m.Installed() {
		return errors.New("MeshAgent is not installed")
	}
	if m.Mode == ModeSystemd {
		return m.Systemd.Install(ctx, Unit, unitContent(m.Dir, m.binary()))
	}
	return m.startChild(ctx)
}

// startChild runs MeshAgent under the agent, restarting it when it exits,
// until ctx ends.
func (m *Manager) startChild(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.child != nil {
		return nil
	}
	cmd, err := m.spawn(ctx)
	if err != nil {
		return err
	}
	m.child = cmd
	go m.supervise(ctx, cmd)
	return nil
}

func (m *Manager) spawn(ctx context.Context) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, m.binary()) //nolint:gosec // our own installed MeshAgent
	cmd.Dir = m.Dir
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting MeshAgent: %w", err)
	}
	return cmd, nil
}

func (m *Manager) supervise(ctx context.Context, cmd *exec.Cmd) {
	for {
		err := cmd.Wait()
		if ctx.Err() != nil {
			return
		}
		m.Log.Warn("MeshAgent exited; restarting", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(cmp.Or(m.RestartDelay, 5*time.Second)):
		}
		next, err := m.spawn(ctx)
		if err != nil {
			m.Log.Error("restarting MeshAgent failed", "error", err)
			continue
		}
		m.mu.Lock()
		m.child, cmd = next, next
		m.mu.Unlock()
	}
}

// NodeID returns MeshAgent's node id as `meshagent -nodeid` prints it (96
// hex digits), or "" while MeshAgent has not created its identity yet.
func (m *Manager) NodeID(ctx context.Context) (string, error) {
	if _, err := os.Stat(filepath.Join(m.Dir, "meshagent.db")); err != nil {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.binary(), "-nodeid") //nolint:gosec // our own installed MeshAgent
	cmd.Dir = m.Dir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("reading MeshAgent's node id: %w", err)
	}
	id := strings.TrimSpace(string(out))
	if _, err := agentproto.MeshNodeKey(id); err != nil {
		return "", fmt.Errorf("MeshAgent printed %q as its node id", id)
	}
	return id, nil
}

// Remove stops MeshAgent and deletes it.
func (m *Manager) Remove(ctx context.Context) error {
	if err := m.Systemd.Remove(ctx, Unit); err != nil {
		return err
	}
	return os.RemoveAll(m.Dir)
}

func unitContent(dir, binary string) string {
	return `[Unit]
Description=MeshAgent for EasyRMM remote access
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=` + dir + `
ExecStart=` + binary + `
StandardOutput=null
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`
}
