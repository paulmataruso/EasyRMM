// Package meshagent installs and runs MeshAgent, MeshCentral's agent, for
// EasyRMM remote access (ADR-0015). The binary and its settings come from
// the EasyRMM server.
//
// MeshAgent runs as a service of its own (a systemd unit, or a Windows
// service) or, where Linux has no systemd, as a child process the EasyRMM
// agent supervises.
package meshagent

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// MeshAgent's service.
const (
	Unit           = "easyrmm-meshagent.service"
	WindowsService = "EasyRMMMeshAgent"
)

// Mode is how MeshAgent is run.
type Mode string

// Modes.
const (
	// ModeService runs MeshAgent as a service of its own.
	ModeService Mode = "service"
	// ModeSystemd is ModeService as enrollments before Windows support
	// recorded it.
	ModeSystemd Mode = "systemd"
	ModeChild   Mode = "child"
)

// Manager installs and runs MeshAgent in one directory.
type Manager struct {
	Dir  string
	Mode Mode
	// Services runs MeshAgent in ModeService.
	Services host.Services
	// Windows selects the Windows names and settings; tests set it.
	Windows bool
	Log     *slog.Logger
	// RestartDelay is the pause before restarting a child MeshAgent that
	// exited (5 s).
	RestartDelay time.Duration

	mu    sync.Mutex
	child *exec.Cmd
}

// NewManager returns a manager for this machine's MeshAgent.
func NewManager(dir string, mode Mode, services host.Services, log *slog.Logger) *Manager {
	if mode == ModeSystemd {
		mode = ModeService
	}
	return &Manager{Dir: dir, Mode: mode, Services: services, Windows: runtime.GOOS == "windows", Log: log}
}

// MeshAgent reads its settings and database from files named after its
// executable: meshagent.msh and meshagent.db beside meshagent(.exe).
func (m *Manager) binary() string {
	if m.Windows {
		return filepath.Join(m.Dir, "meshagent.exe")
	}
	return filepath.Join(m.Dir, "meshagent")
}

func (m *Manager) settings() string { return filepath.Join(m.Dir, "meshagent.msh") }

func (m *Manager) service() host.Service {
	s := host.Service{
		Name:         Unit,
		Description:  "MeshAgent for EasyRMM remote access",
		Binary:       m.binary(),
		Dir:          m.Dir,
		Quiet:        true,
		RestartDelay: 5 * time.Second,
	}
	if m.Windows {
		s.Name, s.DisplayName = WindowsService, "EasyRMM MeshAgent"
		s.Description = "MeshCentral's agent, for EasyRMM remote desktop, terminal and files."
	}
	return s
}

func (m *Manager) asService() bool { return m.Mode == ModeService || m.Mode == ModeSystemd }

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
	if m.Windows {
		// MeshAgent keeps its identity in meshagent.db beside it; Program
		// Files lets every user read.
		if err := host.Protect(m.Dir); err != nil {
			return err
		}
		settings = WithServiceName(settings, WindowsService)
	} else if err := os.MkdirAll(m.Dir, 0o755); err != nil { //nolint:gosec // MeshAgent's directory, like MeshCentral's own installer
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
	if m.asService() {
		return m.Services.Install(ctx, m.service())
	}
	if m.Windows {
		// Started outside the service manager, Windows MeshAgent shows its
		// installation window instead of connecting.
		return errors.New("MeshAgent runs as a Windows service only; install the agent with \"easyrmm-agent install\"")
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
	if m.Services != nil {
		if err := m.Services.Remove(ctx, m.service().Name); err != nil {
			return err
		}
	}
	if m.Windows {
		removeRegistry(WindowsService)
	}
	return os.RemoveAll(m.Dir)
}

// WithServiceName sets meshServiceName in MeshAgent's settings. Windows
// MeshAgent restarts itself after an update through the service of that
// name, "Mesh Agent" unless the settings say otherwise.
func WithServiceName(settings []byte, name string) []byte {
	eol := "\n"
	if bytes.Contains(settings, []byte("\r\n")) {
		eol = "\r\n"
	}
	var out bytes.Buffer
	for line := range strings.Lines(string(settings)) {
		k, _, _ := strings.Cut(line, "=")
		if strings.EqualFold(strings.TrimSpace(k), "meshServiceName") {
			continue
		}
		out.WriteString(line)
	}
	if out.Len() > 0 && !bytes.HasSuffix(out.Bytes(), []byte("\n")) {
		out.WriteString(eol)
	}
	out.WriteString("meshServiceName=" + name + eol)
	return out.Bytes()
}
