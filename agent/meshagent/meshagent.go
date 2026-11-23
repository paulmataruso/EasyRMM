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
	"crypto/sha256"
	"encoding/hex"
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
	// alive: the child process runs (set under mu).
	alive bool
	// supervised ends when the child supervisor has stopped MeshAgent.
	supervised sync.WaitGroup

	errMu   sync.Mutex
	lastErr string
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

// applied records the hash of the settings the server gave, beside them.
func (m *Manager) applied() string { return filepath.Join(m.Dir, "settings.sha256") }

// AppliedSettings is the SHA-256, in hex, of the settings the server gave
// MeshAgent last, or "" when none is recorded (an install from before the
// server moved devices between sites).
func (m *Manager) AppliedSettings() string {
	b, err := os.ReadFile(m.applied())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// writeSettings writes MeshAgent's settings and the hash of what the server
// gave.
func (m *Manager) writeSettings(settings []byte) error {
	sum := sha256.Sum256(settings)
	if m.Windows {
		settings = WithServiceName(settings, WindowsService)
	}
	if err := os.WriteFile(m.settings(), settings, 0o600); err != nil {
		return err
	}
	return os.WriteFile(m.applied(), []byte(hex.EncodeToString(sum[:])+"\n"), 0o600)
}

// Reconfigure replaces MeshAgent's settings, which name the device group it
// joins, and restarts it so that it joins the new one (ADR-0069).
func (m *Manager) Reconfigure(ctx context.Context, settings []byte) error {
	if !m.Installed() {
		return errors.New("MeshAgent is not installed")
	}
	if err := m.writeSettings(settings); err != nil {
		return err
	}
	if m.asService() {
		return m.Services.Restart(ctx, m.service().Name)
	}
	// A child MeshAgent is started again by its supervisor once it exits.
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.child != nil && m.child.Process != nil {
		return m.child.Process.Signal(os.Interrupt)
	}
	return nil
}

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
	return m.note(m.write(ctx, download, settings, false))
}

// Repair puts MeshAgent's program, settings and service back in place: it
// downloads the program first, so that a download that fails leaves what is
// there alone, then stops MeshAgent, writes both again and starts it. Its
// identity, meshagent.db, is not touched: the node id and keys stay
// (ADR-0069).
func (m *Manager) Repair(ctx context.Context, download func(io.Writer) error, settings []byte) error {
	return m.note(m.write(ctx, download, settings, true))
}

// write is Install and Repair. replace stops a running MeshAgent once the
// program is downloaded and starts the new one.
func (m *Manager) write(ctx context.Context, download func(io.Writer) error, settings []byte, replace bool) error {
	if m.Windows {
		// MeshAgent keeps its identity in meshagent.db beside it; Program
		// Files lets every user read.
		if err := host.Protect(m.Dir); err != nil {
			return err
		}
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
	if replace && m.asService() && m.Services != nil {
		// A stopped or missing service is what a repair is for: the stop's
		// failure is not the repair's. A program that stays locked fails
		// the rename below.
		if err := m.Services.Stop(ctx, m.service().Name); err != nil {
			m.Log.Warn("stopping MeshAgent before its repair failed", "error", err)
		}
	}
	if err := m.writeSettings(settings); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), m.binary()); err != nil {
		return err
	}
	if replace && !m.asService() {
		m.killChild()
	}
	return m.Start(ctx)
}

// Restart restarts MeshAgent: its service, or its child process, which the
// supervisor then starts again. A MeshAgent that is not installed, or whose
// service is gone, is an error: it needs Repair.
func (m *Manager) Restart(ctx context.Context) error {
	if !m.Installed() {
		return m.note(errors.New("MeshAgent is not installed"))
	}
	switch {
	case m.asService():
		return m.note(m.Services.Restart(ctx, m.service().Name))
	case m.Windows:
		return m.note(errors.New("MeshAgent runs as a Windows service only"))
	}
	m.mu.Lock()
	running := m.child != nil
	m.mu.Unlock()
	if !running {
		return m.note(m.Start(ctx))
	}
	m.killChild()
	return m.note(nil)
}

// killChild kills the child MeshAgent; its supervisor starts it again.
func (m *Manager) killChild() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.child != nil && m.child.Process != nil {
		_ = m.child.Process.Kill()
	}
}

// State reports what the heartbeat tells the server about MeshAgent
// (ADR-0069).
func (m *Manager) State(ctx context.Context) agentproto.MeshAgentState {
	st := agentproto.MeshAgentState{Installed: m.Installed()}
	if b, err := os.ReadFile(m.settings()); err == nil {
		if h := agentproto.MeshServerHost(b); len(h) <= agentproto.MaxMeshHost {
			st.Host = h
		}
	}
	switch {
	case !st.Installed:
	case m.asService():
		switch m.Services.State(ctx, m.service().Name) {
		case "active", "running":
			st.Running = true
		}
	default:
		m.mu.Lock()
		st.Running = m.alive
		m.mu.Unlock()
	}
	m.errMu.Lock()
	st.Error = m.lastErr
	m.errMu.Unlock()
	return st
}

// note records err as the last error MeshAgent had, or forgets it for nil,
// and returns err.
func (m *Manager) note(err error) error {
	m.errMu.Lock()
	defer m.errMu.Unlock()
	if err == nil {
		m.lastErr = ""
		return nil
	}
	m.lastErr = err.Error()
	if r := []rune(m.lastErr); len(r) > agentproto.MaxMeshAgentError {
		m.lastErr = string(r[:agentproto.MaxMeshAgentError])
	}
	return err
}

// Start runs an installed MeshAgent.
func (m *Manager) Start(ctx context.Context) error { return m.note(m.start(ctx)) }

func (m *Manager) start(ctx context.Context) error {
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
	m.child, m.alive = cmd, true
	m.supervised.Go(func() { m.supervise(ctx, cmd) })
	return nil
}

// Wait waits until a child MeshAgent started with Start has exited, after
// Start's context ended. The agent waits before it restarts into a new
// build, which starts MeshAgent again.
func (m *Manager) Wait() { m.supervised.Wait() }

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
		m.mu.Lock()
		m.alive = false
		m.mu.Unlock()
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
		m.child, cmd, m.alive = next, next, true
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
