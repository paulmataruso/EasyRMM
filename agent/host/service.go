package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Service is a background program the agent installs: the agent itself and
// MeshAgent.
type Service struct {
	// Name is the systemd unit (easyrmm-agent.service) or the Windows
	// service name (EasyRMMAgent).
	Name string
	// DisplayName is what Windows lists in Services.
	DisplayName string
	Description string
	// Documentation is a URL systemd shows for the unit.
	Documentation string
	Binary        string
	Args          []string
	// Dir is the working directory (systemd); "" for the default.
	Dir string
	// Quiet discards the program's standard output (systemd).
	Quiet bool
	// TimeSync orders the unit after time-sync.target (systemd): a clone or a
	// board without a real-time clock must not ask a server before its clock
	// is set (ADR-0056).
	TimeSync bool
	// RestartDelay is the pause before a stopped service is started again.
	RestartDelay time.Duration
}

// Services installs and removes services in the system's service manager.
type Services interface {
	// Install creates or updates a service, sets it to start at boot and
	// starts it unless it is running.
	Install(ctx context.Context, s Service) error
	// Restart restarts a service, or starts it when it is stopped.
	Restart(ctx context.Context, name string) error
	// Stop stops a service and waits until it has stopped. A service that
	// does not exist is an error.
	Stop(ctx context.Context, name string) error
	// Remove stops and deletes a service. A missing service is not an error.
	Remove(ctx context.Context, name string) error
	// State describes a service in the manager's words: active or failed
	// for systemd, running or stopped on Windows.
	State(ctx context.Context, name string) string
}

// The agent's own service.
const (
	AgentUnit           = "easyrmm-agent.service"
	AgentWindowsService = "EasyRMMAgent"
)

// AgentService is the agent's own service, running the installed binary.
func (p Paths) AgentService() Service {
	s := Service{
		Name:          AgentUnit,
		Description:   "EasyRMM agent",
		Documentation: "https://github.com/paulmataruso/easyrmm",
		Binary:        p.Binary(),
		Args:          []string{"run"},
		RestartDelay:  10 * time.Second,
		TimeSync:      true,
	}
	if p.Windows() {
		s.Name, s.DisplayName = AgentWindowsService, "EasyRMM Agent"
		s.Description = "Connects this computer to its EasyRMM server for monitoring, inventory, scripts and remote access."
	}
	return s
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

// Install writes the unit, then enables and starts it.
func (s Systemd) Install(ctx context.Context, svc Service) error {
	return s.install(ctx, svc, true)
}

// Enable writes the unit and enables it without starting it: what an image
// built offline, or a machine whose policy-rc.d forbids starting services,
// needs (ADR-0056). `systemctl enable` works without a running systemd.
func (s Systemd) Enable(ctx context.Context, svc Service) error {
	return s.install(ctx, svc, false)
}

func (s Systemd) install(ctx context.Context, svc Service, start bool) error {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil { //nolint:gosec // the system unit directory
		return err
	}
	if err := os.WriteFile(filepath.Join(s.Dir, svc.Name), []byte(UnitContent(svc)), 0o644); err != nil { //nolint:gosec // units are world-readable
		return err
	}
	if _, err := s.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if !start {
		_, err := s.Run(ctx, "systemctl", "enable", svc.Name)
		return err
	}
	_, err := s.Run(ctx, "systemctl", "enable", "--now", svc.Name)
	return err
}

// Enabler is a service manager that can enable a service without starting it.
type Enabler interface {
	Enable(ctx context.Context, s Service) error
}

// Restart restarts a unit.
func (s Systemd) Restart(ctx context.Context, name string) error {
	_, err := s.Run(ctx, "systemctl", "restart", name)
	return err
}

// Stop stops a unit.
func (s Systemd) Stop(ctx context.Context, name string) error {
	_, err := s.Run(ctx, "systemctl", "stop", name)
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

// UnitContent is the systemd unit that runs a service.
func UnitContent(s Service) string {
	var b strings.Builder
	b.WriteString("[Unit]\nDescription=" + s.Description + "\n")
	if s.Documentation != "" {
		b.WriteString("Documentation=" + s.Documentation + "\n")
	}
	after := "network-online.target"
	if s.TimeSync {
		after += " time-sync.target"
	}
	b.WriteString("After=" + after + "\nWants=network-online.target\n\n[Service]\nType=simple\n")
	if s.Dir != "" {
		b.WriteString("WorkingDirectory=" + s.Dir + "\n")
	}
	cmd := []string{unitQuote(s.Binary)}
	for _, a := range s.Args {
		cmd = append(cmd, unitQuote(a))
	}
	b.WriteString("ExecStart=" + strings.Join(cmd, " ") + "\n")
	if s.Quiet {
		b.WriteString("StandardOutput=null\n")
	}
	delay := max(s.RestartDelay, time.Second)
	b.WriteString("Restart=always\nRestartSec=" + strconv.Itoa(int(delay/time.Second)) + "\n\n[Install]\nWantedBy=multi-user.target\n")
	return b.String()
}

// unitQuote quotes a word of ExecStart when systemd would split or expand it.
func unitQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\$%;") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `$$`, `%`, `%%`)
	return `"` + r.Replace(s) + `"`
}
