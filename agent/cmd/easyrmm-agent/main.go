// Command easyrmm-agent is the EasyRMM endpoint agent.
//
//	easyrmm-agent install --server URL   enroll and run as a service (systemd or Windows)
//	                                     (with an approval token, the service waits until
//	                                     the device is approved in the console)
//	easyrmm-agent enroll --server URL    enroll only; run `easyrmm-agent run` yourself
//	easyrmm-agent run                    the service's main loop
//	easyrmm-agent status                 show the enrollment and last heartbeat
//	easyrmm-agent uninstall              stop and remove the agent and MeshAgent
//	easyrmm-agent version
//
// The deployment token comes from --token or the EASYRMM_TOKEN environment
// variable; the environment keeps it out of the process list.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/inventory"
	"github.com/paulmataruso/easyrmm/agent/jobs"
	"github.com/paulmataruso/easyrmm/agent/meshagent"
	"github.com/paulmataruso/easyrmm/agent/metrics"
	"github.com/paulmataruso/easyrmm/agent/runner"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Version is set at build time with -ldflags.
var Version = "dev"

func main() {
	if started, code := asService(); started {
		os.Exit(code)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "easyrmm-agent:", err)
		os.Exit(1)
	}
}

const usage = `usage: easyrmm-agent <command> [options]

commands:
  install --server URL [--token TOKEN] [--ca-file FILE]
            enroll this machine and run the agent as a service: a systemd
            unit on Linux, the EasyRMMAgent service on Windows
  enroll --server URL [--token TOKEN] [--ca-file FILE]
            enroll only; start the agent with "easyrmm-agent run"
  run       run the agent in the foreground (what the service does)
  status    show the enrollment and the last heartbeat
  uninstall stop and remove the agent and MeshAgent from this machine
  version   print the version

The token can also be given in the EASYRMM_TOKEN environment variable.
With a token that needs approval, the agent waits until the device is
approved in the EasyRMM console, then finishes enrolling on its own.
`

// env bundles what the commands share.
type env struct {
	paths  host.Paths
	store  state.Store
	stdout io.Writer
	log    *slog.Logger
	sd     host.Services
	// Checks of the machine, replaced by tests.
	isRoot      func() bool
	hasServices func() bool
}

func newEnv(stdout, stderr io.Writer) *env {
	p := host.Paths{Root: os.Getenv("EASYRMM_AGENT_ROOT")}
	return &env{
		paths:       p,
		store:       state.Store{Dir: p.State()},
		stdout:      stdout,
		log:         slog.New(slog.NewTextHandler(stderr, nil)),
		sd:          host.SystemServices(p),
		isRoot:      host.IsAdmin,
		hasServices: host.ServicesAvailable,
	}
}

// supported reports whether this system runs the whole agent: health,
// inventory, scripts and MeshAgent.
func supported() bool { return runtime.GOOS == "linux" || runtime.GOOS == "windows" }

// needAdmin explains how to run a command that changes the machine.
func (e *env) needAdmin(what string) error {
	if e.paths.Windows() {
		return fmt.Errorf("run the %s in PowerShell or a command prompt started as administrator", what)
	}
	return fmt.Errorf("run the %s as root", what)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, usage)
		return errors.New("no command given")
	}
	return newEnv(stdout, stderr).dispatch(ctx, args, stderr)
}

func (e *env) dispatch(ctx context.Context, args []string, stderr io.Writer) error {
	stdout := e.stdout
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "install":
		return e.enroll(ctx, rest, true)
	case "enroll":
		return e.enroll(ctx, rest, false)
	case "run":
		return e.run(ctx)
	case "status":
		return e.status(ctx)
	case "uninstall":
		return e.uninstall(ctx)
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "easyrmm-agent %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		return nil
	case "help", "--help", "-h":
		_, _ = io.WriteString(stdout, usage)
		return nil
	}
	_, _ = io.WriteString(stderr, usage)
	return fmt.Errorf("unknown command %q", cmd)
}

// enroll registers this machine with a server; with service, it also
// installs the systemd service.
func (e *env) enroll(ctx context.Context, args []string, service bool) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	server := fs.String("server", "", "EasyRMM server URL, https://rmm.example.com")
	token := fs.String("token", "", "deployment token (or EASYRMM_TOKEN)")
	caFile := fs.String("ca-file", "", "PEM file of a private certificate authority to trust")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if service {
		if !supported() {
			return fmt.Errorf("installing as a service is not supported on %s", runtime.GOOS)
		}
		if !e.isRoot() {
			return e.needAdmin("installation")
		}
		if !e.hasServices() {
			return errors.New("systemd is not running on this machine; use \"easyrmm-agent enroll\" and start \"easyrmm-agent run\" with your service manager")
		}
	}
	if *server == "" {
		return errors.New("--server is required")
	}
	if _, err := client.ParseServer(*server); err != nil {
		return err
	}

	cfg, _, err := e.store.Load()
	var waiting *state.Pending
	if errors.Is(err, state.ErrNotEnrolled) {
		waiting, _, err = e.store.LoadPending()
		if errors.Is(err, state.ErrNotPending) {
			err = state.ErrNotEnrolled
		}
	}
	switch {
	case err == nil && waiting != nil:
		if waiting.Server != mustServer(*server) {
			return fmt.Errorf("this machine waits for approval from %s; run \"easyrmm-agent uninstall\" first", waiting.Server)
		}
		if waiting.Stopped != "" {
			return fmt.Errorf("this machine stopped asking to enroll: %s; run \"easyrmm-agent uninstall\", then install again to ask anew", waiting.Stopped)
		}
		_, _ = fmt.Fprintf(e.stdout, "Already waiting for approval in the EasyRMM console at %s, as device code %s.\n", waiting.Server, waiting.Code)
	case err == nil:
		if cfg.Server != mustServer(*server) {
			return fmt.Errorf("this machine is enrolled with %s; run \"easyrmm-agent uninstall\" first", cfg.Server)
		}
		_, _ = fmt.Fprintf(e.stdout, "Already enrolled with %s as device %s.\n", cfg.Server, cfg.DeviceID)
	case errors.Is(err, state.ErrNotEnrolled):
		tok := *token
		if tok == "" {
			tok = os.Getenv("EASYRMM_TOKEN")
		}
		if tok == "" {
			return errors.New("a deployment token is required (--token or EASYRMM_TOKEN); create one in the EasyRMM console")
		}
		if cfg, waiting, err = e.register(ctx, *server, tok, *caFile, service); err != nil {
			return err
		}
		if waiting != nil {
			_, _ = fmt.Fprintf(e.stdout, "Waiting for approval in the EasyRMM console at %s. Device code: %s\n", waiting.Server, waiting.Code)
			if !service {
				_, _ = fmt.Fprintln(e.stdout, `Start the agent with "easyrmm-agent run": it finishes enrolling once the device is approved.`)
			}
		} else {
			_, _ = fmt.Fprintf(e.stdout, "Enrolled with %s as device %s.\n", cfg.Server, cfg.DeviceID)
		}
	default:
		return err
	}
	if !service {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	_, statErr := os.Stat(e.paths.Binary())
	changed, err := host.InstallExecutable(self, e.paths.Binary())
	if err != nil {
		return fmt.Errorf("installing %s: %w", e.paths.Binary(), err)
	}
	svc := e.paths.AgentService()
	if err := e.sd.Install(ctx, svc); err != nil {
		return err
	}
	// A new build over an installed one: the running service still runs the
	// old one.
	if changed && statErr == nil {
		if err := e.sd.Restart(ctx, svc.Name); err != nil {
			return err
		}
	}
	if e.paths.Windows() {
		_, _ = fmt.Fprintf(e.stdout, "The agent is running as the %s service.\n", svc.Name)
	} else {
		_, _ = fmt.Fprintf(e.stdout, "The agent is running as %s.\n", svc.Name)
	}
	if waiting != nil {
		_, _ = fmt.Fprintln(e.stdout, "It finishes enrolling on its own once the device is approved.")
	}
	return nil
}

func mustServer(s string) string {
	u, _ := client.ParseServer(s)
	return u.String()
}

// register enrolls with the server, or, with a token that needs approval,
// records that the device waits for it.
func (e *env) register(ctx context.Context, server, token, caFile string, service bool) (*state.Config, *state.Pending, error) {
	cfg := &state.Config{Server: mustServer(server), MeshAgentMode: string(meshagent.ModeChild)}
	if service {
		cfg.MeshAgentMode = string(meshagent.ModeService)
	}
	if caFile != "" {
		// Keep a copy: the original may be a temporary file.
		pem, err := os.ReadFile(caFile) //nolint:gosec // a path the administrator chose
		if err != nil {
			return nil, nil, fmt.Errorf("reading the CA file: %w", err)
		}
		if err := host.Protect(e.store.Dir); err != nil {
			return nil, nil, err
		}
		cfg.CAFile = filepath.Join(e.store.Dir, "ca.pem")
		if err := os.WriteFile(cfg.CAFile, pem, 0o600); err != nil { //nolint:gosec // inside the agent's state directory
			return nil, nil, err
		}
	}
	c, err := client.New(client.Options{Server: cfg.Server, CAFile: cfg.CAFile, Version: Version})
	if err != nil {
		return nil, nil, err
	}
	key, err := state.NewKey()
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	resp, err := c.Enroll(ctx, token, key.Public().(ed25519.PublicKey), host.Facts(Version))
	if err != nil {
		return nil, nil, fmt.Errorf("enrolling: %w", err)
	}
	if resp.Pending != nil {
		p := &state.Pending{Server: cfg.Server, CAFile: cfg.CAFile, MeshAgentMode: cfg.MeshAgentMode, Token: token,
			Code: resp.Pending.Code, Since: time.Now().UTC()}
		if err := e.store.SavePending(p, key); err != nil {
			return nil, nil, fmt.Errorf("saving the enrollment: %w", err)
		}
		return nil, p, nil
	}
	if resp.DeviceID == "" {
		return nil, nil, errors.New("enrolling: the server answered without a device")
	}
	cfg.DeviceID, cfg.EnrolledAt, cfg.JobKey = resp.DeviceID, time.Now().UTC(), resp.JobKey
	if err := e.store.Save(cfg, key); err != nil {
		return nil, nil, fmt.Errorf("saving the enrollment: %w", err)
	}
	return cfg, nil, nil
}

func (e *env) mesh(cfg *state.Config) *meshagent.Manager {
	mode := meshagent.Mode(cfg.MeshAgentMode)
	if mode != meshagent.ModeService && mode != meshagent.ModeSystemd {
		mode = meshagent.ModeChild
	}
	return meshagent.NewManager(e.paths.MeshAgent(), mode, e.sd, e.log)
}

func (e *env) run(ctx context.Context) error {
	cfg, key, err := e.store.Load()
	if errors.Is(err, state.ErrNotEnrolled) {
		cfg, key, err = e.awaitApproval(ctx)
	}
	if err != nil {
		return err
	}
	c, err := client.New(client.Options{Server: cfg.Server, CAFile: cfg.CAFile, Version: Version})
	if err != nil {
		return err
	}
	c.SetIdentity(cfg.DeviceID, key)
	r := &runner.Runner{
		Client: c,
		Store:  e.store,
		Facts:  func() agentproto.Facts { return host.Facts(Version) },
		Log:    e.log,
	}
	if supported() {
		// Windows MeshAgent runs only as a service; an agent that was only
		// enrolled goes without it.
		if m := e.mesh(cfg); !m.Windows || m.Mode != meshagent.ModeChild {
			r.Mesh = m
		}
		// Both read the machine itself, as host.Facts does, whatever root
		// the agent keeps its own files under.
		mc := &metrics.Collector{}
		r.Metrics = mc.Collect
		r.Inventory = inventory.Collector{}.Collect
	}
	e.log.Info("EasyRMM agent started", "version", Version, "server", cfg.Server, "device_id", cfg.DeviceID)
	if !supported() {
		return r.Run(ctx)
	}
	w := &jobs.Worker{Client: c, DeviceID: cfg.DeviceID, Dir: e.store.JobsDir(), Log: e.log}
	if cfg.JobKey != "" {
		if err := w.SetKey(cfg.JobKey); err != nil {
			return fmt.Errorf("the pinned job key in the configuration is damaged: %w", err)
		}
	}
	r.OnJobKey = e.pinJobKey(cfg, w)
	var g sync.WaitGroup
	g.Go(func() { _ = w.Run(ctx) })
	err = r.Run(ctx)
	g.Wait()
	return err
}

// pinJobKey pins the server's job-signing key the first time it is seen
// (ADR-0017) and refuses to follow a change.
func (e *env) pinJobKey(cfg *state.Config, w *jobs.Worker) func(string) {
	var warned time.Time
	return func(key string) {
		switch {
		case key == cfg.JobKey:
		case cfg.JobKey == "":
			if err := w.SetKey(key); err != nil {
				e.log.Error("the server sent a job key that is not valid", "error", err)
				return
			}
			cfg.JobKey = key
			if err := e.store.SaveConfig(cfg); err != nil {
				e.log.Error("saving the job key failed", "error", err)
				return
			}
			e.log.Info("pinned the server's job key")
		case time.Since(warned) > time.Hour:
			warned = time.Now()
			e.log.Error("the server's job key differs from the pinned one; jobs signed with it are refused. Reinstall the agent if the server's key was replaced.")
		}
	}
}

func (e *env) status(ctx context.Context) error {
	cfg, _, err := e.store.Load()
	if errors.Is(err, state.ErrNotEnrolled) {
		return e.pendingStatus(ctx)
	}
	if err != nil {
		return err
	}
	w := e.stdout
	_, _ = fmt.Fprintf(w, "Server:     %s\nDevice:     %s\nEnrolled:   %s\n", cfg.Server, cfg.DeviceID, cfg.EnrolledAt.Local().Format(time.RFC1123))
	if supported() && e.hasServices() {
		_, _ = fmt.Fprintf(w, "Service:    %s\n", e.sd.State(ctx, e.paths.AgentService().Name))
	}
	if e.paths.Windows() {
		_, _ = fmt.Fprintf(w, "Log:        %s\n", filepath.Join(e.paths.Logs(), logName))
	}
	st, err := e.store.LoadStatus()
	if errors.Is(err, fs.ErrNotExist) {
		_, _ = fmt.Fprintln(w, "Heartbeat:  none yet")
		return nil
	}
	if err != nil {
		return err
	}
	if !st.LastHeartbeat.IsZero() {
		_, _ = fmt.Fprintf(w, "Heartbeat:  %s\n", st.LastHeartbeat.Local().Format(time.RFC1123))
	}
	if st.LastError != "" {
		_, _ = fmt.Fprintf(w, "Last error: %s (%s)\n", st.LastError, st.LastErrorAt.Local().Format(time.RFC1123))
	}
	if st.MeshAgent != "" {
		_, _ = fmt.Fprintf(w, "MeshAgent:  %s\n", st.MeshAgent)
	}
	if !st.InventoryUploaded.IsZero() {
		_, _ = fmt.Fprintf(w, "Inventory:  sent %s\n", st.InventoryUploaded.Local().Format(time.RFC1123))
	}
	if st.InventoryError != "" {
		_, _ = fmt.Fprintf(w, "Inventory:  not sent: %s\n", st.InventoryError)
	}
	return nil
}

func (e *env) uninstall(ctx context.Context) error {
	if supported() && !e.isRoot() && (e.paths.Root == "" || e.paths.Root == "/") {
		return e.needAdmin("uninstallation")
	}
	cfg, _, err := e.store.Load()
	if err != nil && !errors.Is(err, state.ErrNotEnrolled) {
		e.log.Warn("the enrollment could not be read; removing anyway", "error", err)
	}
	enrolled := cfg != nil
	if cfg == nil {
		cfg = &state.Config{}
	}
	if err := e.sd.Remove(ctx, e.paths.AgentService().Name); err != nil {
		return err
	}
	if err := e.mesh(cfg).Remove(ctx); err != nil {
		return err
	}
	if err := e.store.Remove(); err != nil {
		return err
	}
	later, err := host.RemoveExecutable(e.paths.Binary())
	if err != nil {
		return err
	}
	if e.paths.Windows() {
		// Empty program folders go too; Remove leaves a folder with files.
		_ = os.Remove(filepath.Dir(e.paths.Binary()))
		_ = os.Remove(filepath.Dir(filepath.Dir(e.paths.Binary())))
	}
	if enrolled {
		_, _ = fmt.Fprintln(e.stdout, "EasyRMM agent removed. The device stays listed in the EasyRMM console as offline.")
	} else {
		_, _ = fmt.Fprintln(e.stdout, "EasyRMM agent removed.")
	}
	if later {
		_, _ = fmt.Fprintf(e.stdout, "%s is in use; Windows deletes it at the next restart.\n", e.paths.Binary())
	}
	return nil
}
