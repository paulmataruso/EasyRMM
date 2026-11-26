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
	"github.com/paulmataruso/easyrmm/agent/easypatch"
	"github.com/paulmataruso/easyrmm/agent/hardware"
	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/inventory"
	"github.com/paulmataruso/easyrmm/agent/jobs"
	"github.com/paulmataruso/easyrmm/agent/logship"
	"github.com/paulmataruso/easyrmm/agent/meshagent"
	"github.com/paulmataruso/easyrmm/agent/metrics"
	"github.com/paulmataruso/easyrmm/agent/removal"
	"github.com/paulmataruso/easyrmm/agent/runner"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/agent/update"
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
  repair-install
            put this agent back in place on an enrolled machine: program,
            service and start; the enrollment is kept (run from the
            recovery copy by the EasyPatch agent)
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
	paths host.Paths
	// store is the agent's state, once openStore has checked its folder.
	store  state.Store
	stdout io.Writer
	log    *slog.Logger
	sd     host.Services
	// command runs programs: systemd-run for a removal (ADR-0050).
	command host.Runner
	// Checks of the machine, replaced by tests.
	isRoot      func() bool
	hasServices func() bool
	// service: the Windows service manager runs the agent.
	service bool //nolint:unused // set and read in the Windows-only files
}

func newEnv(stdout, stderr io.Writer) *env {
	p := host.Paths{Root: os.Getenv("EASYRMM_AGENT_ROOT")}
	return &env{
		paths:       p,
		stdout:      stdout,
		log:         slog.New(slog.NewTextHandler(stderr, nil)),
		sd:          host.SystemServices(p),
		command:     host.Exec,
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

// openStore checks the agent's state folder before a command reads or
// writes anything in it (state.Open), and logs what the check changed.
// Each command calls it once it knows it may run; the store refuses
// everything until then.
func (e *env) openStore() error {
	if e.store.Dir() != "" {
		return nil
	}
	s, checked, err := state.Open(e.paths)
	for _, p := range checked.Aside {
		e.log.Warn("the agent did not make this in its state folder, or cannot trust it: it was moved aside and is not read", "moved_to", p)
	}
	for _, p := range checked.Reprotected {
		e.log.Warn("this folder of the agent's had another access list; it was set back to the agent's own", "folder", p)
	}
	if err != nil {
		return err
	}
	e.store = s
	return nil
}

func (e *env) dispatch(ctx context.Context, args []string, stderr io.Writer) error {
	stdout := e.stdout
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "install":
		return e.enroll(ctx, rest, true)
	case "enroll":
		return e.enroll(ctx, rest, false)
	case "repair-install":
		return e.repairInstall(ctx)
	case "run":
		return e.run(ctx)
	case "status":
		return e.status(ctx)
	case "uninstall":
		return e.uninstall(ctx, rest)
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
	if err := e.openStore(); err != nil {
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
	// The folders are locked down and excluded before the service starts
	// (ADR-0070).
	e.defenderInstall(ctx)
	if err := e.putService(ctx); err != nil {
		return err
	}
	svc := e.paths.AgentService()
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

// putService puts this executable in the program directory, registers the
// agent's service as the installer does and starts it; a service that runs
// an older build is restarted into this one.
func (e *env) putService(ctx context.Context) error {
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
	return nil
}

// repairInstall puts this agent back in place on an enrolled machine: its
// program in the program directory, its service registered as the installer
// registers it, and started. The enrollment is not touched and none is made
// (ADR-0069); the EasyPatch agent runs it from the recovery copy.
func (e *env) repairInstall(ctx context.Context) error {
	if !supported() {
		return fmt.Errorf("installing as a service is not supported on %s", runtime.GOOS)
	}
	if !e.isRoot() {
		return e.needAdmin("repair")
	}
	if !e.hasServices() {
		return errors.New("systemd is not running on this machine, so there is no service to put back")
	}
	if err := e.openStore(); err != nil {
		return err
	}
	cfg, _, err := e.store.Load()
	if err != nil {
		return fmt.Errorf("this machine is not enrolled, and a repair makes no enrollment: %w", err)
	}
	e.defenderRepair(ctx)
	if err := e.putService(ctx); err != nil {
		return err
	}
	svc := e.paths.AgentService()
	_, _ = fmt.Fprintf(e.stdout, "Put the agent back in place as %s, enrolled with %s as device %s.\n", svc.Name, cfg.Server, cfg.DeviceID)
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
		if cfg.CAFile, err = e.store.SaveCA(pem); err != nil {
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
	if err := e.openStore(); err != nil {
		return err
	}
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
		Client:   c,
		DeviceID: cfg.DeviceID,
		Store:    e.store,
		Facts:    func() agentproto.Facts { return host.Facts(Version) },
		Log:      e.log,
		// MeshAgent's files are checked with the key pinned for jobs.
		Key: pinnedKey(cfg),
	}
	var mesh *meshagent.Manager
	var ship *logship.Shipper
	if supported() {
		// The agent's log level and its records for the server come first,
		// so that everything below logs through them (ADR-0069).
		ship = e.shipLogs()
		r.Log = e.log
		r.OnLogs = ship.Apply
		// Windows MeshAgent runs only as a service; an agent that was only
		// enrolled goes without it.
		if m := e.mesh(cfg); !m.Windows || m.Mode != meshagent.ModeChild {
			r.Mesh, mesh = m, m
		}
		// Both read the machine itself, as host.Facts does, whatever root
		// the agent keeps its own files under.
		mc := &metrics.Collector{}
		r.Metrics = mc.Collect
		r.Inventory = inventory.Collector{}.Collect
		// Disks are named as the inventory names them (ADR-0065).
		hw := &hardware.Reader{Log: e.log}
		r.Hardware = hw.Read
		if in := e.installedFiles(); in != nil {
			r.Installed = in
		}
		if dm := e.defenderManager(); dm != nil {
			r.Defender = e.withEasyPatch(dm)
		}
	}
	e.log.Info("EasyRMM agent started", "version", Version, "server", cfg.Server, "device_id", cfg.DeviceID)
	if !supported() {
		return r.Run(ctx)
	}
	up := e.updater(cfg, c)
	if up != nil {
		if up.Settle() {
			return e.restart(up.Exe)
		}
		sum := up.SHA256
		r.Facts = func() agentproto.Facts {
			f := host.Facts(Version)
			f.AgentSHA256 = sum
			return f
		}
		r.Update = up
	}
	w := &jobs.Worker{Client: c, DeviceID: cfg.DeviceID, Dir: e.store.JobsDir(), Log: e.log, Finished: r.RefreshInventory}
	if e.paths.Windows() {
		// The state check leaves out the scripts' working folders: scripts
		// ran there as SYSTEM and may have left links or files others own.
		// Nothing there is read; they start empty. openStore checked jobs
		// itself, and RemoveAll follows no link or junction below it.
		if err := w.ClearWork(); err != nil {
			e.log.Warn("emptying the scripts' working folder failed", "error", err)
		}
	}
	if cfg.JobKey != "" {
		if err := w.SetKey(cfg.JobKey); err != nil {
			return fmt.Errorf("the pinned job key in the configuration is damaged: %w", err)
		}
	}
	// The EasyPatch agent's install (ADR-0031) trusts the same key.
	ep := &easypatch.Installer{DeviceID: cfg.DeviceID, Key: pinnedKey(cfg), Dir: e.store.Dir(), Log: e.log,
		Present: inventory.Collector{}.EasyPatch, Finished: r.RefreshInventory, Services: e.sd}
	r.EasyPatch = ep
	// Repairs of the EasyPatch agent (ADR-0069).
	r.Patch = ep
	if up != nil {
		r.Settled = func() bool { return e.keepRecovery(up) }
	}
	if up != nil {
		// An update waits for scripts and for the EasyPatch install.
		up.Jobs = busyJobs{w, ep}
	}
	r.OnJobKey = e.pinJobKey(cfg, w)
	r.Removal = &removal.Remover{
		DeviceID: cfg.DeviceID, Key: pinnedKey(cfg), Dir: e.store.Dir(), Log: e.log,
		Launch: e.launchRemoval, Report: c.Removed,
	}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var g sync.WaitGroup
	g.Go(func() { _ = w.Run(ctx) })
	g.Go(func() { ship.Run(ctx, sendLogs(c)) })
	if ship != nil && mesh != nil {
		// MeshAgent's side of the device's log: what the agent observes of it.
		emit := func(level, msg string, attrs map[string]string) {
			ship.Record(agentproto.LogSourceMeshAgent, level, msg, attrs)
		}
		mesh.OnExit = func(err error) {
			emit("warn", "MeshAgent exited and is restarted: "+fmt.Sprint(err), nil)
		}
		obs := &meshagent.Observer{M: mesh, Emit: emit}
		g.Go(func() { obs.Run(ctx) })
	}
	err = r.Run(ctx)
	cancel()
	g.Wait()
	if errors.Is(err, runner.ErrRemoved) {
		// No service to leave: the agent uninstalls itself once its jobs
		// and MeshAgent have stopped (ADR-0050).
		if mesh != nil {
			mesh.Wait()
		}
		return e.removeOnRequest(parent, e.removalFile())
	}
	if errors.Is(err, runner.ErrRestart) {
		// The new build starts its own MeshAgent child.
		if mesh != nil {
			mesh.Wait()
		}
		return e.restart(up.Exe)
	}
	return err
}

// keepRecovery writes the recovery copy of the running build once it has
// reached the server (ADR-0069). It returns true when there is nothing more
// to try in this run: the copy is made, or making it failed and was logged.
// A build on probation has none made, and tries again at its next heartbeat.
func (e *env) keepRecovery(up *update.Updater) bool {
	if up.OnProbation() {
		return false
	}
	if err := e.store.KeepRecovery(up.Exe); err != nil {
		e.log.Warn("keeping the recovery copy failed; the EasyPatch agent cannot restore this agent until the next start", "error", err)
	}
	return true
}

// updater returns the agent's self-update (ADR-0027), or nil when the agent
// cannot read its own executable.
func (e *env) updater(cfg *state.Config, c *client.Client) *update.Updater {
	exe, sum, err := update.Self()
	if err != nil {
		e.log.Warn("reading the agent's own executable failed; it cannot update itself", "error", err)
		return nil
	}
	return &update.Updater{
		Client: c, DeviceID: cfg.DeviceID, Version: Version, SHA256: sum, Exe: exe, Dir: e.store.Dir(), Log: e.log,
		// The key pinned for jobs signs updates too.
		Key: pinnedKey(cfg),
	}
}

// pinnedKey returns the pinned job-signing key, nil while none is pinned.
func pinnedKey(cfg *state.Config) func() ed25519.PublicKey {
	return func() ed25519.PublicKey {
		k, err := agentproto.DecodeKey(cfg.JobKey)
		if err != nil {
			return nil
		}
		return k
	}
}

// busyJobs holds an update back while scripts run or the EasyPatch agent
// installs.
type busyJobs struct {
	*jobs.Worker
	ep *easypatch.Installer
}

func (b busyJobs) Busy() bool { return b.Worker.Busy() || b.ep.Busy() }

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
	// Only administrators may open the folder on Windows; checking it as
	// anyone else would leave folders of theirs in ProgramData.
	if e.paths.Windows() && !e.isRoot() {
		return e.needAdmin("status command")
	}
	if err := e.openStore(); err != nil {
		return err
	}
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

func (e *env) uninstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	removal := fs.String("removal", "", "the server's uninstall instruction, as the agent saved it (ADR-0050)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if supported() && !e.isRoot() && (e.paths.Root == "" || e.paths.Root == "/") {
		return e.needAdmin("uninstallation")
	}
	if err := e.openStore(); err != nil {
		return err
	}
	if *removal != "" {
		return e.removeOnRequest(ctx, *removal)
	}
	// The recovery copy goes first: nothing may bring back an agent that is
	// being removed (ADR-0069).
	if err := e.store.RemoveRecovery(); err != nil {
		return fmt.Errorf("removing the recovery copy: %w", err)
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
	later, err := e.removeFiles()
	if err != nil {
		return err
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

// removeFiles deletes the agent's state and executables. later reports an
// executable in use, which Windows deletes at the next restart.
func (e *env) removeFiles() (later bool, err error) {
	// What the agent excluded from Defender goes first, while the record
	// and the folders are still there; what could not go is kept in the
	// record for a new install (ADR-0070).
	left := e.defenderRemove()
	defer e.defenderKeep(left)
	if err := e.store.Remove(); err != nil {
		return false, err
	}
	later, err = host.RemoveExecutable(e.paths.Binary())
	if err != nil {
		return later, err
	}
	// What an interrupted update left beside it (ADR-0027).
	for _, ext := range []string{".new", ".old", ".failed"} {
		if l, err := host.RemoveExecutable(e.paths.Binary() + ext); err == nil && l {
			later = true
		}
	}
	// Empty folders of the agent's own go too; Remove leaves a folder with
	// files, such as MeshAgent's when removing it failed.
	if e.paths.Windows() {
		_ = os.Remove(filepath.Dir(e.paths.Binary()))
		_ = os.Remove(filepath.Dir(filepath.Dir(e.paths.Binary())))
	} else {
		_ = os.Remove(filepath.Dir(e.paths.MeshAgent()))
	}
	return later, nil
}
