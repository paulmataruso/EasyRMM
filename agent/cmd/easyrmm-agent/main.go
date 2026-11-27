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
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/paulmataruso/easyrmm/agent/channel"
	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/easypatch"
	"github.com/paulmataruso/easyrmm/agent/escrow"
	"github.com/paulmataruso/easyrmm/agent/escrow/cryptsetup"
	"github.com/paulmataruso/easyrmm/agent/hardware"
	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/inventory"
	"github.com/paulmataruso/easyrmm/agent/jobs"
	"github.com/paulmataruso/easyrmm/agent/logship"
	"github.com/paulmataruso/easyrmm/agent/meshagent"
	"github.com/paulmataruso/easyrmm/agent/metrics"
	"github.com/paulmataruso/easyrmm/agent/removal"
	"github.com/paulmataruso/easyrmm/agent/roles"
	"github.com/paulmataruso/easyrmm/agent/runner"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/agent/trust"
	"github.com/paulmataruso/easyrmm/agent/update"
	"github.com/paulmataruso/easyrmm/agent/winevents"
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
	var ee exitError
	if errors.As(err, &ee) {
		os.Exit(ee.code)
	}
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
  install --package deb|rpm|msi
            what a package's script runs: installs the agent and enrolls it
            from install.conf (or EASYRMM_SERVER and EASYRMM_TOKEN on Linux),
            or waits for that file; where an agent is installed, records the
            package and changes nothing else
  enroll --server URL [--token TOKEN] [--ca-file FILE]
            enroll only; start the agent with "easyrmm-agent run"
  repair-install
            put this agent back in place on an enrolled machine: program,
            service and start; the enrollment is kept (run from the
            recovery copy by the EasyPatch agent)
  quick-assist [--clean]
            one support session for a user, from a Quick Assist link: asks
            first, installs nothing, removes itself when it ends
  builtin NAME
            run one of the agent's builtins as a child process of the agent
            (what a job does); it reads and writes the files named in
            EASYRMM_JOB_INPUT and EASYRMM_JOB_RESULT
  run       run the agent in the foreground (what the service does)
  collect --spool DIR [--audit-socket FILE]
            the log collector (ADR-0060): a process of its own, started by its
            unit or service, that reads the computer's logs and writes
            compressed blocks to the spool; it sends nothing
  collect-unit install|remove
            write and start, or stop and remove, the collector's systemd unit
            (Linux; run as root)
  status    show the enrollment, the server keys this agent trusts, its latest
            accepted instructions and the last heartbeat
  trust-key <generation>:<key> [--force]
            trust only this server job key, as the console prints it, and
            restart the agent's service (run as root or administrator)
  uninstall [--package deb|rpm|msi [--rollback]]
            stop and remove the agent and MeshAgent from this machine; while a
            package holds the agent, remove the package instead
  capabilities
            list what this build can do, one word a line
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
	// Checks of the machine for packages (ADR-0056), replaced by tests.
	getenv           func(string) string
	self             func() (string, error)
	handoff          func(path string, args []string) error
	clock            func() time.Time
	startForbidden   func(ctx context.Context) bool
	systemdInstalled func() bool
	packageInstalled func(ctx context.Context, kind string) bool
	// lastNote is the last thing said of the enrollment file, so that it is
	// said once.
	lastNote string
	// fileUID is who must own the enrollment file and its folders: root.
	// Tests set their own user.
	fileUID uint32
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
		getenv:      os.Getenv,
		self:        selfPath,
		handoff:     handoffExec,
		startForbidden: func(ctx context.Context) bool {
			return host.StartForbidden(ctx, p, host.Exec)
		},
		systemdInstalled: func() bool { return host.SystemdInstalled(p) },
		packageInstalled: func(ctx context.Context, kind string) bool { return host.PackageInstalled(ctx, host.Exec, kind) },
	}
}

// selfPath is this executable's resolved path.
func selfPath() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(self)
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
		if self, err := os.Executable(); err == nil && strings.Contains(strings.ToLower(filepath.Base(self)), "quick-assist") {
			args = []string{"quick-assist"}
		} else {
			_, _ = io.WriteString(stderr, usage)
			return errors.New("no command given")
		}
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
	if done, err := e.handOver(ctx, args); done {
		return err
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "capabilities":
		return e.capabilities()
	case "install":
		if kind, ok := packageKind(rest); ok {
			return e.installPackage(ctx, kind, rest)
		}
		return e.enroll(ctx, rest, true)
	case "enroll":
		return e.enroll(ctx, rest, false)
	case "quick-assist":
		return e.quickAssist(ctx, rest)
	case "builtin":
		return e.builtin(rest)
	case "repair-install":
		return e.repairInstall(ctx)
	case "run":
		return e.run(ctx)
	case "collect":
		return e.collect(ctx, rest)
	case "collect-unit":
		return e.collectUnit(rest)
	case "status":
		return e.status(ctx)
	case "trust-key":
		return e.trustKey(ctx, rest)
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
	fresh := false
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
		fresh = true
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
		// A failed install leaves no service, process or file it made: on a
		// machine this run enrolled, take back what putService may have put.
		if fresh {
			e.rollbackInstall(ctx)
		}
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

// rollbackInstall undoes a failed install on a machine this run enrolled:
// the service stopped and deleted, then the agent's files. Failures are
// logged; the install's own error is the one reported.
func (e *env) rollbackInstall(ctx context.Context) {
	if err := e.sd.Remove(ctx, e.paths.AgentService().Name); err != nil {
		e.log.Warn("could not remove the service of the failed install", "error", err)
	}
	if _, err := e.removeFiles(); err != nil {
		e.log.Warn("could not remove the files of the failed install", "error", err)
	}
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
	var pem []byte
	if caFile != "" {
		// Keep a copy: the original may be a temporary file.
		var err error
		if pem, err = os.ReadFile(caFile); err != nil { //nolint:gosec // a path the administrator chose
			return nil, nil, fmt.Errorf("reading the CA file: %w", err)
		}
	}
	return e.registerPEM(ctx, server, token, pem, service)
}

// registerPEM is register with the certificate authority's PEM in hand.
func (e *env) registerPEM(ctx context.Context, server, token string, caPEM []byte, service bool) (*state.Config, *state.Pending, error) {
	if _, err := client.ParseServer(server); err != nil {
		return nil, nil, permanent{err}
	}
	cfg := &state.Config{Server: mustServer(server), MeshAgentMode: string(meshagent.ModeChild)}
	if service {
		cfg.MeshAgentMode = string(meshagent.ModeService)
	}
	if len(caPEM) > 0 {
		var err error
		if cfg.CAFile, err = e.store.SaveCA(caPEM); err != nil {
			return nil, nil, err
		}
	}
	// A failed enrollment keeps nothing: not the copy of the CA either.
	done := false
	defer func() {
		if !done && cfg.CAFile != "" {
			_ = os.Remove(cfg.CAFile)
		}
	}()
	c, err := client.New(client.Options{Server: cfg.Server, CAFile: cfg.CAFile, TrustSystem: cfg.TrustSystem, Version: Version})
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
		done = true
		return nil, p, nil
	}
	if resp.DeviceID == "" {
		return nil, nil, errors.New("enrolling: the server answered without a device")
	}
	cfg.DeviceID, cfg.EnrolledAt = resp.DeviceID, time.Now().UTC()
	cfg.PinFirstKey(resp.JobKey, resp.JobKeyGeneration)
	if err := e.store.Save(cfg, key); err != nil {
		return nil, nil, fmt.Errorf("saving the enrollment: %w", err)
	}
	done = true
	return cfg, nil, nil
}

func (e *env) mesh(cfg *state.Config) *meshagent.Manager {
	mode := meshagent.Mode(cfg.MeshAgentMode)
	if mode != meshagent.ModeService && mode != meshagent.ModeSystemd {
		mode = meshagent.ModeChild
	}
	return meshagent.NewManager(e.paths.MeshAgent(), mode, e.sd, e.log)
}

// channelEnv is the agent-side off switch of the WebSocket channel: set to
// "off" in the agent's environment, it never connects.
const channelEnv = "EASYRMM_AGENT_CHANNEL"

func (e *env) run(ctx context.Context) error {
	if err := e.openStore(); err != nil {
		return err
	}
	cfg, key, err := e.store.Load()
	if errors.Is(err, state.ErrNotEnrolled) {
		cfg, key, err = e.awaitApproval(ctx)
		if errors.Is(err, state.ErrNotEnrolled) && e.packaged() {
			// Installed by a package without input: wait for install.conf.
			cfg, key, err = e.awaitFile(ctx)
		}
	}
	if err != nil {
		return err
	}
	if supported() {
		// An enrolled agent looks for the file when it starts: what it left is
		// deleted, never used.
		e.sweepFile(cfg)
	}
	c, err := client.New(client.Options{Server: cfg.Server, CAFile: cfg.CAFile, TrustSystem: cfg.TrustSystem, Version: Version})
	if err != nil {
		return err
	}
	jobs.AgentVersion = Version
	c.SetIdentity(cfg.DeviceID, key)
	// The server keys this agent trusts, and the log of what it accepted
	// (ADR-0057). Every check of a signed instruction below reads the keys
	// from the store, so a statement takes effect at once.
	il := &trust.InstructionLog{Store: e.store, Log: e.log}
	ks := &trust.KeyStore{DeviceID: cfg.DeviceID, Install: agentproto.InstallID(key.Public().(ed25519.PublicKey)),
		Config: cfg, Store: e.store, Log: e.log, Record: il.Record}
	if len(ks.Report()) > 0 && len(ks.Keys()) == 0 {
		return errors.New("the pinned job key in the configuration is damaged")
	}
	r := &runner.Runner{
		Client:   c,
		DeviceID: cfg.DeviceID,
		Store:    e.store,
		Accepts:  jobs.Accepts(),
		Facts:    func() agentproto.Facts { return host.Facts(Version) },
		Log:      e.log,
		// MeshAgent's files are checked with the keys trusted for jobs.
		Keys:         ks.Keys,
		JobKeys:      ks,
		Instructions: il,
		Record:       il.Record,
		Authorities:  caFingerprints(cfg.CAFile),
	}
	if runtime.GOOS == "windows" {
		r.Roles = &roles.Scanner{Read: roles.Read}
		// BitLocker recovery keys are escrowed only with the escrow key the
		// server's heartbeat answer carries (ADR-0081).
		r.Escrow = &escrow.Agent{DeviceID: cfg.DeviceID, Keys: ks.Keys, Reader: escrow.SystemReader{}, Manager: escrow.SystemManager{}, LUKS: cryptsetup.System(), Server: c, Store: e.store, Log: e.log}
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
			// The Defender event log, read once a heartbeat where the
			// server asked for it (ADR-0074).
			r.DefenderLog = &winevents.Collector{Source: winevents.NewDefenderSource(), File: winevents.BookmarkPath(e.paths.State())}
		}
	}
	e.log.Info("EasyRMM agent started", "version", Version, "server", cfg.Server, "device_id", cfg.DeviceID)
	if !supported() {
		return r.Run(ctx)
	}
	up := e.updater(cfg, c, ks.Keys, il.Record)
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
	w := &jobs.Worker{Client: c, DeviceID: cfg.DeviceID, Dir: e.store.JobsDir(), Log: e.log, Finished: r.RefreshInventory,
		Keys: ks.Keys, Dropped: ks.Dropped, Report: ks.Report, Record: il.Record}
	if ea, ok := r.Escrow.(*escrow.Agent); ok && e.paths.Windows() {
		// Native actions (ADR-0081): BitLocker's enable runs as agent code, so
		// the recovery password it makes never passes through a script.
		w.Execute = jobs.WithNative(jobs.Execute, map[string]jobs.NativeHandler{agentproto.NativeBitLockerEnable: enableBitLocker(ea)})
	}
	if e.paths.Windows() {
		// The state check leaves out the scripts' working folders: scripts
		// ran there as SYSTEM and may have left links or files others own.
		// Nothing there is read; they start empty. openStore checked jobs
		// itself, and RemoveAll follows no link or junction below it.
		if err := w.ClearWork(); err != nil {
			e.log.Warn("emptying the scripts' working folder failed", "error", err)
		}
	}
	// The EasyPatch agent's install (ADR-0031) trusts the same keys.
	ep := &easypatch.Installer{DeviceID: cfg.DeviceID, Keys: ks.Keys, Record: il.Record, Dir: e.store.Dir(), Log: e.log,
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
	r.OnJobKey = e.pinJobKey(ks, w)
	r.Removal = &removal.Remover{
		DeviceID: cfg.DeviceID, Keys: ks.Keys, Record: il.Record, Dir: e.store.Dir(), Log: e.log,
		Launch: e.launchRemoval, Report: c.Removed,
	}
	// Certificate chains are verified, and trust widened, only for an
	// instruction signed with the pinned job key (ADR-0055).
	r.Trust = &trust.Agent{DeviceID: cfg.DeviceID, Config: cfg, Keys: ks.Keys, Record: il.Record, Store: e.store, Client: c, Log: e.log}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var ch *channel.Channel
	send := sendLogs(c)
	if os.Getenv(channelEnv) != "off" {
		// The WebSocket channel (ADR-0059): wakes, and the server's pushes of
		// jobs, repairs, settings and log instructions, each applied by the
		// code that applies it from a heartbeat or poll answer. While
		// someone follows the logs, batches go over it too, and over HTTPS
		// whenever it cannot take one. EASYRMM_AGENT_CHANNEL=off turns it off.
		ch = channel.New(channel.Config{Dialer: c, DeviceID: cfg.DeviceID, Keys: ks.Keys, Log: e.log, Device: key,
			Handlers: channel.Handlers{Jobs: w.Deliver, Logs: ship.Apply, Repair: r.ApplyRepair, Settings: r.ApplySettings, PollNow: w.PollNow}})
		r.Channel, r.Nudge, r.OnJobsWaiting = ch, ch.Checkin, w.PollNow
		w.Live, w.Changed = ch.Live, ch.LiveChanged()
		send = ch.LogSender(ship.Following, send)
	}
	var g sync.WaitGroup
	g.Go(func() { e.watchFile(ctx, cfg) })
	g.Go(func() { _ = w.Run(ctx) })
	g.Go(func() { ship.Run(ctx, send) })
	e.startCollected(ctx, &g, c)
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
	if ch != nil {
		g.Go(func() { ch.Run(ctx) })
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
func (e *env) updater(cfg *state.Config, c *client.Client, keys func() agentproto.Keys, record agentproto.InstructionRecorder) *update.Updater {
	exe, sum, err := update.Self()
	if err != nil {
		e.log.Warn("reading the agent's own executable failed; it cannot update itself", "error", err)
		return nil
	}
	return &update.Updater{
		Client: c, DeviceID: cfg.DeviceID, Version: Version, SHA256: sum, Exe: exe, Dir: e.store.Dir(), Log: e.log,
		// The keys trusted for jobs sign updates too.
		Keys: keys, Record: record,
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
// (ADR-0017), learns the generation of a key pinned before generations, and
// never follows a key it is not handed by a statement (ADR-0057).
func (e *env) pinJobKey(ks *trust.KeyStore, w *jobs.Worker) func(string, int64) {
	var warned time.Time
	return func(key string, generation int64) {
		had := len(ks.Keys())
		trusted, err := ks.Pin(key, generation)
		switch {
		case err != nil:
			e.log.Error("the server sent a job key that cannot be used", "error", err)
		case trusted && had == 0:
			w.KeysChanged()
			e.log.Info("pinned the server's job key")
		case !trusted && time.Since(warned) > time.Hour:
			warned = time.Now()
			e.log.Error("the server's job key is not one this agent trusts; jobs signed with it are refused. The server hands over a new key with a signed statement; if it cannot, run trust-key on this computer.")
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
	e.packageStatus()
	e.printKeys(cfg)
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
	pkg := fs.String("package", "", "the package whose removal script runs this (deb, rpm or msi)")
	rollback := fs.Bool("rollback", false, "with --package: undo only what the package's install did")
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
	if *pkg != "" {
		return e.uninstallPackage(ctx, *pkg, *rollback)
	}
	if *rollback {
		return errors.New("--rollback goes with --package")
	}
	// While the package manager lists the package, removing the agent by hand
	// would leave the package installed and out of step (ADR-0056).
	if kind := e.packageHolds(ctx); kind != "" {
		return fmt.Errorf("the %s package holds this agent; remove the package instead, which removes the agent: %s", strings.ToUpper(kind), host.PackageRemoveCommand(kind))
	}
	return e.uninstallAll(ctx)
}

// uninstallAll removes the agent: its service, MeshAgent, state, program and
// enrollment file.
func (e *env) uninstallAll(ctx context.Context) error {
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
	// The token goes with the agent: the file is deleted whatever installed it
	// (ADR-0056).
	e.removeEnrollmentFile()
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

// enableBitLocker is the native handler of BitLocker's enable action. The
// parameters are the server's, signed and hash-checked; they are read strictly.
func enableBitLocker(ea *escrow.Agent) jobs.NativeHandler {
	return func(ctx context.Context, params []byte) string {
		var p agentproto.BitLockerEnableParams
		dec := json.NewDecoder(bytes.NewReader(params))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil || p.Computer == "" || p.Volume == "" {
			return agentproto.NativeResult(agentproto.NativeBitLockerEnableVersion, nil, "bad_params", "The action's parameters are not valid.")
		}
		return ea.EnableBitLocker(ctx, p)
	}
}
