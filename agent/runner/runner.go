// Package runner is the agent's main loop: heartbeats with the device's
// metrics, its inventory when the server's copy is out of date, MeshAgent
// once the server offers it, updates of the agent itself and the EasyPatch
// agent's install. Jobs run beside it (package jobs).
package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// MeshAgent is the part of the MeshAgent manager the loop uses.
type MeshAgent interface {
	Installed() bool
	Install(ctx context.Context, download func(io.Writer) error, settings []byte) error
	Start(ctx context.Context) error
	NodeID(ctx context.Context) (string, error)
	// State is reported with each heartbeat (ADR-0069).
	State(ctx context.Context) agentproto.MeshAgentState
	// Restart restarts MeshAgent; an error means it needs Repair.
	Restart(ctx context.Context) error
	// Repair puts MeshAgent's program, settings and service back in place,
	// keeping its identity.
	Repair(ctx context.Context, download func(io.Writer) error, settings []byte) error
	// AppliedSettings is the hash of the settings last applied from the
	// server; Reconfigure applies new ones and restarts MeshAgent.
	AppliedSettings() string
	Reconfigure(ctx context.Context, settings []byte) error
}

// Updater is the agent's self-update (package update, ADR-0027).
type Updater interface {
	// Report returns a failed update attempt to report, or nil.
	Report() *agentproto.UpdateReport
	// Reached is told that a heartbeat got through.
	Reached()
	// Unreached is told that a heartbeat failed; true means a new build was
	// undone and the agent must restart.
	Unreached() bool
	// Apply acts on a heartbeat answer's update instruction, nil for none;
	// true means a new build is in place and the agent must restart.
	Apply(ctx context.Context, u *agentproto.SignedUpdate) bool
}

// EasyPatch installs the EasyPatch agent when the server says so (package
// easypatch, ADR-0031).
type EasyPatch interface {
	// Status is reported with each heartbeat.
	Status() *agentproto.EasyPatchInstallStatus
	// Start acts on a heartbeat answer's install instruction, nil for none.
	Start(ctx context.Context, s *agentproto.SignedEasyPatchInstall)
}

// PatchRepairs carries out repairs of the EasyPatch agent (package
// easypatch, ADR-0069).
type PatchRepairs interface {
	// Restart restarts the EasyPatch agent's service.
	Restart(ctx context.Context) error
	// Repair reinstalls the package of the version installed, keeping the
	// agent's enrollment. within bounds it.
	Repair(ctx, within context.Context, r *agentproto.RepairEasyPatch) error
}

// Removal uninstalls the agent when the server says so (package removal,
// ADR-0050).
type Removal interface {
	// Apply acts on a heartbeat answer's uninstall instruction. True means
	// the agent must stop and uninstall itself in this process; otherwise
	// an uninstaller runs outside the agent's service, or nothing does.
	Apply(ctx context.Context, u *agentproto.SignedUninstall) bool
}

// ErrRestart ends Run when the agent must restart into another build of
// itself.
var ErrRestart = errors.New("runner: the agent must restart into another build")

// ErrRemoved ends Run when the agent must uninstall itself in this process.
var ErrRemoved = errors.New("runner: the agent must uninstall itself")

// Runner runs an enrolled agent.
type Runner struct {
	Client *client.Client
	// DeviceID is this device's id: repair instructions are for it alone.
	DeviceID string
	Store    state.Store
	// Mesh is nil where MeshAgent is not supported.
	Mesh  MeshAgent
	Facts func() agentproto.Facts
	Log   *slog.Logger
	// OnJobKey receives the server's job-signing key from each heartbeat.
	OnJobKey func(key string)
	// Key returns the pinned job-signing key, nil while none is pinned.
	// MeshAgent and its settings are installed only when the server signed
	// them with it.
	Key func() ed25519.PublicKey
	// Metrics measures the device for each heartbeat; nil sends none.
	Metrics func(ctx context.Context) agentproto.Metrics
	// Inventory collects the device's inventory (ADR-0018); nil never
	// uploads one.
	Inventory func(ctx context.Context) agentproto.Inventory
	// Update updates the agent (ADR-0027); nil never does.
	Update Updater
	// EasyPatch installs the EasyPatch agent (ADR-0031); nil never does.
	EasyPatch EasyPatch
	// Removal uninstalls the agent (ADR-0050); nil never does.
	Removal Removal
	// Patch repairs the EasyPatch agent (ADR-0069); nil never does.
	Patch PatchRepairs
	// Settled is called after a heartbeat got through and the build is not
	// on probation, until it returns true: the agent keeps its recovery
	// copy then (ADR-0069). nil does nothing.
	Settled func() bool
	// OnLogs receives how the server wants the agent to log from each
	// heartbeat answer (ADR-0069); nil ignores it.
	OnLogs func(*agentproto.LogInstructions)
	// Hardware reads the device's hardware health (ADR-0065); nil never
	// does. It runs on a goroutine of its own, so that a slow disk never
	// delays a heartbeat.
	Hardware func(ctx context.Context) agentproto.HardwareReport

	// Timing, shortened by tests.
	MinRetry    time.Duration // first retry after a failure (5 s)
	MaxRetry    time.Duration // longest retry interval (5 min)
	InstallWait time.Duration // between MeshAgent install attempts (10 min)
	AfterSetup  time.Duration // next heartbeat after installing MeshAgent (15 s)
	// InventoryEvery is how often the inventory is collected again (1 h).
	InventoryEvery time.Duration
	// InventoryRetry is the wait after a failed upload (15 min).
	InventoryRetry time.Duration
	// HardwareFirst is the wait from Run's start to the first hardware
	// reading (2 min); HardwareEvery is the wait between readings (30
	// min), each plus up to HardwareJitter (1 min).
	HardwareFirst, HardwareEvery, HardwareJitter time.Duration

	status      state.Status
	failures    int
	lastInstall time.Time
	inv         []byte // the inventory's JSON, as hashed and uploaded
	invHash     string
	invNew      bool // inv has the fields added after protocol level 2
	invAt       time.Time
	invFailed   time.Time
	invStale    atomic.Bool
	// meshErr is the last failure of installing MeshAgent, for its state.
	meshErr string
	repair  repairs
	// settled: Settled has returned true.
	settled bool
}

// RefreshInventory has the inventory collected again at the next heartbeat,
// as after a job that may have installed or removed software. It is safe
// to call from any goroutine.
func (r *Runner) RefreshInventory() { r.invStale.Store(true) }

func (r *Runner) defaults() {
	if r.MinRetry == 0 {
		r.MinRetry = 5 * time.Second
	}
	if r.MaxRetry == 0 {
		r.MaxRetry = 5 * time.Minute
	}
	if r.InstallWait == 0 {
		r.InstallWait = 10 * time.Minute
	}
	if r.AfterSetup == 0 {
		r.AfterSetup = 15 * time.Second
	}
	if r.InventoryEvery == 0 {
		r.InventoryEvery = time.Hour
	}
	if r.InventoryRetry == 0 {
		r.InventoryRetry = 15 * time.Minute
	}
	if r.HardwareFirst == 0 {
		r.HardwareFirst = 2 * time.Minute
	}
	if r.HardwareEvery == 0 {
		r.HardwareEvery = 30 * time.Minute
	}
	if r.HardwareJitter == 0 {
		r.HardwareJitter = time.Minute
	}
}

// Run sends heartbeats until ctx ends, or returns ErrRestart when the
// agent must restart into another build, ErrRemoved when it must uninstall
// itself.
func (r *Runner) Run(ctx context.Context) error {
	r.defaults()
	defer r.repair.wait()
	if r.Hardware != nil {
		hctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			r.hardwareLoop(hctx)
		}()
		defer func() {
			cancel()
			<-done
		}()
	}
	if r.Mesh != nil && r.Mesh.Installed() {
		// A systemd unit restarts by itself; a child process needs us.
		if err := r.Mesh.Start(ctx); err != nil {
			r.Log.Error("starting MeshAgent failed", "error", err)
		}
	}
	for {
		wait, err := r.beat(ctx)
		if err != nil && ctx.Err() == nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// beat sends one heartbeat and acts on the answer. It returns how long to
// wait before the next one, or ErrRestart, ErrRemoved or ctx's error.
func (r *Runner) beat(ctx context.Context) (time.Duration, error) {
	f := r.Facts()
	if r.Mesh != nil && r.Mesh.Installed() {
		id, err := r.Mesh.NodeID(ctx)
		if err != nil {
			r.Log.Warn("reading MeshAgent's node id failed", "error", err)
		}
		f.MeshNodeID = id
		f.MeshSettingsSHA256 = r.Mesh.AppliedSettings()
		r.status.MeshNodeID = id
	}
	req := agentproto.HeartbeatRequest{Facts: f}
	if r.Metrics != nil {
		m := r.Metrics(ctx)
		req.Metrics = &m
	}
	if r.Update != nil {
		req.Update = r.Update.Report()
	}
	if r.EasyPatch != nil {
		req.EasyPatch = r.EasyPatch.Status()
	}
	if r.Client.Level() >= 2 {
		// Fields added after protocol level 2 (ADR-0009).
		if r.Mesh != nil {
			st := r.Mesh.State(ctx)
			if st.Error == "" {
				st.Error = r.meshErr
			}
			req.MeshAgent = &st
		}
		req.Repair = r.repair.report(time.Now())
	}
	resp, err := r.Client.Heartbeat(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if r.Update != nil && r.Update.Unreached() {
			return 0, ErrRestart
		}
		return r.failed(err), nil
	}
	r.failures = 0
	if r.Update != nil {
		r.Update.Reached()
		if r.Settled != nil && !r.settled {
			// A build that has reached the server is settled: the moment for
			// its recovery copy (ADR-0069), never during probation.
			r.settled = r.Settled()
		}
	}
	if r.OnJobKey != nil && resp.JobKey != "" {
		r.OnJobKey(resp.JobKey)
	}
	r.status.LastHeartbeat = time.Now().UTC()
	r.status.LastError, r.status.LastErrorAt = "", time.Time{}
	next := jitter(heartbeatInterval(resp.HeartbeatSeconds))
	if resp.Uninstall != nil {
		// The device is being removed: nothing else is done (ADR-0050).
		r.save()
		if r.Removal != nil && r.Removal.Apply(ctx, resp.Uninstall) {
			return 0, ErrRemoved
		}
		return next, nil
	}
	if r.OnLogs != nil {
		r.OnLogs(resp.Logs)
	}
	if r.Inventory != nil {
		r.syncInventory(ctx, resp.InventoryHash)
	}
	if r.Mesh != nil {
		switch {
		case r.Mesh.Installed():
			r.status.MeshAgent = "installed"
			if want := resp.MeshAgent.SettingsSHA256; want != "" && want != r.Mesh.AppliedSettings() {
				if err := r.applyMeshSettings(ctx, want); err != nil {
					r.Log.Error("applying MeshAgent's new settings failed", "error", err)
					r.status.MeshAgent = "settings update failed: " + err.Error()
				} else {
					r.Log.Info("MeshAgent joined its device group again after the device moved")
				}
			}
		case !resp.MeshAgent.Available:
			r.status.MeshAgent = "not available from the server"
		case time.Since(r.lastInstall) >= r.InstallWait:
			r.lastInstall = time.Now()
			if err := r.installMesh(ctx); err != nil {
				r.Log.Error("installing MeshAgent failed", "error", err)
				r.status.MeshAgent = "install failed: " + err.Error()
				r.meshErr = "install failed: " + err.Error()
			} else {
				r.Log.Info("installed MeshAgent")
				r.meshErr = ""
				r.status.MeshAgent = "installed"
				next = r.AfterSetup // report the node id soon
			}
		}
	}
	if r.EasyPatch != nil {
		r.EasyPatch.Start(ctx, resp.EasyPatchInstall)
	}
	if resp.Repair != nil {
		r.startRepair(ctx, resp.Repair)
	}
	if r.Update != nil && r.Update.Apply(ctx, resp.Update) {
		r.save()
		return 0, ErrRestart
	}
	r.save()
	return next, nil
}

// syncInventory collects the inventory when it is due and uploads it when
// the server's copy differs. The fields added after protocol level 2
// (powerShell, ADR-0064) are left out while the server's last answer was of
// a lower level (ADR-0009), and the inventory is collected again when that
// changes.
func (r *Runner) syncInventory(ctx context.Context, serverHash string) {
	newFields := r.Client.Level() >= 2
	if stale := r.invStale.Swap(false); r.inv == nil || stale || newFields != r.invNew || time.Since(r.invAt) >= r.InventoryEvery {
		inv := r.Inventory(ctx)
		if !newFields {
			inv.PowerShell = nil
		}
		b, err := json.Marshal(inv)
		if err != nil {
			r.Log.Error("encoding the inventory failed", "error", err)
			return
		}
		r.inv, r.invHash, r.invNew, r.invAt = b, inv.Hash(), newFields, time.Now()
	}
	if serverHash == r.invHash {
		return
	}
	if !r.invFailed.IsZero() && time.Since(r.invFailed) < r.InventoryRetry {
		return
	}
	if _, err := r.Client.Inventory(ctx, r.inv); err != nil {
		if ctx.Err() == nil {
			r.Log.Warn("uploading the inventory failed", "error", err)
			r.invFailed = time.Now()
			r.status.InventoryError = err.Error()
		}
		return
	}
	r.invFailed = time.Time{}
	r.status.InventoryUploaded, r.status.InventoryError = time.Now().UTC(), ""
	r.Log.Info("uploaded the inventory", "bytes", len(r.inv))
}

func (r *Runner) failed(err error) time.Duration {
	r.failures++
	r.status.LastError, r.status.LastErrorAt = err.Error(), time.Now().UTC()
	r.save()
	wait := r.MinRetry << min(r.failures-1, 10)
	switch client.Code(err) {
	case "device_unknown":
		r.Log.Error("the server does not know this device; it may have been removed. Reinstall the agent with a new deployment token.", "error", err)
		wait = r.MaxRetry
	case "clock_skew":
		r.Log.Error("this machine's clock is wrong; correct it (for example enable NTP)", "error", err)
	default:
		r.Log.Warn("heartbeat failed", "error", err, "attempt", r.failures)
	}
	return jitter(min(wait, r.MaxRetry))
}

// installMesh installs MeshAgent, which runs as SYSTEM or root: its binary
// and settings are used only if the server signed them with the pinned job
// key (agentproto.SignDownload).
func (r *Runner) installMesh(ctx context.Context) error {
	download, settings, err := r.meshPackage(ctx)
	if err != nil {
		return err
	}
	return r.Mesh.Install(ctx, download, settings)
}

// meshPackage fetches MeshAgent's settings and returns them with a function
// that downloads its binary, each checked against the server's signature.
func (r *Runner) meshPackage(ctx context.Context) (func(io.Writer) error, []byte, error) {
	key := r.Key()
	if key == nil {
		return nil, nil, errors.New("no server key is pinned yet to check MeshAgent with")
	}
	settings, signed, err := r.Client.MeshSettings(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := signed.Verify(key); err != nil {
		return nil, nil, fmt.Errorf("MeshAgent's settings: %w", err)
	}
	return func(w io.Writer) error {
		signed, err := r.Client.MeshAgent(ctx, runtime.GOOS, runtime.GOARCH, w)
		if err != nil {
			return err
		}
		if err := signed.Verify(key); err != nil {
			return fmt.Errorf("MeshAgent: %w", err)
		}
		return nil
	}, settings, nil
}

// applyMeshSettings replaces MeshAgent's settings after the device moved to
// another site. MeshAgent runs as SYSTEM or root, so they are used only if
// the server signed them with the pinned job key and they are the settings
// the heartbeat announced.
func (r *Runner) applyMeshSettings(ctx context.Context, want string) error {
	key := r.Key()
	if key == nil {
		return errors.New("no server key is pinned yet to check MeshAgent's settings with")
	}
	settings, signed, err := r.Client.MeshSettings(ctx)
	if err != nil {
		return err
	}
	if err := signed.Verify(key); err != nil {
		return fmt.Errorf("MeshAgent's settings: %w", err)
	}
	if sum := sha256.Sum256(settings); hex.EncodeToString(sum[:]) != want {
		return errors.New("MeshAgent's settings are not the ones the server announced")
	}
	return r.Mesh.Reconfigure(ctx, settings)
}

// heartbeatInterval is the server's heartbeat interval, kept within
// agentproto's bounds so that no answer can silence the agent.
func heartbeatInterval(seconds int) time.Duration {
	if seconds <= 0 {
		return time.Minute
	}
	return time.Duration(min(max(seconds, agentproto.MinHeartbeatSeconds), agentproto.MaxHeartbeatSeconds)) * time.Second
}

func (r *Runner) save() {
	if err := r.Store.SaveStatus(r.status); err != nil {
		r.Log.Warn("saving the agent status failed", "error", err)
	}
}

// hardwareLoop reads the hardware HardwareFirst after Run starts and then
// every HardwareEvery plus up to HardwareJitter, until ctx ends.
func (r *Runner) hardwareLoop(ctx context.Context) {
	wait := r.HardwareFirst
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		r.sendHardware(ctx)
		wait = r.hardwareWait()
	}
}

// hardwareWait is the wait between two readings: HardwareEvery plus up to
// HardwareJitter, so a fleet does not read in lockstep.
func (r *Runner) hardwareWait() time.Duration {
	return r.HardwareEvery + time.Duration(rand.Int64N(int64(r.HardwareJitter)+1)) //nolint:gosec // timing jitter, not security
}

// sendHardware reads the hardware and sends the report once. There is no
// queue: a reading that cannot be sent is dropped, and the next one is
// fresher. An older server without the endpoint answers 404, which is
// dropped quietly.
func (r *Runner) sendHardware(ctx context.Context) {
	report := r.Hardware(ctx)
	if ctx.Err() != nil {
		return
	}
	// A report holds strings and integers only: it always encodes.
	body, _ := json.Marshal(report)
	var e *client.Error
	switch err := r.Client.Hardware(ctx, body); {
	case err == nil, ctx.Err() != nil:
	case errors.As(err, &e) && e.Status == http.StatusNotFound:
		r.Log.Debug("the server does not take hardware reports; the reading is dropped")
	default:
		r.Log.Warn("sending the hardware report failed; the reading is dropped", "error", err)
	}
}

// jitter spreads d by ±10% so a fleet does not report in lockstep.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	spread := int64(d) / 5
	if spread <= 0 {
		return d
	}
	return d - time.Duration(spread/2) + time.Duration(rand.Int64N(spread)) //nolint:gosec // timing jitter, not security
}
