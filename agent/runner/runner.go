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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paulmataruso/easyrmm/agent/channel"
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

// Channel is the agent's WebSocket channel (package channel, ADR-0059). The
// runner only feeds it each heartbeat answer, reports the connection it
// holds, and checks in at once when it is woken; the heartbeat's own timer
// keeps running whatever the channel does.
type Channel interface {
	// Answered receives each heartbeat answer.
	Answered(resp *agentproto.HeartbeatResponse, reported bool)
	// Report names the connection held, nil for none.
	Report() *agentproto.ChannelReport
	// Wakes delivers the server's verified wakes.
	Wakes() <-chan channel.Wake
}

// ErrRestart ends Run when the agent must restart into another build of
// itself.
var ErrRestart = errors.New("runner: the agent must restart into another build")

// ErrRemoved ends Run when the agent must uninstall itself in this process.
var ErrRemoved = errors.New("runner: the agent must uninstall itself")

// RoleScanner detects the roles of a Windows computer, caching the result
// (agent/roles.Scanner).
type RoleScanner interface {
	Roles(ctx context.Context) []agentproto.Role
	Rescan()
}

// EscrowAgent escrows recovery keys (agent/escrow.Agent).
type EscrowAgent interface {
	// Caps is what the agent announces in its heartbeat.
	Caps() []string
	// Answered takes the signed escrow key of a heartbeat answer, nil when it
	// carried none.
	Answered(*agentproto.SignedEscrowKey)
	// Start works in the background and never blocks the heartbeat.
	Start(ctx context.Context)
}

// TrustAgent handles ADR-0055's trust instructions (agent/trust.Agent).
type TrustAgent interface {
	// Caps is what the agent announces in its heartbeat.
	Caps() []string
	// Report is the report of the last instruction handled, nil when none is
	// to be sent.
	Report() *agentproto.TrustReport
	// Answered takes the signed instruction of a heartbeat answer, nil when
	// it carried none, and the server's protocol level.
	Answered(ctx context.Context, level int, s *agentproto.SignedTrust)
}

// KeyFollower is the agent's key store as the runner uses it (ADR-0057).
type KeyFollower interface {
	// Caps is what the agent announces in its heartbeat.
	Caps() []string
	// Report is each key the agent trusts, with its generation.
	Report() []agentproto.TrustedKey
	// Refusal is the statement the agent last refused, nil for none.
	Refusal() *agentproto.KeyRefusal
	// Answered handles a heartbeat answer's statements, the hand-over first.
	Answered(level int, handover, cutover *agentproto.SignedKeyStatement)
}

// InstructionLog is the agent's log of accepted instructions as the runner
// uses it (ADR-0057).
type InstructionLog interface {
	// Report is what the next heartbeat carries; nil unless the server
	// listed the feature.
	Report(featureListed bool) *agentproto.InstructionLogReport
	// Acknowledged takes the server's acknowledgment.
	Acknowledged(ack uint64)
}

// SettingsAgent is the agent's signed settings (agent/settings.Agent,
// ADR-0058).
type SettingsAgent interface {
	// Capabilities and Report are the agent's report for its heartbeat.
	Capabilities() *agentproto.SettingsCapabilities
	Report() *agentproto.SettingsReport
	// Answered takes a heartbeat answer's document, nil when it carried none,
	// and the server's protocol level; true means what the agent reports
	// changed.
	Answered(level int, s *agentproto.SignedSettings) bool
	// Interval is the heartbeat interval in seconds given the answer's, and
	// whether a document set it.
	Interval(answered int) (seconds int, held bool)
}

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
	// OnJobKey receives the server's job-signing key and its generation from
	// each heartbeat answer.
	OnJobKey func(key string, generation int64)
	// Keys returns the job-signing keys the agent trusts, nil while none is
	// pinned. MeshAgent and its settings are installed only when the server
	// signed them with one of them.
	Keys func() agentproto.Keys
	// JobKeys follows the server's job key (ADR-0057): the report of the
	// keys the agent trusts, and the statements that change them; nil
	// reports nothing and takes no statement.
	JobKeys KeyFollower
	// Instructions is the log of the instructions the agent accepted
	// (ADR-0057); nil keeps none. Record is what the code that verifies an
	// instruction calls.
	Instructions InstructionLog
	Record       agentproto.InstructionRecorder
	// Authorities are the SHA-256 fingerprints of the certificates in the
	// ca.pem the agent loaded, sent with the key report (ADR-0057).
	Authorities []string
	// Metrics measures the device for each heartbeat; nil sends none.
	Metrics func(ctx context.Context) agentproto.Metrics
	// Accepts is the job capabilities this build takes, sent with each
	// heartbeat; nil sends none.
	Accepts []string
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

	// Channel is the WebSocket channel (ADR-0059); nil never uses one.
	Channel Channel
	// Nudge asks for a heartbeat soon, after a pushed repair or settings
	// change; OnJobsWaiting has the job worker make one ordinary poll. Both
	// are optional.
	Nudge         func(reason string)
	OnJobsWaiting func()
	// Every, if set, replaces the heartbeat interval the server names (tests).
	Every time.Duration
	// MinWake is the least time between a wake's heartbeat and the one
	// before it (1 s).
	MinWake time.Duration

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
	// Defender keeps the Microsoft Defender exclusions (ADR-0070) and
	// Installed hashes the installed programs; nil never does. Both run
	// only where the server's last answer allowed it.
	Defender  DefenderManager
	Installed InstalledReporter
	// DefenderLog reads Defender's event log for the server (ADR-0074); nil
	// reads none. It runs only where the server's last answer said Events.
	DefenderLog DefenderLogReader
	// Roles detects the Windows roles reported with each heartbeat
	// (ADR-0073); nil reports none.
	Roles RoleScanner
	// Escrow escrows BitLocker recovery keys (ADR-0081); nil escrows none.
	// It works only with the escrow key the server's last answer carried.
	Escrow EscrowAgent
	// Trust verifies certificate chains and widens the agent's trust when a
	// signed instruction asks (ADR-0055); nil does neither.
	Trust TrustAgent
	// Settings holds the signed settings the server sends (ADR-0058); nil
	// takes none, and the agent follows the answer's interval as before.
	Settings SettingsAgent
	// ReportWithin is how soon the next heartbeat comes after a document was
	// applied or refused, and after the first of a process, so that the
	// server hears the report (5 s, within the ADR's 10).
	ReportWithin time.Duration

	// instrFeature: the server's last answer listed the instruction log.
	instrFeature bool

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
	meshMu  sync.Mutex
	repair  repairs
	// settled: Settled has returned true.
	settled bool
	defend  defenderState
	// interval is the interval the agent uses, before jitter, from its last
	// answer (0 before any); metricsAt is when the last heartbeat whose
	// metrics the server accepted was sent (ADR-0058).
	interval  time.Duration
	metricsAt time.Time
}

// RefreshInventory has the inventory collected again at the next heartbeat,
// as after a job that may have installed or removed software. It is safe
// to call from any goroutine.
func (r *Runner) RefreshInventory() { r.invStale.Store(true) }

func (r *Runner) defaults() {
	if r.MinWake == 0 {
		r.MinWake = time.Second
	}
	if r.MinRetry == 0 {
		r.MinRetry = 5 * time.Second
	}
	if r.MaxRetry == 0 {
		r.MaxRetry = 5 * time.Minute
	}
	if r.InstallWait == 0 {
		r.InstallWait = 10 * time.Minute
	}
	if r.ReportWithin == 0 {
		r.ReportWithin = 5 * time.Second
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
	var wakes <-chan channel.Wake
	if r.Channel != nil {
		wakes = r.Channel.Wakes()
	}
	for {
		beatAt := time.Now()
		wait, err := r.beat(ctx)
		if err != nil && ctx.Err() == nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		case <-wakes:
			// A wake brings the next heartbeat forward, never past MinWake.
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(max(0, r.MinWake-time.Since(beatAt))):
			}
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
	if r.Roles != nil {
		f.Roles = r.Roles.Roles(ctx)
	}
	req := agentproto.HeartbeatRequest{Facts: f}
	sentAt := time.Now()
	if r.Metrics != nil && r.metricsDue(sentAt) {
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
		r.defendRequest(ctx, &req)
	}
	if r.Settings != nil && r.Client.Level() >= 2 {
		// The report for signed settings (ADR-0058): none before the first
		// answer of a process, and a heartbeat without it changes nothing on
		// the server.
		req.Capabilities, req.Settings = r.Settings.Capabilities(), r.Settings.Report()
		req.HeartbeatSeconds = int(r.interval / time.Second)
	}
	if r.Channel != nil && r.Client.Level() >= 2 {
		req.Channel = []string{agentproto.ChannelCapability}
		req.Transport = r.Channel.Report()
	}
	if r.Escrow != nil && r.Client.Level() >= 2 {
		req.Caps = r.Escrow.Caps()
	}
	if r.Client.Level() >= 2 {
		req.Accepts = r.Accepts
	}
	if r.Trust != nil && r.Client.Level() >= 2 {
		// Added after level 2: only a server that reads it hears it (ADR-0009).
		req.Caps = append(req.Caps, r.Trust.Caps()...)
		req.Trust = r.Trust.Report()
	}
	if r.JobKeys != nil && r.Client.Level() >= 2 {
		// The keys the agent trusts, the authorities it loaded, a statement
		// it refused and its instruction log, by the same rule: none in a
		// process's first heartbeat, since no answer has been seen.
		req.Caps = append(req.Caps, r.JobKeys.Caps()...)
		req.JobKeys = r.JobKeys.Report()
		req.Authorities = r.Authorities
		req.KeyRefused = r.JobKeys.Refusal()
		if r.Instructions != nil {
			req.InstructionLog = r.Instructions.Report(r.instrFeature)
		}
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
	if r.JobKeys != nil {
		// Before anything else in the answer: its instructions are checked
		// with the keys the agent trusts after the statements (ADR-0057).
		r.JobKeys.Answered(r.Client.Level(), resp.KeyHandover, resp.KeyCutover)
	}
	if r.Instructions != nil {
		r.instrFeature = slices.Contains(resp.Features, agentproto.FeatureInstructionLog)
		if r.instrFeature {
			r.Instructions.Acknowledged(resp.InstructionAck)
		}
	}
	if r.Channel != nil {
		r.Channel.Answered(resp, len(req.Channel) > 0)
	}
	if resp.JobsWaiting && r.OnJobsWaiting != nil {
		r.OnJobsWaiting()
	}
	r.defendAnswered(resp.Defender)
	if resp.RescanRoles && r.Roles != nil {
		r.Roles.Rescan()
	}
	if r.Update != nil {
		r.Update.Reached()
		if r.Settled != nil && !r.settled {
			// A build that has reached the server is settled: the moment for
			// its recovery copy (ADR-0069), never during probation.
			r.settled = r.Settled()
		}
	}
	if r.OnJobKey != nil && resp.JobKey != "" {
		r.OnJobKey(resp.JobKey, resp.JobKeyGeneration)
	}
	if req.Metrics != nil {
		r.metricsAt = sentAt
	}
	r.status.LastHeartbeat = time.Now().UTC()
	r.status.LastError, r.status.LastErrorAt = "", time.Time{}
	r.interval = heartbeatInterval(resp.HeartbeatSeconds)
	if r.Every > 0 {
		r.interval = r.Every
	}
	next := jitter(r.interval)
	if r.Every > 0 {
		next = r.Every
	}
	if resp.Uninstall != nil {
		// The device is being removed: nothing else is done (ADR-0050).
		r.save()
		if r.Removal != nil && r.Removal.Apply(ctx, resp.Uninstall) {
			return 0, ErrRemoved
		}
		return next, nil
	}
	soon := time.Duration(0)
	if r.Settings != nil {
		// The document is handled after the answer's key hand-over, so one
		// signed with a new key verifies. The next heartbeat comes soon after
		// a document was applied or refused, and after the first of a
		// process, which carried no report.
		applied := r.Settings.Answered(r.Client.Level(), resp.Settings)
		// A document's interval, or the answer's when it is shorter, never
		// below the catalogue's minimum (ADR-0058).
		if secs, held := r.Settings.Interval(resp.HeartbeatSeconds); held && r.Every == 0 {
			r.interval = time.Duration(secs) * time.Second
		}
		if applied || (req.Capabilities == nil && r.Client.Level() >= 2) {
			soon = r.ReportWithin
		}
	}
	next = jitter(r.interval)
	if r.Every > 0 {
		next = r.Every
	}
	if r.OnLogs != nil {
		r.OnLogs(resp.Logs)
	}
	if r.Escrow != nil {
		r.Escrow.Answered(resp.Escrow)
		r.Escrow.Start(ctx)
	}
	if r.Trust != nil {
		// After the update was confirmed above: a trust change is made only
		// by a build that reached the server, so a rollback cannot lose it.
		r.Trust.Answered(ctx, r.Client.Level(), resp.Trust)
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
	if soon > 0 {
		next = min(next, soon)
	}
	return next, nil
}

// metricsDue says whether a heartbeat sent at now carries metrics: only 0.8 of
// the interval after the last heartbeat whose metrics the server accepted, so
// that the extra heartbeats (a document applied, a wake) never make two
// measurements seconds apart (ADR-0058). A heartbeat that failed counts as
// carrying none, so the next one carries them.
func (r *Runner) metricsDue(now time.Time) bool {
	if r.metricsAt.IsZero() {
		return true
	}
	every := r.interval
	if every <= 0 {
		every = time.Minute
	}
	return now.Sub(r.metricsAt) >= every*8/10
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
	key := r.Keys()
	if len(key) == 0 {
		return nil, nil, errors.New("no server key is pinned yet to check MeshAgent with")
	}
	settings, signed, err := r.Client.MeshSettings(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := r.verifyDownload(signed, key); err != nil {
		return nil, nil, fmt.Errorf("MeshAgent's settings: %w", err)
	}
	return func(w io.Writer) error {
		signed, err := r.Client.MeshAgent(ctx, runtime.GOOS, runtime.GOARCH, w)
		if err != nil {
			return err
		}
		if err := r.verifyDownload(signed, key); err != nil {
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
	r.meshMu.Lock() // a pushed change and a heartbeat's may arrive together
	defer r.meshMu.Unlock()
	if want == r.Mesh.AppliedSettings() {
		return nil
	}
	key := r.Keys()
	if len(key) == 0 {
		return errors.New("no server key is pinned yet to check MeshAgent's settings with")
	}
	settings, signed, err := r.Client.MeshSettings(ctx)
	if err != nil {
		return err
	}
	if err := r.verifyDownload(signed, key); err != nil {
		return fmt.Errorf("MeshAgent's settings: %w", err)
	}
	if sum := sha256.Sum256(settings); hex.EncodeToString(sum[:]) != want {
		return errors.New("MeshAgent's settings are not the ones the server announced")
	}
	return r.Mesh.Reconfigure(ctx, settings)
}

// verifyDownload checks the server's signature on a download with the keys
// the agent trusts and logs it as an instruction accepted, named by the nonce
// of the request it answered (ADR-0057).
func (r *Runner) verifyDownload(signed client.Signed, keys agentproto.Keys) error {
	if err := signed.Verify(keys); err != nil {
		return err
	}
	if r.Record != nil {
		r.Record(agentproto.InstructionDownload, signed.Nonce, keys.SignerOf(func(k ed25519.PublicKey) bool {
			return signed.Verify(agentproto.Keys{k}) == nil
		}))
	}
	return nil
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
