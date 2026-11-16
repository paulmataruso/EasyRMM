// Package runner is the agent's main loop: heartbeats, and MeshAgent once
// the server offers it. Jobs run beside it (package jobs).
package runner

import (
	"context"
	"io"
	"log/slog"
	"math/rand/v2"
	"runtime"
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
}

// Runner runs an enrolled agent.
type Runner struct {
	Client *client.Client
	Store  state.Store
	// Mesh is nil where MeshAgent is not supported.
	Mesh  MeshAgent
	Facts func() agentproto.Facts
	Log   *slog.Logger
	// OnJobKey receives the server's job-signing key from each heartbeat.
	OnJobKey func(key string)

	// Timing, shortened by tests.
	MinRetry    time.Duration // first retry after a failure (5 s)
	MaxRetry    time.Duration // longest retry interval (5 min)
	InstallWait time.Duration // between MeshAgent install attempts (10 min)
	AfterSetup  time.Duration // next heartbeat after installing MeshAgent (15 s)

	status      state.Status
	failures    int
	lastInstall time.Time
}

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
}

// Run sends heartbeats until ctx ends.
func (r *Runner) Run(ctx context.Context) error {
	r.defaults()
	if r.Mesh != nil && r.Mesh.Installed() {
		// A systemd unit restarts by itself; a child process needs us.
		if err := r.Mesh.Start(ctx); err != nil {
			r.Log.Error("starting MeshAgent failed", "error", err)
		}
	}
	for {
		wait := r.beat(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// beat sends one heartbeat and acts on the answer. It returns how long to
// wait before the next one.
func (r *Runner) beat(ctx context.Context) time.Duration {
	f := r.Facts()
	if r.Mesh != nil && r.Mesh.Installed() {
		id, err := r.Mesh.NodeID(ctx)
		if err != nil {
			r.Log.Warn("reading MeshAgent's node id failed", "error", err)
		}
		f.MeshNodeID = id
		r.status.MeshNodeID = id
	}
	resp, err := r.Client.Heartbeat(ctx, f)
	if err != nil {
		if ctx.Err() != nil {
			return 0
		}
		return r.failed(err)
	}
	r.failures = 0
	if r.OnJobKey != nil && resp.JobKey != "" {
		r.OnJobKey(resp.JobKey)
	}
	r.status.LastHeartbeat = time.Now().UTC()
	r.status.LastError, r.status.LastErrorAt = "", time.Time{}
	next := jitter(time.Duration(resp.HeartbeatSeconds) * time.Second)
	if next <= 0 {
		next = jitter(time.Minute)
	}
	if r.Mesh != nil {
		switch {
		case r.Mesh.Installed():
			r.status.MeshAgent = "installed"
		case !resp.MeshAgent.Available:
			r.status.MeshAgent = "not available from the server"
		case time.Since(r.lastInstall) >= r.InstallWait:
			r.lastInstall = time.Now()
			if err := r.installMesh(ctx); err != nil {
				r.Log.Error("installing MeshAgent failed", "error", err)
				r.status.MeshAgent = "install failed: " + err.Error()
			} else {
				r.Log.Info("installed MeshAgent")
				r.status.MeshAgent = "installed"
				next = r.AfterSetup // report the node id soon
			}
		}
	}
	r.save()
	return next
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

func (r *Runner) installMesh(ctx context.Context) error {
	settings, err := r.Client.MeshSettings(ctx)
	if err != nil {
		return err
	}
	return r.Mesh.Install(ctx, func(w io.Writer) error {
		return r.Client.MeshAgent(ctx, runtime.GOOS, runtime.GOARCH, w)
	}, settings)
}

func (r *Runner) save() {
	if err := r.Store.SaveStatus(r.status); err != nil {
		r.Log.Warn("saving the agent status failed", "error", err)
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
