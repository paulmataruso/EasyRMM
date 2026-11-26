package runner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// stepTimeout bounds one repair step: a service stop waits up to 30 seconds,
// MeshAgent's download is a few megabytes and the EasyPatch agent's package
// some tens. The server gives up on a step the agent does not take after 15
// minutes, so a step ends before that.
const stepTimeout = 12 * time.Minute

// repairs holds the repair step in hand and the outcome of the last one.
type repairs struct {
	mu      sync.Mutex
	running string // ID of the step in hand
	last    *agentproto.RepairReport
	lastAt  time.Time
	wg      sync.WaitGroup
}

// report returns the last step's outcome while it is worth repeating: the
// server settles each outcome idempotently, so it is sent with every
// heartbeat until agentproto.RepairReported after it ended.
func (p *repairs) report(now time.Time) *agentproto.RepairReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last == nil || now.Sub(p.lastAt) >= agentproto.RepairReported {
		return nil
	}
	r := *p.last
	return &r
}

// wait waits for a step in hand.
func (p *repairs) wait() { p.wg.Wait() }

// begin claims a step: false when it is the step in hand or the last one
// done, which the heartbeat answers repeat until the server has settled
// them.
func (p *repairs) begin(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running != "" || (p.last != nil && p.last.ID == id) {
		return false
	}
	p.running = id
	return true
}

func (p *repairs) finish(rep agentproto.RepairReport, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running, p.last, p.lastAt = "", &rep, now
}

// startRepair acts on a heartbeat answer's repair instruction: it checks the
// signature and the device, then carries the step out in the background, so
// that a download or a service that takes a while does not hold the
// heartbeats back. The outcome goes out with the next heartbeats.
func (r *Runner) startRepair(ctx context.Context, s *agentproto.SignedRepair) {
	key := r.Key()
	p, err := agentproto.VerifyRepair(key, *s, r.DeviceID, time.Now())
	if err != nil {
		if errors.Is(err, agentproto.ErrRepairExpired) {
			return // the server's next answer carries a fresh one, or none
		}
		r.Log.Error("refused a repair instruction", "error", err)
		return
	}
	if !r.repair.begin(p.ID) {
		return
	}
	r.Log.Info("repairing", "target", p.Target, "step", p.Step)
	r.repair.wg.Go(func() {
		sctx, cancel := context.WithTimeout(ctx, stepTimeout)
		defer cancel()
		err := r.carryOut(ctx, sctx, p)
		rep := agentproto.RepairReport{ID: p.ID, OK: err == nil}
		if err != nil {
			rep.Error = truncate(err.Error(), agentproto.MaxRepairError)
			r.Log.Warn("a repair step failed", "target", p.Target, "step", p.Step, "error", err)
		} else {
			r.Log.Info("a repair step is done", "target", p.Target, "step", p.Step)
		}
		r.repair.finish(rep, time.Now())
		if r.Nudge != nil {
			r.Nudge("repair") // the outcome is reported in the next heartbeat
		}
	})
}

// carryOut does what the target and step name, from code the agent ships
// with: it never runs a command the server sent. ctx is the agent's own: a
// MeshAgent child process the step starts lives as long as it does. Downloads
// are bounded by within.
func (r *Runner) carryOut(ctx, within context.Context, p agentproto.RepairPayload) error {
	switch p.Target {
	case agentproto.TargetMeshAgent:
		return r.repairMesh(ctx, within, p)
	case agentproto.TargetEasyPatchAgent:
		return r.repairEasyPatch(ctx, within, p)
	}
	return fmt.Errorf("this agent does not repair the %s", p.Target)
}

func (r *Runner) repairMesh(ctx, within context.Context, p agentproto.RepairPayload) error {
	if r.Mesh == nil {
		return errors.New("MeshAgent is not supported on this device")
	}
	switch p.Step {
	case agentproto.StepRestart:
		return r.Mesh.Restart(ctx)
	case agentproto.StepRepair:
		download, settings, err := r.meshPackage(within)
		if err != nil {
			return err
		}
		return r.Mesh.Repair(ctx, download, settings)
	}
	return fmt.Errorf("unknown step %q", p.Step)
}

func (r *Runner) repairEasyPatch(ctx, within context.Context, p agentproto.RepairPayload) error {
	if r.Patch == nil {
		return errors.New("the EasyPatch agent cannot be repaired from this device")
	}
	switch p.Step {
	case agentproto.StepRestart:
		return r.Patch.Restart(within)
	case agentproto.StepRepair:
		// The package manager outlives the agent's own stop, as an install
		// does: only the step's deadline ends it.
		return r.Patch.Repair(ctx, within, p.EasyPatch)
	}
	return fmt.Errorf("unknown step %q", p.Step)
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
