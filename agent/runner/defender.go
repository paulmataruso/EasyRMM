package runner

import (
	"context"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// DefenderManager keeps the agent's Defender exclusions (ADR-0070).
type DefenderManager interface {
	Reconcile(ctx context.Context) *agentproto.DefenderReport
	TakeEvents() []agentproto.DefenderEvent
	RestoreEvents([]agentproto.DefenderEvent)
}

// DefenderLogReader reads the Defender event log after its bookmark and moves
// the bookmark when the server acknowledged a batch (ADR-0074).
type DefenderLogReader interface {
	Next(ctx context.Context) (*agentproto.DefenderLogBatch, error)
	Acked(ack *agentproto.DefenderLogAck, sent *agentproto.DefenderLogBatch) error
}

// InstalledReporter returns the hashes of what is installed when a report
// is due, nil otherwise.
type InstalledReporter interface {
	Due(ctx context.Context) *agentproto.InstalledFiles
}

// defenderEvery is how often the exclusions are reconciled again; the
// folders are also verified again each time, so a folder that became
// writable loses its exclusion within the hour.
const defenderEvery = time.Hour

// defenderLogTimeout bounds one read of the event log.
const defenderLogTimeout = 20 * time.Second

// defenderTimeout bounds one reconcile: Defender can be slow.
const defenderTimeout = 3 * time.Minute

type defenderState struct {
	// allowed is the server's last answer: the agent does nothing before
	// the first one, nor where the server did not say yes.
	allowed bool
	last    time.Time
	// sent is the last report; unsent says the server has not taken it.
	sent   *agentproto.DefenderReport
	unsent bool
	events []agentproto.DefenderEvent
	files  *agentproto.InstalledFiles
	// logOn is the server's last answer about the event log; logSent is the
	// batch on its way, kept until the server acknowledges it.
	logOn   bool
	logSent *agentproto.DefenderLogBatch
}

// defendRequest adds the Defender report and the installed hashes to a
// heartbeat, where the server allowed them.
func (r *Runner) defendRequest(ctx context.Context, req *agentproto.HeartbeatRequest) {
	d := &r.defend
	if !d.allowed {
		return
	}
	if r.Defender != nil {
		if d.sent == nil || time.Since(d.last) >= defenderEvery {
			cctx, cancel := context.WithTimeout(ctx, defenderTimeout)
			rep := r.Defender.Reconcile(cctx)
			cancel()
			d.last = time.Now()
			if d.sent == nil || !sameDefender(d.sent, rep) || len(rep.Events) > 0 {
				d.unsent = true
			}
			rep.Events = append(d.events, rep.Events...)
			d.sent = rep
		}
		if d.unsent && d.sent != nil {
			rep := *d.sent
			req.Defender = &rep
			d.events = rep.Events
		}
	}
	if r.DefenderLog != nil && d.logOn {
		lctx, cancel := context.WithTimeout(ctx, defenderLogTimeout)
		batch, err := r.DefenderLog.Next(lctx)
		cancel()
		if err == nil && batch != nil && batch.Check() == nil {
			d.logSent = batch
			req.DefenderLog = batch
		}
	}
	if r.Installed != nil {
		if f := r.Installed.Due(ctx); f != nil {
			d.files = f
		}
		if d.files != nil {
			req.InstalledFiles = d.files
		}
	}
}

// sameDefender compares what the server shows: state, reasons and folders,
// not the events.
func sameDefender(a, b *agentproto.DefenderReport) bool {
	if (a.EasyPatch == nil) != (b.EasyPatch == nil) || (a.EasyPatch != nil && !sameDefender(a.EasyPatch, b.EasyPatch)) {
		return false
	}
	if a.State != b.State || a.Reason != b.Reason || a.Method != b.Method || len(a.Kinds) != len(b.Kinds) || len(a.Folders) != len(b.Folders) {
		return false
	}
	for i := range a.Kinds {
		if a.Kinds[i] != b.Kinds[i] {
			return false
		}
	}
	for i := range a.Folders {
		if a.Folders[i] != b.Folders[i] {
			return false
		}
	}
	return true
}

// defendAnswered takes the server's answer: whether to act, and that what
// the heartbeat carried arrived.
func (r *Runner) defendAnswered(p *agentproto.DefenderPolicy) {
	d := &r.defend
	d.allowed = p != nil && p.Enabled
	d.logOn = d.allowed && p.Events
	if p != nil && p.EventsAck != nil && d.logSent != nil && r.DefenderLog != nil {
		_ = r.DefenderLog.Acked(p.EventsAck, d.logSent)
	}
	if !d.logOn {
		d.logSent = nil
	}
	if !d.allowed {
		d.sent, d.unsent, d.events, d.files = nil, false, nil, nil
		return
	}
	d.unsent, d.events = false, nil
	if d.sent != nil {
		d.sent.Events = nil
	}
	if d.files != nil && r.Installed != nil {
		d.files = nil
	}
}
