package trust

import (
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// InstructionPersist is where the instruction log is kept (state.Store).
type InstructionPersist interface {
	LoadInstructionLog() state.InstructionLog
	SaveInstructionLog(state.InstructionLog) error
}

// keepRecent is how many acknowledged entries are kept for `status`.
const keepRecent = 20

// InstructionLog is the agent's record of every instruction it accepts
// (ADR-0057): its kind, its ID, the fingerprint of the key that signed it,
// and when. It sends the entries the server has not acknowledged with its
// heartbeats, and the sequence of the last one acknowledged, to a server that
// lists the feature. The server compares them with what it signed: an entry
// it never issued is flagged. It is a tripwire, not proof: code that ran as
// root can erase the log before it is sent.
type InstructionLog struct {
	Store InstructionPersist
	Log   *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu     sync.Mutex
	loaded bool
	log    state.InstructionLog
}

func (l *InstructionLog) now() time.Time {
	if l.Now != nil {
		return l.Now().UTC()
	}
	return time.Now().UTC()
}

func (l *InstructionLog) load() {
	if !l.loaded {
		l.log, l.loaded = l.Store.LoadInstructionLog(), true
	}
}

func (l *InstructionLog) save() {
	if err := l.Store.SaveInstructionLog(l.log); err != nil && l.Log != nil {
		l.Log.Error("saving the instruction log failed", "error", err)
	}
}

// Record appends an accepted instruction. It is an InstructionRecorder.
func (l *InstructionLog) Record(kind, id, signer string) {
	if l == nil || l.Store == nil {
		return
	}
	if len(id) > 200 {
		id = id[:200]
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	// An instruction the server repeats while it is open (an update, an
	// uninstall) is one entry.
	same := func(e agentproto.LoggedInstruction) bool { return e.Kind == kind && e.ID == id && e.Signer == signer }
	if slices.ContainsFunc(l.log.Entries, same) || slices.ContainsFunc(l.log.Recent, same) {
		return
	}
	l.log.Next++
	l.log.Entries = append(l.log.Entries, agentproto.LoggedInstruction{Seq: l.log.Next, Kind: kind, ID: id, Signer: signer, At: l.now()})
	if len(l.log.Entries) > agentproto.MaxInstructionLog {
		l.log.Entries = l.log.Entries[len(l.log.Entries)-agentproto.MaxInstructionLog:]
	}
	l.save()
}

// Report is what the next heartbeat carries: the entries not acknowledged (at
// most MaxInstructionBatch, the oldest first) and the sequence of the last
// one acknowledged. It is nil when the server does not list the feature: then
// nothing is sent and nothing is dropped.
func (l *InstructionLog) Report(featureListed bool) *agentproto.InstructionLogReport {
	if l == nil || l.Store == nil || !featureListed {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	r := &agentproto.InstructionLogReport{Acked: l.log.Acked}
	r.Entries = slices.Clone(l.log.Entries[:min(len(l.log.Entries), agentproto.MaxInstructionBatch)])
	return r
}

// Acknowledged takes the server's acknowledgment: entries up to ack are
// dropped, the last few kept for `status`. An acknowledgment below the one
// already taken, or beyond the log's own sequence, changes nothing.
func (l *InstructionLog) Acknowledged(ack uint64) {
	if l == nil || l.Store == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	if ack <= l.log.Acked || ack > l.log.Next {
		return
	}
	keep := l.log.Entries[:0:0]
	for _, e := range l.log.Entries {
		if e.Seq <= ack {
			l.log.Recent = append(l.log.Recent, e)
		} else {
			keep = append(keep, e)
		}
	}
	if len(l.log.Recent) > keepRecent {
		l.log.Recent = l.log.Recent[len(l.log.Recent)-keepRecent:]
	}
	l.log.Entries, l.log.Acked = keep, ack
	l.save()
}

// Latest returns the newest entries, acknowledged or not, oldest first, for
// `status`.
func (l *InstructionLog) Latest(n int) []agentproto.LoggedInstruction {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	all := append(slices.Clone(l.log.Recent), l.log.Entries...)
	return all[max(0, len(all)-n):]
}
