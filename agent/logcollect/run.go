package logcollect

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"runtime/debug"
	"time"
)

// Options are what `easyrmm-agent collect` runs with.
type Options struct {
	// Spool is the directory blocks are written to.
	Spool string
	// AuditSocket is the agent's socket that passes auditd's log (Linux);
	// empty reads no audit log.
	AuditSocket string
	Every       time.Duration
	Log         *slog.Logger
}

// memoryLimit is the Go runtime's own soft limit, below the unit's MemoryHigh
// and the job object's cap, so that the collector collects garbage before the
// system has to act.
const memoryLimit = 160 << 20

// Confine limits the process itself as far as it can on its own: one
// processor's worth of threads and a memory target, and on Windows its job
// object with a CPU cap and background priority. The unit on Linux enforces
// the same limits from outside; this is the second line.
func Confine() error {
	runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(memoryLimit)
	return confineOS()
}

// Run is the collector process: it confines itself, reads its sources every
// interval, and writes blocks to the spool until ctx ends. It opens no socket
// but the agent's audit socket and holds no secret of the agent's.
func Run(ctx context.Context, o Options) error {
	if o.Spool == "" {
		return errors.New("logcollect: --spool is required")
	}
	log := o.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if err := Confine(); err != nil {
		// A limit that cannot be set is not a reason to collect no logs: the
		// service manager's own limits still apply.
		log.Warn("the collector could not confine itself", "error", err)
	}
	sp := &Spool{Dir: o.Spool}
	if err := sp.Open(); err != nil {
		return err
	}
	c := &Collector{Readers: defaultReaders(o), Spool: sp, Log: log}
	c.Run(ctx, o.Every)
	return nil
}
