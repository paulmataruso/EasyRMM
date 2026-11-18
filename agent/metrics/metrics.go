// Package metrics measures a device for its heartbeat (ADR-0018):
// processor use between two heartbeats, memory, swap (the page files on
// Windows), load (Linux only), uptime, processes and the space used on
// local filesystems (fixed drives on Windows).
package metrics

import (
	"context"
	"sync"
	"time"
)

// Space is a filesystem's size and use as df counts them: Total excludes
// the blocks reserved for root, so Used/Total is df's "Use%".
type Space struct{ Total, Used uint64 }

// Collector measures the machine. Use one Collector for the agent's
// lifetime: processor use is measured since its previous Collect.
type Collector struct {
	// Root prefixes every path; "" on a real machine.
	Root string
	// Statfs reads a filesystem's space; nil asks the kernel.
	Statfs func(path string) (Space, error)
	// FirstWindow is how long the first processor measurement lasts (1 s).
	FirstWindow time.Duration

	mu   sync.Mutex
	prev *cpuTimes
	// wait sleeps for the first window; tests replace it. False when canceled.
	wait func(ctx context.Context, d time.Duration) bool
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

type cpuTimes struct{ busy, total uint64 }

// cpuPercent is processor use since the previous call; the first call
// measures over FirstWindow.
func (c *Collector) cpuPercent(ctx context.Context) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	now, ok := c.cpuTimes()
	if !ok {
		return 0
	}
	if c.prev == nil {
		window := c.FirstWindow
		if window == 0 {
			window = time.Second
		}
		wait := c.wait
		if wait == nil {
			wait = sleep
		}
		first := now
		c.prev = &first
		if !wait(ctx, window) {
			return 0
		}
		if now, ok = c.cpuTimes(); !ok {
			return 0
		}
	}
	prev := *c.prev
	c.prev = &now
	if now.total <= prev.total || now.busy < prev.busy {
		return 0
	}
	return min(float64(now.busy-prev.busy)/float64(now.total-prev.total)*100, 100)
}
