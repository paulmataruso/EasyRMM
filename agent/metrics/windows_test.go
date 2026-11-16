//go:build windows

package metrics

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestCollectWindows measures the real machine: the values cannot be known
// in advance, only that they are there and plausible.
func TestCollectWindows(t *testing.T) {
	c := &Collector{FirstWindow: 200 * time.Millisecond}
	m := c.Collect(context.Background())
	if m.MemoryTotal == 0 || m.MemoryUsed == 0 || m.MemoryUsed > m.MemoryTotal {
		t.Errorf("memory %d of %d", m.MemoryUsed, m.MemoryTotal)
	}
	if m.SwapUsed > m.SwapTotal || m.UptimeSeconds <= 0 || m.Processes < 1 || m.CPUPercent < 0 || m.CPUPercent > 100 {
		t.Errorf("metrics = %+v", m)
	}
	var system bool
	for _, fs := range m.Filesystems {
		if fs.TotalBytes == 0 || fs.UsedBytes > fs.TotalBytes || !strings.HasSuffix(fs.Mount, `:\`) {
			t.Errorf("filesystem %+v", fs)
		}
		if strings.EqualFold(fs.Mount, `C:\`) {
			system = fs.Type != "" && strings.HasPrefix(fs.Device, `\\?\Volume{`)
		}
	}
	if !system {
		t.Errorf("no C: drive with a type and volume name in %+v", m.Filesystems)
	}
	if again := c.Collect(context.Background()); again.CPUPercent < 0 || again.CPUPercent > 100 {
		t.Errorf("second measurement %v", again.CPUPercent)
	}
}
