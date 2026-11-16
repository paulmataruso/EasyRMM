//go:build windows

package inventory

import (
	"context"
	"strings"
	"testing"
)

// TestCollectWindows reads the real machine: only that each part is
// present and plausible can be checked.
func TestCollectWindows(t *testing.T) {
	inv := Collector{}.Collect(context.Background())
	if inv.CPU.Threads == 0 || inv.CPU.Cores == 0 || inv.CPU.Sockets == 0 || inv.CPU.Cores > inv.CPU.Threads || inv.CPU.Model == "" {
		t.Errorf("CPU = %+v", inv.CPU)
	}
	if inv.Memory == 0 || inv.OS.ID != "windows" || !strings.HasPrefix(inv.OS.Name, "Windows") || inv.OS.Version == "" || inv.OS.Timezone == "" {
		t.Errorf("memory %d, OS %+v", inv.Memory, inv.OS)
	}
	if inv.System.Manufacturer == "" && inv.System.BIOSVendor == "" {
		t.Errorf("no firmware: %+v", inv.System)
	}
	if len(inv.Disks) == 0 || inv.Disks[0].SizeBytes == 0 {
		t.Errorf("disks = %+v (needs an administrator)", inv.Disks)
	}
	if len(inv.Interfaces) == 0 {
		t.Error("no network interfaces")
	}
	if inv.PackageManager != "windows" || len(inv.Packages) == 0 {
		t.Errorf("%d programs from %q", len(inv.Packages), inv.PackageManager)
	}
}
