//go:build windows

package inventory

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
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
	// Windows PowerShell first, then the runner's PowerShell 7 (ADR-0064;
	// package powershell checks what each says, as LocalSystem).
	if ps := inv.PowerShell; len(ps) < 2 || ps[0].Edition != agentproto.EditionDesktop || !slices.ContainsFunc(ps, func(p agentproto.PowerShellInstall) bool {
		return p.Edition == agentproto.EditionCore && p.Version != ""
	}) {
		t.Errorf("PowerShell %+v", ps)
	}
}

// TestStorageWindows: every disk has its bus type and a firmware fact with
// its state; the inventory lists the same disks.
func TestStorageWindows(t *testing.T) {
	st := Collector{}.Storage()
	if len(st.Disks) == 0 {
		t.Fatal("no disks (needs an administrator)")
	}
	for _, d := range st.Disks {
		t.Logf("%s: bus %d, model %q, firmware %+v", d.Name, d.Bus, d.Model, *d.Firmware)
		if d.Bus == 0 || d.Firmware.State == "" || (d.Firmware.State == "read") != (d.Firmware.Value != "") {
			t.Errorf("%s: bus %d, firmware %+v", d.Name, d.Bus, *d.Firmware)
		}
	}
	if inv := (Collector{}).Collect(context.Background()); len(inv.Disks) != len(st.Disks) {
		t.Errorf("the inventory lists %d disks, the storage listing %d", len(inv.Disks), len(st.Disks))
	}
}
