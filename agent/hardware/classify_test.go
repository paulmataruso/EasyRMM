package hardware

import (
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func TestEmulated(t *testing.T) {
	for _, m := range []string{
		"QEMU HARDDISK", "QEMU NVMe Ctrl", "Msft Virtual Disk", "VMware Virtual disk", "VMware,  VMware Virtual S",
		"VBOX HARDDISK", "ORCL-VBOX-NVME-VER12", "Red Hat VirtIO", "Amazon Elastic Block Store",
		"Google PersistentDisk", "nvme_card-pd", "ATA QEMU HARDDISK",
	} {
		if !emulated(m) {
			t.Errorf("%q is not emulated", m)
		}
	}
	// A model changed by hand is read as what it says it is.
	for _, m := range []string{"Samsung SSD 980 PRO 1TB", "WDC WD10EFRX-68FYTN0", "EasyRMM Stand-in Disk", "Amazon", ""} {
		if emulated(m) {
			t.Errorf("%q is emulated", m)
		}
	}
}

// TestPlanBus is the ADR's table for Windows, row by row.
func TestPlanBus(t *testing.T) {
	for _, tc := range []struct {
		bus    uint32
		model  string
		state  string
		reason string
		proto  protocol
	}{
		{busNVMe, "Samsung SSD 980 PRO 1TB", "", "", protoNVMe},
		{busSATA, "WDC WD10EFRX-68FYTN0", "", "", protoATA},
		{busATA, "ST500DM002-1BD142", "", "", protoATA},
		// Hardware RAID and single drives behind Intel RST or VMD alike.
		{busRAID, "Intel Raid 0 Volume", "", "", protoEither},
		{busVirtual, "Msft Virtual Disk", agentproto.FactUnsupported, agentproto.ReasonVirtualDisk, 0},
		{busFileBackedVirtual, "Msft Virtual Disk", agentproto.FactUnsupported, agentproto.ReasonVirtualDisk, 0},
		// A Hyper-V disk on the SCSI bus, a QEMU disk on SATA.
		{busSCSI, "Msft Virtual Disk", agentproto.FactUnsupported, agentproto.ReasonVirtualDisk, 0},
		{busSATA, "QEMU HARDDISK", agentproto.FactUnsupported, agentproto.ReasonVirtualDisk, 0},
		{busNVMe, "QEMU NVMe Ctrl", agentproto.FactUnsupported, agentproto.ReasonVirtualDisk, 0},
		{busSpaces, "Storage Space", agentproto.FactUnsupported, agentproto.ReasonStorageSpaces, 0},
		{busUSB, "SanDisk Ultra Fit", agentproto.FactUnavailable, agentproto.ReasonUSBBridge, 0},
		{busSD, "SD Card", agentproto.FactUnsupported, agentproto.ReasonMemoryCard, 0},
		{busMMC, "eMMC", agentproto.FactUnsupported, agentproto.ReasonMemoryCard, 0},
		// SCSI, iSCSI (9), SAS (10), FC (6) and the rest: a later slice.
		{busSCSI, "SEAGATE ST600MM0088", agentproto.FactUnavailable, agentproto.ReasonProtocolNotRead, 0},
		{9, "LIO-ORG disk", agentproto.FactUnavailable, agentproto.ReasonProtocolNotRead, 0},
		{10, "HGST HUH721010AL5200", agentproto.FactUnavailable, agentproto.ReasonProtocolNotRead, 0},
		{6, "3PARdata VV", agentproto.FactUnavailable, agentproto.ReasonProtocolNotRead, 0},
		{0, "", agentproto.FactUnavailable, agentproto.ReasonProtocolNotRead, 0},
	} {
		f, p := planBus(tc.bus, tc.model)
		switch {
		case tc.state == "" && (f != nil || p != tc.proto):
			t.Errorf("bus %d %q: %v, protocol %d", tc.bus, tc.model, f, p)
		case tc.state != "" && (f == nil || f.state != tc.state || f.reason != tc.reason):
			t.Errorf("bus %d %q: %v, want %s %s", tc.bus, tc.model, f, tc.state, tc.reason)
		}
	}
}
