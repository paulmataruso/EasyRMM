//go:build !windows

package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// links makes symbolic links under root, each to its target relative to
// the link's own directory, as sysfs does.
func links(t *testing.T, root string, l map[string]string) {
	t.Helper()
	for link, target := range l {
		p := filepath.Join(root, link)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
}

// storageTree is a sysfs tree constructed for the test, laid out as Linux
// 6.x lays it out (not captured from a machine):
//   - nvme0n1, a namespace of subsystem 0 under native multipath, served by
//     controllers nvme0 and nvme1 through the hidden paths nvme0c0n1 and
//     nvme0c1n1; nvme1 has no firmware_rev;
//   - nvme2n1, a namespace without multipath, whose parent is nvme2;
//   - sda, a SATA disk whose ATA Information VPD page holds its IDENTIFY
//     data, and without device/serial;
//   - sdb, a SAS disk with its Unit Serial Number page;
//   - sdc, a SATA disk on a kernel without the ATA Information page;
//   - sdd, a SATA disk whose page is cut short;
//   - vda, a virtio disk.
func storageTree(t *testing.T) string {
	t.Helper()
	pci := "sys/devices/pci0000:00/"
	subsys := "sys/devices/virtual/nvme-subsystem/nvme-subsys0/"
	root := tree(t, map[string]string{
		pci + "0000:00:01.0/nvme/nvme0/firmware_rev":                       "3B2QGXA7\n",
		pci + "0000:00:01.0/nvme/nvme0/nvme0c0n1/size":                     "1000\n",
		pci + "0000:00:01.0/nvme/nvme0/nvme0c0n1/hidden":                   "1\n",
		pci + "0000:00:02.0/nvme/nvme1/nvme0c1n1/size":                     "1000\n",
		pci + "0000:00:02.0/nvme/nvme1/nvme0c1n1/hidden":                   "1\n",
		subsys + "nvme0n1/size":                                            "1000\n",
		"sys/devices/virtual/nvme-subsystem/nvme-subsys0/serial":           "TESTSERIAL0002\n",
		pci + "0000:00:03.0/nvme/nvme2/firmware_rev":                       "  GDC5302Q \n",
		pci + "0000:00:03.0/nvme/nvme2/nvme2n1/size":                       "2000\n",
		pci + "0000:00:04.0/ata1/host0/target0:0:0/0:0:0:0/vendor":         "ATA     \n",
		pci + "0000:00:04.0/ata1/host0/target0:0:0/0:0:0:0/model":          "WDC WD10EFRX-68F\n",
		pci + "0000:00:04.0/ata1/host0/target0:0:0/0:0:0:0/rev":            "0A82\n",
		pci + "0000:00:04.0/ata1/host0/target0:0:0/0:0:0:0/block/sda/size": "3000\n",
		"sys/block/sdb/size":                                               "4000\n",
		"sys/block/sdb/device/vendor":                                      "SEAGATE \n",
		"sys/block/sdb/device/model":                                       "ST600MM0088     \n",
		"sys/block/sdb/device/rev":                                         "N004\n",
		"sys/block/sdc/size":                                               "5000\n",
		"sys/block/sdc/device/vendor":                                      "ATA\n",
		"sys/block/sdc/device/rev":                                         "0A82\n",
		"sys/block/sdd/size":                                               "6000\n",
		"sys/block/sdd/device/vendor":                                      "ATA\n",
		"sys/block/vda/size":                                               "7000\n",
		"sys/block/vda/device/serial":                                      "vol-1\n",
	})
	sata := pci + "0000:00:04.0/ata1/host0/target0:0:0/0:0:0:0/"
	if err := os.WriteFile(filepath.Join(root, sata, "vpd_pg89"), vpd89("TESTSERIAL0003", "82.00A82", "WDC WD10EFRX-68FYTN0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sys/block/sdb/device/vpd_pg80"), append([]byte{0, 0x80, 0, 20}, "TESTSERIAL0004      "...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sys/block/sdd/device/vpd_pg89"), vpd89("S", "F", "M")[:300], 0o644); err != nil {
		t.Fatal(err)
	}
	links(t, root, map[string]string{
		"sys/block/nvme0n1":    "../devices/virtual/nvme-subsystem/nvme-subsys0/nvme0n1",
		"sys/block/nvme0c0n1":  "../devices/pci0000:00/0000:00:01.0/nvme/nvme0/nvme0c0n1",
		"sys/block/nvme0c1n1":  "../devices/pci0000:00/0000:00:02.0/nvme/nvme1/nvme0c1n1",
		"sys/block/nvme2n1":    "../devices/pci0000:00/0000:00:03.0/nvme/nvme2/nvme2n1",
		"sys/block/sda":        "../devices/pci0000:00/0000:00:04.0/ata1/host0/target0:0:0/0:0:0:0/block/sda",
		"sys/class/nvme/nvme0": "../../devices/pci0000:00/0000:00:01.0/nvme/nvme0",
		"sys/class/nvme/nvme1": "../../devices/pci0000:00/0000:00:02.0/nvme/nvme1",
		"sys/class/nvme/nvme2": "../../devices/pci0000:00/0000:00:03.0/nvme/nvme2",

		subsys + "nvme0n1/multipath/nvme0c0n1":                               "../../../../../pci0000:00/0000:00:01.0/nvme/nvme0/nvme0c0n1",
		subsys + "nvme0n1/multipath/nvme0c1n1":                               "../../../../../pci0000:00/0000:00:02.0/nvme/nvme1/nvme0c1n1",
		pci + "0000:00:01.0/nvme/nvme0/nvme0c0n1/device":                     "../../nvme0",
		pci + "0000:00:02.0/nvme/nvme1/nvme0c1n1/device":                     "../../nvme1",
		pci + "0000:00:03.0/nvme/nvme2/nvme2n1/device":                       "../../nvme2",
		pci + "0000:00:04.0/ata1/host0/target0:0:0/0:0:0:0/block/sda/device": "../../../0:0:0:0",
		// A subsystem's namespace has no controller of its own.
		subsys + "nvme0n1/device": "../../nvme-subsys0",
	})
	return root
}

func TestStorage(t *testing.T) {
	st := Collector{Root: storageTree(t)}.Storage()
	read := func(v string) *agentproto.TextFact { return &agentproto.TextFact{State: agentproto.FactRead, Value: v} }
	notExposed := firmwareNotExposed()
	want := []ListedDisk{
		{Disk: agentproto.Disk{Name: "nvme0n1", Serial: "TESTSERIAL0002", SizeBytes: 1000 * 512, Kind: "nvme", Firmware: read("3B2QGXA7")}, Controllers: []string{"nvme0", "nvme1"}},
		{Disk: agentproto.Disk{Name: "nvme2n1", SizeBytes: 2000 * 512, Kind: "nvme", Firmware: read("GDC5302Q")}, Controllers: []string{"nvme2"}},
		{Disk: agentproto.Disk{Name: "sda", Model: "WDC WD10EFRX-68FYTN0", Serial: "TESTSERIAL0003", SizeBytes: 3000 * 512, Firmware: read("82.00A82")}},
		{Disk: agentproto.Disk{Name: "sdb", Model: "ST600MM0088", Serial: "TESTSERIAL0004", SizeBytes: 4000 * 512, Firmware: read("N004")}},
		{Disk: agentproto.Disk{Name: "sdc", SizeBytes: 5000 * 512, Firmware: notExposed}},
		{Disk: agentproto.Disk{Name: "sdd", SizeBytes: 6000 * 512, Firmware: &agentproto.TextFact{State: agentproto.FactUnknown, Reason: agentproto.ReasonBadAnswer}}},
		{Disk: agentproto.Disk{Name: "vda", Serial: "vol-1", SizeBytes: 7000 * 512, Firmware: &agentproto.TextFact{State: agentproto.FactUnsupported, Reason: agentproto.ReasonVirtualDisk}}},
	}
	if len(st.Disks) != len(want) {
		t.Fatalf("%d disks: %+v", len(st.Disks), st.Disks)
	}
	for i := range want {
		if !reflect.DeepEqual(st.Disks[i], want[i]) {
			t.Errorf("disk %d:\n got %+v %+v\nwant %+v %+v", i, st.Disks[i], st.Disks[i].Firmware, want[i], want[i].Firmware)
		}
	}
	if st.Virtualization != "" {
		t.Errorf("virtualization %q", st.Virtualization)
	}
}

// TestNVMeWithoutController: a namespace whose controller is not in
// /sys/class/nvme has none, and its firmware is not exposed.
func TestNVMeWithoutController(t *testing.T) {
	root := tree(t, map[string]string{"sys/block/nvme0n1/size": "10\n"})
	st := Collector{Root: root}.Storage()
	if len(st.Disks) != 1 || st.Disks[0].Controllers != nil || !reflect.DeepEqual(st.Disks[0].Firmware, firmwareNotExposed()) {
		t.Errorf("disks %+v", st.Disks)
	}
}
