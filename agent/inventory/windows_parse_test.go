package inventory

import (
	"encoding/binary"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// structure builds an SMBIOS structure: the formatted area (type, length,
// handle, then fields) and its strings.
func structure(typ byte, fields []byte, strs ...string) []byte {
	b := append([]byte{typ, byte(4 + len(fields)), 0, 0}, fields...)
	if len(strs) == 0 {
		return append(b, 0, 0)
	}
	for _, s := range strs {
		b = append(append(b, s...), 0)
	}
	return append(b, 0)
}

func TestParseSMBIOS(t *testing.T) {
	var table []byte
	// BIOS: vendor 1, version 2, start segment, release date 3.
	table = append(table, structure(0, []byte{1, 2, 0, 0, 3, 0}, "American Megatrends Inc.", "F.21", "03/14/2024")...)
	// A structure without strings.
	table = append(table, structure(32, []byte{0, 0, 0, 0, 0, 0})...)
	// System: manufacturer 1, product 2, version 3, serial 4.
	table = append(table, structure(1, []byte{1, 2, 3, 4}, "  HP  ", "EliteBook 840 G9", "SBKPF", "To Be Filled By O.E.M.")...)
	table = append(table, structure(127, nil)...)
	table = append(table, structure(1, []byte{1, 0, 0, 0}, "after the end")...)
	got := parseSMBIOS(table)
	want := agentproto.SystemInfo{Manufacturer: "HP", Model: "EliteBook 840 G9", BIOSVendor: "American Megatrends Inc.", BIOSVersion: "F.21", BIOSDate: "03/14/2024"}
	if got != want {
		t.Errorf("parseSMBIOS = %+v", got)
	}
	// Damaged tables stop parsing instead of failing.
	for _, bad := range [][]byte{nil, {1, 2}, {1, 200, 0, 0}, {1, 8, 0, 0, 1, 2, 3, 4, 'x'}, structure(1, []byte{9, 0, 0, 0}, "one")} {
		if got := parseSMBIOS(bad); got.Serial != "" || got.Model != "" {
			t.Errorf("parseSMBIOS(%v) = %+v", bad, got)
		}
	}
}

func TestCountRelations(t *testing.T) {
	entry := func(size uint32) []byte {
		b := make([]byte, size)
		binary.LittleEndian.PutUint32(b[4:], size)
		return b
	}
	buf := append(append(entry(48), entry(48)...), entry(80)...)
	if n := countRelations(buf); n != 3 {
		t.Errorf("count = %d", n)
	}
	if n := countRelations(append(entry(48), make([]byte, 8)...)); n != 1 {
		t.Errorf("count with a zero size = %d", n)
	}
	if n := countRelations([]byte{1, 2, 3}); n != 0 {
		t.Errorf("short buffer = %d", n)
	}
}

func TestParseStorageDescriptor(t *testing.T) {
	desc := func(vendor, product, serial string, bus uint32, removable bool, revision ...string) []byte {
		b := make([]byte, 40)
		add := func(field int, s string) {
			if s == "" {
				return
			}
			binary.LittleEndian.PutUint32(b[field:], uint32(len(b)))
			b = append(append(b, s...), 0)
		}
		add(12, vendor)
		add(16, product)
		add(24, serial)
		for _, r := range revision {
			add(20, r)
		}
		binary.LittleEndian.PutUint32(b[28:], bus)
		if removable {
			b[10] = 1
		}
		return b
	}
	d, ok := parseStorageDescriptor(desc("", "Samsung SSD 980 PRO 1TB", "S5GXNF0R  ", busNVMe, false, "5B2QGXA7"))
	if !ok || d.Model != "Samsung SSD 980 PRO 1TB" || d.Serial != "S5GXNF0R" || d.Revision != "5B2QGXA7" || d.Bus != busNVMe || d.Removable {
		t.Errorf("NVMe = %+v", d)
	}
	if firmwareRead(d.Revision).Value != "5B2QGXA7" || firmwareRead("  ").Reason != agentproto.ReasonNotExposed {
		t.Error("firmware facts")
	}
	d, _ = parseStorageDescriptor(desc("SanDisk ", "Ultra   Fit", "4C530001.", busUSB, false))
	if d.Model != "SanDisk Ultra Fit" || d.Serial != "4C530001" || !d.Removable {
		t.Errorf("USB = %+v", d)
	}
	d, _ = parseStorageDescriptor(desc("", "", "", 11, true))
	if d.Model != "" || !d.Removable {
		t.Errorf("empty = %+v", d)
	}
	bad := desc("x", "y", "z", 11, false)
	binary.LittleEndian.PutUint32(bad[16:], 5000)
	if d, _ := parseStorageDescriptor(bad); d.Model != "x" {
		t.Errorf("offset past the end = %+v", d)
	}
	if _, ok := parseStorageDescriptor(make([]byte, 20)); ok {
		t.Error("short descriptor accepted")
	}
}

func TestProgram(t *testing.T) {
	p, ok := program(uninstallValues{DisplayName: " 7-Zip 24.08 (x64) ", DisplayVersion: "24.08", Publisher: "Igor Pavlov "}, "x64")
	if !ok || p != (agentproto.Package{Name: "7-Zip 24.08 (x64)", Version: "24.08", Arch: "x64", Publisher: "Igor Pavlov"}) {
		t.Errorf("program = %+v, %v", p, ok)
	}
	for _, v := range []uninstallValues{
		{DisplayName: ""},
		{DisplayName: "Driver", SystemComponent: 1},
		{DisplayName: "Update for Office", ParentKeyName: "Office16"},
		{DisplayName: "KB5005565", ReleaseType: "Security Update"},
		{DisplayName: "Hotfix", ReleaseType: "hotfix"},
	} {
		if _, ok := program(v, "x64"); ok {
			t.Errorf("%+v listed", v)
		}
	}
	if windowsArch("amd64") != "x64" || windowsArch("386") != "x86" || windowsArch("arm64") != "arm64" {
		t.Error("windowsArch")
	}
	if dnsServer("fec0:0:0:ffff::1") || dnsServer("") || !dnsServer("192.0.2.53") || !dnsServer("2001:db8::53") {
		t.Error("dnsServer")
	}
	if clean("  Default   string ") != "" || clean(" Dell  Inc. ") != "Dell Inc." {
		t.Error("clean")
	}
}

func TestHypervisor(t *testing.T) {
	for want, s := range map[string]agentproto.SystemInfo{
		"hyper-v": {Manufacturer: "Microsoft Corporation", Model: "Virtual Machine"},
		"vmware":  {Manufacturer: "VMware, Inc.", Model: "VMware20,1"},
		"kvm":     {Manufacturer: "QEMU", Model: "Standard PC (Q35 + ICH9, 2009)"},
		"":        {Manufacturer: "Dell Inc.", Model: "OptiPlex 7090"},
	} {
		if got := hypervisor(s); got != want {
			t.Errorf("hypervisor(%+v) = %q, want %q", s, got, want)
		}
	}
}
