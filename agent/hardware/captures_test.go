package hardware

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Captured answers, in testdata: what QEMU 10.2.1's emulated disks
// answered the agent's own reader, run inside a QEMU guest by the vm test
// (vm_test.go, with EASYRMM_TEST_HARDWARE_CAPTURE set). Its "nvme"
// controller was read through a Debian 12 guest's NVMe ioctl, its
// "ide-hd" disk on AHCI through an Ubuntu 24.04 guest's SG_IO. The
// serial numbers are the ones the test gave the emulated disks. No real
// drive's answer is captured here.

// captured reads one capture from testdata.
func captured(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// seed adds to f each captured answer in testdata whose name ends in
// name.
func seed(f *testing.F, name string) {
	f.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "*"+name+".bin"))
	if err != nil {
		f.Fatal(err)
	}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
}

// TestCapturedNVMe reads QEMU 10.2.1's nvme controller from its captured
// answers: 323 K (50 °C), a warning threshold of 343 K (70 °C), no spare
// reported, and nothing written in a machine that had just started.
func TestCapturedNVMe(t *testing.T) {
	d := nvmeDrive(t, captured(t, "qemu-10.2.1-nvme-health-log"), captured(t, "qemu-10.2.1-nvme-identify-controller"))
	h, err := readNVMe(d)
	if err != nil {
		t.Fatal(err)
	}
	h.Name, h.ReadAt, h.Route = "nvme0n1", time.Now(), d.route()
	checkHealth(t, h)
	wantFacts(t, h, map[string]agentproto.Fact{
		"CriticalWarning": read(0), "Temperature": read(50), "TemperatureLimit": read(70),
		"AvailableSpare": read(0), "AvailableSpareThreshold": read(0), "Wear": read(0),
		"MediaErrors": read(0), "DriveErrors": read(0), "PowerOnHours": read(0),
		"DataWritten": read(0), "UnsafeShutdowns": read(0),
		"SMARTStatus": notKept, "Thresholds": notKept,
	})
}

// TestCapturedATA reads QEMU 10.2.1's ide-hd from its captured answers.
// The register answers, logged as text in the same run, are passing's
// and active's: RETURN STATUS 4Fh/C2h, CHECK POWER MODE count FFh. QEMU
// aborts SMART READ LOG 00h and READ LOG EXT, as the fake does every
// command it was not given.
func TestCapturedATA(t *testing.T) {
	d := &fakeATA{t: t, answers: map[ataCommand]answer{
		ataPowerMode:                      {regs: active},
		smartReturnStatus:                 {regs: passing},
		ataIdentify:                       {data: captured(t, "qemu-10.2.1-ide-hd-identify-device")},
		smartReadData:                     {data: captured(t, "qemu-10.2.1-ide-hd-smart-read-data")},
		smartReadThresholds:               {data: captured(t, "qemu-10.2.1-ide-hd-smart-read-attribute-thresholds")},
		smartReadLog(logSummaryErrors, 1): {data: captured(t, "qemu-10.2.1-ide-hd-smart-read-log-01h")},
	}}
	h, err := readATA(d, false)
	if err != nil {
		t.Fatal(err)
	}
	h.Name, h.ReadAt, h.Route = "sda", time.Now(), d.route()
	checkHealth(t, h)
	wantFacts(t, h, map[string]agentproto.Fact{
		"SMARTStatus": read(agentproto.SMARTPassed), "Temperature": read(31), "PowerMode": read(0xFF),
		"DriveErrors": read(0), "Thresholds": read(7),
		"Wear": notKept, "TemperatureLimit": notKept, "CriticalWarning": notKept,
	})
	var ids []uint8
	for _, a := range h.Attributes {
		ids = append(ids, a.ID)
		if a.Threshold == nil {
			t.Errorf("attribute %d without its threshold", a.ID)
		}
	}
	if want := []uint8{1, 3, 4, 5, 9, 12, 190}; !slices.Equal(ids, want) {
		t.Errorf("attributes %v, want %v", ids, want)
	}
}
