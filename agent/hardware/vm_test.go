//go:build vm

package hardware

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/vmtest"
)

// The machine test's disks. QEMU's NVMe controller keeps its own model,
// "QEMU NVMe Ctrl": up to 10.2 at least it has no property to change it.
// The second SATA disk's model is a neutral name, a stand-in for a real
// drive's, so that the agent reads it as it would a real disk. It fits in
// 16 characters: Linux lists a SATA disk's model as SCSI's product
// identification, the first 16 characters of the drive's.
const standIn = "EasyRMM Stand-in"

var vmDisks = []vmtest.Disk{
	{ID: "nvme0", Kind: vmtest.DiskNVMe, Serial: "EASYRMMNVME01"},
	{ID: "sata0", Kind: vmtest.DiskSATA, Serial: "EASYRMMSATA01"},
	{ID: "sata1", Kind: vmtest.DiskSATA, Serial: "EASYRMMSATA02", Model: standIn},
}

// TestDisksOnMachines runs the machine test (machine_test.go) as root
// inside each distribution's cloud image chosen by EASYRMM_VM_IMAGE
// (internal/vmtest), with an NVMe disk and two SATA disks on AHCI beside
// the virtio-blk boot disk, and checks what it read through the guest's
// kernel: QEMU's disks classified as emulated; the stand-in SATA disk read
// by the agent; the NVMe disk read by the probe, its critical warning set
// and cleared through QMP. With EASYRMM_TEST_HARDWARE_CAPTURE set, the
// answers' bytes are kept there. Run it with `make test-vm`.
func TestDisksOnMachines(t *testing.T) {
	images := vmtest.Selected(t)
	bin := testBinary(t)
	for _, image := range images {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			disksOnMachine(t, image, bin)
		})
	}
}

// testBinary builds this package's tests for the guests: static, stripped.
func testBinary(t *testing.T) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "hardware.test")
	cmd := exec.CommandContext(t.Context(), "go", "test", "-c", "-o", out, "-ldflags=-s -w", ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the test binary: %v\n%s", err, b)
	}
	b, err := os.ReadFile(out) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func disksOnMachine(t *testing.T, image string, bin []byte) {
	vm := vmtest.Boot(t, image, vmtest.Options{Disks: vmDisks})
	ctx := t.Context()
	// The binary goes over in pieces: each WriteFile is one script.
	const piece = 1 << 20
	for i := 0; i*piece < len(bin); i++ {
		if err := vm.WriteFile(ctx, fmt.Sprintf("/root/hardware.test.%03d", i), bin[i*piece:min(len(bin), (i+1)*piece)], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	guest(t, vm, "cat /root/hardware.test.* >/root/hardware.test && rm /root/hardware.test.* && chmod 700 /root/hardware.test && mkdir -p /root/captures")

	first := readMachine(t, vm)
	byModel := func(r machineResult, model string, serial string) (agentproto.DiskHealth, agentproto.DiskHealth, bool) {
		for i, d := range r.Disks {
			if strings.Contains(d.Model, model) && (serial == "" || d.Serial == serial) {
				return r.Report.Disks[i], r.Probe.Disks[i], true
			}
		}
		return agentproto.DiskHealth{}, agentproto.DiskHealth{}, false
	}

	t.Run("virtio", func(t *testing.T) {
		for i, d := range first.Disks {
			if strings.HasPrefix(d.Name, "vd") {
				if h := first.Report.Disks[i]; h.State != agentproto.FactUnsupported || h.Reason != agentproto.ReasonVirtualDisk {
					t.Errorf("%s: %s %s", d.Name, h.State, h.Reason)
				}
				return
			}
		}
		t.Error("no virtio disk listed")
	})

	t.Run("nvme", func(t *testing.T) {
		h, p, ok := byModel(first, "QEMU NVMe Ctrl", "EASYRMMNVME01")
		if !ok {
			t.Fatalf("no NVMe disk listed: %+v", first.Disks)
		}
		if h.State != agentproto.FactUnsupported || h.Reason != agentproto.ReasonVirtualDisk {
			t.Errorf("QEMU's NVMe disk: %s %s", h.State, h.Reason)
		}
		// QEMU reports 323 K (50 °C), a warning threshold of 343 K
		// (70 °C) and the hours since the machine started.
		checkRead(t, "the probe of the NVMe disk", p, agentproto.ProtocolNVMe, "nvme")
		want := map[string]agentproto.Fact{
			"Temperature": agentproto.Read(50), "TemperatureLimit": agentproto.Read(70), "CriticalWarning": agentproto.Read(0),
			"SMARTStatus": agentproto.NotRead(agentproto.FactUnsupported, agentproto.ReasonNotKept),
		}
		wantFacts(t, p, want)
		if p.PowerOnHours.State != agentproto.FactRead || p.MediaErrors.State != agentproto.FactRead || p.AvailableSpare.State != agentproto.FactRead {
			t.Errorf("hours %+v, media errors %+v, spare %+v", p.PowerOnHours, p.MediaErrors, p.AvailableSpare)
		}

		// The critical warning QMP sets shows in the next reading, and
		// its clearing in the one after.
		for _, w := range []int64{0x04, 0} {
			if err := vm.QOMSet("nvme0", "smart_critical_warning", w); err != nil {
				t.Fatal(err)
			}
			_, p, _ := byModel(readMachine(t, vm), "QEMU NVMe Ctrl", "EASYRMMNVME01")
			wantFacts(t, p, map[string]agentproto.Fact{"CriticalWarning": agentproto.Read(w)})
		}
	})

	t.Run("sata", func(t *testing.T) {
		_, _, exit, err := vm.Run(ctx, "test -d /sys/bus/pci/drivers/ahci")
		if err != nil {
			t.Fatal(err)
		}
		if exit != 0 {
			t.Skipf("%s's kernel has no AHCI driver: its SATA disks are not seen", image)
		}
		h, p, ok := byModel(first, "QEMU HARDDISK", "EASYRMMSATA01")
		if !ok {
			t.Fatalf("no SATA disk with QEMU's model listed: %+v", first.Disks)
		}
		if h.State != agentproto.FactUnsupported || h.Reason != agentproto.ReasonVirtualDisk {
			t.Errorf("QEMU's SATA disk: %s %s", h.State, h.Reason)
		}
		checkRead(t, "the probe of QEMU's SATA disk", p, agentproto.ProtocolATA, "sg")

		h, _, ok = byModel(first, standIn, "EASYRMMSATA02")
		if !ok {
			t.Fatalf("no stand-in SATA disk listed: %+v", first.Disks)
		}
		// QEMU's IDE disk: SMART on, attribute 190 at 31 °C, a passing
		// status, "active or idle" (FFh), no errors in its summary log,
		// and neither the general-purpose log nor Device Statistics.
		checkRead(t, "the stand-in SATA disk", h, agentproto.ProtocolATA, "sg")
		notKept := agentproto.NotRead(agentproto.FactUnsupported, agentproto.ReasonNotKept)
		wantFacts(t, h, map[string]agentproto.Fact{
			"SMARTStatus": agentproto.Read(agentproto.SMARTPassed), "Temperature": agentproto.Read(31),
			"PowerMode": agentproto.Read(0xFF), "DriveErrors": agentproto.Read(0),
			"Wear": notKept, "TemperatureLimit": notKept, "CriticalWarning": notKept,
		})
		ids := map[uint8]bool{}
		for _, a := range h.Attributes {
			ids[a.ID] = true
			if a.Threshold == nil {
				t.Errorf("attribute %d without its threshold", a.ID)
			}
		}
		for _, id := range []uint8{1, 3, 4, 5, 9, 12, 190} {
			if !ids[id] {
				t.Errorf("attribute %d missing: %+v", id, h.Attributes)
			}
		}
	})

	if dir := os.Getenv(captureEnv); dir != "" {
		saveCaptures(t, vm, filepath.Join(dir, image))
	}
}

// readMachine runs the machine test on the guest and returns its result.
func readMachine(t *testing.T, vm *vmtest.VM) machineResult {
	t.Helper()
	out := guest(t, vm, machineEnv+"=1 "+machineOutEnv+"=/root/out.json "+captureEnv+"=/root/captures "+
		"/root/hardware.test -test.run '^TestMachine$' -test.v -test.count=1 >/root/test.log 2>&1; "+
		"status=$?; cat /root/test.log >&2; [ $status -eq 0 ] && cat /root/out.json")
	var r machineResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("the machine test's result: %v", err)
	}
	if len(r.Report.Disks) != len(r.Disks) || len(r.Probe.Disks) != len(r.Disks) {
		t.Fatalf("%d disks, %d read, %d probed", len(r.Disks), len(r.Report.Disks), len(r.Probe.Disks))
	}
	return r
}

// guest runs a script as root on the machine and returns its output.
func guest(t *testing.T, vm *vmtest.VM, script string) []byte {
	t.Helper()
	stdout, stderr, exit, err := vm.Run(t.Context(), script)
	if len(stderr) > 0 {
		t.Logf("%s", stderr)
	}
	if err != nil || exit != 0 {
		t.Fatalf("%s: exit %d, %v", script, exit, err)
	}
	return stdout
}

func checkRead(t *testing.T, what string, h agentproto.DiskHealth, protocol, route string) {
	t.Helper()
	if h.State != agentproto.FactRead || h.Protocol != protocol || h.Route != route {
		t.Errorf("%s: %s %s %q, protocol %q, route %q", what, h.State, h.Reason, h.Detail, h.Protocol, h.Route)
	}
}

// saveCaptures copies the guest's captured answers to dir.
func saveCaptures(t *testing.T, vm *vmtest.VM, dir string) {
	t.Helper()
	out := guest(t, vm, "cd /root/captures && tar -cf - . | base64 -w0")
	tarball, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(out)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(context.WithoutCancel(t.Context()), "tar", "-xf", "-", "-C", dir)
	cmd.Stdin = bytes.NewReader(tarball)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unpacking the captures: %v\n%s", err, b)
	}
	t.Logf("captures kept in %s", dir)
}
