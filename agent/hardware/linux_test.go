//go:build linux

package hardware

import (
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/paulmataruso/easyrmm/agent/inventory"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestLinuxLayouts checks the ioctls' structures against the kernel's
// headers: struct nvme_admin_cmd (72 bytes everywhere) and struct
// sg_io_hdr (88 bytes on 64-bit architectures, 64 on 32-bit ones).
func TestLinuxLayouts(t *testing.T) {
	var c nvmeAdminCmd
	var h sgIOHdr
	// sg_io_hdr's offsets from its pointers on, on 32-bit and 64-bit
	// architectures (where usr_ptr is aligned to 8).
	sg := map[uintptr]map[string]uintptr{
		4: {"cmdp": 20, "sbp": 24, "timeout": 28, "usr_ptr": 40, "status": 44, "sb_len_wr": 47, "host_status": 48,
			"driver_status": 50, "resid": 52, "size": 64},
		8: {"cmdp": 24, "sbp": 32, "timeout": 40, "usr_ptr": 56, "status": 64, "sb_len_wr": 67, "host_status": 68,
			"driver_status": 70, "resid": 72, "size": 88},
	}[unsafe.Sizeof(uintptr(0))]
	want := map[string][2]uintptr{
		"nvme_admin_cmd":   {unsafe.Sizeof(c), 72},
		"nsid":             {unsafe.Offsetof(c.nsid), 4},
		"addr":             {unsafe.Offsetof(c.addr), 24},
		"data_len":         {unsafe.Offsetof(c.dataLen), 36},
		"cdw10":            {unsafe.Offsetof(c.cdw10), 40},
		"cdw15":            {unsafe.Offsetof(c.cdw15), 60},
		"timeout_ms":       {unsafe.Offsetof(c.timeoutMS), 64},
		"result":           {unsafe.Offsetof(c.result), 68},
		"dxfer_direction":  {unsafe.Offsetof(h.dxferDirection), 4},
		"cmd_len":          {unsafe.Offsetof(h.cmdLen), 8},
		"mx_sb_len":        {unsafe.Offsetof(h.mxSbLen), 9},
		"dxfer_len":        {unsafe.Offsetof(h.dxferLen), 12},
		"dxferp":           {unsafe.Offsetof(h.dxferp), 16},
		"cmdp":             {unsafe.Offsetof(h.cmdp), sg["cmdp"]},
		"sbp":              {unsafe.Offsetof(h.sbp), sg["sbp"]},
		"timeout":          {unsafe.Offsetof(h.timeout), sg["timeout"]},
		"usr_ptr":          {unsafe.Offsetof(h.usrPtr), sg["usr_ptr"]},
		"status":           {unsafe.Offsetof(h.status), sg["status"]},
		"sb_len_wr":        {unsafe.Offsetof(h.sbLenWr), sg["sb_len_wr"]},
		"host_status":      {unsafe.Offsetof(h.hostStatus), sg["host_status"]},
		"driver_status":    {unsafe.Offsetof(h.driverStatus), sg["driver_status"]},
		"resid":            {unsafe.Offsetof(h.resid), sg["resid"]},
		"sg_io_hdr (size)": {unsafe.Sizeof(h), sg["size"]},
	}
	for name, got := range want {
		if got[0] != got[1] {
			t.Errorf("%s: %d, want %d", name, got[0], got[1])
		}
	}
}

// TestRefusedBeforeTheSystemCall: a command not on the list never reaches
// the ioctl. The devices hold no open file: a system call would fail with
// EBADF, an I/O error, not the list's refusal.
func TestRefusedBeforeTheSystemCall(t *testing.T) {
	sg, nvme := &linuxSG{fd: -1}, &linuxNVMe{fd: -1}
	for c := range ataNames {
		for _, m := range ataMutations(c) {
			if _, ok := ataNames[m]; ok {
				continue
			}
			if _, _, err := sg.ata(m); !errors.Is(err, errNotAllowed) {
				t.Fatalf("%+v: %v", m, err)
			}
		}
	}
	for c := range nvmeNames {
		for _, m := range nvmeMutations(c) {
			if _, err := nvme.nvme(m); !errors.Is(err, errNotAllowed) {
				t.Fatalf("%+v: %v", m, err)
			}
		}
	}
	// A listed command does reach it.
	if _, _, err := sg.ata(ataIdentify); !is(err, agentproto.ReasonIOError) {
		t.Errorf("IDENTIFY on no file: %v", err)
	}
	if _, err := nvme.nvme(nvmeHealthLog); !is(err, agentproto.ReasonIOError) {
		t.Errorf("health log on no file: %v", err)
	}
	if sg.route() != "sg" || nvme.route() != "nvme" {
		t.Error("routes")
	}
}

// growStack uses about n bytes of the goroutine's stack, so that Go moves
// the stack to a larger one.
//
//go:noinline
func growStack(n int) byte {
	var pad [1024]byte
	pad[n%len(pad)] = byte(n)
	if n <= len(pad) {
		return pad[0]
	}
	return growStack(n-len(pad)) ^ pad[n%len(pad)]
}

// TestTransportsSurviveStackGrowth: the kernel's stand-in moves the calling
// goroutine's stack before it reads the request and writes the answer, as
// a stack growth between building a request and its system call would. The
// answer must arrive in the buffers the transport then reads: an address
// kept as an integer would still point into the old stack, and the answer
// would be lost, or written over another goroutine's stack.
func TestTransportsSurviveStackGrowth(t *testing.T) {
	// No collection meanwhile: a collection raises the size new goroutines'
	// stacks start at, after which the stand-in's growth might not move one.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	regs := ataRegisters{count: 0xFF, lbaMid: 0x4F, lbaHigh: 0xC2, status: 0x50}
	saved := ioctl
	t.Cleanup(func() { ioctl = saved })
	ioctl = func(_ int, req uintptr, arg unsafe.Pointer) (uintptr, unix.Errno) {
		growStack(1 << 20)
		switch req {
		case sgIO:
			h := (*sgIOHdr)(arg)
			if cdb := unsafe.Slice((*byte)(h.cmdp), h.cmdLen); cdb[0] != ataPassThrough16 {
				return 0, unix.EIO
			}
			if h.dxferp != nil {
				fill(unsafe.Slice((*byte)(h.dxferp), h.dxferLen))
				h.status = scsiGood
				return 0, 0
			}
			h.sbLenWr = uint8(copy(unsafe.Slice((*byte)(h.sbp), h.mxSbLen), descriptorSense(senseRecoveredError, 0, 0x1D, regs))) //nolint:gosec // at most 64
			h.status = scsiCheckCondition
		case nvmeIoctlAdminCmd:
			cmd := (*nvmeAdminCmd)(arg)
			fill(unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&cmd.addr))), cmd.dataLen)) // little-endian: the low word is the address
		default:
			return 0, unix.ENOTTY
		}
		return 0, 0
	}
	// Each call on a goroutine of its own, whose stack starts small.
	on := func(f func()) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			f()
		}()
		<-done
	}
	sg, nvme := &linuxSG{fd: -1}, &linuxNVMe{fd: -1}
	for range 20 {
		on(func() {
			if b, _, err := sg.ata(smartReadData); err != nil || !filled(b, 512) {
				t.Errorf("SG_IO data: %v", err)
			}
		})
		on(func() {
			if _, r, err := sg.ata(ataPowerMode); err != nil || r == nil || *r != regs {
				t.Errorf("SG_IO sense: %+v, %v", r, err)
			}
		})
		on(func() {
			if b, err := nvme.nvme(nvmeHealthLog); err != nil || !filled(b, 512) {
				t.Errorf("NVMe data: %v", err)
			}
		})
	}
}

func fill(b []byte) {
	for i := range b {
		b[i] = byte(i*7 + 1)
	}
}

func filled(b []byte, n int) bool {
	want := make([]byte, n)
	fill(want)
	return string(b) == string(want)
}

// TestLinuxTransportsOnFiles opens a regular file as each device: the open
// succeeds, and the kernel refuses each ioctl as not for this file, which
// is a refusal, not a disk's failure.
func TestLinuxTransportsOnFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := openSG(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.ata(ataIdentify); !is(err, agentproto.ReasonProtocolNotRead) {
		t.Errorf("SG_IO on a file: %v", err)
	}
	d.close()
	n, err := openNVMe(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.nvme(nvmeHealthLog); !is(err, agentproto.ReasonStorageDriver) {
		t.Errorf("NVMe ioctl on a file: %v", err)
	}
	n.close()
	if _, err := openNVMe(filepath.Join(path, "missing")); !is(err, agentproto.ReasonIOError) {
		t.Errorf("a missing device: %v", err)
	}
	if f := openFailure("/dev/sda", unix.EACCES); f.reason != agentproto.ReasonAccessDenied || f.state != agentproto.FactUnavailable {
		t.Errorf("EACCES: %v", f)
	}
}

// TestOpenSGSuspended: a disk whose SCSI device the kernel has
// runtime-suspended is asleep and not opened, so no command reaches it,
// unless wake; an active one is opened. /dev/sda is a file here, so
// opening succeeds wherever it is tried.
func TestOpenSGSuspended(t *testing.T) {
	root := t.TempDir()
	dev := filepath.Join(root, "dev/sda")
	write(t, dev, "")
	status := filepath.Join(root, "sys/block/sda/device/power/runtime_status")
	for _, tc := range []struct {
		status string
		wake   bool
		asleep bool
	}{
		{"", false, false},
		{"suspended\n", false, true},
		{"suspended\n", true, false},
		{"active\n", false, false},
		{"suspending\n", false, false},
	} {
		if tc.status != "" {
			write(t, status, tc.status)
		}
		d, err := openSG(dev, tc.wake)
		if tc.asleep {
			if !is(err, agentproto.ReasonAsleep) || d != nil {
				t.Errorf("%q, wake %v: %v", tc.status, tc.wake, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q, wake %v: %v", tc.status, tc.wake, err)
			continue
		}
		d.close()
	}
}

// sysfsTree constructs a sysfs and /dev for planLinux (not captured from a
// machine): sda behind an AHCI controller (libata), sdb behind a USB
// bridge (uas), sdc a logical volume of a MegaRAID controller, sdd a SAS
// disk on an HBA, vda virtio, mmcblk0 an SD card, nvme0n1 a namespace of
// controller nvme0, and sde with an emulated model.
func sysfsTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	pci := "sys/devices/pci0000:00/"
	dirs := map[string]string{
		"sda":     pci + "0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sda",
		"sdb":     pci + "0000:00:14.0/usb2/2-1/2-1:1.0/host6/target6:0:0/6:0:0:0/block/sdb",
		"sdc":     pci + "0000:03:00.0/host2/target2:2:0/2:2:0:0/block/sdc",
		"sdd":     pci + "0000:04:00.0/host3/port-3:0/end_device-3:0/target3:0:0/3:0:0:0/block/sdd",
		"sde":     pci + "0000:00:1f.2/ata2/host1/target1:0:0/1:0:0:0/block/sde",
		"vda":     pci + "0000:00:05.0/virtio2/block/vda",
		"mmcblk0": pci + "0000:00:1a.0/mmc_host/mmc0/mmc0:0001/block/mmcblk0",
		"nvme0n1": pci + "0000:00:01.0/nvme/nvme0/nvme0n1",
		"xvda":    "sys/devices/vbd-51712/block/xvda",
	}
	drivers := map[string]string{
		pci + "0000:00:1f.2":                         "ahci",
		pci + "0000:00:14.0":                         "xhci_hcd",
		pci + "0000:00:14.0/usb2/2-1/2-1:1.0":        "uas",
		pci + "0000:03:00.0":                         "megaraid_sas",
		pci + "0000:04:00.0":                         "mpt3sas",
		pci + "0000:00:05.0/virtio2":                 "virtio_blk",
		pci + "0000:00:1a.0/mmc_host/mmc0/mmc0:0001": "mmcblk",
		pci + "0000:00:01.0":                         "nvme",
	}
	for name, dir := range dirs {
		mkdir(t, filepath.Join(root, dir))
		link(t, filepath.Join(root, "sys/block", name), "../"+rel(dir, "sys"))
		dev := filepath.Dir(filepath.Dir(dir))
		if name == "vda" || name == "xvda" {
			dev = filepath.Dir(dir[:len(dir)-len("/block/"+name)] + "/x")
		}
		link(t, filepath.Join(root, dir, "device"), rel(dev, dir))
	}
	for dev, drv := range drivers {
		mkdir(t, filepath.Join(root, "sys/bus/drivers", drv))
		link(t, filepath.Join(root, dev, "driver"), rel("sys/bus/drivers/"+drv, dev))
	}
	write(t, filepath.Join(root, pci, "0000:00:1f.2/ata2/host1/target1:0:0/1:0:0:0/vendor"), "ATA     \n")
	write(t, filepath.Join(root, "sys/module/nvme_core/parameters/admin_timeout"), "30\n")
	return root
}

func mkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, at, target string) {
	t.Helper()
	mkdir(t, filepath.Dir(at))
	if err := os.Symlink(target, at); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path, s string) {
	t.Helper()
	mkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// rel is target relative to the directory dir.
func rel(target, dir string) string {
	r, err := filepath.Rel(dir, target)
	if err != nil {
		panic(err)
	}
	return r
}

// TestPlanLinux is the ADR's table for Linux, row by row.
func TestPlanLinux(t *testing.T) {
	root := sysfsTree(t)
	disk := func(name, model string, controllers ...string) inventory.ListedDisk {
		return inventory.ListedDisk{Disk: agentproto.Disk{Name: name, Model: model, Serial: "S"}, Controllers: controllers}
	}
	for _, tc := range []struct {
		d      inventory.ListedDisk
		state  string
		reason string
		target target
	}{
		{d: disk("sda", "WDC WD10EFRX-68F"), target: target{key: "sg:sda/S", paths: []string{root + "/dev/sda"}, proto: protoATA, limit: time.Minute}},
		{d: disk("sdb", "Ultra Fit"), state: agentproto.FactUnavailable, reason: agentproto.ReasonUSBBridge},
		{d: disk("sdc", "PERC H730P Mini"), state: agentproto.FactUnavailable, reason: agentproto.ReasonRAIDController},
		// SAS on an HBA: ATA PASS-THROUGH is tried, and its refusal read.
		{d: disk("sdd", "ST600MM0088"), target: target{key: "sg:sdd/S", paths: []string{root + "/dev/sdd"}, proto: protoATA, limit: time.Minute}},
		{d: disk("sde", "QEMU HARDDISK"), state: agentproto.FactUnsupported, reason: agentproto.ReasonVirtualDisk},
		{d: disk("vda", ""), state: agentproto.FactUnsupported, reason: agentproto.ReasonVirtualDisk},
		{d: disk("xvda", ""), state: agentproto.FactUnsupported, reason: agentproto.ReasonVirtualDisk},
		{d: disk("mmcblk0", "SD32G"), state: agentproto.FactUnsupported, reason: agentproto.ReasonMemoryCard},
		{d: disk("nvme0n1", "Samsung SSD 980 PRO 1TB", "nvme0", "nvme1"), target: target{
			key: "nvme:nvme0,nvme1/S", paths: []string{root + "/dev/nvme0", root + "/dev/nvme1"}, proto: protoNVMe, limit: 30 * time.Second}},
		{d: disk("nvme0n1", "QEMU NVMe Ctrl", "nvme0"), state: agentproto.FactUnsupported, reason: agentproto.ReasonVirtualDisk},
		{d: disk("nvme1n1", "Samsung SSD 980 PRO 1TB"), state: agentproto.FactUnknown, reason: agentproto.ReasonIOError},
		{d: disk("pmem0", ""), state: agentproto.FactUnavailable, reason: agentproto.ReasonProtocolNotRead},
	} {
		f, got := planLinux(root, tc.d)
		switch {
		case tc.state == "" && f != nil:
			t.Errorf("%s: %v", tc.d.Name, f)
		case tc.state == "" && (got.key != tc.target.key || got.proto != tc.target.proto || got.limit != tc.target.limit ||
			len(got.paths) != len(tc.target.paths) || got.paths[0] != tc.target.paths[0]):
			t.Errorf("%s: %+v, want %+v", tc.d.Name, got, tc.target)
		case tc.state != "" && (f == nil || f.state != tc.state || f.reason != tc.reason):
			t.Errorf("%s: %v, want %s %s", tc.d.Name, f, tc.state, tc.reason)
		}
	}
	if adminTimeout(t.TempDir()) != time.Minute {
		t.Error("the admin queue's default timeout")
	}
}
