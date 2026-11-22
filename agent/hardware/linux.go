//go:build linux

package hardware

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/paulmataruso/easyrmm/agent/inventory"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Linux reads NVMe through the controller's character device with
// NVME_IOCTL_ADMIN_CMD, and ATA through the disk's block device with SG_IO
// and ATA PASS-THROUGH (16), which libata, or a host bus adapter in
// pass-through mode, translates (ADR-0065, "Reading on Linux").
var system = platform{plan: planLinux, openNVMe: openNVMe, openATA: openSG}

// Hardware RAID controllers' drivers: their disks are the controller's
// logical volumes, whose drives only the controller's own tools reach.
var raidDrivers = map[string]bool{
	"megaraid_sas": true, "megaraid_mbox": true, "megaraid": true, "hpsa": true, "cciss": true, "smartpqi": true,
	"aacraid": true, "arcmsr": true, "3w-9xxx": true, "3w-sas": true, "3w-xxxx": true, "ips": true, "ipr": true,
	"esas2r": true, "hptiop": true, "stex": true, "mvumi": true, "pmcraid": true,
}

// usbDrivers drive USB mass storage: a disk behind them is behind a USB
// bridge.
var usbDrivers = map[string]bool{"usb-storage": true, "uas": true}

// sgTimeout is SG_IO's timeout, longer than a disk's spin-up: the kernel's
// own default for SG_IO, stated rather than left to the device.
const sgTimeout = 60 * time.Second

// planLinux tells what a disk is from sysfs: a hypervisor's emulated disk,
// a memory card, a disk behind a USB bridge or a hardware RAID controller,
// or an NVMe namespace or SCSI disk to read.
func planLinux(root string, d inventory.ListedDisk) (*failure, target) {
	base := filepath.Join(root, "/sys/block", d.Name)
	vendor := readSys(filepath.Join(base, "device/vendor"))
	switch {
	case strings.HasPrefix(d.Name, "xvd"):
		return virtualDisk("a Xen disk"), target{}
	case driverOf(filepath.Join(base, "device")) == "virtio_blk":
		return virtualDisk("a virtio disk"), target{}
	case emulated(vendor + " " + d.Model):
		return virtualDisk("an emulated disk's model"), target{}
	case strings.HasPrefix(d.Name, "mmcblk"):
		return fail(agentproto.FactUnsupported, agentproto.ReasonMemoryCard, ""), target{}
	}
	for _, drv := range ancestorDrivers(root, base) {
		switch {
		case usbDrivers[drv]:
			return fail(agentproto.FactUnavailable, agentproto.ReasonUSBBridge, "%s", drv), target{}
		case raidDrivers[drv]:
			return fail(agentproto.FactUnavailable, agentproto.ReasonRAIDController, "%s", drv), target{}
		}
	}
	switch {
	case strings.HasPrefix(d.Name, "nvme"):
		if len(d.Controllers) == 0 {
			return ioError("no NVMe controller found in sysfs for %s", d.Name), target{}
		}
		t := target{key: "nvme:" + strings.Join(d.Controllers, ",") + "/" + d.Serial, proto: protoNVMe, limit: adminTimeout(root)}
		for _, c := range d.Controllers {
			t.paths = append(t.paths, filepath.Join(root, "/dev", c))
		}
		return nil, t
	case strings.HasPrefix(d.Name, "sd"):
		return nil, target{key: "sg:" + d.Name + "/" + d.Serial, paths: []string{filepath.Join(root, "/dev", d.Name)}, proto: protoATA, limit: sgTimeout}
	}
	return notThisProtocol("a %s device", strings.TrimRight(d.Name, "0123456789")), target{}
}

func readSys(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // sysfs, under the collector's root
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// driverOf names the driver bound to a sysfs device, empty when none is.
func driverOf(dev string) string {
	target, err := os.Readlink(filepath.Join(dev, "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

// ancestorDrivers names the drivers bound to the devices a disk hangs
// from, nearest first: its SCSI device, a USB interface, a PCI controller.
func ancestorDrivers(root, base string) []string {
	dir, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil
	}
	top := filepath.Join(root, "/sys/devices")
	var out []string
	for strings.HasPrefix(dir, top+string(filepath.Separator)) {
		if drv := driverOf(dir); drv != "" {
			out = append(out, drv)
		}
		dir = filepath.Dir(dir)
	}
	return out
}

// adminTimeout is the NVMe admin queue's timeout, which a command sent with
// timeout_ms 0 is given: the nvme_core module's admin_timeout, 60 seconds
// unless an operator changed it.
func adminTimeout(root string) time.Duration {
	s, err := strconv.Atoi(readSys(filepath.Join(root, "/sys/module/nvme_core/parameters/admin_timeout")))
	if err != nil || s <= 0 {
		return 60 * time.Second
	}
	return time.Duration(s) * time.Second
}

// openFailure says why a device could not be opened.
func openFailure(path string, err error) *failure {
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return accessDenied("opening %s: %v", path, err)
	}
	return ioError("opening %s: %v", path, err)
}

// ioctl is the system call: a variable so that a test can stand in for the
// kernel (TestTransportsSurviveStackGrowth). arg's object, and every buffer
// it points to, must be pinned by the caller.
var ioctl = func(fd int, req uintptr, arg unsafe.Pointer) (uintptr, unix.Errno) {
	r, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg)) //nolint:gosec // fd is an open descriptor
	return r, errno
}

func openFD(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, openFailure(path, err)
	}
	return fd, nil
}

// nvmeAdminCmd is the kernel's struct nvme_admin_cmd (72 bytes on every
// architecture). Its addr is a __u64 on every architecture, so it cannot be
// an unsafe.Pointer on 32-bit ones: it holds the address of a buffer pinned
// for the call.
type nvmeAdminCmd struct {
	opcode      uint8
	flags       uint8
	rsvd1       uint16
	nsid        uint32
	cdw2        uint32
	cdw3        uint32
	metadata    uint64
	addr        uint64
	metadataLen uint32
	dataLen     uint32
	cdw10       uint32
	cdw11       uint32
	cdw12       uint32
	cdw13       uint32
	cdw14       uint32
	cdw15       uint32
	timeoutMS   uint32
	result      uint32
}

// nvmeIoctlAdminCmd is NVME_IOCTL_ADMIN_CMD: _IOWR('N', 0x41, struct
// nvme_admin_cmd).
const nvmeIoctlAdminCmd = 0xC0484E41

// linuxNVMe is an NVMe controller's character device.
type linuxNVMe struct{ fd int }

func openNVMe(path string) (nvmeDevice, error) {
	fd, err := openFD(path)
	if err != nil {
		return nil, err
	}
	return &linuxNVMe{fd: fd}, nil
}

func (d *linuxNVMe) route() string { return "nvme" }

func (d *linuxNVMe) close() { _ = unix.Close(d.fd) }

func (d *linuxNVMe) nvme(c nvmeCommand) ([]byte, error) {
	if err := checkNVMe(c); err != nil {
		return nil, err
	}
	// Every buffer is allocated, then pinned, before its address is taken:
	// a pinned object neither moves nor is freed until Unpin, so the
	// address the kernel is given stays the buffer's.
	buf := make([]byte, c.length)
	cmd := &nvmeAdminCmd{
		opcode: c.opcode, nsid: c.nsid, dataLen: c.length,
		cdw10: c.cdw10, cdw11: c.cdw11, cdw12: c.cdw12, cdw13: c.cdw13, cdw14: c.cdw14, cdw15: c.cdw15,
		// 0: the admin queue's own timeout, so that a slow controller is
		// not reset by the agent.
		timeoutMS: 0,
	}
	var pin runtime.Pinner
	defer pin.Unpin()
	pin.Pin(cmd)
	pin.Pin(&buf[0])
	cmd.addr = uint64(uintptr(unsafe.Pointer(&buf[0])))                  //nolint:gosec // the ioctl takes the address as a __u64; buf is pinned
	status, errno := ioctl(d.fd, nvmeIoctlAdminCmd, unsafe.Pointer(cmd)) //nolint:gosec // the kernel's struct, pinned
	runtime.KeepAlive(cmd)
	runtime.KeepAlive(buf)
	switch {
	case errno == unix.EACCES || errno == unix.EPERM:
		return nil, accessDenied("NVMe admin command: %v", errno)
	case errno == unix.EINTR || errno == unix.ETIMEDOUT:
		return nil, timedOut("NVMe admin command: %v", errno)
	case errno == unix.ENOTTY || errno == unix.EINVAL:
		return nil, driverRefused("NVMe admin command: %v", errno)
	case errno != 0:
		return nil, ioError("NVMe admin command: %v", errno)
	case status != 0:
		return nil, nvmeStatus(uint32(status)) //nolint:gosec // the status is 15 bits
	}
	return buf, nil
}

// sgIOHdr is the kernel's struct sg_io_hdr: 88 bytes on 64-bit
// architectures, 64 on 32-bit ones. Its pointers are unsafe.Pointer, which
// the garbage collector sees, never addresses kept as integers.
type sgIOHdr struct {
	interfaceID    int32
	dxferDirection int32
	cmdLen         uint8
	mxSbLen        uint8
	iovecCount     uint16
	dxferLen       uint32
	dxferp         unsafe.Pointer
	cmdp           unsafe.Pointer
	sbp            unsafe.Pointer
	timeout        uint32
	flags          uint32
	packID         int32
	usrPtr         unsafe.Pointer
	status         uint8
	maskedStatus   uint8
	msgStatus      uint8
	sbLenWr        uint8
	hostStatus     uint16
	driverStatus   uint16
	resid          int32
	duration       uint32
	info           uint32
}

const (
	sgIO           = 0x2285
	senseLen       = 64
	sgDxferNone    = -1
	sgDxferFromDev = -3
)

// linuxSG is a SCSI disk's block device, for SG_IO.
type linuxSG struct{ fd int }

// suspended reports whether the kernel's runtime power management has
// suspended the disk at path, planLinux's <root>/dev/<name>: its SCSI
// device's power/runtime_status.
func suspended(path string) bool {
	root := filepath.Dir(filepath.Dir(path))
	return readSys(filepath.Join(root, "sys/block", filepath.Base(path), "device/power/runtime_status")) == "suspended"
}

// openSG opens a disk for SG_IO. A disk the kernel has runtime-suspended
// is asleep, and is not opened unless wake: any command, CHECK POWER MODE
// included, would resume it first. A disk that spun down by its own timer
// is told by CHECK POWER MODE.
func openSG(path string, wake bool) (ataDevice, error) {
	if !wake && suspended(path) {
		return nil, errAsleep
	}
	fd, err := openFD(path)
	if err != nil {
		return nil, err
	}
	return &linuxSG{fd: fd}, nil
}

func (d *linuxSG) route() string { return "sg" }

func (d *linuxSG) close() { _ = unix.Close(d.fd) }

func (d *linuxSG) ata(c ataCommand) ([]byte, *ataRegisters, error) {
	if err := checkATA(c); err != nil {
		return nil, nil, err
	}
	// Every buffer is allocated, then pinned, before its address is taken,
	// as in nvme.
	cdb := cdb16(c)
	senseBuf := make([]byte, senseLen)
	var data []byte
	if c.length > 0 {
		data = make([]byte, c.length)
	}
	h := &sgIOHdr{
		interfaceID: 'S', dxferDirection: sgDxferNone, cmdLen: 16, mxSbLen: senseLen,
		timeout: uint32(sgTimeout / time.Millisecond),
	}
	var pin runtime.Pinner
	defer pin.Unpin()
	pin.Pin(h)
	pin.Pin(&cdb[0])
	pin.Pin(&senseBuf[0])
	h.cmdp, h.sbp = unsafe.Pointer(&cdb[0]), unsafe.Pointer(&senseBuf[0]) //nolint:gosec // sg_io_hdr's pointers, to pinned buffers
	if data != nil {
		pin.Pin(&data[0])
		h.dxferDirection, h.dxferLen, h.dxferp = sgDxferFromDev, c.length, unsafe.Pointer(&data[0]) //nolint:gosec // pinned
	}
	_, errno := ioctl(d.fd, sgIO, unsafe.Pointer(h)) //nolint:gosec // the kernel's struct, pinned
	runtime.KeepAlive(h)
	runtime.KeepAlive(cdb)
	runtime.KeepAlive(senseBuf)
	runtime.KeepAlive(data)
	switch {
	case errno == unix.EACCES || errno == unix.EPERM:
		return nil, nil, accessDenied("SG_IO: %v", errno)
	case errno == unix.EINTR || errno == unix.ETIMEDOUT:
		return nil, nil, timedOut("SG_IO: %v", errno)
	case errno == unix.ENOTTY || errno == unix.EINVAL || errno == unix.EOPNOTSUPP:
		// The block device does not take SCSI commands.
		return nil, nil, notThisProtocol("SG_IO: %v", errno)
	case errno != 0:
		return nil, nil, ioError("SG_IO: %v", errno)
	}
	return sgOutcome(c, sgAnswer{status: h.status, hostStatus: h.hostStatus, driverStatus: h.driverStatus, resid: h.resid,
		sense: senseBuf[:min(int(h.sbLenWr), len(senseBuf))]}, data)
}
