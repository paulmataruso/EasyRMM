//go:build !windows

package inventory

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Collect reads the whole inventory from /sys, /proc, /etc and the package
// database.
func (c Collector) Collect(ctx context.Context) agentproto.Inventory {
	inv := agentproto.Inventory{
		System:   c.system(),
		CPU:      c.cpu(),
		Memory:   c.memory(),
		OS:       c.os(),
		Disks:    c.disks(),
		Gateways: c.gateways(),
		DNS:      c.dns(),
	}
	ifaces := c.Interfaces
	if ifaces == nil {
		ifaces = c.systemInterfaces
	}
	if list, err := ifaces(); err == nil {
		inv.Interfaces = list
	}
	if inv.Interfaces == nil {
		inv.Interfaces = []agentproto.Interface{}
	}
	inv.PackageManager, inv.Packages = c.packages(ctx)
	inv.EasyPatch = c.easyPatch(ctx)
	return inv
}

func (c Collector) path(p string) string { return filepath.Join(c.Root, p) }

func (c Collector) read(p string) string {
	b, err := os.ReadFile(c.path(p))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (c Collector) dmi(name string) string {
	v := c.read("/sys/class/dmi/id/" + name)
	if placeholders[strings.ToLower(v)] {
		return ""
	}
	return v
}

func (c Collector) system() agentproto.SystemInfo {
	s := agentproto.SystemInfo{
		Manufacturer: c.dmi("sys_vendor"), Model: c.dmi("product_name"), Serial: c.dmi("product_serial"),
		BIOSVendor: c.dmi("bios_vendor"), BIOSVersion: c.dmi("bios_version"), BIOSDate: c.dmi("bios_date"),
	}
	s.Virtualization = c.virtualization(s)
	return s
}

// virtualization names the container or hypervisor the machine runs in.
func (c Collector) virtualization(s agentproto.SystemInfo) string {
	if v := c.read("/run/systemd/container"); v != "" {
		return "container"
	}
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(c.path(f)); err == nil {
			return "container"
		}
	}
	if h := hypervisor(s); h != "" {
		return h
	}
	if bytes.Contains(c.cpuinfo(), []byte(" hypervisor")) {
		return "vm"
	}
	return ""
}

func (c Collector) cpuinfo() []byte {
	b, _ := os.ReadFile(c.path("/proc/cpuinfo"))
	return b
}

// cpu reads /proc/cpuinfo: one block per logical processor.
func (c Collector) cpu() agentproto.CPUInfo {
	var out agentproto.CPUInfo
	coresPerSocket := map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(c.cpuinfo()))
	physical := ""
	var board, chip string // ARM boards name themselves instead
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "processor":
			out.Threads++
		case "model name":
			if out.Model == "" {
				out.Model = v
			}
		case "Model":
			board = cmp.Or(board, v)
		case "Hardware":
			chip = cmp.Or(chip, v)
		case "physical id":
			physical = v
		case "cpu cores":
			if n, err := strconv.Atoi(v); err == nil {
				coresPerSocket[physical] = n
			}
		}
	}
	out.Model = cmp.Or(out.Model, board, chip)
	out.Model = strings.Join(strings.Fields(out.Model), " ")
	out.Sockets = len(coresPerSocket)
	for _, n := range coresPerSocket {
		out.Cores += n
	}
	if out.Sockets == 0 && out.Threads > 0 { // ARM and others list no sockets
		out.Sockets, out.Cores = 1, out.Threads
	}
	return out
}

func (c Collector) memory() uint64 {
	return meminfo(c.read("/proc/meminfo"))["MemTotal"]
}

// meminfo parses /proc/meminfo into bytes.
func meminfo(s string) map[string]uint64 {
	out := map[string]uint64{}
	for line := range strings.Lines(s) {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			n *= 1024
		}
		out[k] = n
	}
	return out
}

func (c Collector) os() agentproto.OSInfo {
	rel := map[string]string{}
	for _, f := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if s := c.read(f); s != "" {
			rel = osRelease(s)
			break
		}
	}
	name := rel["PRETTY_NAME"]
	if name == "" {
		name = rel["NAME"]
	}
	return agentproto.OSInfo{
		Name: name, ID: rel["ID"], Version: rel["VERSION_ID"],
		Kernel: c.read("/proc/sys/kernel/osrelease"), Timezone: c.timezone(),
	}
}

func osRelease(s string) map[string]string {
	out := map[string]string{}
	for line := range strings.Lines(s) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out
}

func (c Collector) timezone() string {
	if tz := c.read("/etc/timezone"); tz != "" {
		return tz
	}
	if target, err := os.Readlink(c.path("/etc/localtime")); err == nil {
		if _, zone, ok := strings.Cut(target, "zoneinfo/"); ok {
			return zone
		}
	}
	return ""
}

// skippedDisks are block devices that are not disks.
var skippedDisks = []string{"loop", "ram", "zram", "dm-", "md", "sr", "nbd", "fd", "zd"}

// Storage lists the disks as Collect does, with what the hardware reader
// needs, and names the machine's virtualization.
func (c Collector) Storage() Storage {
	return Storage{Virtualization: c.system().Virtualization, Disks: c.listDisks()}
}

func (c Collector) disks() []agentproto.Disk { return disks(c.listDisks()) }

func (c Collector) listDisks() []ListedDisk {
	out := []ListedDisk{}
	entries, err := os.ReadDir(c.path("/sys/block"))
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if slices.ContainsFunc(skippedDisks, func(p string) bool { return strings.HasPrefix(name, p) }) {
			continue
		}
		base := "/sys/block/" + name
		sectors, _ := strconv.ParseUint(c.read(base+"/size"), 10, 64)
		// A hidden disk is a path of a multipath NVMe namespace (nvme0c1n1),
		// listed through its namespace.
		if sectors == 0 || c.read(base+"/hidden") == "1" {
			continue
		}
		d := ListedDisk{Disk: agentproto.Disk{
			Name: name, SizeBytes: sectors * 512, Removable: c.read(base+"/removable") == "1",
			Model: strings.Join(strings.Fields(c.read(base+"/device/model")), " "), Serial: c.read(base + "/device/serial"),
		}}
		switch {
		case strings.HasPrefix(name, "nvme"):
			d.Kind = "nvme"
			d.Controllers = c.nvmeControllers(base)
		case c.read(base+"/queue/rotational") == "1":
			d.Kind = "hdd"
		case c.read(base+"/queue/rotational") == "0":
			d.Kind = "ssd"
		}
		c.identity(&d, base)
		out = append(out, d)
		if len(out) == agentproto.MaxListed {
			break
		}
	}
	return out
}

// nvmeController names an NVMe controller's character device: nvme0.
var nvmeController = regexp.MustCompile(`^nvme[0-9]+$`)

// nvmeControllers finds the NVMe controllers that serve a namespace through
// sysfs, never from its name: under native multipath the block device
// nvmeXnY is a namespace head whose X is the subsystem's number, and its
// paths, linked from the head's multipath directory, are each a hidden disk
// whose parent is a controller (ADR-0065, "Reading on Linux"). Without
// multipath the namespace's own parent is its controller.
func (c Collector) nvmeControllers(base string) []string {
	var out []string
	add := func(disk string) {
		dev, err := filepath.EvalSymlinks(c.path(disk + "/device"))
		if err != nil {
			return
		}
		name := filepath.Base(dev)
		if _, err := os.Stat(c.path("/sys/class/nvme/" + name)); err == nil && nvmeController.MatchString(name) {
			out = appendNew(out, name)
		}
	}
	paths, _ := os.ReadDir(c.path(base + "/multipath"))
	for _, p := range paths {
		add(base + "/multipath/" + p.Name())
	}
	if len(paths) == 0 {
		add(base)
	}
	return out
}

// identity fills the disk's firmware revision (ADR-0065): an NVMe
// controller's, a SATA disk's from the IDENTIFY data in its ATA Information
// VPD page (all eight characters, where device/rev holds the last four), or
// another SCSI disk's device/rev; a SATA disk's whole model from the same
// IDENTIFY data (device/model holds its first 16 characters); and a serial
// number the kernel does not give in device/serial, from the same VPD page
// or, for other SCSI disks, the Unit Serial Number page.
func (c Collector) identity(d *ListedDisk, base string) {
	switch {
	case d.Kind == "nvme":
		d.Firmware = firmwareNotExposed()
		for _, ctrl := range d.Controllers {
			if rev := c.read("/sys/class/nvme/" + ctrl + "/firmware_rev"); rev != "" {
				d.Firmware = firmwareRead(rev)
				break
			}
		}
		return
	case strings.HasPrefix(d.Name, "vd"), strings.HasPrefix(d.Name, "xvd"):
		// virtio-blk and Xen's disks are a hypervisor's: they have no firmware.
		d.Firmware = &agentproto.TextFact{State: agentproto.FactUnsupported, Reason: agentproto.ReasonVirtualDisk}
		return
	}
	if b, err := os.ReadFile(c.path(base + "/device/vpd_pg89")); err == nil {
		id, ok := parseVPD89(b)
		if !ok {
			d.Firmware = &agentproto.TextFact{State: agentproto.FactUnknown, Reason: agentproto.ReasonBadAnswer}
			return
		}
		serial, firmware, model := ataIdentityStrings(id)
		d.Firmware = firmwareRead(firmware)
		if model != "" {
			d.Model = model
		}
		if d.Serial == "" {
			d.Serial = serial
		}
		return
	}
	if d.Serial == "" {
		if b, err := os.ReadFile(c.path(base + "/device/vpd_pg80")); err == nil {
			d.Serial = parseVPD80(b)
		}
	}
	// A SATA disk without the page (a kernel before it) has only device/rev's
	// last four characters, which are not its revision.
	if strings.TrimSpace(c.read(base+"/device/vendor")) == "ATA" {
		d.Firmware = firmwareNotExposed()
		return
	}
	d.Firmware = firmwareRead(c.read(base + "/device/rev"))
}
