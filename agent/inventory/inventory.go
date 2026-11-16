// Package inventory collects a Linux device's inventory (ADR-0018):
// firmware, processor, memory, operating system, disks, network and
// installed packages, from /sys, /proc, /etc and the package database.
//
// Every list is sorted so an unchanged machine produces the same document,
// and every source is optional: what cannot be read is left empty.
package inventory

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Collector reads the inventory. The zero value reads the real machine.
type Collector struct {
	// Root prefixes every path; "" or "/" on a real machine.
	Root string
	// Interfaces lists the network interfaces; nil reads them from the
	// system.
	Interfaces func() ([]agentproto.Interface, error)
	// Run runs a command and returns its standard output; nil runs it for
	// real. Only `rpm` is run.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// LookPath finds a command; nil searches the system's fixed directories.
	LookPath func(name string) (string, error)
}

// Collect reads the whole inventory.
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

// placeholders are what firmware vendors leave in fields they never filled.
var placeholders = map[string]bool{
	"to be filled by o.e.m.": true, "default string": true, "system serial number": true, "system product name": true,
	"system manufacturer": true, "not specified": true, "not applicable": true, "none": true, "n/a": true, "0": true,
	"0123456789": true, "123456789": true, "oem": true, "o.e.m.": true, "chassis serial number": true, "invalid": true,
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
	id := strings.ToLower(s.Manufacturer + " " + s.Model + " " + s.BIOSVendor)
	for _, h := range []struct{ match, name string }{
		{"vmware", "vmware"}, {"virtualbox", "virtualbox"}, {"innotek", "virtualbox"}, {"qemu", "kvm"}, {"kvm", "kvm"},
		{"amazon ec2", "kvm"}, {"google compute engine", "kvm"}, {"xen", "xen"}, {"parallels", "parallels"},
		{"bochs", "kvm"}, {"openstack", "kvm"}, {"proxmox", "kvm"},
	} {
		if strings.Contains(id, h.match) {
			return h.name
		}
	}
	if strings.Contains(id, "microsoft corporation") && strings.Contains(id, "virtual") {
		return "hyper-v"
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

func (c Collector) disks() []agentproto.Disk {
	out := []agentproto.Disk{}
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
		if sectors == 0 {
			continue
		}
		d := agentproto.Disk{
			Name: name, SizeBytes: sectors * 512, Removable: c.read(base+"/removable") == "1",
			Model: strings.Join(strings.Fields(c.read(base+"/device/model")), " "), Serial: c.read(base + "/device/serial"),
		}
		switch {
		case strings.HasPrefix(name, "nvme"):
			d.Kind = "nvme"
		case c.read(base+"/queue/rotational") == "1":
			d.Kind = "hdd"
		case c.read(base+"/queue/rotational") == "0":
			d.Kind = "ssd"
		}
		out = append(out, d)
		if len(out) == agentproto.MaxListed {
			break
		}
	}
	return out
}
