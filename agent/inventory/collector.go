// Package inventory collects a device's inventory (ADR-0018): firmware,
// processor, memory, operating system, disks, network and installed
// software. Linux is read from /sys, /proc, /etc and the package
// database; Windows from the registry, SMBIOS and the system's APIs.
//
// Every list is sorted so an unchanged machine produces the same document,
// and every source is optional: what cannot be read is left empty.
package inventory

import (
	"cmp"
	"context"
	"slices"
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
	// real. Only `rpm` and the EasyPatch agent's `status --json` are run.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// LookPath finds a command; nil searches the system's fixed directories.
	LookPath func(name string) (string, error)
}

// placeholders are what firmware vendors leave in fields they never filled.
var placeholders = map[string]bool{
	"to be filled by o.e.m.": true, "default string": true, "system serial number": true, "system product name": true,
	"system manufacturer": true, "not specified": true, "not applicable": true, "none": true, "n/a": true, "0": true,
	"0123456789": true, "123456789": true, "oem": true, "o.e.m.": true, "chassis serial number": true, "invalid": true,
}

// clean drops a firmware placeholder and squeezes spaces.
func clean(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if placeholders[strings.ToLower(s)] {
		return ""
	}
	return s
}

// hypervisor names the hypervisor a machine's firmware identifies, empty
// for physical hardware.
func hypervisor(s agentproto.SystemInfo) string {
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
	return ""
}

func finish(list []agentproto.Package) []agentproto.Package {
	slices.SortFunc(list, func(a, b agentproto.Package) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Version, b.Version), cmp.Compare(a.Arch, b.Arch))
	})
	list = slices.Compact(list)
	if len(list) > agentproto.MaxPackages {
		list = list[:agentproto.MaxPackages]
	}
	if list == nil {
		list = []agentproto.Package{}
	}
	return list
}

// sortInterfaces puts hardware interfaces first, so a host's own network
// card leads its container bridges, then sorts by name, and caps the list.
func sortInterfaces(list []agentproto.Interface, physical func(name string) bool) []agentproto.Interface {
	for i := range list {
		slices.Sort(list[i].Addresses)
		if len(list[i].Addresses) > agentproto.MaxAddresses {
			list[i].Addresses = list[i].Addresses[:agentproto.MaxAddresses]
		}
	}
	hw := make(map[string]bool, len(list))
	for _, i := range list {
		hw[i.Name] = physical(i.Name)
	}
	slices.SortFunc(list, func(a, b agentproto.Interface) int {
		if hw[a.Name] != hw[b.Name] {
			if hw[a.Name] {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.Name, b.Name)
	})
	if len(list) > agentproto.MaxListed {
		list = list[:agentproto.MaxListed]
	}
	return list
}

func appendNew(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}
