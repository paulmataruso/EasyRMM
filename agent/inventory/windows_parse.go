package inventory

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// The parsers here read what Windows hands out as raw bytes. They are
// plain Go, so they are tested on every platform.

// parseSMBIOS reads the machine and firmware from an SMBIOS structure
// table: the BIOS (type 0) and system (type 1) structures.
func parseSMBIOS(table []byte) agentproto.SystemInfo {
	var out agentproto.SystemInfo
	for len(table) >= 4 {
		typ, length := table[0], int(table[1])
		if length < 4 || length > len(table) {
			break
		}
		formatted, rest := table[:length], table[length:]
		end := bytes.Index(rest, []byte{0, 0})
		if end < 0 {
			break
		}
		strs := strings.Split(string(rest[:end]), "\x00")
		str := func(off int) string {
			if off >= len(formatted) {
				return ""
			}
			i := int(formatted[off])
			if i == 0 || i > len(strs) {
				return ""
			}
			return clean(strs[i-1])
		}
		switch typ {
		case 0:
			out.BIOSVendor, out.BIOSVersion, out.BIOSDate = str(0x04), str(0x05), str(0x08)
		case 1:
			out.Manufacturer, out.Model, out.Serial = str(0x04), str(0x05), str(0x07)
		case 127: // end of table
			return out
		}
		table = rest[end+2:]
	}
	return out
}

// countRelations counts the entries of a GetLogicalProcessorInformationEx
// buffer: one per core, or per socket, for the relation asked.
func countRelations(buf []byte) int {
	n := 0
	for off := 0; off+8 <= len(buf); {
		size := int(binary.LittleEndian.Uint32(buf[off+4:]))
		if size < 8 {
			break
		}
		n++
		off += size
	}
	return n
}

// Storage bus types (STORAGE_BUS_TYPE).
const (
	busUSB  = 7
	busSD   = 12
	busMMC  = 13
	busNVMe = 17
)

// storageDevice is what a STORAGE_DEVICE_DESCRIPTOR says about a disk.
type storageDevice struct {
	Model, Serial string
	Bus           uint32
	Removable     bool
}

// parseStorageDescriptor reads a STORAGE_DEVICE_DESCRIPTOR.
func parseStorageDescriptor(b []byte) (storageDevice, bool) {
	if len(b) < 36 {
		return storageDevice{}, false
	}
	at := func(off int) string {
		o := int(binary.LittleEndian.Uint32(b[off:]))
		if o == 0 || o >= len(b) {
			return ""
		}
		s := b[o:]
		if i := bytes.IndexByte(s, 0); i >= 0 {
			s = s[:i]
		}
		return strings.Join(strings.Fields(string(s)), " ")
	}
	d := storageDevice{
		Model:     strings.TrimSpace(at(12) + " " + at(16)),
		Serial:    strings.Trim(at(24), " ."),
		Bus:       binary.LittleEndian.Uint32(b[28:]),
		Removable: b[10] != 0,
	}
	switch d.Bus {
	case busUSB, busSD, busMMC:
		d.Removable = true
	}
	return d, true
}

// uninstallValues are the values of a program's Uninstall registry key.
type uninstallValues struct {
	DisplayName, DisplayVersion, Publisher string
	// ParentKeyName marks an update of another program.
	ParentKeyName string
	ReleaseType   string
	// SystemComponent 1 hides the program from Programs and Features.
	SystemComponent uint64
}

// program turns an Uninstall key into a package, or false for what
// Programs and Features does not list: updates, system components and
// nameless entries.
func program(v uninstallValues, arch string) (agentproto.Package, bool) {
	name := strings.TrimSpace(v.DisplayName)
	if name == "" || v.SystemComponent == 1 || v.ParentKeyName != "" {
		return agentproto.Package{}, false
	}
	switch strings.ToLower(strings.TrimSpace(v.ReleaseType)) {
	case "update", "hotfix", "security update", "service pack":
		return agentproto.Package{}, false
	}
	return agentproto.Package{
		Name: name, Version: strings.TrimSpace(v.DisplayVersion), Arch: arch,
		Publisher: strings.TrimSpace(v.Publisher),
	}, true
}

// windowsArch names an architecture as Windows does.
func windowsArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "386":
		return "x86"
	}
	return goarch
}

// dnsServer reports whether a DNS server address is a real one: Windows
// lists fec0:0:0:ffff::1-3, deprecated site-local addresses, on IPv6
// interfaces without DNS servers.
func dnsServer(ip string) bool {
	return ip != "" && !strings.HasPrefix(strings.ToLower(ip), "fec0:")
}
