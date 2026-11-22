//go:build windows

package inventory

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/powershell"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

var (
	kernel32                             = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemFirmwareTable           = kernel32.NewProc("GetSystemFirmwareTable")
	procGetLogicalProcessorInformationEx = kernel32.NewProc("GetLogicalProcessorInformationEx")
	procGlobalMemoryStatusEx             = kernel32.NewProc("GlobalMemoryStatusEx")
)

// Collect reads the whole inventory from SMBIOS, the registry and the
// system's APIs. It needs no WMI and no PowerShell.
func (c Collector) Collect(ctx context.Context) agentproto.Inventory {
	inv := agentproto.Inventory{
		System: firmware(),
		CPU:    processors(),
		Memory: totalMemory(),
		OS:     windowsOS(),
		Disks:  physicalDisks(),
	}
	inv.System.Virtualization = hypervisor(inv.System)
	inv.Interfaces, inv.Gateways, inv.DNS = adapters()
	if c.Interfaces != nil {
		if list, err := c.Interfaces(); err == nil {
			inv.Interfaces = list
		}
	}
	inv.PackageManager, inv.Packages = "windows", installedPrograms(ctx)
	inv.EasyPatch = c.easyPatch(ctx)
	inv.PowerShell = powerShell()
	return inv
}

// powerShell lists Windows PowerShell and the PowerShell 7 installs, each
// usable one's whole install checked (ADR-0064). Without Program Files'
// known folders, which Windows always has, it lists Windows PowerShell
// alone.
func powerShell() []agentproto.PowerShellInstall {
	roots, _ := powershell.Roots()
	list, _ := powershell.Discover(roots)
	return list
}

// firmware reads the SMBIOS tables Windows keeps a copy of.
func firmware() agentproto.SystemInfo {
	const rsmb = 'R'<<24 | 'S'<<16 | 'M'<<8 | 'B'
	n, _, _ := procGetSystemFirmwareTable.Call(rsmb, 0, 0, 0)
	if n == 0 {
		return agentproto.SystemInfo{}
	}
	buf := make([]byte, n)
	if got, _, _ := procGetSystemFirmwareTable.Call(rsmb, 0, uintptr(unsafe.Pointer(&buf[0])), n); got == 0 || got > n {
		return agentproto.SystemInfo{}
	}
	// RawSMBIOSData: four version bytes and the table's length, then the table.
	if len(buf) < 8 {
		return agentproto.SystemInfo{}
	}
	size := int(binary.LittleEndian.Uint32(buf[4:]))
	return parseSMBIOS(buf[8:min(len(buf), 8+size)])
}

// relations counts the processor cores (0) or sockets (3).
func relations(relation uintptr) int {
	var n uint32
	_, _, _ = procGetLogicalProcessorInformationEx.Call(relation, 0, uintptr(unsafe.Pointer(&n)))
	if n == 0 {
		return 0
	}
	buf := make([]byte, n)
	if r, _, _ := procGetLogicalProcessorInformationEx.Call(relation, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		return 0
	}
	return countRelations(buf[:min(int(n), len(buf))])
}

func processors() agentproto.CPUInfo {
	out := agentproto.CPUInfo{
		Cores:   relations(0), // RelationProcessorCore
		Sockets: relations(3), // RelationProcessorPackage
		Threads: int(windows.GetActiveProcessorCount(windows.ALL_PROCESSOR_GROUPS)),
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
		name, _, _ := k.GetStringValue("ProcessorNameString")
		out.Model = strings.Join(strings.Fields(name), " ")
		_ = k.Close()
	}
	return out
}

func totalMemory() uint64 {
	var ms struct {
		Length, MemoryLoad                                 uint32
		TotalPhys, AvailPhys, TotalPageFile, AvailPageFile uint64
		TotalVirtual, AvailVirtual, AvailExtendedVirtual   uint64
	}
	ms.Length = uint32(unsafe.Sizeof(ms))
	if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r == 0 {
		return 0
	}
	return ms.TotalPhys
}

func windowsOS() agentproto.OSInfo {
	out := agentproto.OSInfo{Name: "Windows", ID: "windows"}
	if v, err := host.WindowsVersion(); err == nil {
		out.Name, out.Version, out.Kernel = v.Name, v.Version, v.Build
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, registry.QUERY_VALUE); err == nil {
		out.Timezone, _, _ = k.GetStringValue("TimeZoneKeyName")
		_ = k.Close()
	}
	return out
}

// Storage IOCTLs.
const (
	ioctlStorageQueryProperty = 0x2D1400
	ioctlDiskGetLengthInfo    = 0x7405C
	storageDeviceProperty     = 0
	storageSeekPenalty        = 7
)

// physicalDisks reads \\.\PhysicalDrive0 to 63.
func physicalDisks() []agentproto.Disk {
	out := []agentproto.Disk{}
	for i := range 64 {
		name := fmt.Sprintf("PhysicalDrive%d", i)
		if d, ok := physicalDisk(name); ok {
			out = append(out, d)
		}
		if len(out) == agentproto.MaxListed {
			break
		}
	}
	return out
}

func physicalDisk(name string) (agentproto.Disk, bool) {
	path, err := windows.UTF16PtrFromString(`\\.\` + name)
	if err != nil {
		return agentproto.Disk{}, false
	}
	h, err := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return agentproto.Disk{}, false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var length int64
	var n uint32
	if err := windows.DeviceIoControl(h, ioctlDiskGetLengthInfo, nil, 0, (*byte)(unsafe.Pointer(&length)), 8, &n, nil); err != nil || length <= 0 {
		return agentproto.Disk{}, false
	}
	d := agentproto.Disk{Name: name, SizeBytes: uint64(length)}
	desc := make([]byte, 1024)
	if b, ok := queryProperty(h, storageDeviceProperty, desc); ok {
		if sd, ok := parseStorageDescriptor(b); ok {
			d.Model, d.Serial, d.Removable = sd.Model, sd.Serial, sd.Removable
			if sd.Bus == busNVMe {
				d.Kind = "nvme"
			}
		}
	}
	if d.Kind == "" {
		var penalty [12]byte // DEVICE_SEEK_PENALTY_DESCRIPTOR
		if b, ok := queryProperty(h, storageSeekPenalty, penalty[:]); ok && len(b) >= 9 {
			d.Kind = "ssd"
			if b[8] != 0 {
				d.Kind = "hdd"
			}
		}
	}
	return d, true
}

// queryProperty asks a disk for a storage property (STORAGE_PROPERTY_QUERY,
// standard query) and returns the bytes it wrote into out.
func queryProperty(h windows.Handle, property uint32, out []byte) ([]byte, bool) {
	var query [12]byte
	binary.LittleEndian.PutUint32(query[0:], property)
	var n uint32
	if len(out) == 0 || len(out) > 1<<20 {
		return nil, false
	}
	if err := windows.DeviceIoControl(h, ioctlStorageQueryProperty, &query[0], uint32(len(query)), &out[0], uint32(len(out)), &n, nil); err != nil { //nolint:gosec // at most 1 MiB, checked above
		return nil, false
	}
	return out[:min(int(n), len(out))], true
}

// adapters reads the network adapters, the default gateways and the DNS
// servers of the adapters that are up.
func adapters() (list []agentproto.Interface, gateways, dns []string) {
	list, gateways, dns = []agentproto.Interface{}, []string{}, []string{}
	size := uint32(16 << 10)
	var buf []byte
	for range 4 {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return list, gateways, dns
		}
		buf = nil
	}
	if buf == nil {
		return list, gateways, dns
	}
	hardware := map[string]bool{}
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || a.IfType == windows.IF_TYPE_TUNNEL {
			continue
		}
		it := agentproto.Interface{
			Name:      windows.UTF16PtrToString(a.FriendlyName),
			Addresses: []string{},
			Up:        a.OperStatus == windows.IfOperStatusUp,
		}
		if a.PhysicalAddressLength > 0 && int(a.PhysicalAddressLength) <= len(a.PhysicalAddress) {
			it.MAC = net.HardwareAddr(a.PhysicalAddress[:a.PhysicalAddressLength]).String()
		}
		if s := a.TransmitLinkSpeed; s > 0 && s != ^uint64(0) {
			it.SpeedMbps = int(min(s/1_000_000, 1<<31-1))
		}
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			ip := u.Address.IP()
			if ip == nil {
				continue
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			it.Addresses = append(it.Addresses, (&net.IPNet{IP: ip, Mask: net.CIDRMask(int(u.OnLinkPrefixLength), bits)}).String())
		}
		row := windows.MibIfRow2{InterfaceLuid: a.Luid}
		if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row) == nil {
			hardware[it.Name] = row.InterfaceAndOperStatusFlags&0x01 != 0 // HardwareInterface
		}
		list = append(list, it)
		if !it.Up {
			continue
		}
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			if ip := g.Address.IP(); ip != nil && !ip.IsUnspecified() {
				gateways = appendNew(gateways, ip.String())
			}
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			if ip := d.Address.IP(); ip != nil && dnsServer(ip.String()) {
				dns = appendNew(dns, ip.String())
			}
		}
	}
	slices.Sort(gateways)
	return sortInterfaces(list, func(name string) bool { return hardware[name] }), gateways, dns
}

// installedPrograms lists what Programs and Features lists: the machine's
// 64-bit and 32-bit Uninstall keys and those of the users signed in.
func installedPrograms(ctx context.Context) []agentproto.Package {
	const uninstall = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	type source struct {
		root   registry.Key
		path   string
		access uint32
		arch   string
	}
	native := windowsArch(runtime.GOARCH)
	sources := []source{
		{registry.LOCAL_MACHINE, uninstall, registry.WOW64_64KEY, native},
		{registry.LOCAL_MACHINE, uninstall, registry.WOW64_32KEY, "x86"},
	}
	if users, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		sids, _ := users.ReadSubKeyNames(-1)
		_ = users.Close()
		for _, sid := range sids {
			if strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasSuffix(sid, "_Classes") {
				sources = append(sources, source{registry.USERS, sid + `\` + uninstall, 0, native})
			}
		}
	}
	var list []agentproto.Package
	for _, s := range sources {
		if ctx.Err() != nil {
			break
		}
		k, err := registry.OpenKey(s.root, s.path, registry.ENUMERATE_SUB_KEYS|s.access)
		if err != nil {
			continue
		}
		names, _ := k.ReadSubKeyNames(-1)
		_ = k.Close()
		for _, name := range names {
			sub, err := registry.OpenKey(s.root, s.path+`\`+name, registry.QUERY_VALUE|s.access)
			if err != nil {
				continue
			}
			str := func(v string) string {
				x, _, _ := sub.GetStringValue(v)
				return x
			}
			system, _, _ := sub.GetIntegerValue("SystemComponent")
			v := uninstallValues{
				DisplayName: str("DisplayName"), DisplayVersion: str("DisplayVersion"), Publisher: str("Publisher"),
				ParentKeyName: str("ParentKeyName"), ReleaseType: str("ReleaseType"), SystemComponent: system,
			}
			_ = sub.Close()
			if p, ok := program(v, s.arch); ok {
				list = append(list, p)
			}
		}
	}
	return finish(list)
}
