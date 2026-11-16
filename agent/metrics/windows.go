//go:build windows

package metrics

import (
	"context"
	"errors"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

// Collect measures the machine now. Windows has no load average; Load1,
// Load5 and Load15 stay 0.
func (c *Collector) Collect(ctx context.Context) agentproto.Metrics {
	m := agentproto.Metrics{CPUPercent: c.cpuPercent(ctx), Filesystems: volumes()}
	if ms, ok := memoryStatus(); ok {
		m.MemoryTotal = ms.TotalPhys
		m.MemoryUsed = ms.TotalPhys - min(ms.AvailPhys, ms.TotalPhys)
	}
	m.SwapTotal, m.SwapUsed = pageFiles()
	m.UptimeSeconds = int64(windows.DurationSinceBoot() / time.Second)
	m.Processes = processes()
	return m
}

// cpuTimes reads the system's idle, kernel and user time; kernel time
// includes idle time.
func (c *Collector) cpuTimes() (cpuTimes, bool) {
	var idle, kernel, user windows.Filetime
	r, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return cpuTimes{}, false
	}
	ticks := func(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }
	total := ticks(kernel) + ticks(user)
	return cpuTimes{busy: total - min(ticks(idle), total), total: total}, true
}

// memoryStatusEx is MEMORYSTATUSEX.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func memoryStatus() (memoryStatusEx, bool) {
	ms := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	return ms, r != 0
}

// pageFileInformation is the start of SYSTEM_PAGEFILE_INFORMATION; sizes are
// in pages.
type pageFileInformation struct {
	NextEntryOffset uint32
	TotalSize       uint32
	TotalInUse      uint32
	PeakUsage       uint32
}

const systemPageFileInformation = 18

// pageFiles adds up the page files' size and use, Windows' swap.
func pageFiles() (total, used uint64) {
	buf := make([]byte, 4096)
	for range 4 {
		var n uint32
		err := windows.NtQuerySystemInformation(systemPageFileInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &n) //nolint:gosec // a small buffer
		if errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) {
			buf = make([]byte, max(int(n), 2*len(buf)))
			continue
		}
		if err != nil || n == 0 {
			return 0, 0 // no page file
		}
		page := uint64(os.Getpagesize()) //nolint:gosec // a positive page size
		size := int(unsafe.Sizeof(pageFileInformation{}))
		for off := 0; off+size <= int(n) && off+size <= len(buf); {
			info := (*pageFileInformation)(unsafe.Pointer(&buf[off]))
			total += uint64(info.TotalSize) * page
			used += uint64(info.TotalInUse) * page
			if info.NextEntryOffset == 0 {
				break
			}
			off += int(info.NextEntryOffset)
		}
		return total, min(used, total)
	}
	return 0, 0
}

// processes counts the running processes.
func processes() int {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	n := 0
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		n++
	}
	return n
}

// volumes lists the fixed drives with a letter: C:\, D:\...
func volumes() []agentproto.Filesystem {
	out := []agentproto.Filesystem{}
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return out
	}
	for i := range 26 {
		if mask&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, err := windows.UTF16PtrFromString(root)
		if err != nil || windows.GetDriveType(p) != windows.DRIVE_FIXED {
			continue
		}
		var avail, total, free uint64
		// A locked BitLocker drive cannot be measured; it is left out.
		if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil || total == 0 {
			continue
		}
		out = append(out, agentproto.Filesystem{
			Mount: root, Device: volumeName(p), Type: fileSystem(p),
			TotalBytes: total, UsedBytes: total - min(free, total),
		})
		if len(out) == agentproto.MaxListed {
			break
		}
	}
	return out
}

// fileSystem names a volume's file system: NTFS, ReFS, FAT32...
func fileSystem(root *uint16) string {
	var name [windows.MAX_PATH + 1]uint16
	if err := windows.GetVolumeInformation(root, nil, 0, nil, nil, nil, &name[0], uint32(len(name))); err != nil {
		return ""
	}
	return windows.UTF16ToString(name[:])
}

// volumeName is a drive's volume GUID path, \\?\Volume{...}\.
func volumeName(root *uint16) string {
	var name [windows.MAX_PATH + 1]uint16
	if err := windows.GetVolumeNameForVolumeMountPoint(root, &name[0], uint32(len(name))); err != nil {
		return ""
	}
	return windows.UTF16ToString(name[:])
}
