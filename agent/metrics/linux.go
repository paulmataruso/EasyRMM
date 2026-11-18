//go:build !windows

package metrics

import (
	"cmp"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Collect measures the machine now.
func (c *Collector) Collect(ctx context.Context) agentproto.Metrics {
	m := agentproto.Metrics{CPUPercent: c.cpuPercent(ctx), Filesystems: c.filesystems()}
	mem := meminfo(c.read("/proc/meminfo"))
	m.MemoryTotal = mem["MemTotal"]
	avail, ok := mem["MemAvailable"]
	if !ok { // kernels before 3.14
		avail = mem["MemFree"] + mem["Buffers"] + mem["Cached"]
	}
	m.MemoryUsed = m.MemoryTotal - min(avail, m.MemoryTotal)
	m.SwapTotal = mem["SwapTotal"]
	m.SwapUsed = m.SwapTotal - min(mem["SwapFree"], m.SwapTotal)
	if f := strings.Fields(c.read("/proc/loadavg")); len(f) >= 3 {
		m.Load1, m.Load5, m.Load15 = float(f[0]), float(f[1]), float(f[2])
	}
	if f := strings.Fields(c.read("/proc/uptime")); len(f) >= 1 {
		m.UptimeSeconds = int64(float(f[0]))
	}
	if entries, err := os.ReadDir(c.path("/proc")); err == nil {
		for _, e := range entries {
			if _, err := strconv.Atoi(e.Name()); err == nil && e.IsDir() {
				m.Processes++
			}
		}
	}
	return m
}

func (c *Collector) path(p string) string { return filepath.Join(c.Root, p) }

func (c *Collector) read(p string) string {
	b, err := os.ReadFile(c.path(p))
	if err != nil {
		return ""
	}
	return string(b)
}

func float(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// cpuTimes reads the first line of /proc/stat: user nice system idle iowait
// irq softirq steal (guest time is already counted in user).
func (c *Collector) cpuTimes() (cpuTimes, bool) {
	line, _, _ := strings.Cut(c.read("/proc/stat"), "\n")
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return cpuTimes{}, false
	}
	var t cpuTimes
	for i, v := range f[1:min(len(f), 9)] {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return cpuTimes{}, false
		}
		t.total += n
		if i != 3 && i != 4 { // idle and iowait
			t.busy += n
		}
	}
	return t, true
}

// localTypes are the filesystem types that hold a device's data.
var localTypes = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "vfat": true,
	"exfat": true, "ntfs": true, "ntfs3": true, "fuseblk": true, "jfs": true, "reiserfs": true, "bcachefs": true,
}

// filesystems lists the mounted local filesystems, one per device (bind
// mounts and Btrfs subvolumes repeat their device), plus the root
// filesystem whatever its type (overlay in a container).
func (c *Collector) filesystems() []agentproto.Filesystem {
	statfs := c.Statfs
	if statfs == nil {
		statfs = kernelStatfs
	}
	out := []agentproto.Filesystem{}
	seen := map[string]bool{}
	for line := range strings.Lines(c.read("/proc/self/mounts")) {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		dev, mount, typ := unescape(f[0]), unescape(f[1]), f[2]
		if !localTypes[typ] && mount != "/" {
			continue
		}
		if seen[dev] && mount != "/" {
			continue
		}
		// A container's /etc/hostname, /etc/hosts and /etc/resolv.conf are
		// files bind-mounted from the host's disk, not filesystems of its own.
		if fi, err := os.Stat(c.path(mount)); err == nil && !fi.IsDir() {
			continue
		}
		sp, err := statfs(c.path(mount))
		if err != nil || sp.Total == 0 {
			continue
		}
		seen[dev] = true
		out = append(out, agentproto.Filesystem{Mount: mount, Device: dev, Type: typ, TotalBytes: sp.Total, UsedBytes: min(sp.Used, sp.Total)})
	}
	slices.SortFunc(out, func(a, b agentproto.Filesystem) int { return cmp.Compare(a.Mount, b.Mount) })
	// A root filesystem listed twice (rootfs and its real type) keeps one entry.
	out = slices.CompactFunc(out, func(a, b agentproto.Filesystem) bool { return a.Mount == b.Mount })
	if len(out) > agentproto.MaxListed {
		out = out[:agentproto.MaxListed]
	}
	return out
}

// unescape decodes the octal escapes /proc/self/mounts uses for spaces,
// tabs, newlines and backslashes.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
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
