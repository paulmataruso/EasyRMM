//go:build !windows

package metrics

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func write(t *testing.T, root, name, content string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const mounts = `sysfs /sys sysfs rw 0 0
proc /proc proc rw 0 0
/dev/sda2 / ext4 rw,relatime 0 0
/dev/sda1 /boot/efi vfat rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/sdb1 /srv/my\040data xfs rw 0 0
/dev/sdb1 /var/lib/bind xfs rw 0 0
/dev/loop3 /snap/core/1 squashfs ro 0 0
/dev/sdc1 /broken ext4 rw 0 0
/dev/sdd1 /empty ext4 rw 0 0
/dev/sde1 /etc/hostname ext4 rw 0 0
`

func TestCollect(t *testing.T) {
	root := t.TempDir()
	write(t, root, "proc/stat", "cpu  100 0 100 700 100 0 0 0 50 0\ncpu0 1 2 3\n")
	write(t, root, "proc/meminfo", "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 250 kB\nSwapTotal: 400 kB\nSwapFree: 300 kB\n")
	write(t, root, "proc/loadavg", "0.52 0.48 0.40 2/345 6789\n")
	write(t, root, "proc/uptime", "3725.42 7000.10\n")
	write(t, root, "proc/self/mounts", mounts)
	for _, pid := range []string{"1", "42", "4242"} {
		if err := os.MkdirAll(filepath.Join(root, "proc", pid), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, root, "proc/sys/note", "not a process")
	write(t, root, "etc/hostname", "web-01\n")
	spaces := map[string]Space{
		"/": {Total: 100, Used: 40}, "/boot/efi": {Total: 10, Used: 2}, "/srv/my data": {Total: 50, Used: 60}, "/empty": {},
		"/etc/hostname": {Total: 70, Used: 7},
	}
	c := &Collector{Root: root, FirstWindow: time.Millisecond, Statfs: func(p string) (Space, error) {
		rel, _ := filepath.Rel(root, p)
		if sp, ok := spaces["/"+filepath.ToSlash(rel)]; ok || rel == "." {
			if rel == "." {
				return spaces["/"], nil
			}
			return sp, nil
		}
		return Space{}, errors.New("no such filesystem")
	}}

	// The first measurement spans FirstWindow: 100 busy of 400 jiffies.
	c.wait = func(_ context.Context, d time.Duration) bool {
		if d != time.Millisecond {
			t.Errorf("first window %v", d)
		}
		write(t, root, "proc/stat", "cpu  150 0 150 950 150 0 0 0 50 0\ncpu0 1 2 3\n")
		return true
	}
	m := c.Collect(context.Background())
	if math.Abs(m.CPUPercent-25) > 0.001 || m.MemoryTotal != 1000*1024 || m.MemoryUsed != 750*1024 || m.SwapTotal != 400*1024 || m.SwapUsed != 100*1024 {
		t.Errorf("metrics %+v", m)
	}
	if m.Load1 != 0.52 || m.Load5 != 0.48 || m.Load15 != 0.40 || m.UptimeSeconds != 3725 || m.Processes != 3 {
		t.Errorf("load %+v", m)
	}
	want := []agentproto.Filesystem{
		{Mount: "/", Device: "/dev/sda2", Type: "ext4", TotalBytes: 100, UsedBytes: 40},
		{Mount: "/boot/efi", Device: "/dev/sda1", Type: "vfat", TotalBytes: 10, UsedBytes: 2},
		{Mount: "/srv/my data", Device: "/dev/sdb1", Type: "xfs", TotalBytes: 50, UsedBytes: 50},
	}
	if !reflect.DeepEqual(m.Filesystems, want) {
		t.Errorf("filesystems %+v", m.Filesystems)
	}

	// Between heartbeats: 300 busy of 400 jiffies.
	write(t, root, "proc/stat", "cpu  350 0 250 1000 200 0 0 0 0 0\n")
	if m := c.Collect(context.Background()); math.Abs(m.CPUPercent-75) > 0.001 {
		t.Errorf("cpu %v", m.CPUPercent)
	}
	// A counter that went backwards (a container restarted) reads as idle.
	write(t, root, "proc/stat", "cpu  1 0 1 1 1 0 0 0\n")
	if m := c.Collect(context.Background()); m.CPUPercent != 0 {
		t.Errorf("cpu after reset %v", m.CPUPercent)
	}
}

func TestOldKernelAndMissingFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "proc/meminfo", "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 100 kB\nCached: 200 kB\nSwapTotal: 0 kB\nbogus\nOdd: x kB\nEmpty:\n")
	write(t, root, "proc/stat", "intr 1 2 3\n")
	write(t, root, "proc/loadavg", "x y z\n")
	m := (&Collector{Root: root}).Collect(context.Background())
	if m.MemoryUsed != 600*1024 || m.SwapUsed != 0 || m.CPUPercent != 0 || m.Load1 != 0 || len(m.Filesystems) != 0 || m.Filesystems == nil {
		t.Errorf("metrics %+v", m)
	}
	write(t, root, "proc/stat", "cpu  1 2 x 4 5\n")
	if _, ok := (&Collector{Root: root}).cpuTimes(); ok {
		t.Error("read a broken /proc/stat")
	}
}

func TestFirstMeasurementCanceled(t *testing.T) {
	root := t.TempDir()
	write(t, root, "proc/stat", "cpu  1 0 1 1 1 0 0 0\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &Collector{Root: root, FirstWindow: time.Hour}
	if p := c.cpuPercent(ctx); p != 0 || c.prev == nil {
		t.Errorf("canceled first measurement %v %v", p, c.prev)
	}
}

func TestUnescape(t *testing.T) {
	for in, want := range map[string]string{
		`/plain`: "/plain", `/a\040b`: "/a b", `/tab\011x`: "/tab\tx", `/back\134slash`: `/back\slash`, `/short\04`: `/short\04`, `/bad\999`: `/bad\999`,
	} {
		if got := unescape(in); got != want {
			t.Errorf("unescape(%q) = %q", in, got)
		}
	}
}

func TestKernelStatfs(t *testing.T) {
	sp, err := kernelStatfs("/")
	if runtime.GOOS != "linux" {
		if err == nil {
			t.Error("statfs outside Linux")
		}
		return
	}
	if err != nil || sp.Total == 0 || sp.Used > sp.Total {
		t.Errorf("statfs / = %+v, %v", sp, err)
	}
	if _, err := kernelStatfs("/easyrmm/no/such/path"); err == nil {
		t.Error("statfs of a missing path")
	}
	// The real machine, end to end.
	m := (&Collector{FirstWindow: 10 * time.Millisecond}).Collect(context.Background())
	if m.MemoryTotal == 0 || m.Processes == 0 || len(m.Filesystems) == 0 {
		t.Errorf("this machine %+v", m)
	}
}
