//go:build !windows

package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// tree writes files under a new root and returns it.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const x86CPU = `processor	: 0
model name	: Intel(R) Xeon(R)   CPU E5-2670 v2 @ 2.50GHz
physical id	: 0
cpu cores	: 2
flags		: fpu vme hypervisor

processor	: 1
model name	: Intel(R) Xeon(R)   CPU E5-2670 v2 @ 2.50GHz
physical id	: 0
cpu cores	: 2

processor	: 2
model name	: Intel(R) Xeon(R)   CPU E5-2670 v2 @ 2.50GHz
physical id	: 1
cpu cores	: 2

processor	: 3
physical id	: 1
cpu cores	: 2
`

const dpkgStatus = `Package: openssl
Status: install ok installed
Priority: optional
Architecture: amd64
Version: 3.0.13-0ubuntu3.4
Description: Secure Sockets Layer toolkit
 This package contains the openssl binary.
 .
 More text.

Package: removed-thing
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0

Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.21-2ubuntu4
`

func machine(t *testing.T) string {
	t.Helper()
	root := tree(t, map[string]string{
		"sys/class/dmi/id/sys_vendor":     "Dell Inc.\n",
		"sys/class/dmi/id/product_name":   "PowerEdge R640\n",
		"sys/class/dmi/id/product_serial": "To Be Filled By O.E.M.\n",
		"sys/class/dmi/id/bios_vendor":    "Dell Inc.\n",
		"sys/class/dmi/id/bios_version":   "2.19.1\n",
		"sys/class/dmi/id/bios_date":      "04/04/2024\n",
		"proc/cpuinfo":                    x86CPU,
		"proc/meminfo":                    "MemTotal:       16384000 kB\nMemFree:  1000 kB\n",
		"etc/os-release":                  "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n# comment\n",
		"proc/sys/kernel/osrelease":       "6.8.0-45-generic\n",
		"sys/block/sda/size":              "976773168\n",
		"sys/block/sda/queue/rotational":  "1\n",
		"sys/block/sda/removable":         "0\n",
		"sys/block/sda/device/model":      "ST500DM002-1BD14  \n",
		"sys/block/sdb/size":              "1000\n",
		"sys/block/sdb/queue/rotational":  "0\n",
		"sys/block/sdb/removable":         "1\n",
		"sys/block/nvme0n1/size":          "2000409264\n",
		"sys/block/nvme0n1/device/serial": "S4EWNX0R123456\n",
		"sys/block/loop0/size":            "100\n",
		"sys/block/sr0/size":              "100\n",
		"sys/block/vdc/size":              "0\n",
		"proc/net/route":                  "Iface\tDestination\tGateway\tFlags\nens33\t00000000\t0100A8C0\t0003\nens33\t0000A8C0\t00000000\t0001\n",
		"proc/net/ipv6_route":             "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000020573fffefeadc1 00000400 00000001 00000000 00000003 ens33\n",
		"etc/resolv.conf":                 "# generated\nnameserver 127.0.0.53\noptions edns0\n",
		"run/systemd/resolve/resolv.conf": "nameserver 192.0.2.53\nnameserver 2001:db8::53\nnameserver bogus\n",
		"etc/timezone":                    "Europe/Berlin\n",
		"var/lib/dpkg/status":             dpkgStatus,
	})
	return root
}

func TestCollect(t *testing.T) {
	root := machine(t)
	c := Collector{Root: root, Interfaces: func() ([]agentproto.Interface, error) {
		return []agentproto.Interface{{Name: "ens33", MAC: "00:50:56:9e:14:bc", Addresses: []string{"192.168.0.10/24"}, Up: true}}, nil
	}}
	inv := c.Collect(context.Background())

	want := agentproto.SystemInfo{Manufacturer: "Dell Inc.", Model: "PowerEdge R640", BIOSVendor: "Dell Inc.", BIOSVersion: "2.19.1", BIOSDate: "04/04/2024", Virtualization: "vm"}
	if inv.System != want {
		t.Errorf("system %+v", inv.System)
	}
	if inv.CPU != (agentproto.CPUInfo{Model: "Intel(R) Xeon(R) CPU E5-2670 v2 @ 2.50GHz", Sockets: 2, Cores: 4, Threads: 4}) {
		t.Errorf("cpu %+v", inv.CPU)
	}
	if inv.Memory != 16384000*1024 {
		t.Errorf("memory %d", inv.Memory)
	}
	if inv.OS != (agentproto.OSInfo{Name: "Ubuntu 24.04.3 LTS", ID: "ubuntu", Version: "24.04", Kernel: "6.8.0-45-generic", Timezone: "Europe/Berlin"}) {
		t.Errorf("os %+v", inv.OS)
	}
	wantDisks := []agentproto.Disk{
		{Name: "nvme0n1", Serial: "S4EWNX0R123456", SizeBytes: 2000409264 * 512, Kind: "nvme"},
		{Name: "sda", Model: "ST500DM002-1BD14", SizeBytes: 976773168 * 512, Kind: "hdd"},
		{Name: "sdb", SizeBytes: 512000, Kind: "ssd", Removable: true},
	}
	if !reflect.DeepEqual(inv.Disks, wantDisks) {
		t.Errorf("disks %+v", inv.Disks)
	}
	if !reflect.DeepEqual(inv.Gateways, []string{"192.168.0.1", "fe80::205:73ff:fefe:adc1"}) {
		t.Errorf("gateways %v", inv.Gateways)
	}
	if !reflect.DeepEqual(inv.DNS, []string{"192.0.2.53", "2001:db8::53"}) {
		t.Errorf("dns %v", inv.DNS)
	}
	if len(inv.Interfaces) != 1 || inv.Interfaces[0].Name != "ens33" {
		t.Errorf("interfaces %+v", inv.Interfaces)
	}
	if inv.PackageManager != "dpkg" || !reflect.DeepEqual(inv.Packages, []agentproto.Package{
		{Name: "bash", Version: "5.2.21-2ubuntu4", Arch: "amd64"}, {Name: "openssl", Version: "3.0.13-0ubuntu3.4", Arch: "amd64"},
	}) {
		t.Errorf("packages %s %+v", inv.PackageManager, inv.Packages)
	}

	// The same machine produces the same document.
	if again := c.Collect(context.Background()); again.Hash() != inv.Hash() || inv.Hash() == "" {
		t.Error("the hash is not stable")
	}
}

func TestEmptyMachine(t *testing.T) {
	c := Collector{Root: t.TempDir(), Interfaces: func() ([]agentproto.Interface, error) { return nil, errors.New("no network") },
		LookPath: func(string) (string, error) { return "", errors.New("none") }}
	inv := c.Collect(context.Background())
	if inv.Disks == nil || inv.Interfaces == nil || inv.Packages == nil || inv.Gateways == nil || inv.DNS == nil {
		t.Errorf("nil lists encode as null: %+v", inv)
	}
	if inv.PackageManager != "" || inv.System.Virtualization != "" || inv.CPU.Sockets != 0 {
		t.Errorf("empty machine %+v", inv)
	}
}

func TestVirtualizationAndARM(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"container": {"run/systemd/container": "docker\n"},
		"docker":    {".dockerenv": ""},
		"kvm":       {"sys/class/dmi/id/sys_vendor": "QEMU\n"},
		"hyper-v":   {"sys/class/dmi/id/sys_vendor": "Microsoft Corporation\n", "sys/class/dmi/id/product_name": "Virtual Machine\n"},
		"vmware":    {"sys/class/dmi/id/product_name": "VMware20,1\n"},
	} {
		got := Collector{Root: tree(t, files)}.system().Virtualization
		want := map[string]string{"docker": "container"}[name]
		if want == "" {
			want = name
		}
		if got != want {
			t.Errorf("%s: %q", name, got)
		}
	}
	arm := Collector{Root: tree(t, map[string]string{
		"proc/cpuinfo": "processor\t: 0\nBogoMIPS\t: 108.00\n\nprocessor\t: 1\n\nHardware\t: BCM2835\nModel\t: Raspberry Pi 4 Model B Rev 1.4\n",
	})}.cpu()
	if arm != (agentproto.CPUInfo{Model: "Raspberry Pi 4 Model B Rev 1.4", Sockets: 1, Cores: 2, Threads: 2}) {
		t.Errorf("arm %+v", arm)
	}
}

func TestTimezoneLinkAndPlainDNS(t *testing.T) {
	root := tree(t, map[string]string{"etc/resolv.conf": "nameserver 10.0.0.1\nnameserver 10.0.0.1\n"})
	if err := os.Symlink("/usr/share/zoneinfo/America/New_York", filepath.Join(root, "etc/localtime")); err != nil {
		t.Fatal(err)
	}
	c := Collector{Root: root}
	if tz := c.timezone(); tz != "America/New_York" {
		t.Errorf("timezone %q", tz)
	}
	if dns := c.dns(); !reflect.DeepEqual(dns, []string{"10.0.0.1"}) {
		t.Errorf("dns %v", dns)
	}
}

func TestOtherPackageManagers(t *testing.T) {
	apkDB := "C:Q1abc=\nP:musl\nV:1.2.5-r0\nA:x86_64\nT:the musl c library\n\nP:busybox\nV:1.36.1-r29\nA:x86_64\n\n"
	mgr, pkgs := Collector{Root: tree(t, map[string]string{"lib/apk/db/installed": apkDB})}.packages(context.Background())
	if mgr != "apk" || !reflect.DeepEqual(pkgs, []agentproto.Package{{Name: "busybox", Version: "1.36.1-r29", Arch: "x86_64"}, {Name: "musl", Version: "1.2.5-r0", Arch: "x86_64"}}) {
		t.Errorf("apk %s %+v", mgr, pkgs)
	}

	root := tree(t, map[string]string{
		"var/lib/pacman/local/linux-6.9.7.arch1-1/desc": "%NAME%\nlinux\n\n%VERSION%\n6.9.7.arch1-1\n\n%DESC%\nThe Linux kernel\nsecond line\n\n%ARCH%\nx86_64\n",
		"var/lib/pacman/local/ALPM_DB_VERSION":          "9\n",
		"var/lib/pacman/local/broken-1/other":           "x",
	})
	mgr, pkgs = Collector{Root: root}.packages(context.Background())
	if mgr != "pacman" || !reflect.DeepEqual(pkgs, []agentproto.Package{{Name: "linux", Version: "6.9.7.arch1-1", Arch: "x86_64"}}) {
		t.Errorf("pacman %s %+v", mgr, pkgs)
	}

	var args []string
	c := Collector{
		Root:     tree(t, map[string]string{"var/lib/rpm/rpmdb.sqlite": ""}),
		LookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil },
		Run: func(_ context.Context, name string, a ...string) ([]byte, error) {
			args = append([]string{name}, a...)
			return []byte("kernel\t5.14.0-427.el9\tx86_64\nkernel\t5.14.0-362.el9\tx86_64\ngpg-pubkey\tfd431d51-4ae0493b\t(none)\nbash\t5.1.8-9.el9\tx86_64\nkernel\t5.14.0-427.el9\tx86_64\nbad line\n"), nil
		},
	}
	mgr, pkgs = c.packages(context.Background())
	if mgr != "rpm" || !reflect.DeepEqual(pkgs, []agentproto.Package{
		{Name: "bash", Version: "5.1.8-9.el9", Arch: "x86_64"}, {Name: "kernel", Version: "5.14.0-362.el9", Arch: "x86_64"}, {Name: "kernel", Version: "5.14.0-427.el9", Arch: "x86_64"},
	}) {
		t.Errorf("rpm %s %+v", mgr, pkgs)
	}
	if strings.Join(args, " ") != "/usr/bin/rpm -qa --qf "+rpmQuery {
		t.Errorf("rpm ran %q", args)
	}
	c.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("rpm broke") }
	if mgr, pkgs := c.packages(context.Background()); mgr != "" || len(pkgs) != 0 {
		t.Errorf("failed rpm %s %v", mgr, pkgs)
	}
	c.LookPath = func(string) (string, error) { return "", errors.New("none") }
	if mgr, _ := c.packages(context.Background()); mgr != "" {
		t.Errorf("rpm without the command: %s", mgr)
	}
}

func TestPackagesAreCapped(t *testing.T) {
	var b strings.Builder
	for i := range agentproto.MaxPackages + 10 {
		b.WriteString("P:p")
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString("\nV:")
		b.WriteString(filepath.Base(t.Name()))
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString("\n")
		b.WriteString("A:" + string(rune('a'+i/26%26)) + string(rune('a'+i/676%26)) + "\n\n")
	}
	_, pkgs := Collector{Root: tree(t, map[string]string{"lib/apk/db/installed": b.String()})}.packages(context.Background())
	if len(pkgs) != agentproto.MaxPackages {
		t.Errorf("%d packages", len(pkgs))
	}
}

func TestSystemInterfacesAndLookPath(t *testing.T) {
	list, err := Collector{}.systemInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range list {
		if i.Name == "lo" || i.Addresses == nil {
			t.Errorf("interface %+v", i)
		}
	}
	if _, err := lookPath("sh"); err != nil {
		t.Errorf("sh not found: %v", err)
	}
	if _, err := lookPath("easyrmm-no-such-command"); err == nil {
		t.Error("found a missing command")
	}
	if out, err := output(context.Background(), "/bin/sh", "-c", "echo $PATH"); err != nil || strings.TrimSpace(string(out)) != "/usr/sbin:/usr/bin:/sbin:/bin" {
		t.Errorf("output %q %v", out, err)
	}
	many := make([]agentproto.Interface, agentproto.MaxListed+3)
	for i := range many {
		many[i] = agentproto.Interface{Name: string(rune('A' + i%26)), Addresses: make([]string, agentproto.MaxAddresses+2)}
	}
	if got := sortInterfaces(many, func(string) bool { return false }); len(got) != agentproto.MaxListed || len(got[0].Addresses) != agentproto.MaxAddresses {
		t.Errorf("caps %d %d", len(got), len(got[0].Addresses))
	}

	// A host's network card comes before Docker's bridges, which come by name.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sys/class/net/ens33/device"), 0o755); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, i := range sortInterfaces([]agentproto.Interface{{Name: "docker0"}, {Name: "ens33"}, {Name: "br-0dd7"}}, Collector{Root: root}.physical) {
		names = append(names, i.Name)
	}
	if strings.Join(names, " ") != "ens33 br-0dd7 docker0" {
		t.Errorf("order %v", names)
	}
}

// A query past its deadline is asked to stop before it is killed: rpm killed
// outright can leave its Berkeley DB database needing recovery.
func TestQueryAskedToStopFirst(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	marker := filepath.Join(t.TempDir(), "stopped")
	script := `trap 'touch ` + marker + `; exit 7' TERM; sleep 30 >/dev/null 2>&1 & wait`
	if _, err := output(ctx, "/bin/sh", "-c", script); err == nil {
		t.Error("a query past its deadline succeeded")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("not asked to stop: %v", err)
	}

	old := stopGrace
	stopGrace = 300 * time.Millisecond
	t.Cleanup(func() { stopGrace = old })
	ctx2, cancel2 := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel2()
	start := time.Now()
	if _, err := output(ctx2, "/bin/sh", "-c", `trap '' TERM; sleep 5`); err == nil {
		t.Error("a query that would not stop succeeded")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("took %v: not killed after the grace period", took)
	}
}
