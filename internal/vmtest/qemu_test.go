package vmtest

import (
	"bufio"
	"encoding/json"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testMachine(accel string) machine {
	return machine{
		name: "easyrmm-debian-12", accel: accel, memoryMB: 2048, cpus: 2,
		disk: "/cache/run/x/disk.qcow2", sockets: "/tmp/s", console: "/cache/run/x/console.log",
		seedURL: "http://10.0.2.2:4321/", seedDS: "nocloud-net", forward: []int{22, 443},
	}
}

func flag(args []string, name string) []string {
	var values []string
	for i, a := range args {
		if a == name && i+1 < len(args) {
			values = append(values, args[i+1])
		}
	}
	return values
}

func TestQEMUArgs(t *testing.T) {
	for accel, want := range map[string][2]string{"kvm": {"kvm", "host"}, "tcg": {"tcg,thread=multi", "max"}} {
		args := qemuArgs(testMachine(accel))
		if got := [2]string{flag(args, "-accel")[0], flag(args, "-cpu")[0]}; got != want {
			t.Errorf("%s: -accel %s -cpu %s", accel, got[0], got[1])
		}
	}
	args := qemuArgs(testMachine("kvm"))
	for name, want := range map[string]string{
		"-smp":    "2",
		"-m":      "2048",
		"-vga":    "std",
		"-serial": "chardev:console",
		"-qmp":    "unix:/tmp/s/qmp.sock,server=on,wait=off",
		"-smbios": "type=1,serial=ds=nocloud-net;s=http://10.0.2.2:4321/",
	} {
		if got := flag(args, name); len(got) != 1 || got[0] != want {
			t.Errorf("%s %q, want %q", name, got, want)
		}
	}
	for _, want := range []string{
		"socket,id=harness,server=on,wait=off,path=/tmp/s/harness.sock",
		"file,id=console,path=/cache/run/x/console.log",
	} {
		if !slices.Contains(flag(args, "-chardev"), want) {
			t.Errorf("no -chardev %s", want)
		}
	}
	if !slices.Contains(flag(args, "-device"), "virtserialport,bus=vser0.0,chardev=harness,name=org.easyrmm.harness") {
		t.Error("no harness port")
	}
	if !slices.Contains(args, "-nodefaults") {
		t.Error("QEMU's default devices are not turned off")
	}

	// A seed on a CD-ROM replaces the one over HTTP; commas in paths are
	// escaped.
	iso := testMachine("tcg")
	iso.seedISO = "/cache/run/a,b/seed.iso"
	args = qemuArgs(iso)
	if got := flag(args, "-smbios"); len(got) != 0 {
		t.Errorf("-smbios %q beside a seed CD-ROM", got)
	}
	if !slices.Contains(flag(args, "-drive"), "if=none,id=seed,format=raw,readonly=on,file=/cache/run/a,,b/seed.iso") ||
		!slices.Contains(flag(args, "-device"), "ide-cd,drive=seed") {
		t.Errorf("no seed CD-ROM: %q", args)
	}
}

// The machine's only network is QEMU's user networking: no bridge, no tap
// device, no other back end, and forwards on loopback only.
func TestQEMUUserNetworkingOnly(t *testing.T) {
	args := qemuArgs(testMachine("kvm"))
	netdevs := flag(args, "-netdev")
	want := "user,id=net0,hostfwd=tcp:127.0.0.1:0-:22,hostfwd=tcp:127.0.0.1:0-:443"
	if len(netdevs) != 1 || netdevs[0] != want {
		t.Errorf("-netdev %q, want only %q", netdevs, want)
	}
	for _, a := range args {
		if a == "-nic" || a == "-net" || strings.Contains(a, "bridge") || strings.Contains(a, "tap") {
			t.Errorf("argument %q", a)
		}
	}
	noForward := testMachine("tcg")
	noForward.forward = nil
	if got := flag(qemuArgs(noForward), "-netdev"); len(got) != 1 || got[0] != "user,id=net0" {
		t.Errorf("without forwards: %q", got)
	}
}

// The extra disks: each on its sparse file, NVMe controllers with their
// serial, SATA disks on one AHCI controller of their own with their model.
func TestDisks(t *testing.T) {
	dir := t.TempDir()
	disks, err := diskFiles(dir, []Disk{
		{ID: "nvme0", Kind: DiskNVMe, Serial: "EASYRMM0001"},
		{ID: "sata0", Kind: DiskSATA},
		{ID: "sata1", Kind: DiskSATA, Model: "Test, Disk", Serial: "EASYRMM0002"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range disks {
		if fi, err := os.Stat(d.file); err != nil || fi.Size() != 64<<20 || filepath.Dir(d.file) != dir {
			t.Errorf("%s: %v, %v", d.ID, fi, err)
		}
	}
	m := testMachine("tcg")
	m.disks = disks
	args := qemuArgs(m)
	wantDevices := []string{
		"nvme,id=nvme0,drive=nvme0-drive,serial=EASYRMM0001",
		"ahci,id=ahci1",
		"ide-hd,id=sata0,bus=ahci1.0,drive=sata0-drive",
		"ide-hd,id=sata1,bus=ahci1.1,drive=sata1-drive,model=Test,, Disk,serial=EASYRMM0002",
	}
	if got := flag(args, "-device"); !slices.Equal(got[len(got)-len(wantDevices):], wantDevices) {
		t.Errorf("devices %q", got)
	}
	if got := flag(args, "-drive"); len(got) != 4 || got[1] != "if=none,id=nvme0-drive,format=raw,cache=unsafe,file="+filepath.Join(dir, "nvme0.raw") {
		t.Errorf("drives %q", got)
	}

	for _, bad := range [][]Disk{
		{{ID: "", Kind: DiskSATA}},
		{{ID: "a b", Kind: DiskSATA}},
		{{ID: "a", Kind: DiskSATA}, {ID: "a", Kind: DiskSATA}},
		{{ID: "a", Kind: "scsi"}},
		{{ID: "a", Kind: DiskNVMe, Serial: "S", Model: "M"}},
		{{ID: "a", Kind: DiskNVMe}},
	} {
		if _, err := diskFiles(t.TempDir(), bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if _, err := diskFiles(filepath.Join(dir, "missing"), []Disk{{ID: "a", Kind: DiskSATA}}); err == nil {
		t.Error("a missing directory accepted")
	}
}

// From QEMU 10.2; 8.2 prints the same.
const usernet = "Hub -1 (net0):\r\n" +
	"  Protocol[State]    FD  Source Address  Port   Dest. Address  Port RecvQ SendQ\r\n" +
	"  TCP[HOST_FORWARD]  11       127.0.0.1 45617       10.0.2.15    22     0     0\r\n" +
	"  TCP[HOST_FORWARD]  10       127.0.0.1 37681       10.0.2.15   443     0     0\r\n" +
	"  TCP[ESTABLISHED]   25        10.0.2.15 33512   151.101.2.132  443     0     0\r\n"

func TestParseUsernet(t *testing.T) {
	got, err := parseUsernet(usernet)
	if err != nil || !maps.Equal(got, map[int]int{22: 45617, 443: 37681}) {
		t.Errorf("%v, %v", got, err)
	}
	if _, err := parseUsernet("  TCP[HOST_FORWARD]  11  127.0.0.1 0  10.0.2.15 22 0 0\n"); err == nil {
		t.Error("an unbound forward was accepted")
	}
	if got, err := parseUsernet(""); err != nil || len(got) != 0 {
		t.Errorf("empty: %v, %v", got, err)
	}
}

// fakeQMP answers like QEMU: a greeting, an event before an answer, an
// error for an unknown command.
func fakeQMP(t *testing.T) net.Conn {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		w := json.NewEncoder(server)
		_ = w.Encode(map[string]any{"QMP": map[string]any{"version": map[string]any{}}})
		r := bufio.NewReader(server)
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return
			}
			var req struct {
				Execute   string         `json:"execute"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(line, &req); err != nil {
				t.Errorf("QMP request %q: %v", line, err)
				return
			}
			_ = w.Encode(map[string]any{"event": "NIC_RX_FILTER_CHANGED"})
			switch {
			case req.Execute == "qmp_capabilities":
				_ = w.Encode(map[string]any{"return": map[string]any{}})
			case req.Execute == "human-monitor-command" && req.Arguments["command-line"] == "info usernet":
				_ = w.Encode(map[string]any{"return": usernet})
			case req.Execute == "qom-set" && req.Arguments["path"] == "/machine/peripheral/nvme0" &&
				req.Arguments["property"] == "smart_critical_warning" && req.Arguments["value"] == float64(4):
				_ = w.Encode(map[string]any{"return": map[string]any{}})
			default:
				_ = w.Encode(map[string]any{"error": map[string]string{"class": "CommandNotFound", "desc": "The command " + req.Execute + " has not been found"}})
			}
		}
	}()
	return client
}

func TestQMP(t *testing.T) {
	q, err := newQMP(fakeQMP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	ports, err := q.forwards()
	if err != nil || ports[22] != 45617 {
		t.Errorf("forwards %v, %v", ports, err)
	}
	if _, err := q.execute("bogus", nil); err == nil || !strings.Contains(err.Error(), "CommandNotFound") {
		t.Errorf("unknown command: %v", err)
	}
	vm := &VM{image: Image{Name: "debian-12"}, qmp: q}
	if err := vm.QOMSet("nvme0", "smart_critical_warning", 4); err != nil {
		t.Errorf("qom-set: %v", err)
	}
	if err := vm.QOMSet("sata0", "smart_critical_warning", 4); err == nil || !strings.HasPrefix(err.Error(), "debian-12: ") {
		t.Errorf("qom-set of a missing device: %v", err)
	}
	_ = q.close()
	if _, err := q.execute("quit", nil); err == nil {
		t.Error("a closed connection answered")
	}
}

func TestDialUnixStopsWhenQEMUExits(t *testing.T) {
	exited := make(chan struct{})
	close(exited)
	if _, err := dialUnix(t.Context(), t.TempDir()+"/none.sock", exited); err == nil || !strings.Contains(err.Error(), "exited") {
		t.Errorf("got %v", err)
	}
}
