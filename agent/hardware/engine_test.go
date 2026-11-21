//go:build linux

package hardware

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/inventory"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// The reading's engine, on Linux: the real inventory over a sysfs tree
// constructed for the test, the real classification, and devices faked at
// the operating system's boundary, where /dev is opened.

// machineTree constructs sysfs for NVMe namespaces of controller nvme0
// ("nvme0n1", "nvme0n2") and SATA disks ("sda"), with a model each.
func machineTree(t *testing.T, files map[string]string, disks ...string) string {
	t.Helper()
	root := t.TempDir()
	for name, s := range files {
		write(t, filepath.Join(root, name), s)
	}
	for _, d := range disks {
		if strings.HasPrefix(d, "nvme") {
			dir := "sys/devices/pci0000:00/0000:00:01.0/nvme/nvme0/" + d
			write(t, filepath.Join(root, dir, "size"), "100\n")
			link(t, filepath.Join(root, "sys/block", d), rel(dir, "sys/block"))
			link(t, filepath.Join(root, dir, "device"), "..")
			if _, err := filepath.EvalSymlinks(filepath.Join(root, "sys/class/nvme/nvme0")); err != nil {
				link(t, filepath.Join(root, "sys/class/nvme/nvme0"), rel("sys/devices/pci0000:00/0000:00:01.0/nvme/nvme0", "sys/class/nvme"))
			}
			continue
		}
		write(t, filepath.Join(root, "sys/block", d, "size"), "100\n")
		write(t, filepath.Join(root, "sys/block", d, "device/model"), "Stand-in "+d+"\n")
	}
	return root
}

// devices fakes /dev: what opening each path gives, and how often it was
// opened.
type devices struct {
	t     *testing.T
	root  string
	mu    sync.Mutex
	nvme  map[string]func() nvmeDevice
	ata   map[string]func(wake bool) (ataDevice, error)
	opens map[string]int
}

func newDevices(t *testing.T, root string) *devices {
	return &devices{t: t, root: root, nvme: map[string]func() nvmeDevice{}, ata: map[string]func(bool) (ataDevice, error){}, opens: map[string]int{}}
}

// platform is this system's, with the devices opened here, and each
// call's deadline shortened to 50 ms.
func (d *devices) platform() *platform {
	p := system
	p.plan = func(root string, disk inventory.ListedDisk) (*failure, target) {
		f, t := planLinux(root, disk)
		t.limit = 50 * time.Millisecond
		return f, t
	}
	p.openNVMe = func(path string) (nvmeDevice, error) {
		name := strings.TrimPrefix(path, d.root+"/dev/")
		d.mu.Lock()
		d.opens[name]++
		f := d.nvme[name]
		d.mu.Unlock()
		if f == nil {
			return nil, driverRefused("not an NVMe controller")
		}
		return f(), nil
	}
	p.openATA = func(path string, wake bool) (ataDevice, error) {
		name := strings.TrimPrefix(path, d.root+"/dev/")
		d.mu.Lock()
		d.opens[name]++
		f := d.ata[name]
		d.mu.Unlock()
		if f == nil {
			return nil, ioError("no such device")
		}
		return f(wake)
	}
	return &p
}

func (d *devices) opened(name string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.opens[name]
}

// clock is the reader's clock, moved by the test.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newReader(root string, devs *devices) (*Reader, *clock) {
	c := &clock{now: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)}
	return &Reader{Inventory: inventory.Collector{Root: root}, sys: devs.platform(), now: c.get, graceFor: 50 * time.Millisecond}, c
}

func healthyNVMe(t *testing.T) func() nvmeDevice {
	return func() nvmeDevice {
		return nvmeDrive(t, healthLogBytes(0, 310, 100, 10, 3, map[int]uint64{128: 1000}), identifyControllerBytes(343))
	}
}

func healthyATA(t *testing.T) func(bool) (ataDevice, error) {
	return func(bool) (ataDevice, error) { return failingDrive(t), nil }
}

func byName(r agentproto.HardwareReport, name string) agentproto.DiskHealth {
	for _, h := range r.Disks {
		if h.Name == name {
			return h
		}
	}
	return agentproto.DiskHealth{}
}

// TestReadNamesDisksAsTheInventory: each disk is named as the inventory
// names it; two namespaces of one controller read it once; each reading
// holds its own attributes.
func TestReadNamesDisksAsTheInventory(t *testing.T) {
	root := machineTree(t, nil, "nvme0n1", "nvme0n2", "sda", "sdb")
	devs := newDevices(t, root)
	devs.nvme["nvme0"] = healthyNVMe(t)
	devs.ata["sda"] = healthyATA(t)
	devs.ata["sdb"] = healthyATA(t)
	r, c := newReader(root, devs)
	report := r.Read(context.Background())
	if len(report.Disks) != 4 {
		t.Fatalf("%+v", report.Disks)
	}
	for _, h := range report.Disks {
		checkHealth(t, h)
		if h.State != agentproto.FactRead || !h.ReadAt.Equal(c.get()) {
			t.Errorf("%s: %s %s %q at %s", h.Name, h.State, h.Reason, h.Detail, h.ReadAt)
		}
	}
	if h := byName(report, "nvme0n2"); h.Route != "fake" || !sameFact(h.Temperature, read(37)) {
		t.Errorf("nvme0n2: %+v", h)
	}
	if h := byName(report, "sdb"); h.Model != "Stand-in sdb" || len(h.Attributes) != 6 {
		t.Errorf("sdb: %+v", h)
	}
	if n := devs.opened("nvme0"); n != 1 {
		t.Errorf("the controller was opened %d times", n)
	}
	byName(report, "sda").Attributes[0].Raw = 99
	if byName(report, "sdb").Attributes[0].Raw == 99 {
		t.Error("two readings share their attributes")
	}
}

// TestReadStuckCall: a call that does not return is given its deadline
// and the grace, while the other disks are read; it is reported timed out,
// and the disk is not asked again while the call is out, nor for the rest
// that follows a timeout.
func TestReadStuckCall(t *testing.T) {
	root := machineTree(t, nil, "sda", "sdb")
	devs := newDevices(t, root)
	release := make(chan struct{})
	var stuck atomic.Bool
	devs.ata["sda"] = func(bool) (ataDevice, error) {
		d := failingDrive(t)
		d.answers[smartReadData] = answer{err: nil}
		return &blockingATA{fakeATA: d, on: smartReadData, release: release, stuck: &stuck}, nil
	}
	devs.ata["sdb"] = healthyATA(t)
	r, c := newReader(root, devs)

	start := time.Now()
	report := r.Read(context.Background())
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("the reading took %s", took)
	}
	if h := byName(report, "sda"); h.State != agentproto.FactUnknown || h.Reason != agentproto.ReasonTimeout {
		t.Errorf("sda: %s %s %q", h.State, h.Reason, h.Detail)
	}
	if h := byName(report, "sdb"); h.State != agentproto.FactRead {
		t.Errorf("sdb: %s %s", h.State, h.Reason)
	}
	if !stuck.Load() {
		t.Fatal("the call did not block")
	}

	// The call is still out: the disk is not opened again.
	report = r.Read(context.Background())
	if h := byName(report, "sda"); h.Reason != agentproto.ReasonTimedOutRecently || devs.opened("sda") != 1 {
		t.Errorf("while out: %s %s, opened %d", h.State, h.Reason, devs.opened("sda"))
	}
	close(release)
	waitFor(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		for k, m := range r.memory {
			if strings.Contains(k, "sda") {
				return !m.out
			}
		}
		return false
	})
	// Returned, but within the 24 hours' rest.
	c.add(23 * time.Hour)
	if h := byName(r.Read(context.Background()), "sda"); h.Reason != agentproto.ReasonTimedOutRecently || devs.opened("sda") != 1 {
		t.Errorf("resting: %s %s, opened %d", h.State, h.Reason, devs.opened("sda"))
	}
	c.add(2 * time.Hour)
	if h := byName(r.Read(context.Background()), "sda"); h.State != agentproto.FactRead || devs.opened("sda") != 2 {
		t.Errorf("after the rest: %s %s %q, opened %d", h.State, h.Reason, h.Detail, devs.opened("sda"))
	}
}

// blockingATA blocks on one command until released, past every deadline.
type blockingATA struct {
	*fakeATA
	on      ataCommand
	release chan struct{}
	stuck   *atomic.Bool
}

func (d *blockingATA) ata(c ataCommand) ([]byte, *ataRegisters, error) {
	if c == d.on {
		d.stuck.Store(true)
		<-d.release
		return nil, nil, ioError("returned at last")
	}
	return d.fakeATA.ata(c)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 500 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting")
}

// TestReadPanic: a parser's panic makes its disk unknown (agent_error);
// the others are read.
func TestReadPanic(t *testing.T) {
	root := machineTree(t, nil, "sda", "sdb")
	devs := newDevices(t, root)
	devs.ata["sda"] = func(bool) (ataDevice, error) {
		return &panickingATA{failingDrive(t)}, nil
	}
	devs.ata["sdb"] = healthyATA(t)
	r, _ := newReader(root, devs)
	report := r.Read(context.Background())
	if h := byName(report, "sda"); h.State != agentproto.FactUnknown || h.Reason != agentproto.ReasonAgentError || !strings.Contains(h.Detail, "parser") {
		t.Errorf("sda: %s %s %q", h.State, h.Reason, h.Detail)
	}
	if h := byName(report, "sdb"); h.State != agentproto.FactRead {
		t.Errorf("sdb: %s %s", h.State, h.Reason)
	}
	// Nothing is left out: the next reading asks again.
	if byName(r.Read(context.Background()), "sda").Reason != agentproto.ReasonAgentError || devs.opened("sda") != 2 {
		t.Error("the disk was not asked again after a panic")
	}
}

type panickingATA struct{ *fakeATA }

func (d *panickingATA) ata(c ataCommand) ([]byte, *ataRegisters, error) {
	if c == smartReadThresholds {
		panic("a parser's bug")
	}
	return d.fakeATA.ata(c)
}

// TestReadAsleep: a sleeping disk is skipped, and read once, waking it,
// after 24 hours of skipping.
func TestReadAsleep(t *testing.T) {
	root := machineTree(t, nil, "sda")
	devs := newDevices(t, root)
	var woken []bool
	devs.ata["sda"] = func(wake bool) (ataDevice, error) {
		woken = append(woken, wake)
		d := failingDrive(t)
		d.answers[ataPowerMode] = answer{regs: registers(0, 0, 0)}
		return d, nil
	}
	r, c := newReader(root, devs)
	for range 3 {
		h := byName(r.Read(context.Background()), "sda")
		if h.State != agentproto.FactUnknown || h.Reason != agentproto.ReasonAsleep || h.Protocol != agentproto.ProtocolATA || h.Route != "fake" {
			t.Errorf("asleep: %+v", h)
		}
		c.add(10 * time.Hour)
	}
	// 30 hours since it was first found asleep.
	if h := byName(r.Read(context.Background()), "sda"); h.State != agentproto.FactRead {
		t.Errorf("woken: %s %s", h.State, h.Reason)
	}
	if want := []bool{false, false, false, true}; !slices.Equal(woken, want) {
		t.Errorf("wake %v, want %v", woken, want)
	}
	// The count starts again.
	c.add(time.Hour)
	if h := byName(r.Read(context.Background()), "sda"); h.Reason != agentproto.ReasonAsleep {
		t.Errorf("asleep again: %s %s", h.State, h.Reason)
	}
}

// TestReadFailures: the classification's verdicts, a container, a virtual
// machine's failed reads and the reasons that keep the route.
func TestReadFailures(t *testing.T) {
	root := machineTree(t, map[string]string{"proc/cpuinfo": "flags\t\t: fpu hypervisor\n"}, "sda", "sdb", "sdc", "vda")
	write(t, filepath.Join(root, "sys/block/sdc/device/model"), "QEMU HARDDISK\n")
	link(t, filepath.Join(root, "sys/block/vda/device/driver"), "../../../bus/virtio/drivers/virtio_blk")
	devs := newDevices(t, root)
	devs.ata["sda"] = func(bool) (ataDevice, error) { return nil, ioError("EIO on open") }
	devs.ata["sdb"] = func(bool) (ataDevice, error) {
		d := failingDrive(t)
		d.answers[ataIdentify] = answer{data: identifyBytes(true, false, false)}
		return d, nil
	}
	r, _ := newReader(root, devs)
	report := r.Read(context.Background())
	for name, want := range map[string][2]string{
		// On a virtual machine a failed read is the hypervisor's.
		"sda": {agentproto.FactUnsupported, agentproto.ReasonVirtualMachine},
		"sdb": {agentproto.FactUnavailable, agentproto.ReasonSMARTOff},
		"sdc": {agentproto.FactUnsupported, agentproto.ReasonVirtualDisk},
		"vda": {agentproto.FactUnsupported, agentproto.ReasonVirtualDisk},
	} {
		h := byName(report, name)
		checkHealth(t, h)
		if h.State != want[0] || h.Reason != want[1] {
			t.Errorf("%s: %s %s %q, want %v", name, h.State, h.Reason, h.Detail, want)
		}
	}
	if h := byName(report, "sda"); !strings.Contains(h.Detail, "EIO on open") || h.Route != "" {
		t.Errorf("sda: %+v", h)
	}
	if h := byName(report, "sdb"); h.Protocol != agentproto.ProtocolATA || h.Route != "fake" {
		t.Errorf("sdb keeps its route: %+v", h)
	}

	container := machineTree(t, map[string]string{".dockerenv": ""}, "sda")
	r, _ = newReader(container, newDevices(t, container))
	if h := byName(r.Read(context.Background()), "sda"); h.State != agentproto.FactUnavailable || h.Reason != agentproto.ReasonContainer {
		t.Errorf("container: %s %s", h.State, h.Reason)
	}
}

// TestReadPaths: a namespace's controllers are tried in order until one
// answers; a failure of all is the first one's; a fatal error stops.
func TestReadPaths(t *testing.T) {
	root := machineTree(t, nil, "nvme0n1")
	devs := newDevices(t, root)
	r, _ := newReader(root, devs)
	tgt := target{key: "k", paths: []string{root + "/dev/nvme1", root + "/dev/nvme0"}, proto: protoNVMe, limit: time.Second}
	devs.nvme["nvme0"] = healthyNVMe(t)
	w := newWatch()
	if h, err := r.readTarget(tgt, false, w); err != nil || h.State != agentproto.FactRead {
		t.Errorf("second path: %v", err)
	}
	devs.nvme["nvme1"] = func() nvmeDevice {
		return &fakeNVMe{t: t, answers: map[nvmeCommand]answer{nvmeHealthLog: {err: ioError("first")}}}
	}
	devs.nvme["nvme0"] = func() nvmeDevice {
		return &fakeNVMe{t: t, answers: map[nvmeCommand]answer{nvmeHealthLog: {err: ioError("second")}}}
	}
	if _, err := r.readTarget(tgt, false, w); asFailure(err).detail != "first" {
		t.Errorf("all failed: %v", err)
	}
	devs.nvme["nvme1"] = func() nvmeDevice {
		return &fakeNVMe{t: t, answers: map[nvmeCommand]answer{nvmeHealthLog: {err: accessDenied("EACCES")}}}
	}
	before := devs.opened("nvme0")
	if _, err := r.readTarget(tgt, false, w); !is(err, agentproto.ReasonAccessDenied) || devs.opened("nvme0") != before {
		t.Errorf("fatal: %v", err)
	}
}

// TestReadEither: Windows' RAID bus, read on any platform: NVMe first, then
// ATA; a refusal of both is the storage driver's, with both errors.
func TestReadEither(t *testing.T) {
	root := t.TempDir()
	devs := newDevices(t, root)
	r, _ := newReader(root, devs)
	tgt := target{key: "k", paths: []string{root + "/dev/sda"}, proto: protoEither, limit: time.Second}
	w := newWatch()
	devs.ata["sda"] = healthyATA(t)
	if h, err := r.readTarget(tgt, false, w); err != nil || h.Protocol != agentproto.ProtocolATA {
		t.Errorf("ATA: %v %+v", err, h.Protocol)
	}
	devs.nvme["sda"] = healthyNVMe(t)
	if h, err := r.readTarget(tgt, false, w); err != nil || h.Protocol != agentproto.ProtocolNVMe {
		t.Errorf("NVMe: %v %+v", err, h.Protocol)
	}
	delete(devs.nvme, "sda")
	devs.ata["sda"] = func(bool) (ataDevice, error) { return nil, driverRefused("ERROR_INVALID_FUNCTION") }
	_, err := r.readTarget(tgt, false, w)
	if f := asFailure(err); f.reason != agentproto.ReasonStorageDriver || f.detail != "NVMe: not an NVMe controller; ATA: ERROR_INVALID_FUNCTION" {
		t.Errorf("both refused: %v", err)
	}
	devs.ata["sda"] = func(bool) (ataDevice, error) { return nil, ioError("EIO") }
	if _, err := r.readTarget(tgt, false, w); !is(err, agentproto.ReasonIOError) {
		t.Errorf("ATA's own error: %v", err)
	}
}

// TestReadEnds: a reading whose context ends returns what it has, and
// forgets the disks it no longer lists.
func TestReadEnds(t *testing.T) {
	root := machineTree(t, nil, "sda")
	devs := newDevices(t, root)
	release := make(chan struct{})
	defer close(release)
	var stuck atomic.Bool
	devs.ata["sda"] = func(bool) (ataDevice, error) {
		return &blockingATA{fakeATA: failingDrive(t), on: ataIdentify, release: release, stuck: &stuck}, nil
	}
	r, _ := newReader(root, devs)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r.graceFor = time.Hour
	if h := byName(r.Read(ctx), "sda"); h.Reason != agentproto.ReasonAgentError || !strings.Contains(h.Detail, "deadline") {
		t.Errorf("ended: %s %s %q", h.State, h.Reason, h.Detail)
	}

	empty := t.TempDir()
	r.Inventory.Root = empty
	r.Read(context.Background())
	r.mu.Lock()
	n := len(r.memory)
	r.mu.Unlock()
	if n != 1 { // sda's call is still out: it is kept until it returns
		t.Errorf("memory of %d disks", n)
	}
}

func TestClip(t *testing.T) {
	long := strings.Repeat("é", 300)
	if got := clip(long); len([]rune(got)) != agentproto.MaxHardwareDetail {
		t.Errorf("%d characters", len([]rune(got)))
	}
	if clip("short") != "short" {
		t.Error("a short detail changed")
	}
}
