package hardware

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/inventory"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// The machine test reads the disks of the machine it runs on, as root or
// an administrator. It runs only when asked: on CI's Windows runners
// (.github/workflows/backend-tests.yml) and inside the machines of the vm
// test (vm_test.go), which reads its results.
const (
	// machineEnv set to 1 runs the test.
	machineEnv = "EASYRMM_TEST_HARDWARE"
	// machineOutEnv names a file that receives the readings as JSON
	// (machineResult).
	machineOutEnv = "EASYRMM_TEST_HARDWARE_OUT"
	// captureEnv names a directory that receives each answer's bytes, one
	// file per path and command: how the QEMU captures in testdata were
	// made.
	captureEnv = "EASYRMM_TEST_HARDWARE_CAPTURE"
)

// callDeadline is the longest any call may take: Windows' ATA
// pass-through, its 60-second timeout and the 30 seconds before it is
// canceled. Every other call's deadline is 60 seconds.
const callDeadline = 90 * time.Second

// machineResult is what the machine test read.
type machineResult struct {
	// Disks are the inventory's.
	Disks []inventory.ListedDisk `json:"disks"`
	// Report is the agent's reading.
	Report agentproto.HardwareReport `json:"report"`
	// Probe is every disk read through the transports with the
	// classification bypassed: NVMe, then ATA.
	Probe agentproto.HardwareReport `json:"probe"`
}

// TestMachine reads this machine's disks twice: as the agent does, and as
// a probe that asks every disk through the transports whatever it is, so
// that a classification that skipped everything cannot pass. It fails
// unless at least one disk was read through an IOCTL or refused by its
// driver with the refusal recorded; it checks the report's invariants and
// that no call outlived its deadline, and prints each disk.
func TestMachine(t *testing.T) {
	if os.Getenv(machineEnv) != "1" {
		t.Skipf("set %s=1 to read this machine's disks (as root or an administrator)", machineEnv)
	}
	inv := inventory.Collector{}
	st := inv.Storage()
	for _, d := range st.Disks {
		t.Logf("disk %s: bus %d, model %q, controllers %v, firmware %+v", d.Name, d.Bus, d.Model, d.Controllers, d.Firmware)
	}
	calls := &callLog{capture: os.Getenv(captureEnv)}
	sys := calls.wrap(system)
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	start := time.Now()
	res := machineResult{Disks: st.Disks}
	res.Report = (&Reader{Inventory: inv, Log: log, sys: &sys}).Read(t.Context())
	probe := sys
	probe.plan = probePlan
	res.Probe = (&Reader{Inventory: inv, Log: log, sys: &probe}).Read(t.Context())
	t.Logf("both readings took %s", time.Since(start).Round(time.Millisecond))

	answered := 0
	for i, h := range res.Report.Disks {
		p := res.Probe.Disks[i]
		t.Logf("%s (bus %d, %q): %s %s %s %q; probe: %s %s %s %s %q", h.Name, st.Disks[i].Bus, h.Model,
			h.State, h.Reason, h.Route, h.Detail, p.State, p.Reason, p.Protocol, p.Route, p.Detail)
		checkHealth(t, h)
		checkHealth(t, p)
		if p.State == agentproto.FactRead || (refusedReason[p.Reason] && p.Detail != "") {
			answered++
		}
	}
	if answered == 0 {
		t.Errorf("no disk was read through an IOCTL or refused by its driver with the refusal recorded")
	}
	calls.check(t)
	if out := os.Getenv(machineOutEnv); out != "" {
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// refusedReason are a driver's or a device's refusal.
var refusedReason = map[string]bool{
	agentproto.ReasonStorageDriver: true, agentproto.ReasonDeviceRefused: true, agentproto.ReasonProtocolNotRead: true,
}

// probePlan reads every disk, NVMe first and then ATA: on Linux through
// its NVMe controllers or its block device, on Windows through
// \\.\PhysicalDriveN.
func probePlan(root string, d inventory.ListedDisk) (*failure, target) {
	t := target{key: "probe " + d.Name, proto: protoEither, limit: time.Minute}
	switch {
	case runtime.GOOS == "windows":
		t.paths = []string{`\\.\` + d.Name}
	case len(d.Controllers) > 0:
		for _, c := range d.Controllers {
			t.paths = append(t.paths, filepath.Join(root, "/dev", c))
		}
	default:
		t.paths = []string{filepath.Join(root, "/dev", d.Name)}
	}
	return nil, t
}

// checkHealth checks a reading's invariants: a disk read has its protocol
// and route and every fact a state, each read fact a value and every other
// a reason; a disk not read has a known reason and no facts.
func checkHealth(t *testing.T, h agentproto.DiskHealth) {
	t.Helper()
	if h.Name == "" || h.ReadAt.IsZero() {
		t.Errorf("%+v: no name or time", h)
	}
	v := reflect.ValueOf(h)
	for i := range v.NumField() {
		f, ok := v.Field(i).Interface().(agentproto.Fact)
		if !ok {
			continue
		}
		name := v.Type().Field(i).Name
		switch {
		case h.State != agentproto.FactRead && f != (agentproto.Fact{}):
			t.Errorf("%s, not read (%s): fact %s = %+v", h.Name, h.Reason, name, f)
		case h.State != agentproto.FactRead:
		case f.State == agentproto.FactRead && (f.Value == nil || f.Reason != ""):
			t.Errorf("%s: fact %s read without a value: %+v", h.Name, name, f)
		case f.State != agentproto.FactRead && (f.Value != nil || !agentproto.KnownReason(f.Reason) || f.State == ""):
			t.Errorf("%s: fact %s %+v", h.Name, name, f)
		}
	}
	switch {
	case h.State == agentproto.FactRead:
		if h.Reason != "" || h.Protocol == "" || h.Route == "" {
			t.Errorf("%s read: reason %q, protocol %q, route %q", h.Name, h.Reason, h.Protocol, h.Route)
		}
	case !agentproto.KnownReason(h.Reason) || (h.State != agentproto.FactUnknown && h.State != agentproto.FactUnsupported && h.State != agentproto.FactUnavailable):
		t.Errorf("%s: state %q, reason %q", h.Name, h.State, h.Reason)
	case len(h.Attributes) != 0:
		t.Errorf("%s not read, with attributes", h.Name)
	}
	if len([]rune(h.Detail)) > agentproto.MaxHardwareDetail {
		t.Errorf("%s: detail of %d characters", h.Name, len([]rune(h.Detail)))
	}
}

// callLog times every call the transports make, and keeps each answer's
// bytes in capture when set.
type callLog struct {
	capture string
	mu      sync.Mutex
	calls   []call
}

type call struct {
	path, command string
	took          time.Duration
	err           error
}

func (l *callLog) add(path, command string, took time.Duration, data []byte, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, call{path: path, command: command, took: took, err: err})
	if l.capture != "" && err == nil && data != nil {
		name := unsafeName.ReplaceAllString(path+" "+command, "_") + ".bin"
		_ = os.WriteFile(filepath.Join(l.capture, name), data, 0o600)
	}
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9.]+`)

func (l *callLog) check(t *testing.T) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var longest time.Duration
	for _, c := range l.calls {
		longest = max(longest, c.took)
		if c.took > callDeadline {
			t.Errorf("%s %s took %s, past every call's deadline", c.path, c.command, c.took)
		}
	}
	t.Logf("%d calls, the longest %s", len(l.calls), longest.Round(time.Millisecond))
}

// wrap times the calls of a platform's devices.
func (l *callLog) wrap(p platform) platform {
	open, openA := p.openNVMe, p.openATA
	p.openNVMe = func(path string) (nvmeDevice, error) {
		d, err := open(path)
		if err != nil {
			return nil, err
		}
		return loggedNVMe{nvmeDevice: d, path: path, log: l}, nil
	}
	p.openATA = func(path string, wake bool) (ataDevice, error) {
		d, err := openA(path, wake)
		if err != nil {
			return nil, err
		}
		return loggedATA{ataDevice: d, path: path, log: l}, nil
	}
	return p
}

type loggedNVMe struct {
	nvmeDevice
	path string
	log  *callLog
}

func (d loggedNVMe) nvme(c nvmeCommand) ([]byte, error) {
	start := time.Now()
	b, err := d.nvmeDevice.nvme(c)
	d.log.add(d.path, nvmeNames[c], time.Since(start), b, err)
	return b, err
}

type loggedATA struct {
	ataDevice
	path string
	log  *callLog
}

func (d loggedATA) ata(c ataCommand) ([]byte, *ataRegisters, error) {
	start := time.Now()
	b, r, err := d.ataDevice.ata(c)
	data := b
	if r != nil {
		data = fmt.Appendf(nil, "error %02X count %02X lba %02X %02X %02X device %02X status %02X\n",
			r.err, r.count, r.lbaLow, r.lbaMid, r.lbaHigh, r.device, r.status)
	}
	d.log.add(d.path, ataNames[c], time.Since(start), data, err)
	return b, r, err
}
