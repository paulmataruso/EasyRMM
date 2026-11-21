// Package hardware reads the device's hardware health (ADR-0065). Slice 1
// reads disks: the NVMe health log and ATA SMART, on Linux and Windows,
// through the operating system's storage interfaces and with the agent's
// own code: no WMI, no PowerShell, no smartctl and no library.
//
// The agent judges nothing: it reports what it read, fact by fact, each
// with its state, and why what it did not read was not, and the server
// applies its rules. Only the commands of a fixed list are sent
// (commands.go), each read-only.
package hardware

import (
	"context"
	"log/slog"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/agent/inventory"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// rest is how long a disk that timed out is left alone, and how long a
// sleeping disk is skipped before it is read anyway, waking it.
const rest = 24 * time.Hour

// Reader reads the disks' health. A Reader keeps, between readings, which
// disks timed out and which sleep; one Reader serves the agent.
type Reader struct {
	// Inventory lists the disks, so that each reading names them as the
	// inventory does; on Linux its Root is also where /sys and /dev are.
	Inventory inventory.Collector
	Log       *slog.Logger

	// graceFor is how long past a call's own deadline a reading waits for
	// a disk before it reports the disk timed out; 0 is 30 s. Tests
	// change it.
	graceFor time.Duration

	// now is the reader's clock; nil is the system's.
	now func() time.Time
	// sys tells disks apart and opens them; nil is this system's.
	sys *platform

	mu     sync.Mutex
	memory map[string]*memo
}

// memo is what the reader remembers of a target between readings.
type memo struct {
	// out: a call to the disk has not returned yet; nothing more is sent
	// to it until it has.
	out bool
	// rest: after a timeout, the disk is not asked again before this.
	rest time.Time
	// asleep: when the disk was first found asleep in the skips since its
	// last reading.
	asleep time.Time
	seen   bool
}

func (r *Reader) grace() time.Duration {
	if r.graceFor == 0 {
		return 30 * time.Second
	}
	return r.graceFor
}

func (r *Reader) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// job is one target to read and the inventory's disks it serves.
type job struct {
	t     target
	disks []int
	wake  bool
	m     *memo
}

// Read reads every disk the inventory lists and returns what it read. It
// waits for each disk at most its calls' deadlines plus 30 seconds, and returns
// early, with what it has, when ctx ends.
func (r *Reader) Read(ctx context.Context) agentproto.HardwareReport {
	st := r.Inventory.Storage()
	start := r.clock()
	report := agentproto.HardwareReport{Disks: make([]agentproto.DiskHealth, len(st.Disks))}
	var jobs []*job
	byKey := map[string]*job{}
	for i, d := range st.Disks {
		report.Disks[i] = agentproto.DiskHealth{Name: d.Name, Model: d.Model, Serial: d.Serial, ReadAt: start}
		var f *failure
		var t target
		if st.Virtualization == "container" {
			f = fail(agentproto.FactUnavailable, agentproto.ReasonContainer, "")
		} else {
			f, t = r.platform().plan(r.Inventory.Root, d)
		}
		if f != nil {
			setFailure(&report.Disks[i], f)
			continue
		}
		if j := byKey[t.key]; j != nil {
			j.disks = append(j.disks, i)
			continue
		}
		j := &job{t: t, disks: []int{i}}
		byKey[t.key] = j
		jobs = append(jobs, j)
	}

	r.mu.Lock()
	if r.memory == nil {
		r.memory = map[string]*memo{}
	}
	for _, m := range r.memory {
		m.seen = false
	}
	var due []*job
	for _, j := range jobs {
		m := r.memory[j.t.key]
		if m == nil {
			m = &memo{}
			r.memory[j.t.key] = m
		}
		m.seen, j.m = true, m
		if m.out || start.Before(m.rest) {
			for _, i := range j.disks {
				setFailure(&report.Disks[i], fail(agentproto.FactUnknown, agentproto.ReasonTimedOutRecently, ""))
			}
			continue
		}
		j.wake = !m.asleep.IsZero() && start.Sub(m.asleep) >= rest
		m.out = true
		due = append(due, j)
	}
	r.mu.Unlock()

	var wg sync.WaitGroup
	for _, j := range due {
		wg.Go(func() {
			h, err := r.read(ctx, j)
			r.remember(j, err)
			if err != nil {
				f := asFailure(err)
				if virtualMachine(st.Virtualization) && failedRead[f.reason] {
					f = fail(agentproto.FactUnsupported, agentproto.ReasonVirtualMachine, "%s", f.Error())
				}
				route, proto := h.Route, h.Protocol
				h = agentproto.DiskHealth{}
				if answered[f.reason] {
					h.Route, h.Protocol = route, proto
				}
				setFailure(&h, f)
			}
			h.ReadAt = r.clock()
			for _, i := range j.disks {
				d := st.Disks[i]
				h.Name, h.Model, h.Serial = d.Name, d.Model, d.Serial
				report.Disks[i] = h
				// Each disk has its own copy of the attributes.
				report.Disks[i].Attributes = slices.Clone(h.Attributes)
			}
		})
	}
	wg.Wait()

	r.mu.Lock()
	for k, m := range r.memory {
		if !m.seen && !m.out {
			delete(r.memory, k)
		}
	}
	r.mu.Unlock()
	return report
}

// remember notes what a reading found: a timeout rests the disk, a skip
// while asleep starts or continues the count to the day it is woken, and
// any other answer ends it.
func (r *Reader) remember(j *job, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case is(err, agentproto.ReasonTimeout):
		j.m.rest = r.clock().Add(rest)
	case is(err, agentproto.ReasonAsleep):
		if j.m.asleep.IsZero() {
			j.m.asleep = r.clock()
		}
	case is(err, agentproto.ReasonTimedOutRecently):
	default:
		j.m.asleep = time.Time{}
	}
}

// failedRead are the reasons of a read that failed, which on a virtual
// machine make the disk unsupported (virtual_machine), for hypervisors the
// list of emulated models does not name. A timeout, a refused access, a
// sleeping disk and the agent's own error stay as they are.
var failedRead = map[string]bool{
	agentproto.ReasonIOError: true, agentproto.ReasonBadAnswer: true, agentproto.ReasonBadChecksum: true,
	agentproto.ReasonDeviceRefused: true, agentproto.ReasonStorageDriver: true, agentproto.ReasonProtocolNotRead: true,
}

// answered are the reasons given after the disk answered, which keep the
// protocol and route it answered on.
var answered = map[string]bool{
	agentproto.ReasonAsleep: true, agentproto.ReasonNoSMART: true, agentproto.ReasonSMARTOff: true,
	agentproto.ReasonDeviceRefused: true,
}

// virtualMachine reports whether the inventory names the machine as a
// virtual one.
func virtualMachine(virtualization string) bool {
	return virtualization != "" && virtualization != "container"
}

// setFailure makes h a disk not read, for f's reason. Its facts are left
// out.
func setFailure(h *agentproto.DiskHealth, f *failure) {
	h.State, h.Reason, h.Detail = f.state, f.reason, clip(f.detail)
}

// clip cuts a detail to the report's limit, on a character boundary.
func clip(s string) string {
	r := []rune(s)
	if len(r) > agentproto.MaxHardwareDetail {
		r = r[:agentproto.MaxHardwareDetail]
	}
	return string(r)
}

// result is what a disk's goroutine returns.
type result struct {
	h   agentproto.DiskHealth
	err error
}

// read reads one target on a goroutine of its own, under recover, and
// waits for it at most its calls' deadlines plus 30 seconds. A panic makes the
// disk unknown (agent_error); a disk that does not answer in time is
// reported timed out while its call, still out, keeps the disk from being
// asked again until it returns.
func (r *Reader) read(ctx context.Context, j *job) (agentproto.DiskHealth, error) {
	w := newWatch()
	done := make(chan result, 1)
	go func() {
		var res result
		defer func() {
			if p := recover(); p != nil {
				r.log().Error("reading a disk failed in the agent", "disk", j.t.key, "panic", p, "stack", string(debug.Stack()))
				res = result{err: fail(agentproto.FactUnknown, agentproto.ReasonAgentError, "%v", p)}
			}
			r.mu.Lock()
			j.m.out = false
			r.mu.Unlock()
			done <- res
		}()
		res.h, res.err = r.readTarget(j.t, j.wake, w)
	}()
	return w.wait(ctx, done, r.grace())
}

func (r *Reader) log() *slog.Logger {
	if r.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return r.Log
}

func (r *Reader) platform() *platform {
	if r.sys == nil {
		return &system
	}
	return r.sys
}

// readTarget reads a target through each of its paths until one answers;
// a Windows disk on the RAID bus as NVMe, then as ATA.
func (r *Reader) readTarget(t target, wake bool, w *watch) (agentproto.DiskHealth, error) {
	var first agentproto.DiskHealth
	var firstErr error
	for _, path := range t.paths {
		var h agentproto.DiskHealth
		var err error
		if t.proto == protoEither {
			h, err = r.readEither(t, path, wake, w)
		} else {
			h, err = r.readPath(t, path, t.proto, wake, w)
		}
		if err == nil || fatal(err) || is(err, agentproto.ReasonAsleep) {
			return h, err
		}
		if firstErr == nil {
			first, firstErr = h, err
		}
	}
	return first, firstErr
}

// readEither reads a disk whose bus does not tell its protocol: NVMe
// first, which needs no access rights, then ATA. The first answer decides;
// a refusal of both is the storage driver's, with each error.
func (r *Reader) readEither(t target, path string, wake bool, w *watch) (agentproto.DiskHealth, error) {
	h, err := r.readPath(t, path, protoNVMe, wake, w)
	if !refused(err) {
		return h, err
	}
	h, err2 := r.readPath(t, path, protoATA, wake, w)
	if !refused(err2) {
		return h, err2
	}
	return agentproto.DiskHealth{}, driverRefused("NVMe: %s; ATA: %s", asFailure(err).detail, asFailure(err2).detail)
}

// readPath opens one path for one protocol and reads it. Opening is timed
// as a call: it can block on a disk that does not answer.
func (r *Reader) readPath(t target, path string, p protocol, wake bool, w *watch) (agentproto.DiskHealth, error) {
	sys := r.platform()
	var h agentproto.DiskHealth
	w.begin(t.limit)
	if p == protoNVMe {
		d, err := sys.openNVMe(path)
		w.end()
		if err != nil {
			return h, err
		}
		defer d.close()
		h, err = readNVMe(watchedNVMe{nvmeDevice: d, w: w, limit: t.limit})
		h.Route = d.route()
		return h, err
	}
	d, err := sys.openATA(path, wake)
	w.end()
	if err != nil {
		if is(err, agentproto.ReasonAsleep) {
			h.Protocol = agentproto.ProtocolATA
		}
		return h, err
	}
	defer d.close()
	h, err = readATA(watchedATA{ataDevice: d, w: w, limit: t.limit}, wake)
	h.Route = d.route()
	return h, err
}

// watchedNVMe and watchedATA are devices whose calls the reading's watch
// times.
type watchedNVMe struct {
	nvmeDevice
	w     *watch
	limit time.Duration
}

func (x watchedNVMe) nvme(c nvmeCommand) ([]byte, error) {
	x.w.begin(x.limit)
	defer x.w.end()
	return x.nvmeDevice.nvme(c)
}

type watchedATA struct {
	ataDevice
	w     *watch
	limit time.Duration
}

func (x watchedATA) ata(c ataCommand) ([]byte, *ataRegisters, error) {
	x.w.begin(x.limit)
	defer x.w.end()
	return x.ataDevice.ata(c)
}

// watch times a disk's reading: the call out and its deadline.
type watch struct {
	mu sync.Mutex
	// since is when the call out began, or the last one ended; limit is
	// the call's deadline, 0 between calls.
	since    time.Time
	limit    time.Duration
	progress chan struct{}
}

func newWatch() *watch {
	return &watch{since: time.Now(), progress: make(chan struct{}, 1)}
}

func (w *watch) set(limit time.Duration) {
	w.mu.Lock()
	w.since, w.limit = time.Now(), limit
	w.mu.Unlock()
	select {
	case w.progress <- struct{}{}:
	default:
	}
}

func (w *watch) begin(limit time.Duration) { w.set(limit) }

func (w *watch) end() { w.set(0) }

// deadline is when the disk will have been waited for long enough.
func (w *watch) deadline(grace time.Duration) time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.since.Add(w.limit + grace)
}

// wait returns the reading's result, or a timeout once the call out has
// outlived its deadline plus grace (or, between calls, grace).
func (w *watch) wait(ctx context.Context, done <-chan result, grace time.Duration) (agentproto.DiskHealth, error) {
	for {
		timer := time.NewTimer(time.Until(w.deadline(grace)))
		select {
		case res := <-done:
			timer.Stop()
			return res.h, res.err
		case <-w.progress:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			return agentproto.DiskHealth{}, ctx.Err()
		case <-timer.C:
			if !time.Now().Before(w.deadline(grace)) {
				return agentproto.DiskHealth{}, timedOut("no answer %s after the call's deadline", grace)
			}
		}
	}
}
