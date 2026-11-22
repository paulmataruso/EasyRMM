//go:build windows

package hardware

import (
	"errors"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/agent/inventory"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Windows reads NVMe through IOCTL_STORAGE_QUERY_PROPERTY's
// protocol-specific property on a handle opened with no access rights, and
// ATA through IOCTL_ATA_PASS_THROUGH on one opened for reading and writing
// (ADR-0065, "Reading on Windows"). No driver of EasyRMM's, no WMI.
var system = platform{plan: planWindows, openNVMe: openNVMe, openATA: openATA}

const (
	// ioctlStorageQueryProperty is IOCTL_STORAGE_QUERY_PROPERTY: FILE_ANY_ACCESS
	// in its access bits, so a handle opened with no access rights may ask.
	ioctlStorageQueryProperty = 0x2D1400
	// ioctlATAPassThrough is IOCTL_ATA_PASS_THROUGH: read and write access.
	ioctlATAPassThrough = 0x4D02C

	// nvmeTimeout is how long a query is waited for before it is
	// canceled.
	nvmeTimeout = 60 * time.Second
	// ataTimeout is the port driver's timeout for a pass-through
	// (ataTimeoutSeconds); cancelGrace later the call is canceled.
	ataTimeout  = ataTimeoutSeconds * time.Second
	cancelGrace = 30 * time.Second
)

var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procGetDevicePowerState = kernel32.NewProc("GetDevicePowerState")
	procCancelSynchronousIo = kernel32.NewProc("CancelSynchronousIo")
)

// planWindows reads a disk's bus type and model (planBus); the disk is
// opened as \\.\PhysicalDriveN.
func planWindows(_ string, d inventory.ListedDisk) (*failure, target) {
	f, p := planBus(d.Bus, d.Model)
	if f != nil {
		return f, target{}
	}
	limit := nvmeTimeout
	if p == protoATA {
		limit = ataTimeout
	}
	return nil, target{key: d.Name + "/" + d.Serial, paths: []string{`\\.\` + d.Name}, proto: p, limit: limit}
}

// openFailure says why a disk could not be opened.
func openFailure(err error) *failure {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return accessDenied("opening the disk: %v", err)
	}
	return ioError("opening the disk: %v", err)
}

func open(path string, access, flags uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, ioError("%v", err)
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return windows.InvalidHandle, openFailure(err)
	}
	return h, nil
}

// callError says what a failed DeviceIoControl means: a driver on the way
// that does not take the request, a refused access, a canceled or timed
// out call, or another error.
func callError(what string, err error) *failure {
	var errno windows.Errno
	errors.As(err, &errno)
	switch errno {
	case windows.ERROR_NOT_SUPPORTED, windows.ERROR_INVALID_FUNCTION, windows.ERROR_INVALID_PARAMETER:
		return driverRefused("%s: %v (%d)", what, err, uint32(errno))
	case windows.ERROR_ACCESS_DENIED:
		return accessDenied("%s: %v", what, err)
	case windows.ERROR_OPERATION_ABORTED, windows.ERROR_SEM_TIMEOUT:
		return timedOut("%s: %v", what, err)
	}
	return ioError("%s: %v (%d)", what, err, uint32(errno))
}

// busy is a failure for a disk with a call from an earlier reading still
// out: nothing more is sent to it until that call has returned.
func busy() *failure {
	return fail(agentproto.FactUnknown, agentproto.ReasonTimedOutRecently, "a call from an earlier reading has not returned")
}

// outstanding is an NVMe query canceled after its deadline that had not
// completed: its handle, event and memory, kept until it does.
type outstanding struct {
	path string
	h    windows.Handle
	ev   windows.Handle
	mem  uintptr
	ov   *windows.Overlapped
}

var (
	outMu sync.Mutex
	out   []*outstanding
	// stuck are the disks whose ATA pass-through has not returned.
	stuck = map[string]bool{}
)

// release frees a query's resources once it has completed.
func (o *outstanding) release() {
	_ = windows.CloseHandle(o.ev)
	_ = windows.CloseHandle(o.h)
	_ = windows.VirtualFree(o.mem, 0, windows.MEM_RELEASE)
}

// sweep checks the canceled queries without waiting, frees those that
// completed, and reports whether path still has one out.
func sweep(path string) bool {
	outMu.Lock()
	defer outMu.Unlock()
	still := out[:0]
	pending := stuck[path]
	for _, o := range out {
		var n uint32
		if err := windows.GetOverlappedResult(o.h, o.ov, &n, false); errors.Is(err, windows.ERROR_IO_INCOMPLETE) {
			still = append(still, o)
			pending = pending || o.path == path
			continue
		}
		o.release()
	}
	clear(out[len(still):])
	out = still
	return pending
}

// winNVMe is a disk opened, with no access rights, for NVMe queries.
type winNVMe struct {
	path string
	h    windows.Handle
	// property is the form that answered: the device's, else the
	// adapter's; 0 before the first answer.
	property uint32
	// canceled: a query did not complete, and its handle is kept with it.
	canceled bool
}

func openNVMe(path string) (nvmeDevice, error) {
	if sweep(path) {
		return nil, busy()
	}
	h, err := open(path, 0, windows.FILE_FLAG_OVERLAPPED)
	if err != nil {
		return nil, err
	}
	return &winNVMe{path: path, h: h}, nil
}

func (d *winNVMe) route() string {
	if d.property == propertyAdapterProtocol {
		return "adapter"
	}
	return "device"
}

func (d *winNVMe) close() {
	if !d.canceled {
		_ = windows.CloseHandle(d.h)
	}
}

// nvme asks the device form of the protocol-specific property, as
// Microsoft's example does, and the adapter form only where the device form
// is refused; the form that answered is used for the rest of the reading.
func (d *winNVMe) nvme(c nvmeCommand) ([]byte, error) {
	if err := checkNVMe(c); err != nil {
		return nil, err
	}
	if d.property != 0 {
		return d.query(d.property, c)
	}
	b, err := d.query(propertyDeviceProtocol, c)
	if !is(err, agentproto.ReasonStorageDriver) {
		d.property = propertyDeviceProtocol
		return b, err
	}
	b, err2 := d.query(propertyAdapterProtocol, c)
	if !is(err2, agentproto.ReasonStorageDriver) {
		d.property = propertyAdapterProtocol
		return b, err2
	}
	return nil, driverRefused("device form: %s; adapter form: %s", asFailure(err).detail, asFailure(err2).detail)
}

// query sends one query overlapped, its OVERLAPPED and buffer outside Go's
// heap, and waits nvmeTimeout for it. A query still out then is canceled
// and left with its memory, which a later sweep frees once it completes:
// no goroutine waits on it.
func (d *winNVMe) query(property uint32, c nvmeCommand) ([]byte, error) {
	in := nvmeQuery(property, c)
	ovSize := unsafe.Sizeof(windows.Overlapped{})
	mem, err := windows.VirtualAlloc(0, ovSize+uintptr(len(in)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return nil, ioError("allocating the query: %v", err)
	}
	base := *(*unsafe.Pointer)(unsafe.Pointer(&mem)) // memory the kernel writes to, outside Go's heap
	ov := (*windows.Overlapped)(base)
	buf := unsafe.Slice((*byte)(unsafe.Add(base, ovSize)), len(in))
	copy(buf, in)
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.VirtualFree(mem, 0, windows.MEM_RELEASE)
		return nil, ioError("creating an event: %v", err)
	}
	ov.HEvent = ev
	free := func() {
		_ = windows.CloseHandle(ev)
		_ = windows.VirtualFree(mem, 0, windows.MEM_RELEASE)
	}
	n := uint32(len(buf)) //nolint:gosec // at most 48 + 4,096 bytes
	err = windows.DeviceIoControl(d.h, ioctlStorageQueryProperty, &buf[0], n, &buf[0], n, nil, ov)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		_, _ = windows.WaitForSingleObject(ev, uint32(nvmeTimeout/time.Millisecond))
		err = nil
	}
	if err == nil {
		err = windows.GetOverlappedResult(d.h, ov, &n, false)
	}
	if errors.Is(err, windows.ERROR_IO_INCOMPLETE) {
		_ = windows.CancelIoEx(d.h, ov)
		outMu.Lock()
		out = append(out, &outstanding{path: d.path, h: d.h, ev: ev, mem: mem, ov: ov})
		outMu.Unlock()
		d.canceled = true
		return nil, timedOut("the query did not complete in %s; canceled", nvmeTimeout)
	}
	defer free()
	if err != nil {
		return nil, callError("IOCTL_STORAGE_QUERY_PROPERTY", err)
	}
	return nvmeAnswer(buf, n, c.length)
}

// winATA is a disk opened for reading and writing, for ATA pass-through.
type winATA struct {
	path string
	h    windows.Handle
	// handedOff: a call did not return in time; its goroutine closes the
	// handle when it does.
	handedOff bool
}

// openATA first opens the disk for query only and asks Windows whether it
// is in the working state: a disk that is not is asleep, and is skipped
// unless wake, with no pass-through, since opening it for reading and
// writing can already spin it up.
func openATA(path string, wake bool) (ataDevice, error) {
	if sweep(path) {
		return nil, busy()
	}
	q, err := open(path, 0, 0)
	if err != nil {
		return nil, err
	}
	// on is heap-allocated and pinned for the call, as every buffer the
	// agent hands the kernel is.
	on := new(int32)
	var pin runtime.Pinner
	pin.Pin(on)
	r, _, _ := procGetDevicePowerState.Call(uintptr(q), uintptr(unsafe.Pointer(on)))
	runtime.KeepAlive(on)
	pin.Unpin()
	_ = windows.CloseHandle(q)
	if r != 0 && *on == 0 && !wake {
		return nil, errAsleep
	}
	h, err := open(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0)
	if err != nil {
		return nil, err
	}
	return &winATA{path: path, h: h}, nil
}

func (d *winATA) route() string { return "ata" }

func (d *winATA) close() {
	if !d.handedOff {
		_ = windows.CloseHandle(d.h)
	}
}

// syncCall is one pass-through on a goroutine locked to its thread, so
// that the thread can be told to cancel it.
type syncCall struct {
	mu       sync.Mutex
	thread   windows.Handle
	finished bool
	n        uint32
	err      error
	done     chan struct{}
}

// run sends the pass-through. The goroutine never unlocks its thread, so
// that when it ends Go ends the thread too, and a cancel can never reach a
// thread that has moved on to other work.
func (s *syncCall) run(h windows.Handle, buf []byte, ready chan<- error) {
	runtime.LockOSThread()
	th, err := windows.OpenThread(windows.THREAD_TERMINATE, false, windows.GetCurrentThreadId())
	s.thread = th
	ready <- err
	if err != nil {
		return
	}
	// The buffer, allocated before its address is taken, is pinned for
	// the call: ATA_PASS_THROUGH_EX finds its data by an offset from the
	// buffer's start, never by a pointer, and the call takes the buffer as
	// a pointer the garbage collector sees.
	var pin runtime.Pinner
	pin.Pin(&buf[0])
	n := uint32(len(buf)) //nolint:gosec // at most 48 + 4,096 bytes
	err = windows.DeviceIoControl(h, ioctlATAPassThrough, &buf[0], n, &buf[0], n, &n, nil)
	runtime.KeepAlive(buf)
	pin.Unpin()
	s.mu.Lock()
	s.finished, s.n, s.err = true, n, err
	_ = windows.CloseHandle(th)
	s.mu.Unlock()
	close(s.done)
}

// cancel cancels the call's synchronous I/O, unless it has returned.
func (s *syncCall) cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.finished {
		_, _, _ = procCancelSynchronousIo.Call(uintptr(s.thread))
	}
}

// ata sends one pass-through, synchronous as Microsoft requires, and waits
// for it the port driver's timeout and cancelGrace more; then it cancels
// the call. A call that still does not return keeps its goroutine, which
// closes the handle when it does; the disk is not asked again meanwhile.
func (d *winATA) ata(c ataCommand) ([]byte, *ataRegisters, error) {
	if err := checkATA(c); err != nil {
		return nil, nil, err
	}
	buf := ataPassThrough(c)
	s := &syncCall{done: make(chan struct{})}
	ready := make(chan error, 1)
	go s.run(d.h, buf, ready)
	if err := <-ready; err != nil {
		return nil, nil, ioError("opening the calling thread: %v", err)
	}
	timer := time.NewTimer(ataTimeout + cancelGrace)
	defer timer.Stop()
	select {
	case <-s.done:
	case <-timer.C:
		s.cancel()
		d.handedOff = true
		outMu.Lock()
		stuck[d.path] = true
		outMu.Unlock()
		go func() {
			<-s.done
			_ = windows.CloseHandle(d.h)
			outMu.Lock()
			delete(stuck, d.path)
			outMu.Unlock()
		}()
		return nil, nil, timedOut("ATA pass-through: no answer %s after its timeout; canceled", cancelGrace)
	}
	if s.err != nil {
		return nil, nil, callError("IOCTL_ATA_PASS_THROUGH", s.err)
	}
	return ataAnswer(c, buf, s.n)
}
