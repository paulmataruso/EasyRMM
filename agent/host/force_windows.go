//go:build windows

package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// exitWait is how long a terminated process may take to be gone.
const exitWait = 10 * time.Second

// StopImage terminates every process that runs the program at image and
// waits for each to exit. The match is on the whole path, case-insensitive,
// never on the name: another vendor's program of the same name elsewhere is
// left alone. It returns what it terminated, as "name (pid N)".
func StopImage(image string) ([]string, error) {
	want := filepath.Clean(image)
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("listing processes: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	var pids []uint32
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err := windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID != 0 && int(e.ProcessID) != os.Getpid() {
			pids = append(pids, e.ProcessID)
		}
	}
	var done []string
	var errs []error
	for _, pid := range pids {
		got, ok := imagePath(pid)
		if !ok || !strings.EqualFold(filepath.Clean(got), want) {
			continue
		}
		if err := terminate(pid); err != nil {
			errs = append(errs, fmt.Errorf("terminating %s (pid %d): %w", filepath.Base(got), pid, err))
			continue
		}
		done = append(done, fmt.Sprintf("%s (pid %d)", filepath.Base(got), pid))
	}
	return done, errors.Join(errs...)
}

// imagePath is the full path of the program a process runs.
func imagePath(pid uint32) (string, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	n := uint32(windows.MAX_LONG_PATH)
	buf := make([]uint16, n)
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", false
	}
	return windows.UTF16ToString(buf[:n]), true
}

// terminate ends a process and waits for it to be gone. A process that has
// already exited counts as ended.
func terminate(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil // gone already
		}
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	// Access denied also means the process is already exiting: the wait
	// decides.
	if err := windows.TerminateProcess(h, 1); err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return err
	}
	ev, err := windows.WaitForSingleObject(h, uint32(exitWait/time.Millisecond))
	if err != nil {
		return err
	}
	if ev != windows.WAIT_OBJECT_0 {
		return errors.New("it did not exit")
	}
	return nil
}

// ForceStop stops a service that did not answer its stop request: it
// terminates the service's process, then every process that runs image (a
// service's helpers run from the same program), and waits until the service
// reports STOPPED. It returns what it terminated.
func (WindowsServices) ForceStop(ctx context.Context, name, image string) ([]string, error) {
	m, err := connect()
	if err != nil {
		return nil, err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(name)
	if err != nil {
		return nil, fmt.Errorf("opening the %s service: %w", name, err)
	}
	defer func() { _ = s.Close() }()
	st, err := s.Query()
	if err != nil {
		return nil, err
	}
	var done []string
	var errs []error
	if st.State != svc.Stopped && st.ProcessId != 0 && int(st.ProcessId) != os.Getpid() {
		if err := terminate(st.ProcessId); err != nil {
			errs = append(errs, fmt.Errorf("terminating the service's process (pid %d): %w", st.ProcessId, err))
		} else {
			done = append(done, fmt.Sprintf("the service's process (pid %d)", st.ProcessId))
		}
	}
	more, err := StopImage(image)
	done = append(done, more...)
	if err != nil {
		errs = append(errs, err)
	}
	if err := waitStopped(ctx, s); err != nil {
		errs = append(errs, err)
	}
	return done, errors.Join(errs...)
}

// waitStopped waits up to 30 seconds for the service to report STOPPED.
func waitStopped(ctx context.Context, s *mgr.Service) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("the service does not report STOPPED after its processes were terminated")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
