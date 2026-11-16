//go:build windows

package host

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func systemDescription() string {
	v, err := WindowsVersion()
	if err != nil {
		return "Windows"
	}
	return v.Name
}

// WindowsInfo is the Windows release, from the registry.
type WindowsInfo struct {
	// Name is the release as people know it: Windows 11 Pro 23H2.
	Name string
	// Version is major.minor.build: 10.0.22631.
	Version string
	// Build is the build with its update revision: 22631.4460.
	Build string
	// Server is true on Windows Server.
	Server bool
}

// WindowsVersion reads the Windows release from the registry.
func WindowsVersion() (WindowsInfo, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return WindowsInfo{}, err
	}
	defer func() { _ = k.Close() }()
	str := func(name string) string {
		v, _, _ := k.GetStringValue(name)
		return v
	}
	num := func(name string) (uint64, bool) {
		v, _, err := k.GetIntegerValue(name)
		return v, err == nil
	}
	build, _ := strconv.Atoi(str("CurrentBuildNumber"))
	display := str("DisplayVersion")
	if display == "" {
		display = str("ReleaseId")
	}
	major, ok := num("CurrentMajorVersionNumber")
	minor, _ := num("CurrentMinorVersionNumber")
	version := str("CurrentVersion") // 6.3 before Windows 10
	if ok {
		version = fmt.Sprintf("%d.%d", major, minor)
	}
	info := WindowsInfo{
		Name:    WindowsName(str("ProductName"), display, build),
		Version: fmt.Sprintf("%s.%d", version, build),
		Build:   strconv.Itoa(build),
		Server:  str("InstallationType") == "Server",
	}
	if ubr, ok := num("UBR"); ok {
		info.Build += "." + strconv.FormatUint(ubr, 10)
	}
	return info, nil
}

// IsAdmin reports whether the agent runs elevated, as an administrator or
// as the system.
func IsAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// ServicesAvailable reports whether the agent can install itself as a
// service; Windows always can.
func ServicesAvailable() bool { return true }

// SystemServices returns the Windows service manager.
func SystemServices(Paths) Services { return WindowsServices{} }

// protectedDACL grants full control to SYSTEM and Administrators only, for
// everything below, and drops what the parent grants: ProgramData and
// Program Files let every user read.
const protectedDACL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// Protect creates dir if needed and makes it reachable by SYSTEM and
// Administrators only.
func Protect(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(protectedDACL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// RemoveExecutable deletes an installed program. A running program cannot
// be deleted on Windows: it is then deleted at the next restart, and later
// is true.
func RemoveExecutable(path string) (later bool, err error) {
	err = os.Remove(path)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	p, perr := windows.UTF16PtrFromString(path)
	if perr != nil {
		return false, err
	}
	if merr := windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); merr != nil {
		return false, fmt.Errorf("%w; scheduling its removal at restart failed too: %w", err, merr)
	}
	return true, nil
}

// replaceFile moves src over dst. A running program cannot be overwritten
// on Windows, but it can be renamed: the old one moves aside and is deleted
// once it no longer runs.
func replaceFile(src, dst string) error {
	if _, err := os.Stat(dst); err != nil {
		return os.Rename(src, dst)
	}
	old := dst + ".old"
	if err := os.Remove(old); err != nil && !errors.Is(err, fs.ErrNotExist) {
		old = fmt.Sprintf("%s.old-%d", dst, time.Now().UnixNano())
	}
	if err := os.Rename(dst, old); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		_ = os.Rename(old, dst)
		return err
	}
	_, _ = RemoveExecutable(old)
	return nil
}

// WindowsServices installs and removes Windows services. Services run as
// LocalSystem, start at boot and are restarted by Windows when they fail.
type WindowsServices struct{}

func connect() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("connecting to the Windows service manager: %w", err)
	}
	return m, nil
}

// commandLine quotes a service's program and arguments as mgr.CreateService
// does.
func commandLine(binary string, args []string) string {
	s := syscall.EscapeArg(binary)
	for _, a := range args {
		s += " " + syscall.EscapeArg(a)
	}
	return s
}

// Install creates or updates the service and starts it unless it runs.
func (WindowsServices) Install(_ context.Context, s Service) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	service, err := m.OpenService(s.Name)
	if err != nil {
		service, err = m.CreateService(s.Name, s.Binary, mgr.Config{
			DisplayName:  s.DisplayName,
			Description:  s.Description,
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		}, s.Args...)
		if err != nil {
			return fmt.Errorf("creating the %s service: %w", s.Name, err)
		}
	} else {
		cfg, err := service.Config()
		if err != nil {
			_ = service.Close()
			return fmt.Errorf("reading the %s service: %w", s.Name, err)
		}
		cfg.BinaryPathName = commandLine(s.Binary, s.Args)
		cfg.DisplayName, cfg.Description, cfg.StartType = s.DisplayName, s.Description, mgr.StartAutomatic
		if err := service.UpdateConfig(cfg); err != nil {
			_ = service.Close()
			return fmt.Errorf("updating the %s service: %w", s.Name, err)
		}
	}
	defer func() { _ = service.Close() }()
	delay := max(s.RestartDelay, time.Second)
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: delay}
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, uint32((24 * time.Hour).Seconds())); err != nil {
		return fmt.Errorf("setting the %s service's recovery: %w", s.Name, err)
	}
	// An exit with an error code counts as a failure too, not only a crash.
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("setting the %s service's recovery: %w", s.Name, err)
	}
	st, err := service.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		if err := service.Start(); err != nil {
			return fmt.Errorf("starting the %s service: %w", s.Name, err)
		}
	}
	return nil
}

// stopService stops a service and waits up to 30 seconds for it.
func stopService(ctx context.Context, s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return err
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if st, err = s.Query(); err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.New("the service did not stop within 30 seconds")
}

// Restart stops a service if it runs, then starts it.
func (WindowsServices) Restart(ctx context.Context, name string) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("opening the %s service: %w", name, err)
	}
	defer func() { _ = s.Close() }()
	if err := stopService(ctx, s); err != nil {
		return fmt.Errorf("stopping the %s service: %w", name, err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("starting the %s service: %w", name, err)
	}
	return nil
}

// Remove stops and deletes a service.
func (WindowsServices) Remove(ctx context.Context, name string) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opening the %s service: %w", name, err)
	}
	defer func() { _ = s.Close() }()
	stopErr := stopService(ctx, s)
	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("deleting the %s service: %w", name, err)
	}
	if stopErr != nil {
		return fmt.Errorf("the %s service was deleted but did not stop: %w", name, stopErr)
	}
	return nil
}

// State is the service's state: running, stopped, starting, stopping,
// paused, or "not installed".
func (WindowsServices) State(_ context.Context, name string) string {
	m, err := connect()
	if err != nil {
		return "unknown"
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return "not installed"
	}
	if err != nil {
		return "unknown"
	}
	defer func() { _ = s.Close() }()
	st, err := s.Query()
	if err != nil {
		return "unknown"
	}
	switch st.State {
	case svc.Running:
		return "running"
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Paused, svc.PausePending, svc.ContinuePending:
		return "paused"
	}
	return "unknown"
}
