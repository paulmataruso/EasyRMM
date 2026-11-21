//go:build windows

package host

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

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
//
// Any user may create folders under ProgramData. There, every folder from
// ProgramData down to dir must also be a plain folder (not a link) owned by
// the system, the Administrators group, TrustedInstaller or the account the
// agent runs as. A folder someone else made beforehand is moved aside and
// made anew rather than used: whatever access list we set, its owner could
// change it again, or could hold it open to add files later, and then
// replace the agent's settings and key. Folders are created with their
// access list, so there is no moment when other users can reach them.
func Protect(dir string) error {
	return protect(dir, cmp.Or(os.Getenv("ProgramData"), `C:\ProgramData`))
}

func protect(dir, shared string) error {
	dir, shared = filepath.Clean(dir), filepath.Clean(shared)
	rel, err := filepath.Rel(shared, dir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		// Not below ProgramData: Program Files, where only administrators
		// create folders.
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil { //nolint:gosec // only the last folder is the agent's own
			return err
		}
		if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
			return mkdirProtected(dir)
		}
		return setProtected(dir)
	}
	p := shared
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		p = filepath.Join(p, part)
		if _, _, err := trustedFolder(p, false); err != nil {
			return err
		}
	}
	return nil
}

// checkState makes dir, the agent's state folder below shared (ProgramData),
// safe to read before anything in it is read or written:
//   - every folder from shared down to dir is made a protected folder that
//     only administrators made, as Protect does;
//   - dir's access list must also let no one but the system, the
//     Administrators group and TrustedInstaller change it or what it holds
//     (othersMayChange). Another list that lets no one else in is set back
//     to the protected one; a list that does let someone else in means what
//     dir holds may have been changed in place;
//   - a folder that fails is moved aside, with all it holds, and made anew;
//   - in a folder that passes, the entries named must be plain files with a
//     single link, or plain folders, that a trusted account owns and no one
//     else may change. An entry that fails moves aside with the rest of its
//     group, into a folder beside dir, and is not read.
//
// Entries are checked in order, so a folder must come before the entries
// in it. Nothing else in dir is checked: the agent reads nothing else.
func checkState(dir, shared string, entries [][]string) (StateCheck, error) {
	var c StateCheck
	dir, shared = filepath.Clean(dir), filepath.Clean(shared)
	rel, err := filepath.Rel(shared, dir)
	if err != nil || rel == "." || !filepath.IsLocal(rel) {
		return c, fmt.Errorf("the agent's state folder %s is not below %s", dir, shared)
	}
	// ProgramData is always there; a test's root needs one made.
	if err := os.MkdirAll(shared, 0o755); err != nil { //nolint:gosec // ProgramData, or a test's
		return c, err
	}
	// Protecting a folder above rewrites what dir and its files inherit, so
	// whether others could change them is read first, as it stands. A list
	// that cannot be read counts as letting them.
	others, err := othersMayChangeFolder(dir)
	if errors.Is(err, fs.ErrNotExist) {
		others = false
	} else if err != nil {
		others = true
	}
	p := shared
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		p = filepath.Join(p, part)
		// What was below a folder moved aside went with it, and is made anew.
		moved, reprotected, err := trustedFolder(p, i == len(parts)-1 && others)
		if moved != "" {
			c.Aside = append(c.Aside, moved)
		}
		if reprotected {
			c.Reprotected = append(c.Reprotected, p)
		}
		if err != nil {
			return c, err
		}
	}
	moved, err := trustedEntries(dir, entries)
	c.Aside = append(c.Aside, moved...)
	return c, err
}

// trustedFolder makes p a protected folder that only administrators made,
// creating it, or replacing one that someone else made. A folder of theirs
// with another access list gets the protected one, unless others could
// change it: then it is replaced too. It returns where it moved a folder it
// replaced, and whether it set a folder's access list back.
func trustedFolder(p string, others bool) (aside string, reprotected bool, err error) {
	fi, err := os.Lstat(p) //nolint:gosec // below ProgramData, from the system's environment
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, mkdirProtected(p)
	}
	if err != nil {
		return "", false, err
	}
	if plainFolder(fi) {
		ok, err := trustedOwner(p)
		if err != nil {
			return "", false, err
		}
		if ok {
			// Setting an access list rewrites the lists of everything below,
			// so a folder that has the protected one keeps it as it is.
			protected, err := protectedACL(p)
			if err != nil || protected {
				return "", false, err
			}
			if !others {
				if err := setProtected(p); err != nil {
					return "", false, err
				}
				return "", true, nil
			}
		}
	}
	aside = fmt.Sprintf("%s.untrusted-%d", p, time.Now().UnixNano())
	if err := os.Rename(p, aside); err != nil { //nolint:gosec // below ProgramData, from the system's environment
		return "", false, fmt.Errorf("%s was not made by an administrator, or others could change it, so the agent will not use it, and moving it aside failed: %w; delete it and try again", p, err)
	}
	return aside, false, mkdirProtected(p)
}

// trustedEntries checks the entries of dir that entries name (checkState),
// and moves aside each group with an entry that fails.
func trustedEntries(dir string, entries [][]string) ([]string, error) {
	var aside []string
	away := "" // the folder beside dir that what fails moves to
	for _, group := range entries {
		var found []string
		ok := true
		for _, name := range group {
			matches, err := match(dir, name)
			if err != nil {
				return aside, err
			}
			for _, m := range matches {
				good, err := trustedEntry(m)
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				if err != nil {
					return aside, err
				}
				found, ok = append(found, m), ok && good
			}
		}
		if ok {
			continue
		}
		if away == "" {
			away = fmt.Sprintf("%s.untrusted-%d", dir, time.Now().UnixNano())
			if err := mkdirProtected(away); err != nil {
				return aside, err
			}
		}
		for _, m := range found {
			rel, err := filepath.Rel(dir, m)
			if err != nil {
				return aside, err
			}
			to := filepath.Join(away, rel)
			if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
				return aside, err
			}
			if err := os.Rename(m, to); err != nil {
				return aside, fmt.Errorf("the agent cannot trust %s, and moving it aside failed: %w; delete it and try again", m, err)
			}
			aside = append(aside, to)
		}
	}
	return aside, nil
}

// match lists what name, relative to dir, names. Only its last element may
// be a pattern; its folder is read as it is, so it must have been checked.
func match(dir, name string) ([]string, error) {
	folder, pattern := filepath.Split(filepath.Join(dir, name))
	folder = filepath.Clean(folder)
	if !strings.ContainsAny(pattern, `*?[`) {
		return []string{filepath.Join(folder, pattern)}, nil
	}
	list, err := os.ReadDir(folder)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range list {
		if ok, err := filepath.Match(pattern, e.Name()); err != nil {
			return nil, err
		} else if ok {
			out = append(out, filepath.Join(folder, e.Name()))
		}
	}
	return out, nil
}

// trustedEntry reports whether p is a plain file with a single link, or a
// plain folder, that a trusted account owns and no one else may change
// (othersMayChange). It looks at p itself, never through a link. What it
// may not look at is not trusted: only its owner can have kept the system
// and administrators out.
func trustedEntry(p string) (bool, error) {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return false, err
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return false, nil
	}
	if err != nil {
		return false, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return false, &fs.PathError{Op: "stat", Path: p, Err: err}
	}
	folder := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || !folder && info.NumberOfLinks != 1 {
		return false, nil
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, &fs.PathError{Op: "read the owner and access list of", Path: p, Err: err}
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !trusted(owner) {
		return false, err
	}
	others, err := othersMayChange(sd, folder)
	if err != nil {
		return false, &fs.PathError{Op: "read the access list of", Path: p, Err: err}
	}
	return !others, nil
}

// plainFolder reports whether fi is a folder and not a link, junction or
// other reparse point.
func plainFolder(fi fs.FileInfo) bool {
	if fi.Mode().Type() != fs.ModeDir {
		return false
	}
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

// trustedOwner reports whether p's owner is trusted.
func trustedOwner(p string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false, err
	}
	return trusted(owner), nil
}

// trusted reports whether owner is the system, the Administrators group,
// TrustedInstaller, or the account the agent runs as. What an elevated
// administrator creates, files and folders alike, belongs to the
// Administrators group: Windows makes it the default owner of an elevated
// administrator's token. (The "Default owner for objects created by members
// of the Administrators group" policy that could make it the administrator's
// own account is ignored since Windows Vista, KB 947721.) What the agent's
// service creates belongs to the system or to the Administrators group.
func trusted(owner *windows.SID) bool {
	if slices.Contains(administration, owner.String()) {
		return true
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && owner.Equals(u.User.Sid)
}

// protectedACL reports whether p's access list is the protected one: not
// inherited, full control for SYSTEM and Administrators, and nothing for
// anyone else, in any order.
func protectedACL(p string) (bool, error) {
	got, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	want, err := windows.SecurityDescriptorFromString(protectedDACL)
	if err != nil {
		return false, err
	}
	control, _, err := got.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false, err
	}
	a, ok, err := accessList(got)
	if err != nil || !ok {
		return false, err
	}
	b, _, err := accessList(want)
	return err == nil && sameEntries(a, b), err
}

// othersMayChangeFolder reports whether the folder p's access list lets
// anyone but the administration change it, or what it holds
// (othersMayChange).
func othersMayChangeFolder(p string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	return othersMayChange(sd, true)
}

// othersMayChange reports whether sd's access list lets anyone but the
// system, the Administrators group and TrustedInstaller change what it
// protects (othersMayWrite), folder telling whether that is a folder. A
// missing access list lets everyone.
func othersMayChange(sd *windows.SECURITY_DESCRIPTOR, folder bool) (bool, error) {
	acl, ok, err := accessList(sd)
	if err != nil {
		return false, err
	}
	return !ok || othersMayWrite(acl, folder), nil
}

// accessList reads the entries of sd's access list. ok is false when it
// has none at all, which lets everyone do everything; an empty one lets no
// one do anything.
func accessList(sd *windows.SECURITY_DESCRIPTOR) (acl []aclEntry, ok bool, err error) {
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return nil, false, nil
	}
	if err != nil || dacl == nil {
		return nil, false, err
	}
	acl = []aclEntry{}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, false, err
		}
		e := aclEntry{kind: ace.Header.AceType, flags: ace.Header.AceFlags, mask: uint32(ace.Mask)}
		switch e.kind {
		case aceAllowed, aceDenied, aceAllowedCallback, aceDeniedCallback:
			// These keep the SID they name at SidStart; the object kinds
			// keep theirs after the objects' GUIDs.
			e.who = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		}
		acl = append(acl, e)
	}
	return acl, true, nil
}

// mkdirProtected creates a folder with the protected access list from the
// start.
func mkdirProtected(p string) error {
	sd, err := windows.SecurityDescriptorFromString(protectedDACL)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa)) //nolint:gosec // a small struct's size
	if err := windows.CreateDirectory(name, &sa); err != nil {
		return &fs.PathError{Op: "mkdir", Path: p, Err: err}
	}
	return nil
}

// setProtected replaces an existing folder's access list.
func setProtected(p string) error {
	sd, err := windows.SecurityDescriptorFromString(protectedDACL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
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
