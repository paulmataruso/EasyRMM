//go:build windows

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/agent/host"
)

// The tests in this file and in update_windows_test.go change the computer
// they run on: they create a local user, write the agent's real folders
// under ProgramData and Program Files, and install the agent's service.
// They run only where EASYRMM_TEST_MACHINE is set, which CI's Windows
// runner, a computer made for the job, does in a step of its own.

// machineTest skips a test that changes the computer unless it may, and
// fails one that may but is not elevated, or finds the agent installed.
func machineTest(t *testing.T) host.Paths {
	t.Helper()
	if os.Getenv("EASYRMM_TEST_MACHINE") == "" {
		t.Skip("changes this computer; set EASYRMM_TEST_MACHINE on a computer made for the test")
	}
	if !host.IsAdmin() {
		t.Fatal("needs an elevated test")
	}
	p := host.Paths{OS: "windows"}
	for _, dir := range []string{filepath.Dir(p.State()), filepath.Dir(filepath.Dir(p.Binary()))} {
		if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s is there: the test needs a computer without the agent (%v)", dir, err)
		}
	}
	t.Cleanup(func() { removeAgentFolders(t, p) })
	return p
}

// removeAgentFolders deletes the agent's folders, and what a check moved
// aside beside them. RemoveAll deletes a junction, not what it points to.
func removeAgentFolders(t *testing.T, p host.Paths) {
	t.Helper()
	top := filepath.Dir(p.State())
	aside, _ := filepath.Glob(top + ".untrusted-*")
	for _, dir := range append(aside, top, filepath.Dir(filepath.Dir(p.Binary()))) {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("removing %s: %v", dir, err)
		}
	}
}

// asUserFlag makes the test binary the helper that runs as a standard user
// (standardUser.run).
const asUserFlag = "--easyrmm-as-standard-user"

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == asUserFlag {
		os.Exit(asStandardUser(os.Args[2], os.Args[3:]))
	}
	os.Exit(m.Run())
}

// deniedExit is the helper's exit code when Windows denied it access.
const deniedExit = 5

// asStandardUser is the helper: it does what ops say, records how it went
// in the file out, and returns its exit code.
func asStandardUser(out string, ops []string) int {
	err := userOps(ops)
	msg, code := "ok", 0
	if err != nil {
		msg, code = err.Error(), 1
		if errors.Is(err, fs.ErrPermission) {
			code = deniedExit
		}
	}
	_ = os.WriteFile(out, []byte(msg), 0o600)
	return code
}

// userOps does ops in order: "standard" checks that the helper's token is
// not an administrator's; "mkdir DIR" creates DIR and the folders above it;
// "copy FROM TO" copies a file; "junction LINK TARGET" makes a junction, as
// mklink does; "create FILE" creates a file.
func userOps(ops []string) error {
	args := func(n int) ([]string, error) {
		if len(ops) < n+1 {
			return nil, fmt.Errorf("%s takes %d arguments", ops[0], n)
		}
		a := ops[1 : n+1]
		ops = ops[n+1:]
		return a, nil
	}
	for len(ops) > 0 {
		var err error
		switch op := ops[0]; op {
		case "standard":
			ops = ops[1:]
			err = standardToken()
		case "mkdir":
			var a []string
			if a, err = args(1); err == nil {
				err = os.MkdirAll(a[0], 0o755)
			}
		case "copy":
			var a []string
			if a, err = args(2); err == nil {
				var b []byte
				if b, err = os.ReadFile(a[0]); err == nil {
					err = os.WriteFile(a[1], b, 0o644)
				}
			}
		case "junction":
			var a []string
			if a, err = args(2); err == nil {
				var out []byte
				cmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
				if out, err = exec.Command(cmd, "/c", "mklink", "/J", a[0], a[1]).CombinedOutput(); err != nil {
					err = fmt.Errorf("mklink: %w: %s", err, out)
				}
			}
		case "create":
			var a []string
			if a, err = args(1); err == nil {
				err = os.WriteFile(a[0], []byte("written by a standard user"), 0o644)
			}
		default:
			err = fmt.Errorf("unknown operation %q", op)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// standardToken fails when the process runs elevated, or as a member of
// the Administrators group.
func standardToken() error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	// The zero token is the calling thread's, as CheckTokenMembership needs.
	member, err := windows.Token(0).IsMember(admins)
	if err != nil {
		return err
	}
	if member || windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("the helper runs as an administrator")
	}
	return nil
}

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd              = netapi32.NewProc("NetUserAdd")
	procNetUserDel              = netapi32.NewProc("NetUserDel")
	procCreateProcessWithLogonW = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateProcessWithLogonW")
)

// userInfo1 is USER_INFO_1 (lmaccess.h).
type userInfo1 struct {
	name, password    *uint16
	passwordAge, priv uint32
	homeDir, comment  *uint16
	flags             uint32
	scriptPath        *uint16
}

// standardUser is a local account made for a test, a member of Users only,
// and the copy of the test binary it runs as the helper.
type standardUser struct {
	name     string
	password string // never logged
	sid      *windows.SID
	exe      string // the helper, where the user may run it
	work     string // where the helper writes how it went
	runs     int
}

// errDenied is what standardUser.run returns when Windows denied the user.
var errDenied = errors.New("access denied")

// newStandardUser makes a local standard user with a random password, which
// stays in this process's memory, and deletes the account when t ends.
func newStandardUser(t *testing.T) *standardUser {
	t.Helper()
	suffix := make([]byte, 4)
	secret := make([]byte, 24)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	// Upper and lower case, a digit and a symbol, for any complexity policy.
	u := &standardUser{name: "easyrmm-" + hex.EncodeToString(suffix), password: "Aa1!" + base64.RawURLEncoding.EncodeToString(secret)}
	name, err := windows.UTF16PtrFromString(u.name)
	if err != nil {
		t.Fatal(err)
	}
	password, err := windows.UTF16PtrFromString(u.password)
	if err != nil {
		t.Fatal(err)
	}
	const userPrivUser, ufScript, ufDontExpirePasswd = 1, 0x1, 0x10000
	info := userInfo1{name: name, password: password, priv: userPrivUser, flags: ufScript | ufDontExpirePasswd}
	var field uint32
	r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&field)))
	runtime.KeepAlive(&info)
	if r != 0 {
		t.Fatalf("creating a local user: NetUserAdd failed with %d (field %d)", r, field)
	}
	t.Cleanup(func() {
		if r, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(name))); r != 0 {
			t.Errorf("deleting the local user %s: NetUserDel failed with %d", u.name, r)
		}
	})
	if u.sid, _, _, err = windows.LookupSID("", u.name); err != nil {
		t.Fatal(err)
	}

	// The test binary is in the runner's own temporary folder, which users
	// may not read: the helper runs from a copy in a folder they may.
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	u.work = filepath.Join(dir, "work")
	mkdirACL(t, bin, readableByUsers)
	mkdirACL(t, u.work, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)") // Users may change
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	u.exe = filepath.Join(bin, "helper.exe")
	if err := os.WriteFile(u.exe, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := u.run(t, "standard"); err != nil {
		t.Fatalf("the helper as %s: %v", u.name, err)
	}
	return u
}

// readableByUsers lets Users read and run what a folder holds.
const readableByUsers = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

// mkdirACL creates a folder with the access list sddl describes.
func mkdirACL(t *testing.T, p, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	if err := windows.CreateDirectory(name, &sa); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
}

// run runs the helper as the user, logged on as Windows logs on a user who
// signs in at the computer, with ops (userOps). It returns errDenied when
// Windows denied the user access.
func (u *standardUser) run(t *testing.T, ops ...string) error {
	t.Helper()
	u.runs++
	out := filepath.Join(u.work, fmt.Sprintf("run-%d.txt", u.runs))
	line := syscall.EscapeArg(u.exe) + " " + asUserFlag + " " + syscall.EscapeArg(out)
	for _, a := range ops {
		line += " " + syscall.EscapeArg(a)
	}
	cmdline, err := windows.UTF16FromString(line)
	if err != nil {
		t.Fatal(err)
	}
	// The user's own environment, without a profile loaded: only what the
	// helper and cmd need.
	var env []uint16
	for _, kv := range []string{
		"SystemRoot=" + os.Getenv("SystemRoot"), "SystemDrive=" + os.Getenv("SystemDrive"),
		"ProgramData=" + os.Getenv("ProgramData"), "TEMP=" + u.work, "TMP=" + u.work,
		"Path=" + filepath.Join(os.Getenv("SystemRoot"), "System32"),
	} {
		s, err := windows.UTF16FromString(kv)
		if err != nil {
			t.Fatal(err)
		}
		env = append(env, s...)
	}
	env = append(env, 0)
	ptrs := make([]*uint16, 4)
	for i, s := range []string{u.name, ".", u.password, filepath.Dir(u.exe)} {
		if ptrs[i], err = windows.UTF16PtrFromString(s); err != nil {
			t.Fatal(err)
		}
	}
	si := windows.StartupInfo{Flags: windows.STARTF_USESHOWWINDOW, ShowWindow: windows.SW_HIDE}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	const logonFlags = 0 // no profile: the account signs in, its profile is not made
	ok, _, callErr := procCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(ptrs[0])), uintptr(unsafe.Pointer(ptrs[1])), uintptr(unsafe.Pointer(ptrs[2])),
		logonFlags, 0, uintptr(unsafe.Pointer(&cmdline[0])), windows.CREATE_UNICODE_ENVIRONMENT,
		uintptr(unsafe.Pointer(&env[0])), uintptr(unsafe.Pointer(ptrs[3])),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	runtime.KeepAlive(ptrs)
	runtime.KeepAlive(cmdline)
	runtime.KeepAlive(env)
	if ok == 0 {
		t.Fatalf("starting the helper as %s: %v", u.name, callErr)
	}
	defer func() {
		_ = windows.CloseHandle(pi.Thread)
		_ = windows.CloseHandle(pi.Process)
	}()
	if ev, err := windows.WaitForSingleObject(pi.Process, 120_000); err != nil || ev != windows.WAIT_OBJECT_0 {
		t.Fatalf("waiting for the helper: %d, %v", ev, err)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
		t.Fatal(err)
	}
	msg, _ := os.ReadFile(out)
	switch code {
	case 0:
		return nil
	case deniedExit:
		return fmt.Errorf("%w: %s", errDenied, msg)
	}
	return fmt.Errorf("the helper exited with %d: %s", code, msg)
}

// owner returns the SID that owns p, not following a link.
func owner(t *testing.T, p string) *windows.SID {
	t.Helper()
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("opening %s: %v", p, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	o, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// securityOf is p's owner and access list, as SDDL.
func securityOf(t *testing.T, p string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("reading the access list of %s: %v", p, err)
	}
	return sd.String()
}

// untrusted lists what a check moved aside in the agent's folders.
func untrusted(p host.Paths) []string {
	top := filepath.Dir(p.State())
	var all []string
	for _, pattern := range []string{top + ".untrusted-*", filepath.Join(top, "*.untrusted-*")} {
		m, _ := filepath.Glob(pattern)
		all = append(all, m...)
	}
	return all
}
