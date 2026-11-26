//go:build windows

package registry

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/registryrules"
)

// The Windows backend. Keys are opened one name at a time with
// REG_OPTION_OPEN_LINK, so Windows never follows a link for the builtin, and
// the kernel's name of every key is asked for with NtQueryKey. Nothing is
// enabled in the process's token: the backup and restore privileges stay
// off, so Windows' permissions hold.

const (
	optionOpenLink = 0x00000008 // REG_OPTION_OPEN_LINK
	wow64Key       = 0x0100     // KEY_WOW64_64KEY
	wow32Key       = 0x0200     // KEY_WOW64_32KEY
	access         = windows.KEY_QUERY_VALUE | windows.KEY_ENUMERATE_SUB_KEYS
	keyNameInfo    = 3 // KeyNameInformation
)

var (
	ntdll          = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryKey = ntdll.NewProc("NtQueryKey")
)

type winBackend struct{ arch string }

// NewBackend is the registry of this machine, read by a process of the
// machine's own architecture: an emulated or 32-bit process would see other
// views.
func NewBackend() (Backend, error) {
	var process, native uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &process, &native); err != nil {
		return nil, fmt.Errorf("asking which architecture this process runs as: %w", err)
	}
	if process != 0 {
		return nil, errors.New("this process is emulated or 32-bit, and would read another view of the registry; the agent must run as the machine's own architecture")
	}
	switch native {
	case 0x8664:
		return &winBackend{arch: agentproto.ArchX64}, nil
	case 0xAA64:
		return &winBackend{arch: agentproto.ArchARM64}, nil
	}
	return nil, fmt.Errorf("the machine's architecture (%#x) is not one the registry editor reads", native)
}

func (b *winBackend) Arch() string { return b.arch }

func viewFlag(v registryrules.View) uint32 {
	if v == registryrules.View32 {
		return wow32Key
	}
	return wow64Key
}

func errOf(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return ErrDenied
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return ErrNotFound
	}
	return err
}

type winKey struct {
	h      windows.Handle
	view   registryrules.View
	kernel string
	link   *string
	linked bool
}

func (b *winBackend) Root(h registryrules.Hive, v registryrules.View) (Key, error) {
	var root windows.Handle
	switch h {
	case registryrules.HKLM:
		root = windows.HKEY_LOCAL_MACHINE
	case registryrules.HKU:
		root = windows.HKEY_USERS
	default:
		return nil, fmt.Errorf("hive %s is not a root", h)
	}
	var out windows.Handle
	if err := windows.RegOpenKeyEx(root, nil, optionOpenLink, access|viewFlag(v), &out); err != nil {
		return nil, errOf(err)
	}
	return &winKey{h: out, view: v}, nil
}

func (k *winKey) Close() { _ = windows.RegCloseKey(k.h) }

func (k *winKey) OpenChild(name string) (Key, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, ErrNotFound // a name with a NUL is not one Windows has
	}
	var out windows.Handle
	if err := windows.RegOpenKeyEx(k.h, p, optionOpenLink, access|viewFlag(k.view), &out); err != nil {
		return nil, errOf(err)
	}
	return &winKey{h: out, view: k.view}, nil
}

// Kernel is the kernel's name of the key (NtQueryKey, KeyNameInformation).
func (k *winKey) Kernel() string {
	if k.kernel != "" {
		return k.kernel
	}
	buf := make([]byte, 1024)
	for range 4 {
		var n uint32
		r, _, _ := procNtQueryKey.Call(uintptr(k.h), keyNameInfo, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)))
		switch uint32(r) { //nolint:gosec // an NTSTATUS: only its 32 bits are the status
		case 0:
			length := *(*uint32)(unsafe.Pointer(&buf[0]))
			if int(4+length) > len(buf) {
				return ""
			}
			u := make([]uint16, length/2)
			for i := range u {
				u[i] = *(*uint16)(unsafe.Pointer(&buf[4+2*i]))
			}
			k.kernel = windows.UTF16ToString(u)
			return k.kernel
		case 0xC0000023, 0x80000005: // STATUS_BUFFER_TOO_SMALL, STATUS_BUFFER_OVERFLOW
			buf = make([]byte, n+16)
		default:
			return ""
		}
	}
	return ""
}

func (k *winKey) regKey() registry.Key { return registry.Key(syscall.Handle(k.h)) }

func (k *winKey) Info() (Info, error) {
	var subs, vals uint32
	var ft windows.Filetime
	if err := windows.RegQueryInfoKey(k.h, nil, nil, nil, &subs, nil, nil, &vals, nil, nil, nil, &ft); err != nil {
		return Info{}, errOf(err)
	}
	return Info{Subkeys: int(subs), Values: int(vals), LastWrite: time.Unix(0, ft.Nanoseconds())}, nil
}

func (k *winKey) SubkeyNames() ([]string, error) {
	names, err := k.regKey().ReadSubKeyNames(-1)
	return names, errOf(err)
}

func (k *winKey) ValueNames() ([]string, error) {
	names, err := k.regKey().ReadValueNames(-1)
	return names, errOf(err)
}

func (k *winKey) ValueInfo(name string) (uint32, int, error) {
	n, typ, err := k.regKey().GetValue(name, nil)
	if err != nil && !errors.Is(err, registry.ErrShortBuffer) {
		return 0, 0, errOf(err)
	}
	return typ, n, nil
}

func (k *winKey) ReadValue(name string) (uint32, []byte, error) {
	size := 256
	for range 5 {
		buf := make([]byte, size)
		n, typ, err := k.regKey().GetValue(name, buf)
		switch {
		case err == nil:
			return typ, buf[:n], nil
		case errors.Is(err, registry.ErrShortBuffer):
			size = n + 64
		default:
			return 0, nil, errOf(err)
		}
	}
	return 0, nil, errors.New("the value kept changing while it was read")
}

// LinkTarget reads SymbolicLinkValue of a key opened as a link: a REG_LINK
// holding the target's kernel path.
func (k *winKey) LinkTarget() (string, bool) {
	if k.linked {
		if k.link == nil {
			return "", false
		}
		return *k.link, true
	}
	k.linked = true
	n, typ, err := k.regKey().GetValue("SymbolicLinkValue", nil)
	if err != nil && !errors.Is(err, registry.ErrShortBuffer) {
		return "", false
	}
	if typ != registryrules.TypeLink {
		return "", false
	}
	buf := make([]byte, n)
	n, _, err = k.regKey().GetValue("SymbolicLinkValue", buf)
	if err != nil {
		return "", false
	}
	u := make([]uint16, n/2)
	for i := range u {
		u[i] = uint16(buf[2*i]) | uint16(buf[2*i+1])<<8
	}
	t := windows.UTF16ToString(u)
	k.link = &t
	return t, true
}

// Hivelist reads the loaded hives and their files.
func (b *winBackend) Hivelist() ([]HiveFile, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\hivelist`, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}
	var out []HiveFile
	for _, n := range names {
		file, _, err := k.GetStringValue(n)
		if err != nil {
			continue
		}
		out = append(out, HiveFile{Key: n, File: file})
	}
	return out, nil
}

// SIDLabel names the account of a SID the machine knows; a SID of a hive not
// loaded for a user, or one it cannot translate, has none.
func (b *winBackend) SIDLabel(s string) string {
	if !strings.HasPrefix(s, "S-1-5-") && !strings.HasPrefix(s, "S-1-12-1-") {
		return ""
	}
	sid, err := windows.StringToSid(s)
	if err != nil {
		return ""
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}
