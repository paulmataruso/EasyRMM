//go:build windows

// Package wintest is what the Windows tests that change the computer share
// (internal/winpolicy's and Windows hardening's, ADR-0054): keys planted
// under HKLM and removed when the test ends, and access lists that let an
// account, or no one, read a key, file or folder, for the reads that fail,
// set back when the test ends. Only tests that run on computers made for
// them (CI's runners, test guests) use it.
package wintest

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// SystemSID is LocalSystem's.
const SystemSID = "S-1-5-18"

// The rights a deny takes: a key's values and subkeys (KEY_QUERY_VALUE,
// KEY_ENUMERATE_SUB_KEYS), a file's data or a folder's list
// (FILE_READ_DATA). Reading and setting the access list stay, so that it
// can be set back.
const (
	keyRead  = "0x9"
	fileRead = "0x1"
)

// KeyExists reports whether a key under HKLM exists, readable or not.
func KeyExists(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return !errors.Is(err, registry.ErrNotExist)
	}
	_ = k.Close()
	return true
}

// Plant makes a key under HKLM that does not exist yet, with DWORD
// (uint32) and string values, and removes it, and the parents it made,
// when the test ends.
func Plant(t testing.TB, path string, values map[string]any) {
	t.Helper()
	if KeyExists(path) {
		t.Fatalf(`HKLM\%s exists already`, path)
	}
	top := path
	for p := path; strings.Contains(p, `\`); {
		p = p[:strings.LastIndex(p, `\`)]
		if KeyExists(p) {
			break
		}
		top = p
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	t.Cleanup(func() { DeleteTree(t, top) })
	for name, v := range values {
		switch v := v.(type) {
		case uint32:
			err = k.SetDWordValue(name, v)
		case string:
			err = k.SetStringValue(name, v)
		default:
			t.Fatalf("value %s: %T", name, v)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// DeleteTree deletes a key under HKLM and its subkeys.
func DeleteTree(t testing.TB, path string) {
	t.Helper()
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS); err == nil {
		names, _ := k.ReadSubKeyNames(-1)
		_ = k.Close()
		for _, n := range names {
			DeleteTree(t, path+`\`+n)
		}
	}
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, path); err != nil && !errors.Is(err, registry.ErrNotExist) {
		t.Errorf(`delete HKLM\%s: %v`, path, err)
	}
}

// DenyKeyRead lets no one, LocalSystem included, read a key under HKLM,
// until the test ends; LocalSystem and Administrators may still delete it.
func DenyKeyRead(t testing.TB, path string) {
	t.Helper()
	setUntilCleanup(t, `MACHINE\`+path, windows.SE_REGISTRY_KEY,
		"D:P(D;;"+keyRead+";;;SY)(D;;"+keyRead+";;;BA)(A;;KA;;;BA)(A;;KA;;;SY)", true)
}

// DenyKeyReadTo lets one account (by SID) not read a key under HKLM, until
// the test ends; everyone else keeps the access they had. Windows' own
// keys may be named: only processes of that account are refused.
func DenyKeyReadTo(t testing.TB, path, sid string) {
	t.Helper()
	name := `MACHINE\` + path
	sd, err := windows.GetNamedSecurityInfo(name, windows.SE_REGISTRY_KEY, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read the access list of %s: %v", name, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	sddl := sd.String()
	deny := "(D;;" + keyRead + ";;;" + sid + ")"
	if i := strings.Index(sddl, "("); i >= 0 {
		sddl = sddl[:i] + deny + sddl[i:]
	} else {
		sddl += deny
	}
	setUntilCleanup(t, name, windows.SE_REGISTRY_KEY, sddl, control&windows.SE_DACL_PROTECTED != 0)
}

// Unreadable makes a key under HKLM that an account (by SID) cannot read,
// until the test ends: a key that exists keeps everyone else's access
// (DenyKeyReadTo); one that does not is planted and denied to everyone
// (DenyKeyRead).
func Unreadable(t testing.TB, path, sid string) {
	t.Helper()
	if KeyExists(path) {
		DenyKeyReadTo(t, path, sid)
		return
	}
	Plant(t, path, map[string]any{"EasyRMMTest": uint32(1)})
	DenyKeyRead(t, path)
}

// DenyFileRead lets no one, LocalSystem included, read a file's data or
// list a folder, until the test ends; LocalSystem and Administrators may
// still write and delete it.
func DenyFileRead(t testing.TB, path string) {
	t.Helper()
	setUntilCleanup(t, path, windows.SE_FILE_OBJECT,
		"D:P(D;;"+fileRead+";;;SY)(D;;"+fileRead+";;;BA)(A;;FA;;;SY)(A;;FA;;;BA)", true)
}

// CurrentSID is the SID of the account the test runs as.
func CurrentSID(t testing.TB) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

// setUntilCleanup sets an object's access list, protected from what its
// parent passes down or not, and sets the one it had back when the test
// ends, before what was registered earlier (such as Plant's removal) runs.
func setUntilCleanup(t testing.TB, name string, kind windows.SE_OBJECT_TYPE, sddl string, protected bool) {
	t.Helper()
	old, err := windows.GetNamedSecurityInfo(name, kind, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read the access list of %s: %v", name, err)
	}
	oldDACL, _, err := old.DACL()
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := old.Control()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(name, kind, daclInfo(protected), nil, nil, dacl, nil); err != nil {
		t.Fatalf("set the access list of %s: %v", name, err)
	}
	t.Cleanup(func() {
		if err := windows.SetNamedSecurityInfo(name, kind, daclInfo(control&windows.SE_DACL_PROTECTED != 0), nil, nil, oldDACL, nil); err != nil {
			t.Errorf("set the access list of %s back: %v", name, err)
		}
	})
}

func daclInfo(protected bool) windows.SECURITY_INFORMATION {
	if protected {
		return windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION
}
