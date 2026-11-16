//go:build windows

package host

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestProtectWindows checks the agent's folders: an access list of their
// own, not inherited, for SYSTEM and administrators only.
func TestProtectWindows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := Protect(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	s := sd.String()
	if !strings.HasPrefix(s, "D:P") || !strings.Contains(s, ";;;SY)") || !strings.Contains(s, ";;;BA)") || strings.Contains(s, ";;;BU)") || strings.Contains(s, ";;;WD)") {
		t.Errorf("access list = %s", s)
	}
	// Protecting again is harmless.
	if err := Protect(dir); err != nil {
		t.Error(err)
	}
}

// enablePrivilege turns on a privilege the test's token holds but has off,
// such as SeRestorePrivilege, which lets an administrator name another
// account as a file's owner.
func enablePrivilege(t *testing.T, name string) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		t.Skip(err)
	}
	defer func() { _ = token.Close() }()
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, p, &luid); err != nil {
		t.Skip(err)
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	if err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil); err != nil {
		t.Skip(err)
	}
}

// TestProtectReplacesSomeoneElsesFolder: below ProgramData, a folder that a
// standard user made before the agent was installed, with the agent's
// settings planted in it, is moved aside and made anew; so is a junction.
func TestProtectReplacesSomeoneElsesFolder(t *testing.T) {
	shared := t.TempDir() // stands for ProgramData
	top := filepath.Join(shared, "EasyRMM")
	state := filepath.Join(top, "Agent")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(state, "agent.json")
	if err := os.WriteFile(planted, []byte(`{"server":"http://127.0.0.1:9"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	enablePrivilege(t, "SeRestorePrivilege")
	if err := windows.SetNamedSecurityInfo(top, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, users, nil, nil, nil); err != nil {
		t.Skipf("cannot give the folder another owner here: %v", err)
	}
	if ok, _ := trustedOwner(top); ok {
		t.Fatal("a folder owned by Users counts as trusted")
	}

	if err := protect(state, shared); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(planted); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the planted settings are still in the agent's folder")
	}
	for _, p := range []string{top, state} {
		if ok, err := trustedOwner(p); !ok || err != nil {
			t.Errorf("%s: trusted owner %v %v", p, ok, err)
		}
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		if s := sd.String(); !strings.HasPrefix(s, "D:P") || strings.Contains(s, ";;;BU)") {
			t.Errorf("%s: access list = %s", p, s)
		}
	}
	if aside, _ := filepath.Glob(filepath.Join(shared, "EasyRMM.untrusted-*")); len(aside) != 1 {
		t.Errorf("moved aside: %v", aside)
	}

	// A junction where the folder should be is moved aside too, and what it
	// pointed at is left alone.
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", state, elsewhere).CombinedOutput(); err != nil {
		t.Skipf("mklink: %v %s", err, out)
	}
	if err := protect(state, shared); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(state)
	if err != nil || !plainFolder(fi) {
		t.Fatalf("the agent's folder is not a plain folder: %v", err)
	}
	if _, err := os.Stat(elsewhere); err != nil {
		t.Fatalf("the junction's target was touched: %v", err)
	}

	// Protecting again, as every save does, keeps the folders.
	if err := os.WriteFile(filepath.Join(state, "kept"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := protect(state, shared); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "kept")); err != nil {
		t.Fatal("a trusted folder was replaced")
	}
}

func TestWindowsVersion(t *testing.T) {
	v, err := WindowsVersion()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v.Name, "Windows") || !strings.HasPrefix(v.Version, "10.0.") || v.Build == "" {
		t.Errorf("version = %+v", v)
	}
	if !IsAdmin() {
		t.Log("not elevated: services are not installed by this test")
	}
}
