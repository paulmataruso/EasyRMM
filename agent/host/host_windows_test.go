//go:build windows

package host

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// ownedByUsers makes BUILTIN\Users the owner of paths: what a standard user
// makes belongs to them, and stands here for what an attacker planted.
func ownedByUsers(t *testing.T, paths ...string) {
	t.Helper()
	if !IsAdmin() {
		t.Skip("giving files another owner needs an elevated test")
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	enablePrivilege(t, "SeRestorePrivilege")
	for _, p := range paths {
		if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, users, nil, nil, nil); err != nil {
			t.Fatalf("giving %s another owner: %v", p, err)
		}
	}
}

// junction makes link a junction to target.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
}

// stateLayout is like the agent's own (state.layout).
var stateLayout = [][]string{
	{"agent.json", "device.key"}, {"status.json"}, {"update.json"},
	{"logs"}, {filepath.Join("logs", "*")},
	{"jobs"}, {filepath.Join("jobs", "journal")}, {filepath.Join("jobs", "journal", "*")},
	{"easypatch"}, {filepath.Join("easypatch", "*")},
}

// stateFiles are what an enrolled agent keeps in its folder.
var stateFiles = []string{"agent.json", "device.key", "status.json", "update.json", filepath.Join("logs", "agent.log"),
	filepath.Join("jobs", "journal", "run.json"), filepath.Join("jobs", "work", "run-1", "script.ps1"), filepath.Join("easypatch", "agent.msi")}

// enrolledState makes a state folder as the agent leaves it, below a
// stand-in for ProgramData.
func enrolledState(t *testing.T) (dir, shared string) {
	t.Helper()
	shared = t.TempDir()
	dir = filepath.Join(shared, "EasyRMM", "Agent")
	if c, err := checkState(dir, shared, stateLayout); err != nil || len(c.Aside) != 0 || len(c.Reprotected) != 0 {
		t.Fatalf("a new state folder: %v, changed %+v", err, c)
	}
	for _, f := range stateFiles {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, shared
}

// setACL gives p the access list sddl describes, as its own.
func setACL(t *testing.T, p, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("setting the access list of %s: %v", p, err)
	}
}

// inherit makes p take its access list from its folder, and nothing else.
func inherit(t *testing.T, p string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("making %s inherit its access list: %v", p, err)
	}
}

// TestWindowsValues: the access list values acl.go keeps for every system
// are Windows' own.
func TestWindowsValues(t *testing.T) {
	const fileDeleteChild = 0x40 // not in x/sys/windows
	want := uint32(windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | fileDeleteChild |
		windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | windows.GENERIC_WRITE)
	if writeRights != want {
		t.Errorf("writeRights = %#x, want %#x", writeRights, want)
	}
	if aceAllowed != windows.ACCESS_ALLOWED_ACE_TYPE || aceDenied != windows.ACCESS_DENIED_ACE_TYPE || aceInheritOnly != windows.INHERIT_ONLY_ACE {
		t.Error("an entry kind or flag differs from Windows'")
	}
	for i, typ := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(typ)
		if err != nil || sid.String() != administration[i] {
			t.Errorf("%v = %v, want %s", typ, sid, administration[i])
		}
	}
}

// TestAccessList: what accessList reads from Windows is what the rule
// reads: who each entry names, and lists that let everyone in.
func TestAccessList(t *testing.T) {
	for sddl, want := range map[string]bool{
		protectedDACL:                        false,
		protectedDACL + "(A;OICI;FR;;;BU)":   false,
		protectedDACL + "(D;;FA;;;BU)":       false,
		"D:(A;;FA;;;SY)(A;;FA;;;BA)":         false,
		"D:":                                 false,
		protectedDACL + "(A;;FW;;;BU)":       true,
		protectedDACL + "(A;;0x40000;;;WD)":  true,
		protectedDACL + "(A;OICIIO;FW;;;AU)": true,
		// CREATOR OWNER and CREATOR GROUP name whoever creates something
		// later, who must already be let in: Program Files' list (ADR-0064).
		protectedDACL + "(A;OICIIO;FA;;;CO)(A;OICIIO;FA;;;CG)": false,
		"D:NO_ACCESS_CONTROL": true, // everyone may do everything
		"O:SY":                true, // no access list at all
		protectedDACL + "(OA;;FW;bf967aba-0de6-11d0-a285-00aa003049e2;;SY)": true,
	} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatalf("%s: %v", sddl, err)
		}
		if got, err := othersMayChange(sd, true); got != want || err != nil {
			t.Errorf("%s: others may change %v %v, want %v", sddl, got, err, want)
		}
	}
}

// TestProtectedACL: what mkdirProtected and setProtected make is the
// protected access list, so an agent's own folder passes; a folder that
// inherits its list does not, nor one with another entry; the order of the
// entries does not matter.
func TestProtectedACL(t *testing.T) {
	root := t.TempDir()
	made, set, plain := filepath.Join(root, "made"), filepath.Join(root, "set"), filepath.Join(root, "plain")
	if err := mkdirProtected(made); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{set, plain} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := setProtected(set); err != nil {
		t.Fatal(err)
	}
	reordered, extra := filepath.Join(root, "reordered"), filepath.Join(root, "extra")
	for _, p := range []string{reordered, extra} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	setACL(t, reordered, "D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
	setACL(t, extra, protectedDACL+"(A;;FA;;;BA)")
	for p, want := range map[string]bool{made: true, set: true, reordered: true, plain: false, extra: false} {
		if ok, err := protectedACL(p); ok != want || err != nil {
			t.Errorf("%s: protected %v %v", filepath.Base(p), ok, err)
		}
	}
	if _, err := checkState(root, filepath.Join(root, "elsewhere"), nil); err == nil {
		t.Error("a state folder outside ProgramData was accepted")
	}
}

// TestCheckState: a state folder, and each entry the agent reads or writes
// there, must be plain, single, made by the system or an administrator, and
// changeable by no one else. What is not moves aside and is not read; an
// access list that differs but lets no one else in is set back; what the
// agent does not read, such as the scripts' working folders, is left alone.
func TestCheckState(t *testing.T) {
	// plus is the protected access list with one more entry.
	plus := func(ace string) string { return protectedDACL + ace }
	cases := []struct {
		name  string
		plant func(t *testing.T, dir, outside string)
		// whole is the folder, below ProgramData, that moved aside with all
		// it held; gone are the entries that moved aside on their own;
		// reprotected are the folders, below ProgramData, whose access list
		// was set back.
		whole       string
		gone        []string
		reprotected []string
		// empty is a state folder that held nothing.
		empty bool
	}{
		{name: "the agent's own state", plant: func(*testing.T, string, string) {}},
		{name: "what scripts left in their working folders", plant: func(t *testing.T, dir, outside string) {
			run := filepath.Join(dir, "jobs", "work", "run-1")
			junction(t, filepath.Join(run, "junction"), outside)
			if err := os.Link(filepath.Join(outside, "file"), filepath.Join(run, "link")); err != nil {
				t.Fatal(err)
			}
			ownedByUsers(t, filepath.Join(run, "script.ps1"))
		}},
		{name: "a folder made by a user", whole: `EasyRMM\Agent`, plant: func(t *testing.T, dir, _ string) {
			ownedByUsers(t, dir)
		}},
		{name: "a folder above made by a user", whole: "EasyRMM", plant: func(t *testing.T, dir, _ string) {
			ownedByUsers(t, filepath.Dir(dir))
		}},

		// The state folder's access list.
		{name: "an empty folder that inherits its access list", empty: true, reprotected: []string{`EasyRMM\Agent`}, plant: func(t *testing.T, dir, _ string) {
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "another Administrators entry", reprotected: []string{`EasyRMM\Agent`}, plant: func(t *testing.T, dir, _ string) {
			setACL(t, dir, plus("(A;;FA;;;BA)"))
		}},
		{name: "Users may read", reprotected: []string{`EasyRMM\Agent`}, plant: func(t *testing.T, dir, _ string) {
			setACL(t, dir, plus("(A;OICI;FR;;;BU)"))
		}},
		{name: "the entries in another order", plant: func(t *testing.T, dir, _ string) {
			setACL(t, dir, "D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
		}},
		{name: "generic rights", reprotected: []string{`EasyRMM\Agent`}, plant: func(t *testing.T, dir, _ string) {
			setACL(t, dir, "D:PAI(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GR;;;BU)")
		}},
		{name: "Users may add files", whole: `EasyRMM\Agent`, plant: func(t *testing.T, dir, _ string) {
			setACL(t, dir, plus("(A;;0x2;;;BU)"))
		}},
		{name: "Users may write what the folder holds later", whole: `EasyRMM\Agent`, plant: func(t *testing.T, dir, _ string) {
			setACL(t, dir, plus("(A;OICIIO;FW;;;BU)"))
		}},
		{name: "the folder above let Users write the files", whole: `EasyRMM\Agent`, reprotected: []string{"EasyRMM"}, plant: func(t *testing.T, dir, _ string) {
			// Protecting the folder above takes this from the state folder
			// and its files; the check reads it first.
			setACL(t, filepath.Dir(dir), plus("(A;OICI;FW;;;BU)"))
			inherit(t, dir)
		}},

		// The entries.
		{name: "a configuration made by a user", gone: []string{"agent.json", "device.key"}, plant: func(t *testing.T, dir, _ string) {
			ownedByUsers(t, filepath.Join(dir, "agent.json"))
		}},
		{name: "Users may write the configuration", gone: []string{"agent.json", "device.key"}, plant: func(t *testing.T, dir, _ string) {
			setACL(t, filepath.Join(dir, "agent.json"), "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)")
		}},
		{name: "Users may change the key's access list", gone: []string{"agent.json", "device.key"}, plant: func(t *testing.T, dir, _ string) {
			setACL(t, filepath.Join(dir, "device.key"), "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x40000;;;BU)")
		}},
		{name: "Users may read the status", plant: func(t *testing.T, dir, _ string) {
			setACL(t, filepath.Join(dir, "status.json"), "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
		}},
		{name: "Users may not write the status", plant: func(t *testing.T, dir, _ string) {
			setACL(t, filepath.Join(dir, "status.json"), "D:P(D;;0x6;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)")
		}},
		{name: "Users may write what logs holds later", gone: []string{"logs"}, plant: func(t *testing.T, dir, _ string) {
			setACL(t, filepath.Join(dir, "logs"), plus("(A;OICIIO;FW;;;BU)"))
		}},
		{name: "a hard-linked key", gone: []string{"agent.json", "device.key"}, plant: func(t *testing.T, dir, outside string) {
			key := filepath.Join(dir, "device.key")
			if err := os.Remove(key); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(outside, "file"), key); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a status made by a user", gone: []string{"status.json"}, plant: func(t *testing.T, dir, _ string) {
			ownedByUsers(t, filepath.Join(dir, "status.json"))
		}},
		{name: "an update marker made by a user", gone: []string{"update.json"}, plant: func(t *testing.T, dir, _ string) {
			ownedByUsers(t, filepath.Join(dir, "update.json"))
		}},
		{name: "a junction at logs", gone: []string{"logs"}, plant: func(t *testing.T, dir, outside string) {
			replaceWithJunction(t, filepath.Join(dir, "logs"), outside)
		}},
		{name: "a junction at jobs", gone: []string{"jobs"}, plant: func(t *testing.T, dir, outside string) {
			replaceWithJunction(t, filepath.Join(dir, "jobs"), outside)
		}},
		{name: "a junction at easypatch", gone: []string{"easypatch"}, plant: func(t *testing.T, dir, outside string) {
			replaceWithJunction(t, filepath.Join(dir, "easypatch"), outside)
		}},
		{name: "a package made by a user", gone: []string{filepath.Join("easypatch", "agent.msi")}, plant: func(t *testing.T, dir, _ string) {
			ownedByUsers(t, filepath.Join(dir, "easypatch", "agent.msi"))
		}},
		{name: "a journal entry that shuts administrators out", gone: []string{filepath.Join("jobs", "journal", "run.json")}, plant: func(t *testing.T, dir, _ string) {
			p := filepath.Join(dir, "jobs", "journal", "run.json")
			ownedByUsers(t, p)
			setACL(t, p, "D:P(D;;FA;;;WD)")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, shared := enrolledState(t)
			outside := t.TempDir()
			if err := os.WriteFile(filepath.Join(outside, "file"), []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			c.plant(t, dir, outside)
			checked, err := checkState(dir, shared, stateLayout)
			if err != nil {
				t.Fatal(err)
			}
			aside := checked.Aside
			if b, err := os.ReadFile(filepath.Join(outside, "file")); err != nil || string(b) != "outside" {
				t.Errorf("what a link pointed to changed: %q, %v", b, err)
			}
			for _, p := range []string{dir, filepath.Dir(dir)} {
				if ok, err := protectedACL(p); !ok || err != nil {
					t.Errorf("%s is not protected: %v", p, err)
				}
			}
			var reprotected []string
			for _, r := range c.reprotected {
				reprotected = append(reprotected, filepath.Join(shared, r))
			}
			if !slices.Equal(checked.Reprotected, reprotected) {
				t.Errorf("access lists set back: %v, want %v", checked.Reprotected, reprotected)
			}
			if c.whole != "" {
				moved, _ := filepath.Glob(filepath.Join(shared, c.whole) + ".untrusted-*")
				if len(aside) != 1 || len(moved) != 1 || aside[0] != moved[0] {
					t.Fatalf("moved aside %v, found %v", aside, moved)
				}
				if left, _ := os.ReadDir(dir); len(left) != 0 {
					t.Errorf("the new folder holds %v", left)
				}
				return
			}
			if c.empty {
				if left, err := os.ReadDir(dir); len(left) != 0 || err != nil || len(aside) != 0 {
					t.Errorf("the folder holds %v, %v; moved aside %v", left, err, aside)
				}
				return
			}
			if len(c.gone) == 0 {
				if len(aside) != 0 {
					t.Errorf("moved aside %v", aside)
				}
			} else if away, _ := filepath.Glob(dir + ".untrusted-*"); len(away) != 1 || len(aside) != len(c.gone) {
				t.Errorf("moved aside %v, into %v", aside, away)
			} else {
				for _, g := range c.gone {
					if _, err := os.Lstat(filepath.Join(away[0], g)); err != nil {
						t.Errorf("%s was not moved aside: %v", g, err)
					}
				}
			}
			// The rest stays, untouched.
		next:
			for _, f := range stateFiles {
				for _, g := range c.gone {
					if f == g || strings.HasPrefix(f, g+string(filepath.Separator)) {
						continue next
					}
				}
				if b, err := os.ReadFile(filepath.Join(dir, f)); err != nil || string(b) != f {
					t.Errorf("%s: %q, %v", f, b, err)
				}
			}
		})
	}
}

// replaceWithJunction puts a junction to target where p was.
func replaceWithJunction(t *testing.T, p, target string) {
	t.Helper()
	if err := os.RemoveAll(p); err != nil {
		t.Fatal(err)
	}
	junction(t, p, target)
}
