//go:build windows

package powershell

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// These tests check what the agent's service sees, so they run as
// LocalSystem: CI's job "PowerShell 7 as LocalSystem" starts them through a
// scheduled task with EASYRMM_TEST_SYSTEM set, on a runner where PowerShell
// 7 was installed from Microsoft's MSI, Microsoft's x86 ZIP unpacked into
// Program Files (x86) (EASYRMM_TEST_PWSH_X86) and the Store package
// installed by winget, or as winget would where the runner has none
// (EASYRMM_TEST_PWSH_STORE). As an administrator they
// would test something else: the account the agent runs as is trusted too.

// systemTest skips a test unless it may run, and fails one that is not
// running as LocalSystem.
func systemTest(t *testing.T) {
	t.Helper()
	if os.Getenv("EASYRMM_TEST_SYSTEM") == "" {
		t.Skip("runs as LocalSystem on a computer made for it; CI's job sets EASYRMM_TEST_SYSTEM")
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatalf("not running as LocalSystem (%v)", err)
	}
}

// printed starts a PowerShell and returns what it prints for command.
func printed(t *testing.T, exe, command string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command).CombinedOutput() //nolint:gosec // a test's PowerShell
	if err != nil {
		t.Fatalf("%s: %v\n%s", exe, err, out)
	}
	return strings.TrimSpace(string(out))
}

// archOf turns a process's PROCESSOR_ARCHITECTURE into the inventory's
// names.
func archOf(s string) string {
	switch strings.ToUpper(s) {
	case "AMD64":
		return agentproto.ArchX64
	case "ARM64":
		return agentproto.ArchARM64
	case "X86":
		return agentproto.ArchX86
	}
	return "unknown " + s
}

// TestDiscoverAsSystem: discovery finds the runner's Windows PowerShell and
// PowerShell 7 and reads what each says of itself; a run uses the PowerShell
// 7 the inventory lists first; the x86 build and the Store package are
// reported and not used.
func TestDiscoverAsSystem(t *testing.T) {
	systemTest(t)
	roots, err := Roots()
	if err != nil || len(roots) != 2 {
		t.Fatalf("roots %q %v", roots, err)
	}
	start := time.Now()
	list := Discover(roots)
	for _, p := range list {
		t.Logf("found %+v", p)
	}
	t.Logf("discovery, with the usable installs checked, took %s", time.Since(start))

	d := list[0]
	if d.Edition != agentproto.EditionDesktop || !d.Usable || d.Reason != "" || !strings.EqualFold(d.Path, DesktopPath()) {
		t.Fatalf("Windows PowerShell %+v", d)
	}
	reg, err := registryVersion()
	t.Logf("the registry names Windows PowerShell %s (%v)", reg, err)
	if want := printed(t, d.Path, "$PSVersionTable.PSVersion.ToString()"); d.Version != want {
		t.Errorf("Windows PowerShell's version %q, its $PSVersionTable %q", d.Version, want)
	}
	if want := archOf(printed(t, d.Path, "$env:PROCESSOR_ARCHITECTURE")); d.Arch != want {
		t.Errorf("Windows PowerShell's architecture %q, its process %q", d.Arch, want)
	}
	if e := printed(t, d.Path, "$PSVersionTable.PSEdition"); e != d.Edition {
		t.Errorf("edition %q", e)
	}

	run, err := ForRun(roots)
	if err != nil {
		t.Fatal(err)
	}
	run.Release()
	c := run.Interpreter
	if !strings.EqualFold(c.Path, filepath.Join(roots[0], `PowerShell\7\pwsh.exe`)) || list[1].Edition != agentproto.EditionCore || !list[1].Usable || list[1].Path != c.Path {
		t.Fatalf("a run uses %+v; the inventory lists %+v", c, list[1])
	}
	if list[1].Preview || list[1].Store {
		t.Errorf("chose %+v", list[1])
	}
	if want := printed(t, c.Path, "$PSVersionTable.PSVersion.ToString()"); c.Version != want {
		t.Errorf("PowerShell 7's version %q, its $PSVersionTable %q", c.Version, want)
	}
	if want := archOf(printed(t, c.Path, "$env:PROCESSOR_ARCHITECTURE")); c.Arch != want || c.Arch != nativeArch() {
		t.Errorf("PowerShell 7's architecture %q, its process %q, the computer %q", c.Arch, want, nativeArch())
	}
	if e := printed(t, c.Path, "$PSVersionTable.PSEdition"); e != c.Edition {
		t.Errorf("edition %q", e)
	}

	x86 := os.Getenv("EASYRMM_TEST_PWSH_X86")
	if x86 == "" {
		t.Fatal("EASYRMM_TEST_PWSH_X86 is not set (the x86 ZIP's pwsh.exe in Program Files (x86))")
	}
	found := false
	for _, p := range list {
		if strings.EqualFold(p.Path, x86) {
			found = true
			if p.Arch != agentproto.ArchX86 || p.Usable || p.Reason != reasonX86 {
				t.Errorf("the x86 build %+v", p)
			}
			if want := printed(t, p.Path, "$PSVersionTable.PSVersion.ToString()"); p.Version != want {
				t.Errorf("the x86 build's version %q, its $PSVersionTable %q", p.Version, want)
			}
		}
	}
	if !found {
		t.Errorf("the x86 build at %s was not found", x86)
	}

	store := os.Getenv("EASYRMM_TEST_PWSH_STORE")
	if store == "" {
		t.Fatal("EASYRMM_TEST_PWSH_STORE is not set (the Store package's pwsh.exe)")
	}
	found = false
	for _, p := range list {
		if strings.EqualFold(p.Path, store) {
			found = true
			if !p.Store || p.Usable || p.Reason != reasonStore || p.Version == "" || p.Arch == "" {
				t.Errorf("the Store install %+v", p)
			}
		}
	}
	if !found {
		t.Errorf("the Store install at %s was not found", store)
	}
	// What happens when LocalSystem starts the Store install's pwsh.exe, for
	// the decision on Store installs (ADR-0064): recorded, not judged.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, store, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", //nolint:gosec // the test's own install
		"$PSVersionTable.PSVersion.ToString(); [Environment]::UserName; $PSHOME").CombinedOutput()
	t.Logf("LocalSystem started the Store install's pwsh.exe: error %v, output:\n%s", err, out)
}

// TestUntrustedInstallAsSystem: a copy of the runner's install in a Program
// Files of its own passes the whole check; a file deep in it that Users may
// change, or a junction in it, makes it found, not used, naming the entry,
// and a run never starts it; a library open to write makes it blocked.
func TestUntrustedInstallAsSystem(t *testing.T) {
	systemTest(t)
	roots, err := Roots()
	if err != nil {
		t.Fatal(err)
	}
	// A folder in Program Files has Program Files' access list, which only
	// administrators may change: a Program Files of the test's own.
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	root := filepath.Join(roots[0], "EasyRMM test "+hex.EncodeToString(b))
	install := filepath.Join(root, `PowerShell\7`)
	if err := copyTree(filepath.Join(roots[0], `PowerShell\7`), install); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	pwsh := filepath.Join(install, "pwsh.exe")

	find := func() agentproto.PowerShellInstall {
		t.Helper()
		start := time.Now()
		list := Discover([]string{root})
		t.Logf("checked in %s", time.Since(start))
		for _, p := range list {
			if strings.EqualFold(p.Path, pwsh) {
				return p
			}
		}
		t.Fatalf("the copy was not found: %+v", list)
		return agentproto.PowerShellInstall{}
	}
	if p := find(); !p.Usable {
		t.Fatalf("the copy is not usable: %+v", p)
	}
	run, err := ForRun([]string{root})
	if err != nil || !strings.EqualFold(run.Interpreter.Path, pwsh) {
		t.Fatalf("a run of the copy: %+v %v", run, err)
	}
	run.Release()

	// The deepest file in the copy, opened to Users.
	deep := ""
	_ = filepath.WalkDir(install, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Count(p, `\`) > strings.Count(deep, `\`) {
			deep = p
		}
		return nil
	})
	if strings.Count(deep, `\`)-strings.Count(install, `\`) < 3 {
		t.Fatalf("no file deep in the install: %q", deep)
	}
	icacls(t, deep, "/grant", "*S-1-5-32-545:(M)")
	p := find()
	if p.Usable || !strings.HasPrefix(p.Reason, deep+" can be changed by ") || !strings.Contains(p.Reason, "Users") {
		t.Errorf("with %s open to Users: %+v", deep, p)
	}
	_, err = ForRun([]string{root})
	var missing *NotFound
	if !errors.As(err, &missing) || !strings.Contains(err.Error(), deep) {
		t.Errorf("a run with the file open to Users: %v", err)
	}
	icacls(t, deep, "/remove:g", "*S-1-5-32-545")
	if p := find(); !p.Usable {
		t.Fatalf("closed again, the copy is not usable: %+v", p)
	}

	// A junction inside the install.
	junction := filepath.Join(install, "Modules", "EasyRMM junction")
	if out, err := exec.Command(filepath.Join(system32(), "cmd.exe"), "/d", "/c", "mklink", "/J", junction, root).CombinedOutput(); err != nil { //nolint:gosec // the test's own folders
		t.Fatalf("mklink: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(junction) }) // before the copy goes
	if p := find(); p.Usable || p.Reason != junction+" is a link, junction or other reparse point: not used, since what it runs and loads must be changeable by administrators only." {
		t.Errorf("with a junction: %+v", p)
	}
	if _, err := ForRun([]string{root}); !errors.As(err, &missing) {
		t.Errorf("a run with a junction in the install: %v", err)
	}
	if err := os.Remove(junction); err != nil {
		t.Fatal(err)
	}

	// A library held open by a program that may write to it: found and
	// blocked, and a run fails even where the script allows Windows
	// PowerShell, as anyone who may read a file can hold it so. The largest,
	// which Windows compresses below.
	dll, size := "", int64(0)
	if err := filepath.WalkDir(install, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !strings.EqualFold(filepath.Ext(p), ".dll") {
			return nil
		}
		if fi, err := d.Info(); err == nil && fi.Size() > size {
			dll, size = p, fi.Size()
		}
		return nil
	}); err != nil || dll == "" {
		t.Fatalf("no library in the copy (%v)", err)
	}
	w, err := os.OpenFile(dll, os.O_WRONLY, 0) //nolint:gosec // the test's own copy
	if err != nil {
		t.Fatal(err)
	}
	if p := find(); p.Usable || !p.Blocked || p.Reason != dll+" is open in another program that may write to it"+busySuffix {
		t.Errorf("with %s open to write: %+v", dll, p)
	}
	if _, err := ForRun([]string{root}); err == nil || errors.As(err, &missing) || err.Error() != dll+" is open in another program that may write to it; the script was not run" {
		t.Errorf("a run with a library open to write: %v", err)
	}
	_ = w.Close()

	// A run holds the program and the libraries until it lets go.
	run, err = ForRun([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{pwsh, dll} {
		if w, err := os.OpenFile(f, os.O_WRONLY, 0); err == nil { //nolint:gosec // as above
			_ = w.Close()
			t.Errorf("%s opened to write while a run holds it", f)
		}
	}
	run.Release()
	if w, err := os.OpenFile(dll, os.O_WRONLY, 0); err != nil { //nolint:gosec // as above
		t.Errorf("let go: %v", err)
	} else {
		_ = w.Close()
	}

	// Compressed by Windows (compact /exe): still plain files, and used.
	out, err := exec.Command(filepath.Join(system32(), "compact.exe"), "/c", "/exe:xpress4k", pwsh, dll).CombinedOutput() //nolint:gosec // the test's own copy
	if err != nil || strings.Count(string(out), "[OK]") != 2 {
		t.Fatalf("compact did not compress them: %v\n%s", err, out)
	}
	for _, f := range []string{pwsh, dll} {
		name, _ := windows.UTF16PtrFromString(f)
		a, err := windows.GetFileAttributes(name)
		t.Logf("compressed %s: attributes %#x (%v)", filepath.Base(f), a, err)
	}
	if p := find(); !p.Usable {
		t.Errorf("compressed: %+v", p)
	}
	if run, err := ForRun([]string{root}); err != nil {
		t.Errorf("a run of the compressed copy: %v", err)
	} else {
		run.Release()
	}
}

// TestModuleFoldersAsSystem: what a run loads from outside the install.
// The copy's powershell.config.json names its shared module folder: one in
// the test's Program Files is used; one that does not exist, or whose
// folder Users may empty, makes the copy found and blocked, and a run
// fails without falling back. SYSTEM's own powershell.config.json, outside
// the install, that Users may change blocks the copy too, refused unread;
// $PSHOME's is one of the install's own files, so Users changing it makes
// the copy found and not used.
func TestModuleFoldersAsSystem(t *testing.T) {
	systemTest(t)
	roots, err := Roots()
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	root := filepath.Join(roots[0], "EasyRMM test "+hex.EncodeToString(b))
	install := filepath.Join(root, `PowerShell\7`)
	if err := copyTree(filepath.Join(roots[0], `PowerShell\7`), install); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	pwsh := filepath.Join(install, "pwsh.exe")
	config := filepath.Join(install, "powershell.config.json")
	find := func() agentproto.PowerShellInstall {
		t.Helper()
		list := Discover([]string{root})
		for _, p := range list {
			if strings.EqualFold(p.Path, pwsh) {
				return p
			}
		}
		t.Fatalf("the copy was not found: %+v", list)
		return agentproto.PowerShellInstall{}
	}
	names := func(folder string) {
		t.Helper()
		body := `{"PSModulePath": "` + strings.ReplaceAll(folder, `\`, `\\`) + `"}`
		if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	blocked := func(what, reason string) {
		t.Helper()
		if p := find(); p.Usable || !p.Blocked || !strings.Contains(p.Reason, reason) ||
			!strings.HasSuffix(p.Reason, "Scripts that allow Windows PowerShell 5.1 do not run in it instead.") {
			t.Errorf("%s: %+v", what, p)
		}
		_, err := ForRun([]string{root})
		var missing *NotFound
		if err == nil || errors.As(err, &missing) || !strings.Contains(err.Error(), reason) || !strings.HasSuffix(err.Error(), "; the script was not run") {
			t.Errorf("a run, %s: %v", what, err)
		}
	}

	shared := filepath.Join(root, "Modules here")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	names(shared)
	if p := find(); !p.Usable || p.Blocked {
		t.Fatalf("a configured folder in Program Files: %+v", p)
	}
	run, err := ForRun([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	run.Release()
	if all, _, _, err := moduleFolders(install); err != nil || len(all) != 5 || !strings.EqualFold(all[1], shared) {
		t.Errorf("module folders %q (%v), want the configured one second", all, err)
	}

	gone := filepath.Join(root, "Not made")
	names(gone)
	blocked("a configured folder that does not exist", config+" names the module folder "+gone+", which does not exist")

	open := filepath.Join(root, "Open")
	if err := os.MkdirAll(filepath.Join(open, "Modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	icacls(t, open, "/grant", "*S-1-5-32-545:(DC)")
	names(filepath.Join(open, "Modules"))
	blocked("a configured folder whose folder Users may empty", open+` can be replaced, or what it holds deleted, by BUILTIN\Users`)

	names(shared)
	docs, err := windows.KnownFolderPath(windows.FOLDERID_Documents, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(docs, "PowerShell", "powershell.config.json")
	if _, err := os.Lstat(own); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("SYSTEM already has %s (%v); the test would change it", own, err)
	}
	var made []string
	for d := filepath.Dir(own); ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil {
			break
		}
		made = append(made, d)
	}
	t.Cleanup(func() {
		_ = os.Remove(own)
		for _, d := range made {
			_ = os.Remove(d)
		}
	})
	if err := os.MkdirAll(filepath.Dir(own), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	icacls(t, own, "/grant", "*S-1-5-32-545:(M)")
	blocked("SYSTEM's own configuration Users may change", "PowerShell 7 would read its configuration from "+own+", and "+own+" can be changed by BUILTIN\\Users")
	if err := os.Remove(own); err != nil {
		t.Fatal(err)
	}
	if p := find(); !p.Usable || p.Blocked {
		t.Fatalf("SYSTEM's configuration removed: %+v", p)
	}

	icacls(t, config, "/grant", "*S-1-5-32-545:(M)")
	if p := find(); p.Usable || p.Blocked || !strings.HasPrefix(p.Reason, config+" can be changed by BUILTIN\\Users") {
		t.Errorf("the install's own configuration Users may change: %+v", p)
	}
	var missing *NotFound
	if _, err := ForRun([]string{root}); !errors.As(err, &missing) {
		t.Errorf("a run, the install's own configuration Users may change: %v", err)
	}
}

func icacls(t *testing.T, path string, args ...string) {
	t.Helper()
	out, err := exec.Command(filepath.Join(system32(), "icacls.exe"), append([]string{path}, args...)...).CombinedOutput() //nolint:gosec // the test's own files
	if err != nil {
		t.Fatalf("icacls %s: %v\n%s", args, err, out)
	}
}

// copyTree copies a folder's files and folders, which take the access list
// their new folder passes on.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(to, 0o755)
		}
		if !d.Type().IsRegular() {
			return errors.New(p + " is not a file or folder")
		}
		in, err := os.Open(p) //nolint:gosec // the runner's install
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		out, err := os.Create(to) //nolint:gosec // the test's folder
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			return err
		}
		return out.Close()
	})
}
