//go:build windows

package host

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The checks of ADR-0064 on what a PowerShell install runs and loads. They
// make folders with the protected access list, so they need an elevated
// test, as CI's Windows job is.

func elevated(t *testing.T) {
	t.Helper()
	if !IsAdmin() {
		t.Skip("needs an elevated test")
	}
}

// installLike is a protected folder with a program, libraries and a text
// file in it, as an install of PowerShell 7 has.
func installLike(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "install")
	if err := mkdirProtected(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"pwsh.exe", "a.dll", filepath.Join("lib", "b.dll"), "readme.txt"} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func wantUntrusted(t *testing.T, what string, err error, path, reason string) {
	t.Helper()
	var u *Untrusted
	linked := strings.HasPrefix(reason, "has ") && strings.HasSuffix(reason, " hard links")
	if !errors.As(err, &u) || !strings.EqualFold(u.Path, path) || u.Reason != reason || u.Busy != (reason == busyReason) || u.Linked != linked {
		t.Errorf("%s: %+v (%v), want %s %s", what, u, err, path, reason)
	}
}

// TestCheckTreeFindsHardLinks: a file with a second hard link, which the
// test makes, fails a check that allows it one link only, as linked, not
// busy, and passes one that allows links (ADR-0064).
func TestCheckTreeFindsHardLinks(t *testing.T) {
	elevated(t)
	dir := installLike(t)
	dll := filepath.Join(dir, "a.dll")
	if err := os.Link(dll, filepath.Join(filepath.Dir(dir), "link.dll")); err != nil {
		t.Fatal(err)
	}
	wantUntrusted(t, "a second link", CheckTree(dir, false), dll, "has 2 hard links")
	wantUntrusted(t, "the one entry", CheckEntry(dll, false), dll, "has 2 hard links")
	if err := CheckTree(dir, true); err != nil {
		t.Errorf("with links allowed: %v", err)
	}
}

// TestCheckTreeFindsWriters: a file held open by a program that may write
// to it fails the check, as an access list fixed afterwards would not stop
// that program, and so does one a reader holds without sharing it; both are
// busy. A reader that shares the file does not fail it.
func TestCheckTreeFindsWriters(t *testing.T) {
	elevated(t)
	dir := installLike(t)
	dll := filepath.Join(dir, "a.dll")
	if err := CheckTree(dir, false); err != nil {
		t.Fatalf("a protected install: %v", err)
	}
	r, err := os.Open(dll) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckTree(dir, false); err != nil {
		t.Errorf("with a reader: %v", err)
	}
	_ = r.Close()
	w, err := os.OpenFile(dll, os.O_WRONLY, 0) //nolint:gosec // as above
	if err != nil {
		t.Fatal(err)
	}
	wantUntrusted(t, "with a writer", CheckTree(dir, false), dll, "is open in another program that may write to it")
	wantUntrusted(t, "the one entry", CheckEntry(dll, false), dll, "is open in another program that may write to it")
	// The agent's own state is checked as before: the agent may hold its
	// own files open.
	if why, err := entryProblem(dll, false, false); why != "" || err != nil {
		t.Errorf("as state: %q %v", why, err)
	}
	_ = w.Close()
	name, _ := windows.UTF16PtrFromString(dll)
	h, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantUntrusted(t, "with a reader that shares nothing", CheckTree(dir, false), dll, "is open in another program that may write to it")
	_ = windows.CloseHandle(h)
	if err := CheckTree(dir, false); err != nil {
		t.Errorf("the writer closed: %v", err)
	}
}

// TestCheckTreeHolding: the files a check holds cannot be written, deleted
// or renamed until they are let go, and can still be read; the others are
// not held; a check that fails holds nothing.
func TestCheckTreeHolding(t *testing.T) {
	elevated(t)
	dir := installLike(t)
	isHeld := func(p string) bool {
		return strings.EqualFold(filepath.Ext(p), ".dll") || strings.EqualFold(filepath.Base(p), "pwsh.exe")
	}
	held, err := CheckTreeHolding(dir, false, isHeld)
	if err != nil || len(held.handles) != 3 {
		t.Fatalf("held %+v: %v", held, err)
	}
	for _, f := range []string{"pwsh.exe", "a.dll", filepath.Join("lib", "b.dll")} {
		p := filepath.Join(dir, f)
		if w, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil { //nolint:gosec // the test's own file
			_ = w.Close()
			t.Errorf("%s was opened to write while held", f)
		} else if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			t.Errorf("%s: %v", f, err)
		}
		if err := os.Rename(p, p+".old"); err == nil {
			t.Errorf("%s was renamed while held", f)
		}
		if b, err := os.ReadFile(p); err != nil || string(b) != f { //nolint:gosec // as above
			t.Errorf("%s read while held: %q %v", f, b, err)
		}
	}
	if w, err := os.OpenFile(filepath.Join(dir, "readme.txt"), os.O_WRONLY, 0); err != nil {
		t.Errorf("a file not held: %v", err)
	} else {
		_ = w.Close()
	}
	held.Close()
	held.Close() // twice is harmless
	if w, err := os.OpenFile(filepath.Join(dir, "a.dll"), os.O_WRONLY, 0); err != nil {
		t.Errorf("let go: %v", err)
	} else {
		_ = w.Close()
	}

	// z.txt comes after the held files and fails: nothing stays held.
	z := filepath.Join(dir, "z.txt")
	if err := os.WriteFile(z, []byte("z"), 0o600); err != nil {
		t.Fatal(err)
	}
	setACL(t, z, protectedDACL+"(A;;FW;;;BU)")
	held, err = CheckTreeHolding(dir, false, isHeld)
	if held != nil {
		t.Error("a failed check holds files")
	}
	wantUntrusted(t, "a file open to Users", err, z, `can be changed by BUILTIN\Users`)
	if w, err := os.OpenFile(filepath.Join(dir, "a.dll"), os.O_WRONLY, 0); err != nil {
		t.Errorf("after a failed check: %v", err)
	} else {
		_ = w.Close()
	}
}

// TestCheckTreeCompressedFiles: a file Windows compressed (compact /exe) is
// a plain file; other reparse points, a junction here, still fail. Windows'
// overlay filter hides a compressed file's reparse point (seen on CI's
// runners: the file reads as a plain file, its tag 0), so the tags a
// file may carry are tested apart (TestReparseTags).
func TestCheckTreeCompressedFiles(t *testing.T) {
	elevated(t)
	dir := installLike(t)
	big := filepath.Join(dir, "big.dll")
	if err := os.WriteFile(big, bytes.Repeat([]byte("EasyRMM compressible text. "), 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(filepath.Join(os.Getenv("SystemRoot"), `System32\compact.exe`), "/c", "/exe:xpress4k", big).CombinedOutput() //nolint:gosec // the test's own file
	if err != nil || !bytes.Contains(out, []byte("[OK]")) || !bytes.Contains(out, []byte("1 files within 1 directories were compressed")) {
		t.Fatalf("compact did not compress it: %v\n%s", err, out)
	}
	name, _ := windows.UTF16PtrFromString(big)
	h, err := windows.CreateFile(name, inspectAccess, shareAll, nil, windows.OPEN_EXISTING, inspectFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	var info windows.ByHandleFileInformation
	_ = windows.GetFileInformationByHandle(h, &info)
	tag, err := reparseTag(h)
	_ = windows.CloseHandle(h)
	t.Logf("compressed: attributes %#x, reparse tag %#x (%v)", info.FileAttributes, tag, err)
	if err := CheckTree(dir, false); err != nil {
		t.Errorf("with a compressed library: %v", err)
	}
	if b, err := os.ReadFile(big); err != nil || !bytes.HasPrefix(b, []byte("EasyRMM compressible text. ")) { //nolint:gosec // as above
		t.Errorf("reading it: %v", err)
	}

	j := filepath.Join(dir, "j")
	junction(t, j, t.TempDir())
	wantUntrusted(t, "a junction", CheckTree(dir, false), j, "is a link, junction or other reparse point")
}

// TestReparseTags: a file with the overlay filter's or deduplication's tag
// is a plain file; any other tag, and any folder that is a reparse point,
// is refused.
func TestReparseTags(t *testing.T) {
	for _, c := range []struct {
		tag     uint32
		folder  bool
		refused bool
	}{
		{reparseWOF, false, false},
		{reparseDedup, false, false},
		{reparseWOF, true, true},
		{reparseDedup, true, true},
		{windows.IO_REPARSE_TAG_SYMLINK, false, true},
		{windows.IO_REPARSE_TAG_MOUNT_POINT, true, true},
		{0x9000001A, false, true}, // a cloud files placeholder
		{0, false, true},
	} {
		if got := reparseRefused(c.tag, c.folder); got != c.refused {
			t.Errorf("tag %#x, folder %v: refused %v", c.tag, c.folder, got)
		}
	}
}

// TestCheckAbove: what would let someone else put another folder in a
// checked one's place, from above it. Windows' own folders and a protected
// folder in ProgramData pass, even where a folder below them does not
// exist yet; ProgramData itself lets users create folders, so a folder that
// does not exist right below it fails; each planted access list, owner or
// junction on the way fails, naming its folder.
func TestCheckAbove(t *testing.T) {
	elevated(t)
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	base := filepath.Join(programData, "EasyRMM above "+hex.EncodeToString(b))
	if err := mkdirProtected(base); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	folder := func(rel, ace string) string {
		t.Helper()
		p := filepath.Join(base, rel)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if ace != "" {
			setACL(t, p, protectedDACL+ace)
		}
		return p
	}
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(system32, `WindowsPowerShell\v1.0\Modules`),
		filepath.Join(system32, `config\systemprofile\Documents\PowerShell\Modules`),
		base, filepath.Join(base, "missing", "Modules"),
	} {
		if err := CheckAbove(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	err = CheckAbove(filepath.Join(programData, "EasyRMM missing "+hex.EncodeToString(b), "Modules"))
	wantUntrusted(t, "missing below ProgramData", err, programData, `lets BUILTIN\Users create folders in it`)

	const replaced = `can be replaced, or what it holds deleted, by BUILTIN\Users`
	parent := folder("deletes", "(A;;0x40;;;BU)")
	wantUntrusted(t, "Users delete what the parent holds", CheckAbove(folder(`deletes\Modules`, "")), parent, replaced)
	parent = folder("lists", "(A;;WD;;;BU)")
	wantUntrusted(t, "Users change the parent's access list", CheckAbove(folder(`lists\Modules`, "")), parent, replaced)
	child := folder(`own\Modules`, "(A;;SD;;;BU)")
	wantUntrusted(t, "Users delete the folder itself", CheckAbove(child), child, replaced)
	parent = folder("owned", "")
	ownedByUsers(t, parent)
	wantUntrusted(t, "a parent Users own", CheckAbove(folder(`owned\Modules`, "")), parent, `is owned by BUILTIN\Users`)

	// Adding a folder counts only where the folder does not exist.
	parent = folder("adds", "(A;;0x4;;;BU)")
	if err := CheckAbove(folder(`adds\Modules`, "")); err != nil {
		t.Errorf("an existing folder where Users may add folders: %v", err)
	}
	wantUntrusted(t, "a missing folder where Users may add folders", CheckAbove(filepath.Join(parent, "missing", "Modules")), parent, `lets BUILTIN\Users create folders in it`)

	real := folder("real", "")
	j := filepath.Join(base, "j")
	junction(t, j, real)
	folder(`real\Modules`, "")
	wantUntrusted(t, "a junction on the way", CheckAbove(filepath.Join(j, "Modules")), j, "is a link, junction or other reparse point")
}

func TestSystemRoot(t *testing.T) {
	pd := os.Getenv("ProgramData")
	pf := os.Getenv("ProgramFiles")
	sr := os.Getenv("SystemRoot")
	for _, tc := range []struct {
		path string
		want bool
	}{
		{pd, true},
		{pf, true},
		{sr, true},
		{strings.ToUpper(pd), true},
		{filepath.Join(pd, "EasyRMM"), false},
		{filepath.Dir(pd), false},
		{`C:\`, false},
		{`C:\NotASystemRoot`, false},
	} {
		if got := systemRoot(tc.path); got != tc.want {
			t.Errorf("systemRoot(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestCheckSubtreeToleratesOpenFilesAndFindsWriters: ADR-0070 verifies the
// folders it excludes without the exclusive open (the agent's own log is
// open), and still finds a file or folder anyone else may write.
func TestCheckSubtreeToleratesOpenFilesAndFindsWriters(t *testing.T) {
	elevated(t)
	dir := installLike(t)
	held, err := os.OpenFile(filepath.Join(dir, "a.dll"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if err := CheckSubtree(dir); err != nil {
		t.Fatalf("an open file failed the subtree check: %v", err)
	}
	if err := CheckTree(dir, false); err == nil {
		t.Fatal("the exclusive check was expected to refuse a file open for writing")
	}
	out, err := exec.Command("icacls", filepath.Join(dir, "lib"), "/grant", "*S-1-5-32-545:(OI)(CI)(W)").CombinedOutput()
	if err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	wantUntrusted(t, "a folder Users may write", CheckSubtree(dir), filepath.Join(dir, "lib"), "can be changed by BUILTIN\\Users")
}
