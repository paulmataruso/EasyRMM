//go:build windows

package host

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// OpenPrivate, the check of the enrollment file (ADR-0056), on Windows'
// access lists. They make folders with the protected access list and files
// owned by another account, so they need an elevated test, as CI's Windows
// job is.

const adminsOnly = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// enrollmentTree makes EasyRMM\Package\Enrollment as the MSI makes it,
// below a temporary folder, and returns the top, the folder and the file's
// path.
func enrollmentTree(t *testing.T) (top, dir, file string) {
	t.Helper()
	elevated(t)
	top = filepath.Join(t.TempDir(), "EasyRMM")
	dir = filepath.Join(top, "Package", "Enrollment")
	for _, d := range []string{top, filepath.Dir(dir), dir} {
		if err := mkdirProtected(d); err != nil {
			t.Fatal(err)
		}
	}
	return top, dir, filepath.Join(dir, "install.conf")
}

func writeProtected(t *testing.T, file string) {
	t.Helper()
	if err := os.WriteFile(file, []byte("[enrollment]\nserver=https://rmm.example.com\ntoken=ert_x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setACL(t, file, adminsOnly)
}

func wantProblem(t *testing.T, what string, err error, reason string, readable bool) {
	t.Helper()
	var p *Problem
	if !errors.As(err, &p) {
		t.Errorf("%s: not refused: %v", what, err)
		return
	}
	if !strings.Contains(p.Reason, reason) || p.Readable != readable {
		t.Errorf("%s: refused as %+v, want %q readable=%v", what, p, reason, readable)
	}
}

func TestOpenPrivateReadsAFileOnlyAdministratorsCanRead(t *testing.T) {
	top, _, file := enrollmentTree(t)
	if _, err := OpenPrivate(file, top); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no file: %v", err)
	}
	writeProtected(t, file)
	f, err := OpenPrivate(file, top)
	if err != nil {
		t.Fatalf("a file made as the MSI makes it: %v", err)
	}
	b, err := io.ReadAll(f.File)
	_ = f.Close()
	if err != nil || !strings.Contains(string(b), "ert_x") || f.Meta == "" {
		t.Errorf("read %q, %v", b, err)
	}
}

func TestOpenPrivateRefusals(t *testing.T) {
	t.Run("an entry for Users", func(t *testing.T) {
		top, _, file := enrollmentTree(t)
		writeProtected(t, file)
		setACL(t, file, adminsOnly+"(A;;FR;;;BU)")
		_, err := OpenPrivate(file, top)
		wantProblem(t, "Users may read", err, "can be read by", true)
	})
	t.Run("everyone", func(t *testing.T) {
		top, _, file := enrollmentTree(t)
		writeProtected(t, file)
		setACL(t, file, adminsOnly+"(A;;FR;;;WD)")
		_, err := OpenPrivate(file, top)
		wantProblem(t, "Everyone may read", err, "can be read by", true)
	})
	t.Run("Users may write", func(t *testing.T) {
		top, _, file := enrollmentTree(t)
		writeProtected(t, file)
		setACL(t, file, adminsOnly+"(A;;FA;;;BU)")
		_, err := OpenPrivate(file, top)
		wantProblem(t, "Users may write", err, "can be changed by", true)
	})
	t.Run("no access list", func(t *testing.T) {
		top, _, file := enrollmentTree(t)
		writeProtected(t, file)
		setACL(t, file, "D:P(A;;FA;;;WD)")
		_, err := OpenPrivate(file, top)
		wantProblem(t, "a list for everyone", err, "", true)
	})
	t.Run("another owner", func(t *testing.T) {
		top, _, file := enrollmentTree(t)
		writeProtected(t, file)
		ownedByUsers(t, file)
		_, err := OpenPrivate(file, top)
		wantProblem(t, "owned by Users", err, "is owned by", false)
	})
	t.Run("a second hard link", func(t *testing.T) {
		top, dir, file := enrollmentTree(t)
		writeProtected(t, file)
		if err := os.Link(file, filepath.Join(filepath.Dir(dir), "other")); err != nil {
			t.Fatal(err)
		}
		_, err := OpenPrivate(file, top)
		wantProblem(t, "two links", err, "hard links", false)
	})
	t.Run("a folder where Users may create", func(t *testing.T) {
		top, dir, file := enrollmentTree(t)
		writeProtected(t, file)
		setACL(t, dir, adminsOnly+"(A;OICI;FA;;;BU)")
		_, err := OpenPrivate(file, top)
		wantProblem(t, "Users write the folder", err, "its folder", false)
	})
	t.Run("a folder Users may read", func(t *testing.T) {
		top, dir, file := enrollmentTree(t)
		writeProtected(t, file)
		// Under Program Files users may read but create nothing.
		setACL(t, dir, adminsOnly+"(A;OICI;FR;;;BU)")
		f, err := OpenPrivate(file, top)
		if err != nil {
			t.Fatalf("a folder users may read: %v", err)
		}
		_ = f.Close()
	})
	t.Run("a junction for a folder", func(t *testing.T) {
		top, dir, file := enrollmentTree(t)
		writeProtected(t, file)
		real := dir + "-real"
		if err := os.Rename(dir, real); err != nil {
			t.Fatal(err)
		}
		junction(t, dir, real)
		_, err := OpenPrivate(file, top)
		wantProblem(t, "a junction", err, "reparse point", false)
	})
	t.Run("a link for the file", func(t *testing.T) {
		top, dir, file := enrollmentTree(t)
		target := filepath.Join(dir, "real.conf")
		writeProtected(t, target)
		if err := os.Symlink(target, file); err != nil {
			t.Skipf("no privilege to make a symbolic link: %v", err)
		}
		_, err := OpenPrivate(file, top)
		wantProblem(t, "a symbolic link", err, "reparse point", false)
	})
}

func TestOpenPrivateHoldsTheFile(t *testing.T) {
	top, _, file := enrollmentTree(t)
	writeProtected(t, file)
	f, err := OpenPrivate(file, top)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	// While it is open, no one else may write or delete it: it cannot be
	// swapped between the check and the read.
	if err := os.Remove(file); err == nil {
		t.Error("the file was deleted while it was held open")
	}
	if g, err := os.OpenFile(file, os.O_WRONLY, 0); err == nil {
		_ = g.Close()
		t.Error("the file was opened for writing while it was held open")
	}
}
