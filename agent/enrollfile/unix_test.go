//go:build !windows

package enrollfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tree makes <root>/etc/easyrmm-agent as root's would be, owned by the user
// running the test.
func tree(t *testing.T) Policy {
	t.Helper()
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	dir := filepath.Join(etc, "easyrmm-agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	return Policy{Path: filepath.Join(dir, "install.conf"), Top: etc, UID: uint32(os.Getuid()), //nolint:gosec // a user id
		Now: func() time.Time { return time.Now().Add(time.Hour) }}
}

func write(t *testing.T, p Policy, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p.Path, []byte("[enrollment]\nserver=https://rmm.example.com\ntoken=ert_x\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.Path, mode); err != nil {
		t.Fatal(err)
	}
}

func refusal(t *testing.T, err error, want string, readable bool) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("not refused: %v", err)
	}
	if !strings.Contains(r.Reason, want) || r.Readable != readable {
		t.Errorf("refused as %+v, want %q readable=%v", r, want, readable)
	}
}

func TestReadChecksTheOpenFile(t *testing.T) {
	p := tree(t)
	if _, _, err := Read(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no file: %v", err)
	}
	write(t, p, 0o600)
	f, fp, err := Read(p)
	if err != nil || f.Token != "ert_x" || fp == "" {
		t.Fatalf("Read = %+v, %q, %v", f, fp, err)
	}
	// A chmod alone changes the fingerprint.
	if err := os.Chmod(p.Path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, fp2, err := Read(p); err != nil || fp2 == fp {
		t.Errorf("a chmod left the fingerprint: %v", err)
	}
}

func TestReadRefusals(t *testing.T) {
	t.Run("mode", func(t *testing.T) {
		for _, m := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
			p := tree(t)
			write(t, p, m)
			_, _, err := Read(p)
			refusal(t, err, "0600 or stricter", true)
		}
	})
	t.Run("owner", func(t *testing.T) {
		p := tree(t)
		write(t, p, 0o600)
		p.UID++
		_, _, err := Read(p)
		refusal(t, err, "owned by user", false)
	})
	t.Run("symbolic link", func(t *testing.T) {
		p := tree(t)
		target := filepath.Join(t.TempDir(), "t")
		if err := os.WriteFile(target, []byte("[enrollment]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p.Path); err != nil {
			t.Fatal(err)
		}
		_, _, err := Read(p)
		refusal(t, err, "symbolic link", false)
	})
	t.Run("hard link", func(t *testing.T) {
		p := tree(t)
		write(t, p, 0o600)
		if err := os.Link(p.Path, filepath.Join(t.TempDir(), "l")); err != nil {
			t.Fatal(err)
		}
		_, _, err := Read(p)
		refusal(t, err, "2 hard links", false)
	})
	t.Run("not a regular file", func(t *testing.T) {
		p := tree(t)
		if err := os.Mkdir(p.Path, 0o700); err != nil {
			t.Fatal(err)
		}
		_, _, err := Read(p)
		refusal(t, err, "not a regular file", false)
	})
	t.Run("folders", func(t *testing.T) {
		p := tree(t)
		write(t, p, 0o600)
		if err := os.Chmod(filepath.Dir(p.Path), 0o720); err != nil {
			t.Fatal(err)
		}
		_, _, err := Read(p)
		refusal(t, err, "can be changed by others", false)
		if err := os.Chmod(filepath.Dir(p.Path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p.Top, 0o757); err != nil {
			t.Fatal(err)
		}
		_, _, err = Read(p)
		refusal(t, err, "can be changed by others", false)
	})
	t.Run("a link for a folder", func(t *testing.T) {
		p := tree(t)
		write(t, p, 0o600)
		dir := filepath.Dir(p.Path)
		moved := dir + ".real"
		if err := os.Rename(dir, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, dir); err != nil {
			t.Fatal(err)
		}
		_, _, err := Read(p)
		refusal(t, err, "not a plain folder", false)
	})
	t.Run("too large", func(t *testing.T) {
		p := tree(t)
		if err := os.WriteFile(p.Path, []byte(strings.Repeat("#", MaxSize+10)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := Read(p)
		refusal(t, err, "too large", false)
	})
}

func TestReadWaitsForAFileToSettle(t *testing.T) {
	p := tree(t)
	write(t, p, 0o600)
	p.Now = nil
	if _, _, err := Read(p); !errors.Is(err, ErrSettling) {
		t.Fatalf("a file written now: %v", err)
	}
	now := time.Now()
	p.Now = func() time.Time { return now.Add(Settle - time.Second) }
	if _, _, err := Read(p); !errors.Is(err, ErrSettling) {
		t.Errorf("4 seconds old: %v", err)
	}
	p.Now = func() time.Time { return now.Add(Settle + time.Second) }
	if _, _, err := Read(p); err != nil {
		t.Errorf("6 seconds old: %v", err)
	}
}

func TestReadOfABadFileGivesAFingerprint(t *testing.T) {
	p := tree(t)
	if err := os.WriteFile(p.Path, []byte("[enrollment]\nbogus=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, fp, err := Read(p); err == nil || fp == "" {
		t.Errorf("a file that does not parse: %q, %v", fp, err)
	}
}
