package quickassist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/qaticket"
)

func TestNewCode(t *testing.T) {
	for range 50 {
		c, err := NewCode()
		if err != nil || len(c) != 6 || strings.Trim(c, "0123456789") != "" {
			t.Fatalf("code %q %v", c, err)
		}
	}
}

func TestCleanRemovesOnlyFoldersNoLiveRunnerHolds(t *testing.T) {
	base := t.TempDir()
	mk := func(name string, lock bool) (string, *os.File) {
		d := filepath.Join(base, name)
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(filepath.Join(d, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if lock {
			if err := lockFile(f); err != nil {
				t.Fatal(err)
			}
			return d, f
		}
		_ = f.Close()
		return d, nil
	}
	crashed, _ := mk(FolderPrefix+"crashed", false)
	live, lf := mk(FolderPrefix+"live", true)
	defer func() { _ = lf.Close() }()
	other := filepath.Join(base, "somebody-elses")
	_ = os.Mkdir(other, 0o700)
	nolock := filepath.Join(base, FolderPrefix+"nolock")
	_ = os.Mkdir(nolock, 0o700)

	n, err := Clean(base)
	if err != nil || n != 2 {
		t.Fatalf("Clean: %d %v", n, err)
	}
	for dir, want := range map[string]bool{crashed: false, nolock: false, live: true, other: true} {
		if _, err := os.Stat(dir); (err == nil) != want {
			t.Errorf("%s exists=%v want %v", filepath.Base(dir), err == nil, want)
		}
	}
	if _, err := Clean(filepath.Join(base, "missing")); err == nil {
		t.Error("a missing base is an error")
	}
}

func TestCleanupVerifiesAndReports(t *testing.T) {
	dir := filepath.Join(t.TempDir(), FolderPrefix+"x")
	lock, err := makeFolder(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := makeFolder(dir); err == nil {
		t.Fatal("a second runner took the same folder")
	}
	_ = os.WriteFile(filepath.Join(dir, "data"), []byte("x"), 0o600)
	rep := cleanup(dir, lock)
	if rep.Result != "verified" || len(rep.Checks) != 5 || len(rep.ManifestSHA256) != 64 {
		t.Fatalf("report: %+v", rep)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("the folder is still there")
	}
	for _, c := range rep.Checks {
		if !c.OK {
			t.Errorf("check %s failed", c.Name)
		}
	}
}

func TestRunRefusesAProgramWithoutAUsableTicket(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub
	now := time.Unix(2_000_000, 0)
	write := func(extra []byte) string {
		f := filepath.Join(t.TempDir(), "runner")
		if err := os.WriteFile(f, append([]byte("exe"), extra...), 0o700); err != nil {
			t.Fatal(err)
		}
		return f
	}
	good, _ := qaticket.Sign(key, qaticket.Ticket{Link: "l", Server: "https://rmm.example.test", Expiry: now.Add(time.Hour).Unix()})
	old, _ := qaticket.Sign(key, qaticket.Ticket{Link: "l", Server: "https://rmm.example.test", Expiry: now.Add(-time.Hour).Unix()})
	bad := append([]byte{}, good...)
	bad[10] ^= 0xff

	cases := map[string]struct {
		file string
		want string
	}{
		"none":    {write(nil), "no ticket"},
		"expired": {write(old), "expired"},
		"damaged": {write(bad), "damaged"},
	}
	for name, c := range cases {
		var out bytes.Buffer
		err := Run(context.Background(), Options{Self: c.file, BaseDir: t.TempDir(), In: strings.NewReader("YES\n"), Out: &out, Now: func() time.Time { return now }})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if strings.Contains(out.String(), "session code") {
			t.Errorf("%s: the consent text was shown for a program that cannot run", name)
		}
	}

	// The user says no: nothing is sent and the folder is never made.
	var out bytes.Buffer
	base := t.TempDir()
	err := Run(context.Background(), Options{Self: write(good), BaseDir: base, In: strings.NewReader("no\n"), Out: &out, Now: func() time.Time { return now }})
	if !errors.Is(err, ErrDeclined) || !strings.Contains(out.String(), "rmm.example.test") || !strings.Contains(out.String(), "Canceled") {
		t.Fatalf("cancel: %v\n%s", err, out.String())
	}
	if m, _ := filepath.Glob(filepath.Join(base, FolderPrefix+"*")); len(m) != 0 {
		t.Fatal("a folder was made before consent")
	}
}
