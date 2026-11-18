package state

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// checkModes checks that only the owner can read the state, and that a key
// others can read is refused.
func checkModes(t *testing.T, s Store) {
	t.Helper()
	for name, want := range map[string]os.FileMode{"": 0o700, keyFile: 0o600, configFile: 0o600} {
		st, err := os.Stat(filepath.Join(s.Dir, name))
		if err != nil || st.Mode().Perm() != want {
			t.Errorf("%s mode = %v, %v", name, st.Mode().Perm(), err)
		}
	}
	if err := os.Chmod(filepath.Join(s.Dir, keyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "owner only") {
		t.Errorf("readable key: %v", err)
	}
	_ = os.Chmod(filepath.Join(s.Dir, keyFile), 0o600)
}

func TestSaveAndLoad(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "state")}
	if _, _, err := s.Load(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("empty store: %v", err)
	}
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Server: "https://rmm.example.com", DeviceID: "d1", EnrolledAt: time.Unix(1_800_000_000, 0).UTC(), MeshAgentMode: "child"}
	if err := s.Save(cfg, key); err != nil {
		t.Fatal(err)
	}
	got, k, err := s.Load()
	if err != nil || *got != *cfg || !k.Equal(key) {
		t.Fatalf("loaded %+v, %v", got, err)
	}
	// Windows protects the folder with its access list instead
	// (host.TestProtectWindows); file modes there say nothing.
	if runtime.GOOS != "windows" {
		checkModes(t, s)
	}

	// Damaged files are reported.
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(s.Dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(keyFile, "-----BEGIN SOMETHING-----\nAAAA\n-----END SOMETHING-----\n")
	if _, _, err := s.Load(); err == nil {
		t.Error("foreign PEM accepted as the key")
	}
	_ = os.Remove(filepath.Join(s.Dir, keyFile))
	if _, _, err := s.Load(); err == nil {
		t.Error("missing key accepted")
	}
	write(configFile, `{"server":""}`)
	if _, _, err := s.Load(); err == nil {
		t.Error("incomplete config accepted")
	}
	write(configFile, `not json`)
	if _, _, err := s.Load(); err == nil {
		t.Error("corrupt config accepted")
	}
	if err := os.Chmod(filepath.Join(s.Dir, configFile), 0o000); err == nil && os.Geteuid() != 0 {
		if _, _, err := s.Load(); err == nil {
			t.Error("unreadable config accepted")
		}
	}

	if err := s.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Error("state directory kept")
	}
}

func TestStatus(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, err := s.LoadStatus(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no status yet: %v", err)
	}
	st := Status{LastHeartbeat: time.Unix(1_800_000_000, 0).UTC(), MeshAgent: "installed", MeshNodeID: "AB"}
	if err := s.SaveStatus(st); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadStatus()
	if err != nil || got != st {
		t.Errorf("status = %+v, %v", got, err)
	}
	if err := (Store{Dir: filepath.Join(t.TempDir(), "missing")}).SaveStatus(st); err == nil {
		t.Error("status saved into a missing directory")
	}
}

func TestPendingEnrollment(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "state")}
	if _, _, err := s.LoadPending(); !errors.Is(err, ErrNotPending) {
		t.Fatalf("empty store: %v", err)
	}
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	p := &Pending{Server: "https://rmm.example.com", MeshAgentMode: "service", Token: "ert_x", Code: "ABCD-EFGH", Since: time.Now().UTC()}
	if err := s.SavePending(p, key); err != nil {
		t.Fatal(err)
	}
	// Waiting is not enrolled.
	if _, _, err := s.Load(); !errors.Is(err, ErrNotEnrolled) {
		t.Errorf("pending loads as enrolled: %v", err)
	}
	got, gotKey, err := s.LoadPending()
	if err != nil || got.Token != "ert_x" || got.Code != "ABCD-EFGH" || !gotKey.Equal(key) {
		t.Fatalf("load pending: %+v %v", got, err)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(s.Dir, pendingFile))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("pending file mode %v %v", st.Mode().Perm(), err)
		}
	}
	got.Stopped, got.StoppedAt = "rejected", time.Now()
	if err := s.UpdatePending(got); err != nil {
		t.Fatal(err)
	}
	if again, _, _ := s.LoadPending(); again.Stopped != "rejected" {
		t.Errorf("update lost: %+v", again)
	}

	// Approved: an enrollment with the same key, and the token is gone.
	if err := s.Approved(&Config{Server: got.Server, DeviceID: "d1", MeshAgentMode: got.MeshAgentMode, EnrolledAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	cfg, k, err := s.Load()
	if err != nil || cfg.DeviceID != "d1" || !k.Equal(key) {
		t.Fatalf("after approval: %+v %v", cfg, err)
	}
	if _, _, err := s.LoadPending(); !errors.Is(err, ErrNotPending) {
		t.Errorf("pending file kept: %v", err)
	}
	if err := s.Approved(cfg); err != nil {
		t.Errorf("approving twice: %v", err)
	}

	// Damaged files are reported.
	if err := os.WriteFile(filepath.Join(s.Dir, pendingFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LoadPending(); err == nil {
		t.Error("damaged pending file accepted")
	}
	if err := os.WriteFile(filepath.Join(s.Dir, pendingFile), []byte(`{"server":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LoadPending(); err == nil {
		t.Error("pending file without a token accepted")
	}
}
