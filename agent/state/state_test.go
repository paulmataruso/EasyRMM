package state

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/host"
)

// open opens the store of a state folder under a test's own root.
func open(t *testing.T) Store {
	t.Helper()
	s, checked, err := Open(host.Paths{Root: t.TempDir()})
	if err != nil || len(checked.Aside) != 0 {
		t.Fatalf("open: %v, moved aside %v", err, checked.Aside)
	}
	return s
}

// checkModes checks that only the owner can read the state, and that a key
// others can read is refused.
func checkModes(t *testing.T, s Store) {
	t.Helper()
	for name, want := range map[string]os.FileMode{"": 0o700, keyFile: 0o600, configFile: 0o600} {
		st, err := os.Stat(filepath.Join(s.Dir(), name))
		if err != nil || st.Mode().Perm() != want {
			t.Errorf("%s mode = %v, %v", name, st.Mode().Perm(), err)
		}
	}
	if err := os.Chmod(filepath.Join(s.Dir(), keyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "owner only") {
		t.Errorf("readable key: %v", err)
	}
	_ = os.Chmod(filepath.Join(s.Dir(), keyFile), 0o600)
}

func TestSaveAndLoad(t *testing.T) {
	s := open(t)
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
	if err != nil || !reflect.DeepEqual(*got, *cfg) || !k.Equal(key) {
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
		if err := os.WriteFile(filepath.Join(s.Dir(), name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(keyFile, "-----BEGIN SOMETHING-----\nAAAA\n-----END SOMETHING-----\n")
	if _, _, err := s.Load(); err == nil {
		t.Error("foreign PEM accepted as the key")
	}
	_ = os.Remove(filepath.Join(s.Dir(), keyFile))
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
	if err := os.Chmod(filepath.Join(s.Dir(), configFile), 0o000); err == nil && os.Geteuid() != 0 {
		if _, _, err := s.Load(); err == nil {
			t.Error("unreadable config accepted")
		}
	}

	if err := s.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Dir()); !errors.Is(err, os.ErrNotExist) {
		t.Error("state directory kept")
	}
}

// TestUncheckedStore: a store that Open did not make, after checking its
// folder, reads and writes nothing.
func TestUncheckedStore(t *testing.T) {
	var s Store
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Server: "https://rmm.example.com", DeviceID: "d1"}
	p := &Pending{Server: cfg.Server, Token: "ert_x"}
	_, _, loadErr := s.Load()
	_, _, pendingErr := s.LoadPending()
	_, caErr := s.SaveCA([]byte("ca"))
	_, statusErr := s.LoadStatus()
	for name, err := range map[string]error{
		"Load": loadErr, "LoadPending": pendingErr, "SaveCA": caErr, "LoadStatus": statusErr,
		"Save": s.Save(cfg, key), "SavePending": s.SavePending(p, key), "UpdatePending": s.UpdatePending(p),
		"SaveConfig": s.SaveConfig(cfg), "Approved": s.Approved(cfg), "SaveStatus": s.SaveStatus(Status{}),
		"Remove": s.Remove(),
	} {
		if !errors.Is(err, errNotOpened) {
			t.Errorf("%s on an unchecked store: %v", name, err)
		}
	}
	if s.Dir() != "" {
		t.Errorf("dir = %q", s.Dir())
	}
}

// TestLayout: what the check covers is what the agent's packages read and
// write in the folder.
func TestLayout(t *testing.T) {
	var names []string
	for _, group := range layout {
		names = append(names, group...)
	}
	all := strings.Join(names, " ")
	for _, want := range []string{configFile, keyFile, pendingFile, caFile, statusFile, ".tmp-*", "removal.json", "update.json",
		"logs", filepath.Join("logs", "*"), "jobs", filepath.Join("jobs", "journal", "*"), "easypatch", filepath.Join("easypatch", "*")} {
		if !strings.Contains(" "+all+" ", " "+want+" ") {
			t.Errorf("the check leaves out %s", want)
		}
	}
	if strings.Contains(all, "work") {
		t.Error("the scripts' working folders are checked")
	}
	if len(layout[0]) != 4 || layout[0][1] != keyFile {
		t.Errorf("the enrollment is not one group: %v", layout[0])
	}
}

// TestCAFile keeps a copy of the certificate authority in the folder.
func TestCAFile(t *testing.T) {
	s := open(t)
	path, err := s.SaveCA([]byte("ca"))
	if err != nil || path != filepath.Join(s.Dir(), caFile) {
		t.Fatalf("SaveCA = %s, %v", path, err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "ca" {
		t.Errorf("ca.pem = %q, %v", b, err)
	}
}

func TestStatus(t *testing.T) {
	s := open(t)
	if err := os.MkdirAll(s.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
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
	if err := os.RemoveAll(s.Dir()); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveStatus(st); err == nil {
		t.Error("status saved into a missing directory")
	}
}

func TestPendingEnrollment(t *testing.T) {
	s := open(t)
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
		st, err := os.Stat(filepath.Join(s.Dir(), pendingFile))
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
	if err := os.WriteFile(filepath.Join(s.Dir(), pendingFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LoadPending(); err == nil {
		t.Error("damaged pending file accepted")
	}
	if err := os.WriteFile(filepath.Join(s.Dir(), pendingFile), []byte(`{"server":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LoadPending(); err == nil {
		t.Error("pending file without a token accepted")
	}
}

func TestRecoveryCopy(t *testing.T) {
	s := open(t)
	exe := filepath.Join(t.TempDir(), "easyrmm-agent")
	if err := os.WriteFile(exe, []byte("build one"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.KeepRecovery(exe); err != nil {
		t.Fatal(err)
	}
	cp := s.RecoveryCopy(exe)
	if cp != filepath.Join(s.Dir(), "recovery", "easyrmm-agent") {
		t.Errorf("copy at %s", cp)
	}
	st, err := os.Stat(cp)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if runtime.GOOS != "windows" {
		// Windows has no modes; its access lists are the host package's.
		if st.Mode().Perm() != 0o700 {
			t.Errorf("copy mode %v", st.Mode().Perm())
		}
		if d, err := os.Stat(filepath.Dir(cp)); err != nil || d.Mode().Perm() != 0o700 {
			t.Errorf("folder: %v", err)
		}
	}
	// A new build replaces it, and nothing is left beside it.
	if err := os.WriteFile(exe, []byte("build two"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.KeepRecovery(exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cp); string(b) != "build two" {
		t.Errorf("copy = %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(cp), "*")); len(left) != 1 {
		t.Errorf("recovery folder holds %v", left)
	}
	if err := s.RemoveRecovery(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(cp)); err == nil {
		t.Error("recovery folder kept")
	}
	if err := s.RemoveRecovery(); err != nil {
		t.Errorf("removing what is not there: %v", err)
	}
	if err := s.KeepRecovery(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("kept a copy of a program that is not there")
	}
	var unopened Store
	if err := unopened.KeepRecovery(exe); !errors.Is(err, errNotOpened) {
		t.Errorf("unchecked store: %v", err)
	}
	if err := unopened.RemoveRecovery(); !errors.Is(err, errNotOpened) {
		t.Errorf("unchecked store: %v", err)
	}
}

func TestEscrowKeyVersionIsKept(t *testing.T) {
	s := open(t)
	if err := s.protect(); err != nil {
		t.Fatal(err)
	}
	if k := s.LoadEscrowKey(); k != (EscrowKey{}) {
		t.Fatalf("empty store: %+v", k)
	}
	if err := s.SaveEscrowKey(EscrowKey{KeyID: "k1", Version: 3}); err != nil {
		t.Fatal(err)
	}
	if k := s.LoadEscrowKey(); k.KeyID != "k1" || k.Version != 3 {
		t.Fatalf("loaded: %+v", k)
	}
	// A damaged file is no version, not a crash.
	if err := os.WriteFile(filepath.Join(s.Dir(), escrowFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if k := s.LoadEscrowKey(); k != (EscrowKey{}) {
		t.Fatalf("damaged file: %+v", k)
	}
}

func TestPackageRecord(t *testing.T) {
	s := Store{dir: t.TempDir()}
	if _, err := s.LoadPackage(); !errors.Is(err, ErrNoPackage) {
		t.Fatalf("no record: %v", err)
	}
	want := &Package{Kind: "deb", Was: "rpm", Made: true, At: time.Now().UTC().Truncate(time.Second), Note: "x"}
	if err := s.SavePackage(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadPackage()
	if err != nil || got.Kind != "deb" || got.Was != "rpm" || !got.Made || got.Note != "x" {
		t.Fatalf("LoadPackage = %+v, %v", got, err)
	}
	if err := s.RemovePackage(); err != nil {
		t.Fatal(err)
	}
	if err := s.RemovePackage(); err != nil {
		t.Errorf("removing twice: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, packageFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadPackage(); err == nil || errors.Is(err, ErrNoPackage) {
		t.Errorf("a damaged record: %v", err)
	}
	// A store that Open did not make reads and writes nothing.
	if _, err := (Store{}).LoadPackage(); err == nil {
		t.Error("an unopened store read the record")
	}
}
