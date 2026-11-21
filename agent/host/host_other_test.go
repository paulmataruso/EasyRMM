//go:build !windows

package host

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtect(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := Protect(dir); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("mode = %v, %v", st.Mode().Perm(), err)
	}
	if IsAdmin() != (os.Geteuid() == 0) || SystemServices(Paths{}) == nil {
		t.Error("system checks")
	}
	_ = ServicesAvailable()
}

func TestExec(t *testing.T) {
	out, err := Exec(context.Background(), "sh", "-c", "echo hello")
	if err != nil || strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("Exec = %q, %v", out, err)
	}
	if _, err := Exec(context.Background(), "sh", "-c", "echo oops >&2; exit 3"); err == nil || !strings.Contains(err.Error(), "oops") {
		t.Errorf("failing command: %v", err)
	}
	_ = Available() // depends on the machine; must not panic
}

// TestCheckStateElsewhere: outside Windows only root reaches the state
// folder, and the check changes nothing: it makes no folder and moves
// nothing aside, even what Windows would.
func TestCheckStateElsewhere(t *testing.T) {
	p := Paths{Root: t.TempDir()}
	layout := [][]string{{"agent.json"}, {filepath.Join("logs", "*")}}
	if c, err := p.CheckState(layout); err != nil || len(c.Aside) != 0 || len(c.Reprotected) != 0 {
		t.Fatalf("check: %v, changed %+v", err, c)
	}
	if _, err := os.Stat(p.State()); !os.IsNotExist(err) {
		t.Errorf("the check made the state folder: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(p.State(), "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.State(), "agent.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(p.State(), "logs", "linked")); err != nil {
		t.Fatal(err)
	}
	if c, err := p.CheckState(layout); err != nil || len(c.Aside) != 0 || len(c.Reprotected) != 0 {
		t.Fatalf("check: %v, changed %+v", err, c)
	}
	for _, f := range []string{"agent.json", filepath.Join("logs", "linked")} {
		if _, err := os.Lstat(filepath.Join(p.State(), f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}
