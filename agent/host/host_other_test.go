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
