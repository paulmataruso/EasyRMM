package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStableRefusesWhatCannotBeOffered(t *testing.T) {
	for name, dir := range map[string]string{"missing": filepath.Join(t.TempDir(), "nope"), "empty": t.TempDir(), "unset": ""} {
		if _, err := loadStable(dir); err == nil || !strings.Contains(err.Error(), "EASYRMM_DEV_SCOPE_ORG") {
			t.Errorf("%s: %v", name, err)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "easyrmm-agent-linux-amd64"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := loadStable(dir); err != nil || len(b.List()) != 1 {
		t.Errorf("loaded: %v", err)
	}
}
