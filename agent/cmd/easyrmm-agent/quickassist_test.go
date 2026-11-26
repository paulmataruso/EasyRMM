package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/agent/quickassist"
)

func TestQuickAssistCommand(t *testing.T) {
	h := newHarness(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"quick-assist", "--bogus"}, "bogus"},
		{[]string{"quick-assist", "extra"}, "takes no arguments"},
		{[]string{"quick-assist", "--poll=-1s"}, "too short"},
		{[]string{"quick-assist", "--poll=1ms"}, "too short"},
	} {
		if err := h.run(c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.args, err, c.want)
		}
	}

	// --clean removes the folders a crashed session left, and only those.
	base := t.TempDir()
	left := filepath.Join(base, quickassist.FolderPrefix+"old")
	keep := filepath.Join(base, "other")
	for _, d := range []string{left, keep} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.run("quick-assist", "--clean", "--base-dir", base); err != nil {
		t.Fatalf("clean: %v", err)
	}
	if !strings.Contains(h.out.String(), "Removed 1 leftover") {
		t.Errorf("output: %q", h.out.String())
	}
	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Errorf("leftover folder remains: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("an unrelated folder was removed: %v", err)
	}
	if err := h.run("quick-assist", "--clean", "--base-dir", filepath.Join(base, "missing")); err == nil {
		t.Error("clean of a missing folder: no error")
	}

	// Without a ticket in the program, a run is refused before any contact.
	self := filepath.Join(t.TempDir(), "prog")
	if err := os.WriteFile(self, []byte("not a program with a ticket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.run("quick-assist", "--self", self, "--base-dir", t.TempDir()); err == nil {
		t.Error("run without a ticket: no error")
	}
}
