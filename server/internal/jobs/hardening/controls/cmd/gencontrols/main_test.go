package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/jobs/hardening/controls"
)

func TestRunRegenerates(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("../..")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, controls.RelatedFile)); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), dir, ""); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, controls.RelatedFile))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("../..", controls.RelatedFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("run wrote a related.json other than the checked-in one")
	}
}

func TestRunRefuses(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if err := run(context.Background(), missing, ""); err == nil {
		t.Error("run accepted a directory without cites.json")
	}
	if err := run(context.Background(), missing, t.TempDir()); err == nil {
		t.Error("run extracted from an empty directory")
	}
}
