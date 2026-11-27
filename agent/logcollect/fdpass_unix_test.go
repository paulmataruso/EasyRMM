//go:build !windows

package logcollect

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditDescriptorsCrossTheSocket(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit")
	if err := os.Mkdir(audit, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(audit, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("audit.log", "current\n")
	write("audit.log.1", "newer rotated\n")
	write("audit.log.2", "older rotated\n")
	write("other.txt", "ignored")

	sock := filepath.Join(dir, "a.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeAudit(ctx, sock, func() ([]*os.File, error) { return AuditFiles(audit) }) }()
	var files []*os.File
	var err error
	for range 50 { // the listener starts in the background
		if files, err = FetchAudit(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range files {
		b, _ := io.ReadAll(f)
		got = append(got, string(b))
		_ = f.Close()
	}
	want := []string{"older rotated\n", "newer rotated\n", "current\n"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("got %q, want oldest first", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAuditFilesWithNoLog(t *testing.T) {
	if _, err := AuditFiles(t.TempDir()); err == nil {
		t.Fatal("no audit log, no error")
	}
}
