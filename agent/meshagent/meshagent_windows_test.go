//go:build windows

package meshagent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/agent/host"
)

// gone reports whether a process has exited.
func gone(pid uint32) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return true
	}
	defer func() { _ = windows.CloseHandle(h) }()
	ev, _ := windows.WaitForSingleObject(h, 0)
	return ev == windows.WAIT_OBJECT_0
}

func childPID(t *testing.T, dir string) uint32 {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(filepath.Join(dir, "child.pid")); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				return uint32(n)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("the stand-in's child process did not start")
	return 0
}

// TestForceStopAndRepairOnWindows runs a real service that ignores stop
// requests and has a child process of the same program, and checks that
// Restart and Repair succeed against it, and leave another MeshAgent of the
// same name alone.
func TestForceStopAndRepairOnWindows(t *testing.T) {
	if !host.IsAdmin() {
		t.Skip("installing a service needs an elevated test")
	}
	stub := filepath.Join(t.TempDir(), "stubagent.exe")
	if out, err := exec.Command("go", "build", "-o", stub, "./testdata/stubagent").CombinedOutput(); err != nil {
		t.Fatalf("building the stand-in: %v\n%s", err, out)
	}
	image, err := os.ReadFile(stub)
	if err != nil {
		t.Fatal(err)
	}
	download := func(w io.Writer) error { _, err := io.Copy(w, bytes.NewReader(image)); return err }

	m := NewManager(filepath.Join(t.TempDir(), "MeshAgent"), ModeService, host.WindowsServices{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	t.Cleanup(func() {
		_ = m.Services.Remove(ctx, WindowsService)
		_, _ = host.StopImage(m.binary())
	})

	// Another vendor's MeshAgent: the same name in another folder.
	other := filepath.Join(t.TempDir(), "meshagent.exe")
	if err := os.WriteFile(other, image, 0o755); err != nil { //nolint:gosec // a test program
		t.Fatal(err)
	}
	bystander := exec.Command(other, "-kvm1")
	if err := bystander.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bystander.Process.Kill() })

	if err := m.Repair(ctx, download, []byte("MeshID=0x1\n")); err != nil {
		t.Fatalf("the first repair: %v", err)
	}
	child := childPID(t, m.Dir)

	_ = os.Remove(filepath.Join(m.Dir, "child.pid"))
	if err := m.Restart(ctx); err != nil {
		t.Fatalf("Restart against a service that ignores stop: %v", err)
	}
	if got := m.Services.State(ctx, WindowsService); got != "running" {
		t.Fatalf("after Restart the service is %s", got)
	}
	if !gone(child) {
		t.Error("the child process of the old service survived the restart")
	}
	child = childPID(t, m.Dir)

	_ = os.Remove(filepath.Join(m.Dir, "child.pid"))
	if err := m.Repair(ctx, download, []byte("MeshID=0x1\n")); err != nil {
		t.Fatalf("Repair against a service that ignores stop: %v", err)
	}
	if got := m.Services.State(ctx, WindowsService); got != "running" {
		t.Fatalf("after Repair the service is %s", got)
	}
	if !gone(child) {
		t.Error("the child process survived the repair")
	}
	if gone(uint32(bystander.Process.Pid)) {
		t.Error("another vendor's MeshAgent, from another folder, was terminated")
	}
	if left, _ := filepath.Glob(filepath.Join(m.Dir, ".meshagent-*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}
