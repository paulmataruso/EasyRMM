//go:build vm

package vmtest_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/vmtest"
)

// TestSmoke boots each image chosen by EASYRMM_VM_IMAGE (all without it)
// and drives it through the whole API: scripts, a file, a forwarded port,
// a restart. Run it with `make test-vm`.
func TestSmoke(t *testing.T) {
	for _, name := range vmtest.Selected(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			smoke(t, name)
		})
	}
}

func smoke(t *testing.T, name string) {
	vm := vmtest.Boot(t, name, vmtest.Options{Forward: []int{22}})
	ctx := t.Context()

	if out := run(t, vm, "id -u"); out != "0" {
		t.Errorf("id -u: %q, want 0", out)
	}
	osRelease := run(t, vm, "cat /etc/os-release")
	id, version := osReleaseValue(osRelease, "ID"), osReleaseValue(osRelease, "VERSION_ID")
	t.Logf("os-release: ID=%s VERSION_ID=%s", id, version)
	wantID, wantVersion, _ := strings.Cut(name, "-")
	if wantID == "alma" {
		wantID = "almalinux"
	}
	if id != wantID || (version != wantVersion && !strings.HasPrefix(version, wantVersion+".")) {
		t.Errorf("os-release: ID=%s VERSION_ID=%s, want %s %s", id, version, wantID, wantVersion)
	}
	if state, err := vm.WaitBooted(ctx); err != nil || state != "running" {
		t.Errorf("systemd: %q, %v; want running", state, err)
	}

	// Every byte value, line ends and a trailing NUL survive the trip.
	data := make([]byte, 0, 600)
	for i := range 512 {
		data = append(data, byte(i))
	}
	data = append(data, "\r\nlast line\n\x00"...)
	const path = "/root/easyrmm smoke's file"
	if err := vm.WriteFile(ctx, path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	if got := run(t, vm, `stat -c '%a %U:%G' "/root/easyrmm smoke's file"`); got != "640 root:root" {
		t.Errorf("mode and owner: %q, want 640 root:root", got)
	}
	stdout, _, _, err := vm.Run(ctx, `cat "/root/easyrmm smoke's file"`)
	if err != nil || !bytes.Equal(stdout, data) {
		t.Errorf("read back %d bytes (%v), wrote %d", len(stdout), err, len(data))
	}

	// The guest's sshd answers through the forwarded port.
	banner := sshBanner(t, vm.HostPort(22))
	t.Logf("sshd through 127.0.0.1:%d: %s", vm.HostPort(22), banner)
	if !strings.HasPrefix(banner, "SSH-2.0-") {
		t.Errorf("banner %q, want SSH-2.0-…", banner)
	}

	before := run(t, vm, "cat /proc/sys/kernel/random/boot_id")
	if err := vm.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	if after := run(t, vm, "cat /proc/sys/kernel/random/boot_id"); after == before {
		t.Errorf("boot id %s unchanged by the restart", after)
	}
	if state, err := vm.WaitBooted(ctx); err != nil || state != "running" {
		t.Errorf("systemd after the restart: %q, %v; want running", state, err)
	}
	stdout, _, _, err = vm.Run(ctx, `cat "/root/easyrmm smoke's file"`)
	if err != nil || !bytes.Equal(stdout, data) {
		t.Errorf("after the restart, read back %d bytes (%v), wrote %d", len(stdout), err, len(data))
	}
	if banner := sshBanner(t, vm.HostPort(22)); !strings.HasPrefix(banner, "SSH-2.0-") {
		t.Errorf("after the restart, banner %q", banner)
	}

	if err := vm.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// run runs a script that must succeed and returns its trimmed output.
func run(t *testing.T, vm *vmtest.VM, script string) string {
	t.Helper()
	stdout, stderr, exit, err := vm.Run(t.Context(), script)
	if err != nil {
		t.Fatalf("%s: %v", script, err)
	}
	if exit != 0 {
		t.Fatalf("%s: exit %d: %s", script, exit, stderr)
	}
	return strings.TrimSpace(string(stdout))
}

func osReleaseValue(osRelease, key string) string {
	for line := range strings.Lines(osRelease) {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), key+"="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// sshBanner reads the server's first line through the forwarded port. QEMU
// accepts on the host before the guest does, so a refusal in the guest
// reads as a closed connection: try again for a while.
func sshBanner(t *testing.T, port int) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	var last error
	for ctx.Err() == nil {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(time.Minute))
			line, rerr := bufio.NewReader(conn).ReadString('\n')
			_ = conn.Close()
			if rerr == nil {
				return strings.TrimSpace(line)
			}
			err = rerr
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("no SSH banner on 127.0.0.1:%d: %v", port, last)
	return ""
}
