package vmtest

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests run the guest's runner (runner.sh) on this computer, over
// pipes instead of the virtio-serial port, with the host's side of the
// protocol. They only run harmless scripts in temporary directories, and
// never VM.Restart, which would restart this computer.

type localRunner struct {
	ch   *channel
	boot string
	cmd  *exec.Cmd
}

func startRunner(t *testing.T) *localRunner {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the runner is a Linux script")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "runner.sh")
	if err := os.WriteFile(script, runnerScript, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", script)
	cmd.Env = append(os.Environ(), "EASYRMM_HARNESS_DIR="+filepath.Join(dir, "work"))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() && stderr.Len() > 0 {
			t.Logf("runner's stderr: %s", stderr.String())
		}
	})
	r := &localRunner{ch: newChannel(stdout, stdin), cmd: cmd}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if r.boot, err = r.ch.ping(ctx); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *localRunner) exec(t *testing.T, script string) result {
	t.Helper()
	res, err := r.ch.exec(t.Context(), r.boot, script, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestRunnerPing(t *testing.T) {
	r := startRunner(t)
	want, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	if r.boot != strings.TrimSpace(string(want)) {
		t.Errorf("boot id %q, want %q", r.boot, want)
	}
}

func TestRunnerExec(t *testing.T) {
	r := startRunner(t)
	res := r.exec(t, "echo out; echo err >&2; exit 3")
	if string(res.stdout) != "out\n" || string(res.stderr) != "err\n" || res.exit != 3 {
		t.Errorf("got %q %q %d", res.stdout, res.stderr, res.exit)
	}
	res = r.exec(t, ":")
	if len(res.stdout) != 0 || len(res.stderr) != 0 || res.exit != 0 {
		t.Errorf("empty script: %q %q %d", res.stdout, res.stderr, res.exit)
	}
	// Standard input is /dev/null, not the channel.
	res = r.exec(t, "cat; echo done")
	if string(res.stdout) != "done\n" {
		t.Errorf("stdin: %q", res.stdout)
	}
	res = r.exec(t, `printf '\000\001\377\n\r'`)
	if !bytes.Equal(res.stdout, []byte{0, 1, 0xff, '\n', '\r'}) {
		t.Errorf("binary output %q", res.stdout)
	}
}

func TestRunnerLargeScriptAndOutput(t *testing.T) {
	r := startRunner(t)
	big := strings.Repeat("0123456789abcdef", 1<<16) // 1 MiB
	res := r.exec(t, "cat <<'EOF'\n"+big+"\nEOF\nhead -c 3000000 /dev/zero")
	if want := big + "\n" + strings.Repeat("\x00", 3000000); string(res.stdout) != want || res.exit != 0 {
		t.Errorf("got %d bytes, exit %d; want %d bytes", len(res.stdout), res.exit, len(want))
	}
}

func TestRunnerTimeout(t *testing.T) {
	r := startRunner(t)
	start := time.Now()
	res, err := r.ch.exec(t.Context(), r.boot, "echo started; sleep 30", 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if res.exit != 124 || string(res.stdout) != "started\n" {
		t.Errorf("got %q exit %d, want started and 124", res.stdout, res.exit)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %s", d)
	}
}

func TestRunnerRefusesAnotherBoot(t *testing.T) {
	r := startRunner(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	_, err := r.ch.exec(t.Context(), "an-earlier-boot", "touch "+shellQuote(marker), time.Minute)
	if !errors.Is(err, errStale) {
		t.Fatalf("got %v, want errStale", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the stale script ran: %v", err)
	}
	if res := r.exec(t, "echo still in step"); string(res.stdout) != "still in step\n" {
		t.Errorf("after the refusal: %q", res.stdout)
	}
}

func TestRunnerRefusals(t *testing.T) {
	r := startRunner(t)
	for name, tc := range map[string]struct {
		frame string // %[1]s is the id, %[2]s the boot id
		want  string
	}{
		"short length": {"X %[1]s %[2]s 5 3\nZWNobyBoaQ==\n", "framing"},
		"bad base64":   {"X %[1]s %[2]s 5 4\n@@@@\n", "base64"},
		"bad timeout":  {"X %[1]s %[2]s soon 4\nZWNo\n", "request"},
		"bad length":   {"X %[1]s %[2]s 5 -4\nZWNo\n", "request"},
	} {
		t.Run(name, func(t *testing.T) {
			f, err := r.ch.call(t.Context(), "RE", func(id string) []byte {
				return fmt.Appendf(nil, tc.frame, id, r.boot)
			})
			if err != nil {
				t.Fatal(err)
			}
			if f[0] != "E" || len(f) < 3 || f[2] != tc.want {
				t.Errorf("got %q, want E … %s", f, tc.want)
			}
			// The stream is still in step.
			if res := r.exec(t, "echo ok"); string(res.stdout) != "ok\n" {
				t.Errorf("after the refusal: %q", res.stdout)
			}
		})
	}
}

func TestRunnerSkipsNoise(t *testing.T) {
	r := startRunner(t)
	if _, err := r.ch.w.Write([]byte("hello\n\nP\nX 1 2\nR 3 0  \nZm9v\n")); err != nil {
		t.Fatal(err)
	}
	if res := r.exec(t, "echo ok"); string(res.stdout) != "ok\n" {
		t.Errorf("after noise: %q", res.stdout)
	}
}

func TestRunnerConcurrentCalls(t *testing.T) {
	r := startRunner(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			res, err := r.ch.exec(t.Context(), r.boot, fmt.Sprintf("echo %d", i), time.Minute)
			if err != nil || string(res.stdout) != fmt.Sprintf("%d\n", i) {
				t.Errorf("call %d: %q, %v", i, res.stdout, err)
			}
		})
	}
	wg.Wait()
}

func TestChannelStops(t *testing.T) {
	r := startRunner(t)
	done := make(chan error, 1)
	go func() {
		_, err := r.ch.exec(t.Context(), r.boot, "sleep 30", time.Minute)
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	_ = r.cmd.Process.Kill()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a call survived the runner")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the pending call did not end")
	}
	if _, err := r.ch.ping(t.Context()); err == nil {
		t.Error("a ping after the channel closed succeeded")
	}
}

func TestChannelCallEndsWithContext(t *testing.T) {
	r := startRunner(t)
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if _, err := r.ch.exec(ctx, r.boot, "sleep 2", time.Minute); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v", err)
	}
	// The runner finishes the abandoned script, then answers the next.
	if res := r.exec(t, "echo next"); string(res.stdout) != "next\n" {
		t.Errorf("next: %q", res.stdout)
	}
}

// Before the runner opens its port nothing reads the socket, and a write
// waits. net.Pipe's writes wait for a reader in the same way.
func TestChannelWriteEndsWithContext(t *testing.T) {
	host, guest := net.Pipe()
	defer host.Close()
	defer guest.Close()
	c := newChannel(host, host)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.ping(ctx); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("ping nobody reads: %v after %s", err, time.Since(start))
	}

	// A runner that answers pings: the channel still works, and the write
	// deadline is gone.
	go func() {
		r := bufio.NewReader(guest)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if f := strings.Fields(line); len(f) == 2 && f[0] == "P" {
				_, _ = fmt.Fprintf(guest, "P %s boot-1\n", f[1])
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	if boot, err := c.ping(t.Context()); err != nil || boot != "boot-1" {
		t.Errorf("ping after a timed-out write: %q, %v", boot, err)
	}
}

// The same over a Unix socket whose buffer is full, as the harness socket
// gets when a machine never opens its port and the pings pile up.
func TestChannelWriteToAFullSocket(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var d net.Dialer
	host, err := d.DialContext(t.Context(), "unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	guest, err := ln.Accept() // and never reads
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	for filled := false; !filled; {
		_ = host.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := host.Write([]byte("P 0\n"))
		filled = errors.Is(err, os.ErrDeadlineExceeded)
		if err != nil && !filled {
			t.Fatal(err)
		}
	}
	_ = host.SetWriteDeadline(time.Time{})

	c := newChannel(host, host)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.ping(ctx); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Errorf("ping into a full socket: %v after %s", err, time.Since(start))
	}
}

// A request cut short midway would leave the runner reading the rest of it:
// the channel stops.
func TestChannelStopsOnAPartialWrite(t *testing.T) {
	host, guest := net.Pipe()
	defer host.Close()
	defer guest.Close()
	c := newChannel(host, host)
	go func() { _, _ = io.ReadFull(guest, make([]byte, 10)) }() // then stops reading

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	_, err := c.exec(ctx, "boot-1", strings.Repeat("echo x\n", 1000), time.Minute)
	if err == nil || !strings.Contains(err.Error(), "10 of ") {
		t.Fatalf("exec: %v", err)
	}
	if _, err := c.ping(t.Context()); err == nil || !strings.Contains(err.Error(), "bytes sent") {
		t.Errorf("ping after a partial write: %v", err)
	}
}

// waitRunner takes the runner's boot, waits out the boot before a restart,
// and says when QEMU exited under it.
func TestVMWaitRunner(t *testing.T) {
	r := startRunner(t)
	vm := &VM{t: t, image: Image{Name: "local"}, ch: r.ch, exited: make(chan struct{})}
	if err := vm.waitRunner(t.Context(), ""); err != nil || vm.bootID != r.boot {
		t.Fatalf("boot %q, %v; want %q", vm.bootID, err, r.boot)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	err := vm.waitRunner(ctx, r.boot)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "still the boot before the restart") {
		t.Errorf("waiting for another boot: %v", err)
	}

	// The channel breaks just before QEMU's exit is known.
	_ = r.cmd.Process.Kill()
	go func() {
		time.Sleep(200 * time.Millisecond)
		vm.waitErr = errors.New("signal: terminated")
		close(vm.exited)
	}()
	if err := vm.waitRunner(t.Context(), ""); err == nil || !strings.HasPrefix(err.Error(), "QEMU exited (signal: terminated): ") {
		t.Errorf("after QEMU exited: %v", err)
	}
}

// VM.Run and VM.WriteFile need only the channel, so they run against the
// local runner too.
func TestVMRunAndWriteFile(t *testing.T) {
	r := startRunner(t)
	vm := &VM{t: t, image: Image{Name: "local"}, ch: r.ch, bootID: r.boot}

	stdout, stderr, exit, err := vm.Run(t.Context(), "echo hi; echo there >&2; exit 4")
	if err != nil || string(stdout) != "hi\n" || string(stderr) != "there\n" || exit != 4 {
		t.Errorf("Run: %q %q %d %v", stdout, stderr, exit, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, _, exit, err := vm.Run(ctx, "sleep 1; echo slept"); err != nil || exit != 0 {
		t.Errorf("Run within a deadline: exit %d, %v", exit, err)
	}

	path := filepath.Join(t.TempDir(), "it's a file")
	data := []byte("line\n\x00\xff'\"$(x)`y`\n")
	if err := vm.WriteFile(t.Context(), path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, data) {
		t.Errorf("read back %q, %v", got, err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, %v", st.Mode(), err)
	}
	// An existing file is truncated and gets the new mode.
	if err := vm.WriteFile(t.Context(), path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "short" {
		t.Errorf("rewritten: %q, %v", got, err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("rewritten mode %v, %v", st.Mode(), err)
	}
	err = vm.WriteFile(t.Context(), filepath.Join(t.TempDir(), "missing", "file"), data, 0o600)
	if err == nil || !strings.Contains(err.Error(), "exit") {
		t.Errorf("into a missing directory: %v", err)
	}

	vm.bootID = "an-earlier-boot"
	if _, _, _, err := vm.Run(t.Context(), "true"); !errors.Is(err, errStale) {
		t.Errorf("for an earlier boot: %v", err)
	}
}
