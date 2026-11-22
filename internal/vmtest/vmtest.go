// Package vmtest boots Linux distributions' cloud images under QEMU for
// tests that need a whole machine: systemd, a firewall, sshd, restarts
// (ADR-0051, "Testing").
//
//	vm := vmtest.Boot(t, "debian-12", vmtest.Options{Forward: []int{22}})
//	stdout, stderr, exit, err := vm.Run(ctx, "sshd -T")
//	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", vm.HostPort(22)))
//
// Each machine boots from a qcow2 overlay on the pinned image (images.go),
// which is downloaded once into EASYRMM_VM_CACHE and checked against its
// vendor's digest every time a test process first uses it. The overlay is
// deleted when the test ends.
//
// The network is QEMU's user networking: the machine reaches the host as
// 10.0.2.2, and the host reaches the guest ports in Options.Forward on
// 127.0.0.1. There is never a bridge or a tap device.
//
// Tests drive the machine over a virtio-serial port, not over its network,
// so that a firewall or a ban the test applies cannot cut them off.
// cloud-init, seeded over HTTP by the harness (NoCloud, named in the
// machine's SMBIOS serial number; a CD-ROM where cloud-init cannot take
// that, see SeedISO), installs a small sh runner (runner.sh) that runs
// each script as root and answers with its output and exit code. The serial console is logged to a file, and its end is
// attached to a failed test's output.
//
// QEMU uses KVM when /dev/kvm can be opened, and otherwise emulates the
// processor (TCG), which works but takes minutes to boot.
package vmtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// LogDirEnv names a directory that receives each machine's serial console
// log when the machine is closed, for CI to keep after a failure.
const LogDirEnv = "EASYRMM_VM_LOG_DIR"

// DefaultRunTimeout bounds a script whose context has no deadline.
const DefaultRunTimeout = 30 * time.Minute

// Options configure a machine. The zero value is a usable machine without
// forwarded ports.
type Options struct {
	// Forward lists guest TCP ports to reach from the host, each on a free
	// port of 127.0.0.1 that HostPort returns.
	Forward []int
	// MemoryMB is the machine's memory: 2048 when zero.
	MemoryMB int
	// CPUs is its number of processors: 2 with KVM and 4 without when
	// zero.
	CPUs int
	// DiskGB is the least size of its disk: the image's own size or 10 GB,
	// whichever is larger, when zero.
	DiskGB int
	// BootTimeout bounds Boot and each Restart, from starting until
	// systemd has finished starting the machine: 10 minutes with KVM and
	// 45 without when zero.
	BootTimeout time.Duration
	// Disks are emulated disks beside the boot disk, for tests of the
	// disks' own interfaces (the agent's hardware reader).
	Disks []Disk
}

// Disk kinds.
const (
	// DiskNVMe is an NVMe controller (-device nvme) with one namespace.
	DiskNVMe = "nvme"
	// DiskSATA is a disk (ide-hd) on an AHCI controller (-device ahci),
	// which the guest's kernel drives through libata.
	DiskSATA = "sata"
)

// Disk is an emulated disk, backed by a sparse file of 64 MiB in the
// machine's directory.
type Disk struct {
	// ID names the device, for QOMSet: letters, digits, "-" and "_".
	ID   string
	Kind string
	// Model replaces QEMU's own model ("QEMU HARDDISK") of a SATA disk.
	// QEMU's NVMe controller, up to 10.2 at least, has no such property,
	// so an NVMe disk with a model is refused.
	Model  string
	Serial string
}

// QOMSet sets a property of one of the machine's devices, as QMP's
// qom-set does: how a test changes what an emulated device reports, such
// as an NVMe controller's smart_critical_warning.
func (vm *VM) QOMSet(id, property string, value any) error {
	_, err := vm.qmp.execute("qom-set", map[string]any{"path": "/machine/peripheral/" + id, "property": property, "value": value})
	if err != nil {
		return fmt.Errorf("%s: %w", vm.image.Name, err)
	}
	return nil
}

// VM is a running machine. Its methods may be called concurrently; the
// machine runs one script at a time, in the order they arrive.
type VM struct {
	t     testing.TB
	image Image
	m     machine
	dir   string // the overlay and logs
	ports map[int]int
	boot  time.Duration

	cmd     *exec.Cmd
	cancel  context.CancelFunc
	exited  chan struct{} // closed when QEMU has exited
	waitErr error         // QEMU's exit, once exited is closed

	seed *seedServer
	qmp  *qmp
	conn io.Closer // the harness socket
	ch   *channel

	mu     sync.Mutex
	bootID string // of the boot scripts are sent for

	closeOnce sync.Once
	closeErr  error
	report    string // what a failed test shows, kept by Close
}

// Boot starts a machine from the named image and returns once systemd has
// finished starting it (running or degraded; see WaitBooted). It fails the
// test when the machine does not get that far. The machine is stopped and
// its disk deleted when the test ends.
func Boot(t testing.TB, image string, opts Options) *VM {
	t.Helper()
	img, err := lookup(image)
	if err != nil {
		t.Fatal(err)
	}
	progs := []string{"qemu-system-x86_64", "qemu-img"}
	if img.Seed == SeedISO {
		progs = append(progs, "xorriso")
	}
	for _, prog := range progs {
		if _, err := exec.LookPath(prog); err != nil {
			t.Fatalf("%s is needed to boot %s: %v", prog, img.Name, err)
		}
	}
	if opts.MemoryMB == 0 {
		opts.MemoryMB = 2048
	}
	if opts.DiskGB == 0 {
		opts.DiskGB = 10
	}
	accel := "tcg"
	if usableKVM() {
		accel = "kvm"
	}
	if opts.CPUs == 0 {
		// Emulated with two, Fedora 45's udev does not start within
		// systemd's 90 seconds for the disks to appear.
		opts.CPUs = 2
		if accel == "tcg" {
			opts.CPUs = 4
		}
	}
	if opts.BootTimeout == 0 {
		opts.BootTimeout = 10 * time.Minute
		if accel == "tcg" {
			opts.BootTimeout = 45 * time.Minute
		}
	}

	ctx := t.Context()
	cache := cacheDir()
	base, err := fetch(ctx, filepath.Join(cache, "images"), img, t.Logf)
	if err != nil {
		t.Fatal(err)
	}

	vm := &VM{t: t, image: img, boot: opts.BootTimeout, exited: make(chan struct{})}
	t.Cleanup(func() {
		if err := vm.Close(); err != nil {
			t.Errorf("closing %s: %v", img.Name, err)
		}
		if t.Failed() {
			t.Logf("%s, after the failure:\n%s", img.Name, vm.report)
		}
	})
	if err := vm.start(ctx, base, accel, opts); err != nil {
		t.Fatalf("starting %s: %v", img.Name, err)
	}
	start := time.Now()
	bctx, cancel := context.WithTimeout(ctx, opts.BootTimeout)
	defer cancel()
	if err := vm.waitRunner(bctx, ""); err != nil {
		t.Fatalf("%s did not answer on the harness channel: %v", img.Name, err)
	}
	t.Logf("%s answers on the harness channel after %s (%s)", img.Name, time.Since(start).Round(time.Second), accel)
	state, err := vm.WaitBooted(bctx)
	if err != nil {
		t.Fatalf("%s did not finish starting: %v", img.Name, err)
	}
	t.Logf("%s booted in %s: %s", img.Name, time.Since(start).Round(time.Second), state)
	return vm
}

// start creates the overlay and starts QEMU and the seed server.
func (vm *VM) start(ctx context.Context, base, accel string, opts Options) error {
	var err error
	if err = os.MkdirAll(filepath.Join(cacheDir(), "run"), 0o750); err != nil {
		return err
	}
	if vm.dir, err = os.MkdirTemp(filepath.Join(cacheDir(), "run"), vm.image.Name+"-"); err != nil {
		return err
	}
	// Unix socket paths are short (108 bytes); the cache may be deep.
	sockets, err := os.MkdirTemp("", "easyrmm-vm-")
	if err != nil {
		return err
	}
	vm.m = machine{
		name:     "easyrmm-" + vm.image.Name,
		accel:    accel,
		memoryMB: opts.MemoryMB,
		cpus:     opts.CPUs,
		disk:     filepath.Join(vm.dir, "disk.qcow2"),
		sockets:  sockets,
		console:  filepath.Join(vm.dir, "console.log"),
		seedDS:   vm.image.Seed,
		forward:  opts.Forward,
	}

	if vm.m.disks, err = diskFiles(vm.dir, opts.Disks); err != nil {
		return err
	}
	size, err := virtualSize(ctx, base)
	if err != nil {
		return err
	}
	size = max(size, int64(opts.DiskGB)<<30)
	if out, err := exec.CommandContext(ctx, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", //nolint:gosec // the harness's own files
		"-b", base, vm.m.disk, strconv.FormatInt(size, 10)).CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img create: %w: %s", err, out)
	}

	idb := make([]byte, 8)
	_, _ = rand.Read(idb)
	hostname := "easyrmm-" + strings.ReplaceAll(vm.image.Name, ".", "-")
	seed := map[string][]byte{
		"meta-data":   metaData("easyrmm-vm-"+hex.EncodeToString(idb), hostname),
		"user-data":   userData(),
		"vendor-data": nil,
	}
	if vm.image.Seed == SeedISO {
		if vm.m.seedISO, err = seedISO(ctx, vm.dir, seed); err != nil {
			return err
		}
	} else {
		if vm.seed, err = startSeed(ctx, seed); err != nil {
			return err
		}
		vm.m.seedURL = vm.seed.url()
	}

	// QEMU outlives neither the test nor, through Pdeathsig, a test
	// process that is killed.
	qctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	vm.cancel = cancel
	vm.cmd = exec.CommandContext(qctx, "qemu-system-x86_64", qemuArgs(vm.m)...) //nolint:gosec // the harness's own command line
	vm.cmd.WaitDelay = 10 * time.Second
	killWithParent(vm.cmd)
	qlog, err := os.Create(filepath.Join(vm.dir, "qemu.log"))
	if err != nil {
		return err
	}
	vm.cmd.Stdout, vm.cmd.Stderr = qlog, qlog
	if err := vm.cmd.Start(); err != nil {
		_ = qlog.Close()
		return err
	}
	go func() {
		vm.waitErr = vm.cmd.Wait()
		_ = qlog.Close()
		close(vm.exited)
	}()

	dctx, dcancel := context.WithTimeout(ctx, time.Minute)
	defer dcancel()
	conn, err := dialUnix(dctx, vm.m.qmpSocket(), vm.exited)
	if err != nil {
		return err
	}
	if vm.qmp, err = newQMP(conn); err != nil {
		_ = conn.Close()
		return err
	}
	if vm.ports, err = vm.qmp.forwards(); err != nil {
		return err
	}
	for _, p := range opts.Forward {
		if vm.ports[p] == 0 {
			return fmt.Errorf("QEMU reports no forward for guest port %d", p)
		}
	}
	hconn, err := dialUnix(dctx, vm.m.harnessSocket(), vm.exited)
	if err != nil {
		return err
	}
	vm.conn = hconn
	vm.ch = newChannel(hconn, hconn)
	return nil
}

func virtualSize(ctx context.Context, image string) (int64, error) {
	out, err := exec.CommandContext(ctx, "qemu-img", "info", "-U", "--output=json", image).Output() //nolint:gosec // the harness's own files
	if err != nil {
		return 0, fmt.Errorf("qemu-img info %s: %w", image, err)
	}
	var info struct {
		VirtualSize int64 `json:"virtual-size"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return 0, fmt.Errorf("qemu-img info %s: %w", image, err)
	}
	if info.VirtualSize <= 0 {
		return 0, fmt.Errorf("qemu-img info %s: no virtual size", image)
	}
	return info.VirtualSize, nil
}

// waitRunner pings the runner until it answers from a boot other than
// notBoot, then sends scripts to that boot.
func (vm *VM) waitRunner(ctx context.Context, notBoot string) error {
	// What the pings found, for the error at ctx's end; not the ping that
	// end cut short.
	last := errors.New("no answer")
	for {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		boot, err := vm.ch.ping(pctx)
		cancel()
		switch {
		case err == nil && boot != notBoot:
			vm.mu.Lock()
			vm.bootID = boot
			vm.mu.Unlock()
			return nil
		case err == nil:
			last = errors.New("still the boot before the restart")
		case ctx.Err() == nil:
			last = errors.New("no answer")
		}
		select {
		case <-vm.exited:
			if vm.waitErr != nil {
				return fmt.Errorf("QEMU exited: %w", vm.waitErr)
			}
			return errors.New("QEMU exited")
		case <-ctx.Done():
			return fmt.Errorf("%w (last ping: %w)", ctx.Err(), last)
		default:
		}
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			// The channel itself failed, most likely because QEMU is
			// exiting: say so when it has.
			select {
			case <-vm.exited:
				if vm.waitErr != nil {
					return fmt.Errorf("QEMU exited (%w): %w", vm.waitErr, err)
				}
				return fmt.Errorf("QEMU exited: %w", err)
			case <-time.After(10 * time.Second):
				return err
			}
		}
		if err == nil {
			time.Sleep(time.Second) // the old boot answered; it is going down
		}
	}
}

// waitBootedScript waits until systemd has finished starting the machine
// (is-system-running --wait needs systemd 240; Rocky Linux 8 has 239) and
// prints the state, and when it is not "running" the failed units and the
// boot's errors.
const waitBootedScript = `while :; do
	state=$(systemctl is-system-running 2>/dev/null)
	case $state in
	initializing | starting) sleep 1 ;;
	*) break ;;
	esac
done
echo "$state"
if [ "$state" != running ]; then
	echo "failed units (unit, result):"
	systemctl list-units --all --state=failed --no-legend --plain 2>/dev/null |
		while read -r unit _; do
			echo "$unit $(systemctl show -p Result --value "$unit" 2>/dev/null)"
		done
	echo "errors this boot:"
	journalctl -b -p err -q --no-pager -o short-monotonic 2>/dev/null | tail -n 20
fi
`

// WaitBooted waits until systemd has finished starting the machine, and
// returns its state: "running", or for instance "degraded" followed by the
// units that failed and the boot's errors. Boot and Restart have already
// waited.
func (vm *VM) WaitBooted(ctx context.Context) (string, error) {
	stdout, stderr, _, err := vm.Run(ctx, waitBootedScript)
	if err != nil {
		return "", err
	}
	state := strings.TrimSpace(string(stdout))
	if state == "" {
		return "", fmt.Errorf("systemctl is-system-running printed nothing: %s", stderr)
	}
	return state, nil
}

// Run runs a shell script (sh) as root on the machine, with standard input
// /dev/null, and returns its output and exit code. A script that is still
// running at the context's deadline, or after DefaultRunTimeout without
// one, is killed, with exit code 124. err is about the harness, never the
// script: the machine stopped, restarted before the script ran, or ctx
// ended.
func (vm *VM) Run(ctx context.Context, script string) (stdout, stderr []byte, exit int, err error) {
	timeout := DefaultRunTimeout
	if d, ok := ctx.Deadline(); ok {
		timeout = time.Until(d)
	}
	vm.mu.Lock()
	boot := vm.bootID
	vm.mu.Unlock()
	r, err := vm.ch.exec(ctx, boot, script, timeout)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("%s: %w", vm.image.Name, err)
	}
	return r.stdout, r.stderr, r.exit, nil
}

// WriteFile creates or truncates the file at path on the machine, owned by
// root, writes data to it and sets its permission bits to perm (an
// existing file's too, unlike os.WriteFile). The directory must exist.
func (vm *VM) WriteFile(ctx context.Context, path string, data []byte, perm fs.FileMode) error {
	script := fmt.Sprintf("set -e\numask 077\nprintf '%%s' '%s' | base64 -d >%s\nchmod %o %s\n",
		base64.StdEncoding.EncodeToString(data), shellQuote(path), perm.Perm(), shellQuote(path))
	_, stderr, exit, err := vm.Run(ctx, script)
	if err != nil {
		return err
	}
	if exit != 0 {
		return fmt.Errorf("%s: writing %s: exit %d: %s", vm.image.Name, path, exit, bytes.TrimSpace(stderr))
	}
	return nil
}

// restartScript has the machine restart a second later through a transient
// timer, so that the runner answers first.
const restartScript = `systemd-run --quiet --on-active=1 --timer-property=AccuracySec=100ms "$(command -v systemctl)" reboot`

// Restart restarts the machine cleanly (systemctl reboot) and returns once
// it has finished starting again, as Boot does. It fails when cloud-init
// fetched its seed again: then a test's firewall rule or ban against the
// host's address could hold up a restart.
func (vm *VM) Restart(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, vm.boot)
	defer cancel()
	start := time.Now()
	vm.mu.Lock()
	old := vm.bootID
	vm.mu.Unlock()
	seeds := vm.seed.count()
	_, stderr, exit, err := vm.Run(ctx, restartScript)
	if err != nil {
		return err
	}
	if exit != 0 {
		return fmt.Errorf("%s: asking for a restart: exit %d: %s", vm.image.Name, exit, bytes.TrimSpace(stderr))
	}
	if err := vm.waitRunner(ctx, old); err != nil {
		return fmt.Errorf("%s did not come back on the harness channel: %w", vm.image.Name, err)
	}
	state, err := vm.WaitBooted(ctx)
	if err != nil {
		return err
	}
	if vm.seed.count() != seeds {
		return fmt.Errorf("%s: cloud-init fetched its seed again when restarting (%s)", vm.image.Name, vm.seed.log())
	}
	vm.t.Logf("%s restarted in %s: %s", vm.image.Name, time.Since(start).Round(time.Second), state)
	return nil
}

// HostPort is the port on 127.0.0.1 that reaches guestPort, which must be
// in Options.Forward.
func (vm *VM) HostPort(guestPort int) int {
	vm.t.Helper()
	p, ok := vm.ports[guestPort]
	if !ok {
		vm.t.Fatalf("%s: guest port %d is not forwarded (Options.Forward)", vm.image.Name, guestPort)
	}
	return p
}

// Close stops QEMU and deletes the machine's disk. Boot has the test call
// it at its end; calling it again does nothing.
func (vm *VM) Close() error {
	vm.closeOnce.Do(func() { vm.closeErr = vm.close() })
	return vm.closeErr
}

func (vm *VM) close() error {
	var errs []error
	if vm.conn != nil {
		_ = vm.conn.Close()
	}
	if vm.cmd != nil && vm.cmd.Process != nil {
		if vm.qmp != nil {
			_, _ = vm.qmp.execute("quit", nil) // QEMU may close before answering
		}
		select {
		case <-vm.exited:
		case <-time.After(15 * time.Second):
		}
		vm.cancel() // kills QEMU if it has not exited
		<-vm.exited
	}
	if vm.qmp != nil {
		_ = vm.qmp.close()
	}
	if vm.seed != nil {
		_ = vm.seed.close()
	}
	if vm.m.sockets != "" {
		errs = append(errs, os.RemoveAll(vm.m.sockets))
	}
	if vm.dir != "" {
		vm.report = vm.failureReport()
		if dir := os.Getenv(LogDirEnv); dir != "" {
			errs = append(errs, keepConsole(dir, vm.t.Name(), vm.m.console))
		}
		errs = append(errs, os.RemoveAll(vm.dir))
	}
	return errors.Join(errs...)
}

// failureReport is the end of the serial console, QEMU's own output and
// the seed requests.
func (vm *VM) failureReport() string {
	var b strings.Builder
	fmt.Fprintf(&b, "--- serial console (last %d lines; the whole log goes to $%s when set)\n", consoleLines, LogDirEnv)
	b.WriteString(tail(vm.m.console, consoleLines))
	if q := tail(filepath.Join(vm.dir, "qemu.log"), 20); q != "" {
		fmt.Fprintf(&b, "--- QEMU\n%s", q)
	}
	switch {
	case vm.seed != nil:
		fmt.Fprintf(&b, "--- seed requests: %s\n", vm.seed.log())
	case vm.m.seedISO != "":
		b.WriteString("--- seed: a CD-ROM labeled cidata\n")
	}
	return b.String()
}

const consoleLines = 80

var escapes = regexp.MustCompile("\x1b(\\[[0-9;?]*[ -/]*[@-~]|[()][0-9A-Za-z]|[@-Z\\\\-_])|\r")

// tail returns a file's last n lines with terminal escapes removed.
func tail(path string, n int) string {
	f, err := os.Open(path) //nolint:gosec // the harness's own log
	if err != nil {
		return ""
	}
	defer f.Close()
	const most = 256 << 10
	if st, err := f.Stat(); err == nil && st.Size() > most {
		_, _ = f.Seek(-most, io.SeekEnd)
	}
	b, _ := io.ReadAll(f)
	lines := strings.Split(strings.TrimRight(escapes.ReplaceAllString(string(b), ""), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 1 && lines[0] == "" {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// keepConsole copies the console log into dir, named after the test.
func keepConsole(dir, test, console string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil { //nolint:gosec // the directory the person running the tests chose
		return err
	}
	b, err := os.ReadFile(console) //nolint:gosec // the harness's own log
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	name := strings.NewReplacer("/", "_", " ", "_").Replace(test) + ".console.log"
	return os.WriteFile(filepath.Join(dir, name), b, 0o600) //nolint:gosec // as above
}

// shellQuote quotes s for sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
