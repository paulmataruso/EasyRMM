package vmtest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// machine is what qemuArgs needs to start one.
type machine struct {
	name     string
	accel    string // "kvm" or "tcg"
	memoryMB int
	cpus     int
	disk     string // the overlay
	sockets  string // directory of the QMP and harness sockets
	console  string // file that receives the serial console
	seedURL  string // the seed over HTTP, named "ds=<seedDS>" in the SMBIOS serial
	seedDS   string
	seedISO  string // or the seed on a CD-ROM
	forward  []int
}

// usableKVM reports whether /dev/kvm can be opened for QEMU.
func usableKVM() bool {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func (m machine) qmpSocket() string     { return filepath.Join(m.sockets, "qmp.sock") }
func (m machine) harnessSocket() string { return filepath.Join(m.sockets, "harness.sock") }

// qemuArgs is QEMU's command line. The network is QEMU's user networking
// only, with host forwards on 127.0.0.1: never a bridge or a tap device.
// The host picks each forward's port (":0"); QMP tells which.
func qemuArgs(m machine) []string {
	accel, cpu := "tcg,thread=multi", "max"
	if m.accel == "kvm" {
		accel, cpu = "kvm", "host"
	}
	netdev := "user,id=net0"
	for _, p := range m.forward {
		netdev += fmt.Sprintf(",hostfwd=tcp:127.0.0.1:0-:%d", p)
	}
	args := []string{
		"-name", m.name,
		"-nodefaults", "-no-user-config",
		// Rocky Linux 9's GRUB never starts the kernel without a display
		// adapter; nobody looks at it.
		"-vga", "std",
		"-display", "none",
		"-machine", "q35",
		"-accel", accel,
		"-cpu", cpu,
		"-smp", strconv.Itoa(m.cpus),
		"-m", strconv.Itoa(m.memoryMB),
		"-drive", "if=none,id=disk0,format=qcow2,cache=unsafe,discard=unmap,file=" + optValue(m.disk),
		"-device", "virtio-blk-pci,drive=disk0",
		"-netdev", netdev,
		"-device", "virtio-net-pci,netdev=net0",
		"-object", "rng-random,id=rng0,filename=/dev/urandom",
		"-device", "virtio-rng-pci,rng=rng0",
		"-device", "virtio-serial-pci,id=vser0",
		"-chardev", "socket,id=harness,server=on,wait=off,path=" + optValue(m.harnessSocket()),
		"-device", "virtserialport,bus=vser0.0,chardev=harness,name=" + portName,
		"-chardev", "file,id=console,path=" + optValue(m.console),
		"-serial", "chardev:console",
		"-qmp", "unix:" + optValue(m.qmpSocket()) + ",server=on,wait=off",
	}
	if m.seedISO != "" {
		return append(args,
			"-drive", "if=none,id=seed,format=raw,readonly=on,file="+optValue(m.seedISO),
			"-device", "ide-cd,drive=seed")
	}
	return append(args, "-smbios", "type=1,serial=ds="+m.seedDS+";s="+m.seedURL)
}

// optValue escapes a value for QEMU's comma-separated options.
func optValue(s string) string {
	return strings.ReplaceAll(s, ",", ",,")
}

// dialUnix connects to a socket QEMU creates, waiting for it to appear.
func dialUnix(ctx context.Context, path string, exited <-chan struct{}) (net.Conn, error) {
	var d net.Dialer
	for {
		conn, err := d.DialContext(ctx, "unix", path)
		if err == nil {
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("connecting to %s: %w", path, err)
		case <-exited:
			return nil, errors.New("QEMU exited")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// qmp is a minimal client of the QEMU Machine Protocol.
type qmp struct {
	mu   sync.Mutex
	conn net.Conn
	r    *bufio.Reader
}

func newQMP(conn net.Conn) (*qmp, error) {
	q := &qmp{conn: conn, r: bufio.NewReader(conn)}
	if _, err := q.r.ReadBytes('\n'); err != nil { // the greeting
		return nil, fmt.Errorf("QMP greeting: %w", err)
	}
	if _, err := q.execute("qmp_capabilities", nil); err != nil {
		return nil, err
	}
	return q, nil
}

// execute runs a command and returns its result, skipping events.
func (q *qmp) execute(command string, args any) (json.RawMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	req := map[string]any{"execute": command}
	if args != nil {
		req["arguments"] = args
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := q.conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := q.conn.Write(append(b, '\n')); err != nil {
		return nil, fmt.Errorf("QMP %s: %w", command, err)
	}
	for {
		line, err := q.r.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("QMP %s: %w", command, err)
		}
		var resp struct {
			Return json.RawMessage `json:"return"`
			Error  *struct {
				Class string `json:"class"`
				Desc  string `json:"desc"`
			} `json:"error"`
		}
		if err := json.Unmarshal(line, &resp); err != nil {
			return nil, fmt.Errorf("QMP %s: %w", command, err)
		}
		switch {
		case resp.Error != nil:
			return nil, fmt.Errorf("QMP %s: %s: %s", command, resp.Error.Class, resp.Error.Desc)
		case resp.Return != nil:
			return resp.Return, nil
		}
	}
}

// forwards returns the host port of each forwarded guest port, from the
// monitor's "info usernet".
func (q *qmp) forwards() (map[int]int, error) {
	raw, err := q.execute("human-monitor-command", map[string]string{"command-line": "info usernet"})
	if err != nil {
		return nil, err
	}
	var out string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return parseUsernet(out)
}

// parseUsernet reads lines such as
//
//	TCP[HOST_FORWARD]  11       127.0.0.1 45617       10.0.2.15    22     0     0
//
// into guest port 22 → host port 45617.
func parseUsernet(out string) (map[int]int, error) {
	ports := map[int]int{}
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) < 6 || f[0] != "TCP[HOST_FORWARD]" {
			continue
		}
		host, err1 := strconv.Atoi(f[3])
		guest, err2 := strconv.Atoi(f[5])
		if err1 != nil || err2 != nil || host == 0 {
			return nil, fmt.Errorf("unexpected forward in info usernet: %q", strings.TrimSpace(line))
		}
		ports[guest] = host
	}
	return ports, nil
}

func (q *qmp) close() error {
	return q.conn.Close()
}
