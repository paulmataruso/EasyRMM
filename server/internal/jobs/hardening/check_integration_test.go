//go:build integration

// Package hardening tests EasyRMM's hardening script, linux.sh (ADR-0051),
// which the jobs package sends to agents. The script is the product; this
// package only runs it.
package hardening

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const (
	resultTag = "EASYRMM-HARDENING-RESULT-V1 "
	// Where the script is mounted, read-only, in each container.
	scriptPath = "/opt/easyrmm/linux.sh"
)

// The modules in the order the script reports them.
var allModules = []string{"ssh", "firewall", "fail2ban", "kernel", "audit", "permissions", "services",
	"kernel-modules", "sudo", "time", "shared-memory", "usb-storage", "mac", "integrity"}

// What a container's kernel, clock and devices make not applicable there.
var containerNotApplicable = []string{"kernel-modules", "usb-storage", "time", "audit", "mac", "shared-memory"}

var states = []string{"in_place", "partly", "not_in_place", "not_applicable", "managed_elsewhere", "not_supported", "half_applied", "failed"}

// The result line's shape, as the server reads it.
type result struct {
	Version  int      `json:"version"`
	Mode     string   `json:"mode"`
	Platform platform `json:"platform"`
	Modules  []module `json:"modules"`
}

type platform struct {
	ID        string `json:"id"`
	VersionID string `json:"versionId"`
	Family    string `json:"family"`
	Container string `json:"container"`
	Support   string `json:"support"`
}

type module struct {
	Module  string   `json:"module"`
	State   string   `json:"state"`
	Reason  string   `json:"reason"`
	Missing []string `json:"missing"`
	Changes []string `json:"changes"`
	Ports   *ports   `json:"ports"`
}

type ports struct {
	TCP     []string `json:"tcp"`
	UDP     []string `json:"udp"`
	Docker  []string `json:"docker"`
	Unknown []string `json:"unknown"`
}

func (r result) module(t *testing.T, name string) module {
	t.Helper()
	for _, m := range r.Modules {
		if m.Module == name {
			return m
		}
	}
	t.Fatalf("no %s in the result", name)
	return module{}
}

// TestCheckInContainers runs `linux.sh check` in a container of each
// distribution in EASYRMM_TEST_HARDENING_IMAGES (pinned in the Makefile),
// with no network, as root, with the script mounted read-only. Containers
// exercise the container path only; machines are ADR-0051's main test.
func TestCheckInContainers(t *testing.T) {
	images := strings.Fields(os.Getenv("EASYRMM_TEST_HARDENING_IMAGES"))
	if len(images) == 0 {
		t.Fatal("EASYRMM_TEST_HARDENING_IMAGES is not set (Linux images to run the hardening script in; see the Makefile)")
	}
	script, err := filepath.Abs("linux.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range images {
		name, _, _ := strings.Cut(image, "@")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := startContainer(t, image, script)
			checkAll(t, c)
			usageErrors(t, c)
			options(t, c)
			listeningPorts(t, c)
			journal(t, c)
			platforms(t, c)
		})
	}
}

// platforms: what os-release says decides the family and whether apply may
// run. Each case replaces the container's os-release (after the filesystem
// check above).
func platforms(t *testing.T, c *container) {
	for _, tc := range []struct {
		osRelease string
		want      platform
	}{
		{"ID=debian\nVERSION_ID=\"12\"", platform{ID: "debian", VersionID: "12", Family: "debian", Support: "full"}},
		{"ID=debian\nVERSION_ID=\"13\"", platform{ID: "debian", VersionID: "13", Family: "debian", Support: "full"}},
		{"ID=debian\nVERSION_ID=\"11\"", platform{ID: "debian", VersionID: "11", Family: "debian", Support: "check_only"}},
		{"ID=debian\nVERSION_ID=\"14\"", platform{ID: "debian", VersionID: "14", Family: "debian", Support: "check_only"}},
		{"ID=debian\nVERSION_ID=\"10\"", platform{ID: "debian", VersionID: "10", Family: "debian", Support: "unsupported"}},
		// Debian testing has no VERSION_ID.
		{"ID=debian", platform{ID: "debian", Family: "debian", Support: "unsupported"}},
		{"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"", platform{ID: "ubuntu", VersionID: "22.04", Family: "debian", Support: "full"}},
		{"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"", platform{ID: "ubuntu", VersionID: "26.04", Family: "debian", Support: "full"}},
		{"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"20.04\"", platform{ID: "ubuntu", VersionID: "20.04", Family: "debian", Support: "check_only"}},
		{"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.10\"", platform{ID: "ubuntu", VersionID: "26.10", Family: "debian", Support: "check_only"}},
		// An interim release older than the newest tested one.
		{"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"25.10\"", platform{ID: "ubuntu", VersionID: "25.10", Family: "debian", Support: "unsupported"}},
		{"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"18.04\"", platform{ID: "ubuntu", VersionID: "18.04", Family: "debian", Support: "unsupported"}},
		{"ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"8.10\"", platform{ID: "rocky", VersionID: "8.10", Family: "rhel", Support: "full"}},
		{"ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"10.0\"", platform{ID: "almalinux", VersionID: "10.0", Family: "rhel", Support: "full"}},
		{"ID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.6\"", platform{ID: "rhel", VersionID: "9.6", Family: "rhel", Support: "full"}},
		{"ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"11.0\"", platform{ID: "rocky", VersionID: "11.0", Family: "rhel", Support: "check_only"}},
		{"ID=\"centos\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"7\"", platform{ID: "centos", VersionID: "7", Family: "rhel", Support: "unsupported"}},
		{"ID=\"ol\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.4\"", platform{ID: "ol", VersionID: "9.4", Family: "rhel", Support: "unsupported"}},
		{"ID=fedora\nVERSION_ID=43", platform{ID: "fedora", VersionID: "43", Family: "fedora", Support: "full"}},
		{"ID=fedora\nVERSION_ID=45", platform{ID: "fedora", VersionID: "45", Family: "fedora", Support: "check_only"}},
		{"ID=fedora\nVERSION_ID=42", platform{ID: "fedora", VersionID: "42", Family: "fedora", Support: "unsupported"}},
		{"ID=\"amzn\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"2023\"", platform{ID: "amzn", VersionID: "2023", Family: "fedora", Support: "unsupported"}},
		{"ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"22\"", platform{ID: "linuxmint", VersionID: "22", Family: "debian", Support: "unsupported"}},
		{"ID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\nVERSION_ID=\"15.6\"", platform{ID: "opensuse-leap", VersionID: "15.6", Family: "other", Support: "unsupported"}},
		// Single quotes, and a line that would run a command if the file were
		// sourced.
		{"ID='debian'\nVERSION_ID='12'\nNAME=$(touch /tmp/ran)", platform{ID: "debian", VersionID: "12", Family: "debian", Support: "full"}},
		{"", platform{Family: "other", Support: "unsupported"}},
	} {
		docker(t, "exec", c.name, "sh", "-c", `rm -f /etc/os-release /usr/lib/os-release && printf '%s\n' "$1" >/etc/os-release`, "sh", tc.osRelease)
		out, errOut, code := c.run(t, "sh", scriptPath, "check", "services")
		if code != 0 {
			t.Fatalf("%q: exit %d\n%s\n%s", tc.osRelease, code, out, errOut)
		}
		tc.want.Container = "docker"
		if got := parse(t, out, []string{"services"}).Platform; got != tc.want {
			t.Errorf("%q: platform %+v, want %+v", tc.osRelease, got, tc.want)
		}
	}
	if _, _, code := c.run(t, "test", "-e", "/tmp/ran"); code == 0 {
		t.Error("os-release was run, not read")
	}
}

// checkAll runs check on every module with each shell the image has, and
// checks that nothing but /run/sshd changed on the container's filesystem.
func checkAll(t *testing.T, c *container) {
	before := c.diff(t)
	out, errOut, code := c.run(t, "sh", scriptPath, "check", "all")
	if code != 0 {
		t.Fatalf("check all: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	r := parse(t, out, allModules)
	c.platform(t, r.Platform)

	for _, name := range containerNotApplicable {
		if m := r.module(t, name); m.State != "not_applicable" || m.Reason == "" {
			t.Errorf("%s in a container: %+v", name, m)
		}
	}
	// The kernel's network settings are the container's own; nothing else
	// of the kernel's is reported.
	k := r.module(t, "kernel")
	if !slices.Contains([]string{"in_place", "partly", "not_in_place"}, k.State) {
		t.Errorf("kernel in a container: %+v", k)
	}
	for _, s := range k.Missing {
		if !strings.HasPrefix(s, "net.") {
			t.Errorf("kernel in a container reports %q", s)
		}
	}
	// Without an SSH server, neither ssh nor fail2ban applies.
	if !c.has(t, "sshd") {
		for _, name := range []string{"ssh", "fail2ban"} {
			if m := r.module(t, name); m.State != "not_applicable" {
				t.Errorf("%s without sshd: %+v", name, m)
			}
		}
	}

	// The same result from every shell the image has: dash (sh on Debian
	// and Ubuntu) and bash (sh on Rocky Linux and Fedora).
	for _, shell := range []string{"bash", "dash"} {
		if !c.has(t, shell) {
			continue
		}
		o, e, code := c.run(t, shell, scriptPath, "check", "all")
		if code != 0 || lastLine(o) != lastLine(out) {
			t.Errorf("%s: exit %d, result differs from sh's:\n%s\nvs\n%s\nstderr:\n%s", shell, code, lastLine(o), lastLine(out), e)
		}
	}

	after := c.diff(t)
	for _, line := range after {
		if slices.Contains(before, line) || line == "A /run/sshd" || line == "C /run" {
			continue
		}
		t.Errorf("check changed the container's filesystem: %s", line)
	}
}

// usageErrors: a bad mode, module or option exits 2 with a message on
// stderr and no result; not being root exits 3.
func usageErrors(t *testing.T, c *container) {
	for _, args := range [][]string{
		{},
		{"check"},
		{"apply", "all"},
		{"undo", "all"},
		{"status", "all"},
		{"CHECK", "all"},
		{"check", ""},
		{"check", "bogus"},
		{"check", "ssh,bogus"},
		{"check", "ssh,,kernel"},
		{"check", ",ssh"},
		{"check", "ssh,"},
		{"check", "all,ssh"},
		{"check", "SSH"},
		{"check", "all", "bogus"},
		{"check", "all", "--epel"},
		{"check", "all", "epel=yes"},
		{"check", "all", "allow-tcp="},
		{"check", "all", "allow-tcp=0"},
		{"check", "all", "allow-tcp=65536"},
		{"check", "all", "allow-tcp=08080"},
		{"check", "all", "allow-tcp=90-80"},
		{"check", "all", "allow-tcp=80-90-100"},
		{"check", "all", "allow-tcp=80;id"},
		{"check", "all", "allow-udp=53,"},
		{"check", "all", "allow-udp=http"},
		{"check", "all", "trusted="},
		{"check", "all", "trusted=10.0.0.0/33"},
		{"check", "all", "trusted=10.0.0.256"},
		{"check", "all", "trusted=10.0.0.0/"},
		{"check", "all", "trusted=10.0.0/8"},
		{"check", "all", "trusted=2001:db8:::1"},
		{"check", "all", "trusted=2001:db8::1::2"},
		{"check", "all", "trusted=2001:db8::/129"},
		{"check", "all", "trusted=1:2:3:4:5:6:7:8:9"},
		{"check", "all", "trusted=example.com"},
		{"check", "all", "trusted=10.0.0.0/8 10.1.0.0/16"},
	} {
		out, errOut, code := c.run(t, append([]string{"sh", scriptPath}, args...)...)
		if code != 2 || strings.TrimSpace(errOut) == "" || strings.Contains(out, resultTag) {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want exit 2 with a message", args, code, out, errOut)
		}
	}
	out, errOut, code := c.runAs(t, "65534:65534", "sh", scriptPath, "check", "all")
	if code != 3 || strings.TrimSpace(errOut) == "" || strings.Contains(out, resultTag) {
		t.Errorf("not root: exit %d, stdout %q, stderr %q; want exit 3 with a message", code, out, errOut)
	}
}

// options: every option in its valid forms is accepted, and the firewall
// lists the operator's ports as ones apply would leave open. The chosen
// modules come back in the script's order, once each.
func options(t *testing.T, c *container) {
	out, errOut, code := c.run(t, "sh", scriptPath, "check", "integrity,firewall,fail2ban,firewall",
		"allow-tcp=8080,9000-9100", "allow-udp=53", "allow-tcp=443",
		"trusted=10.0.0.0/8,2001:db8::/32,192.0.2.7,::1,fe80::1/64",
		"root-password-off", "password-off", "epel")
	if code != 0 {
		t.Fatalf("options: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	r := parse(t, out, []string{"firewall", "fail2ban", "integrity"})
	fw := r.module(t, "firewall")
	if fw.Ports == nil {
		t.Fatalf("firewall without ports: %+v", fw)
	}
	for _, p := range []string{"443", "8080", "9000-9100"} {
		if !slices.Contains(fw.Ports.TCP, p) {
			t.Errorf("firewall TCP ports %q lack %s", fw.Ports.TCP, p)
		}
	}
	if !slices.Contains(fw.Ports.UDP, "53") {
		t.Errorf("firewall UDP ports %q lack 53", fw.Ports.UDP)
	}
}

// listeningPorts: sockets listening outside loopback are ports apply would
// leave open; loopback ones are not. Needs perl or python3 in the image to
// listen with.
func listeningPorts(t *testing.T, c *container) {
	var listen []string
	switch {
	case c.has(t, "perl"):
		listen = []string{"perl", "-MIO::Socket::INET", "-e",
			`my @s = (IO::Socket::INET->new(LocalAddr => "0.0.0.0:8443", Listen => 5),` +
				`IO::Socket::INET->new(LocalAddr => "127.0.0.1:9999", Listen => 5),` +
				`IO::Socket::INET->new(LocalAddr => "0.0.0.0:5355", Proto => "udp"),` +
				`IO::Socket::INET->new(LocalAddr => "127.0.0.1:5356", Proto => "udp"));` +
				`grep { !defined } @s and die; sleep 600`}
	case c.has(t, "python3"):
		listen = []string{"python3", "-c",
			"import socket, time\n" +
				"for a, p, k in ((\"0.0.0.0\", 8443, 1), (\"127.0.0.1\", 9999, 1), (\"0.0.0.0\", 5355, 2), (\"127.0.0.1\", 5356, 2)):\n" +
				"    s = socket.socket(socket.AF_INET, k); s.bind((a, p))\n" +
				"    s.listen() if k == 1 else None\n" +
				"    globals()[str(p)] = s\n" +
				"time.sleep(600)\n"}
	default:
		t.Log("no perl or python3 in this image to listen with: listening ports not tested here")
		return
	}
	docker(t, append([]string{"exec", "-d", c.name}, listen...)...)
	// 8443 is 20FB in the kernel's socket table.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(docker(t, "exec", c.name, "cat", "/proc/net/tcp"), ":20FB ") {
		if time.Now().After(deadline) {
			t.Fatal("the test listener did not start")
		}
		time.Sleep(200 * time.Millisecond)
	}
	out, errOut, code := c.run(t, "sh", scriptPath, "check", "firewall")
	if code != 0 {
		t.Fatalf("firewall: exit %d\n%s\n%s", code, out, errOut)
	}
	fw := parse(t, out, []string{"firewall"}).module(t, "firewall")
	if fw.Ports == nil || !slices.Contains(fw.Ports.TCP, "8443") || slices.Contains(fw.Ports.TCP, "9999") ||
		!slices.Contains(fw.Ports.UDP, "5355") || slices.Contains(fw.Ports.UDP, "5356") {
		t.Errorf("listening ports: %+v", fw.Ports)
	}
}

// journal: a module whose apply or undo was interrupted (an intent without a
// done mark) is half applied; one that finished is not.
func journal(t *testing.T, c *container) {
	docker(t, "exec", c.name, "sh", "-c",
		"mkdir -p /var/lib/easyrmm-hardening/modules/ssh /var/lib/easyrmm-hardening/modules/kernel && "+
			"touch /var/lib/easyrmm-hardening/modules/ssh/intent /var/lib/easyrmm-hardening/modules/kernel/intent "+
			"/var/lib/easyrmm-hardening/modules/kernel/done")
	out, errOut, code := c.run(t, "sh", scriptPath, "check", "ssh,kernel")
	if code != 0 {
		t.Fatalf("journal: exit %d\n%s\n%s", code, out, errOut)
	}
	r := parse(t, out, []string{"ssh", "kernel"})
	if m := r.module(t, "ssh"); m.State != "half_applied" || m.Reason == "" {
		t.Errorf("ssh with an intent and no done mark: %+v", m)
	}
	if m := r.module(t, "kernel"); m.State == "half_applied" {
		t.Errorf("kernel with an intent and a done mark: %+v", m)
	}
}

// parse checks the result line's shape and returns it.
func parse(t *testing.T, stdout string, wantModules []string) result {
	t.Helper()
	line := lastLine(stdout)
	if !strings.HasPrefix(line, resultTag) {
		t.Fatalf("the last line of stdout is not the result:\n%s", stdout)
	}
	if len(line) >= 64*1024 {
		t.Errorf("the result line is %d bytes", len(line))
	}
	raw := strings.TrimPrefix(line, resultTag)
	// Empty strings, arrays and objects are left out.
	for _, empty := range []string{`:""`, `:[]`, `:{}`} {
		if strings.Contains(raw, empty) {
			t.Errorf("the result has an empty value (%s): %s", empty, raw)
		}
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var r result
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("decoding the result: %v\n%s", err, raw)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("more after the result's JSON: %s", raw)
	}
	if r.Version != 1 || r.Mode != "check" {
		t.Errorf("version %d, mode %q", r.Version, r.Mode)
	}
	if !slices.Contains([]string{"debian", "rhel", "fedora", "other"}, r.Platform.Family) ||
		!slices.Contains([]string{"none", "lxc", "docker", "podman", "other"}, r.Platform.Container) ||
		!slices.Contains([]string{"full", "check_only", "unsupported"}, r.Platform.Support) {
		t.Errorf("platform %+v", r.Platform)
	}
	var got []string
	for _, m := range r.Modules {
		got = append(got, m.Module)
		if !slices.Contains(states, m.State) {
			t.Errorf("%s: state %q", m.Module, m.State)
		}
		switch m.State {
		case "not_applicable", "managed_elsewhere", "not_supported", "failed", "half_applied":
			if m.Reason == "" {
				t.Errorf("%s is %s without a reason", m.Module, m.State)
			}
		case "partly":
			if len(m.Missing) == 0 {
				t.Errorf("%s is partly in place with nothing missing", m.Module)
			}
		}
		if m.Ports != nil && m.Module != "firewall" {
			t.Errorf("%s has ports", m.Module)
		}
		strs := append(append([]string{m.Reason}, m.Missing...), m.Changes...)
		lists := [][]string{m.Missing, m.Changes}
		if m.Ports != nil {
			lists = append(lists, m.Ports.TCP, m.Ports.UDP, m.Ports.Docker, m.Ports.Unknown)
			for _, l := range lists[2:] {
				strs = append(strs, l...)
			}
		}
		for _, l := range lists {
			if len(l) > 50 {
				t.Errorf("%s: a list of %d entries", m.Module, len(l))
			}
		}
		for _, s := range strs {
			if utf8.RuneCountInString(s) > 300 {
				t.Errorf("%s: a string of %d characters: %s", m.Module, utf8.RuneCountInString(s), s)
			}
		}
	}
	if !slices.Equal(got, wantModules) {
		t.Errorf("modules %q, want %q", got, wantModules)
	}
	return r
}

func lastLine(s string) string {
	s = strings.TrimRight(s, "\n")
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// The platforms the script reports full support for, by os-release ID: an
// independent copy of the script's table, for the images tested here.
var fullSupport = map[string][]string{
	"debian": {"12", "13"}, "ubuntu": {"22.04", "24.04", "26.04"},
	"rocky": {"8", "9", "10"}, "almalinux": {"8", "9", "10"}, "rhel": {"8", "9", "10"},
	"fedora": {"43", "44"},
}

var families = map[string]string{
	"debian": "debian", "ubuntu": "debian",
	"rocky": "rhel", "almalinux": "rhel", "rhel": "rhel",
	"fedora": "fedora",
}

type container struct {
	name  string
	cache map[string]bool
}

// startContainer runs IMAGE with no network and the script mounted
// read-only, removed when the test ends.
func startContainer(t *testing.T, image, script string) *container {
	t.Helper()
	if _, _, err := dockerRun(10*time.Second, "image", "inspect", image); err != nil {
		if out, errOut, err := dockerRun(10*time.Minute, "pull", "-q", image); err != nil {
			t.Fatalf("docker pull %s: %v\n%s%s", image, err, out, errOut)
		}
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	c := &container{name: "easyrmm-testhardening-" + hex.EncodeToString(b), cache: map[string]bool{}}
	docker(t, "run", "-d", "--rm", "--network", "none", "--name", c.name,
		"-v", script+":"+scriptPath+":ro", image, "sleep", "infinity")
	t.Cleanup(func() { _, _, _ = dockerRun(time.Minute, "rm", "-f", c.name) })
	return c
}

// run runs a command in the container as root: its stdout, stderr and exit
// status.
func (c *container) run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	return c.runAs(t, "0:0", args...)
}

func (c *container) runAs(t *testing.T, user string, args ...string) (string, string, int) {
	t.Helper()
	out, errOut, err := dockerRun(5*time.Minute, append([]string{"exec", "--user", user, c.name}, args...)...)
	var exit *exec.ExitError
	switch {
	case err == nil:
		return out, errOut, 0
	case errors.As(err, &exit):
		return out, errOut, exit.ExitCode()
	default:
		t.Fatalf("docker exec %q: %v\n%s", args, err, errOut)
		return "", "", -1
	}
}

// has reports whether the container has a command.
func (c *container) has(t *testing.T, cmd string) bool {
	t.Helper()
	if v, ok := c.cache[cmd]; ok {
		return v
	}
	_, _, code := c.run(t, "sh", "-c", `command -v "$1" >/dev/null`, "sh", cmd)
	c.cache[cmd] = code == 0
	return code == 0
}

// diff lists what changed in the container's filesystem since it started.
func (c *container) diff(t *testing.T) []string {
	t.Helper()
	out := strings.TrimSpace(docker(t, "diff", c.name))
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

// platform checks the reported platform against the container's
// os-release, read here independently of the script.
func (c *container) platform(t *testing.T, p platform) {
	t.Helper()
	osr := map[string]string{}
	for _, line := range strings.Split(docker(t, "exec", c.name, "cat", "/etc/os-release"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if u, err := strconv.Unquote(v); err == nil {
			v = u
		}
		osr[k] = v
	}
	id, version := osr["ID"], osr["VERSION_ID"]
	major, _, _ := strings.Cut(version, ".")
	want := platform{ID: id, VersionID: version, Family: families[id], Container: "docker", Support: "full"}
	if want.Family == "" {
		t.Fatalf("no expectations for %s in this test", id)
	}
	if !slices.Contains(fullSupport[id], version) && !slices.Contains(fullSupport[id], major) {
		t.Fatalf("%s %s is not a fully supported release; pick one for the test", id, version)
	}
	if p != want {
		t.Errorf("platform %+v, want %+v", p, want)
	}
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, errOut, err := dockerRun(2*time.Minute, args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s%s", strings.Join(args, " "), err, out, errOut)
	}
	return out
}

func dockerRun(timeout time.Duration, args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var out, errOut bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	return out.String(), errOut.String(), err
}
