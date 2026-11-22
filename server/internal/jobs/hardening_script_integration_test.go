//go:build integration

package jobs

// The hardening script (hardening/linux.sh, ADR-0051) as agents receive it:
// the script this package embeds, run in containers, its result read by
// parseHardeningResult, the parser the server uses.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Where the script is mounted, read-only, in each container.
const scriptPath = "/opt/easyrmm/linux.sh"

// TestCheckInContainers runs `linux.sh` in a container of each
// distribution in EASYRMM_TEST_HARDENING_IMAGES (pinned in the Makefile),
// with no network, as root, with the script mounted read-only: check, then
// apply and undo of what a container leaves them to do. Containers
// exercise the container path, the record and its interruptions; machines
// are ADR-0051's main test.
func TestCheckInContainers(t *testing.T) {
	images := strings.Fields(os.Getenv("EASYRMM_TEST_HARDENING_IMAGES"))
	if len(images) == 0 {
		t.Fatal("EASYRMM_TEST_HARDENING_IMAGES is not set (Linux images to run the hardening script in; see the Makefile)")
	}
	script := filepath.Join(t.TempDir(), "linux.sh")
	if err := os.WriteFile(script, []byte(hardeningScript), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, image := range images {
		name, _, _ := strings.Cut(image, "@")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := startScriptContainer(t, image, script)
			scriptCheckAll(t, c)
			scriptUsageErrors(t, c)
			scriptOptions(t, c)
			scriptListeningPorts(t, c)
			scriptJournal(t, c)
			scriptApplyUndo(t, c)
			scriptInterrupted(t, c)
			scriptFailures(t, c)
			scriptPackagesLeft(t, c)
			scriptRollbackLeaves(t, c)
			scriptModuleStream(t, c)
			scriptPackageRecovery(t, c)
			scriptDanglingUnitLink(t, c)
			scriptPlatforms(t, c)
		})
	}
}

// scriptPlatforms: what os-release says decides the family and whether apply may
// run. Each case replaces the container's os-release (after the filesystem
// check above).
func scriptPlatforms(t *testing.T, c *scriptContainer) {
	for _, tc := range []struct {
		osRelease string
		want      HardeningPlatform
	}{
		{"ID=debian\nVERSION_ID=\"12\"", HardeningPlatform{ID: "debian", VersionID: "12", Family: "debian", Support: "full"}},
		{"ID=debian\nVERSION_ID=\"13\"", HardeningPlatform{ID: "debian", VersionID: "13", Family: "debian", Support: "full"}},
		{"ID=debian\nVERSION_ID=\"11\"", HardeningPlatform{ID: "debian", VersionID: "11", Family: "debian", Support: "check_only"}},
		{"ID=debian\nVERSION_ID=\"14\"", HardeningPlatform{ID: "debian", VersionID: "14", Family: "debian", Support: "check_only"}},
		{"ID=debian\nVERSION_ID=\"10\"", HardeningPlatform{ID: "debian", VersionID: "10", Family: "debian", Support: "unsupported"}},
		// Debian testing has no VERSION_ID.
		{"ID=debian", HardeningPlatform{ID: "debian", Family: "debian", Support: "unsupported"}},
		{"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"", HardeningPlatform{ID: "ubuntu", VersionID: "22.04", Family: "debian", Support: "full"}},
		{"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"", HardeningPlatform{ID: "ubuntu", VersionID: "26.04", Family: "debian", Support: "full"}},
		{"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"20.04\"", HardeningPlatform{ID: "ubuntu", VersionID: "20.04", Family: "debian", Support: "check_only"}},
		{"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.10\"", HardeningPlatform{ID: "ubuntu", VersionID: "26.10", Family: "debian", Support: "check_only"}},
		// An interim release older than the newest tested one.
		{"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"25.10\"", HardeningPlatform{ID: "ubuntu", VersionID: "25.10", Family: "debian", Support: "unsupported"}},
		{"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"18.04\"", HardeningPlatform{ID: "ubuntu", VersionID: "18.04", Family: "debian", Support: "unsupported"}},
		{"ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"8.10\"", HardeningPlatform{ID: "rocky", VersionID: "8.10", Family: "rhel", Support: "full"}},
		{"ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"10.0\"", HardeningPlatform{ID: "almalinux", VersionID: "10.0", Family: "rhel", Support: "full"}},
		{"ID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.6\"", HardeningPlatform{ID: "rhel", VersionID: "9.6", Family: "rhel", Support: "full"}},
		{"ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"11.0\"", HardeningPlatform{ID: "rocky", VersionID: "11.0", Family: "rhel", Support: "check_only"}},
		{"ID=\"centos\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"7\"", HardeningPlatform{ID: "centos", VersionID: "7", Family: "rhel", Support: "unsupported"}},
		{"ID=\"ol\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.4\"", HardeningPlatform{ID: "ol", VersionID: "9.4", Family: "rhel", Support: "unsupported"}},
		{"ID=fedora\nVERSION_ID=43", HardeningPlatform{ID: "fedora", VersionID: "43", Family: "fedora", Support: "full"}},
		{"ID=fedora\nVERSION_ID=46", HardeningPlatform{ID: "fedora", VersionID: "46", Family: "fedora", Support: "check_only"}},
		{"ID=fedora\nVERSION_ID=42", HardeningPlatform{ID: "fedora", VersionID: "42", Family: "fedora", Support: "unsupported"}},
		{"ID=\"amzn\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"2023\"", HardeningPlatform{ID: "amzn", VersionID: "2023", Family: "fedora", Support: "unsupported"}},
		{"ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"22\"", HardeningPlatform{ID: "linuxmint", VersionID: "22", Family: "debian", Support: "unsupported"}},
		{"ID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\nVERSION_ID=\"15.6\"", HardeningPlatform{ID: "opensuse-leap", VersionID: "15.6", Family: "other", Support: "unsupported"}},
		// Single quotes, and a line that would run a command if the file were
		// sourced.
		{"ID='debian'\nVERSION_ID='12'\nNAME=$(touch /tmp/ran)", HardeningPlatform{ID: "debian", VersionID: "12", Family: "debian", Support: "full"}},
		{"", HardeningPlatform{Family: "other", Support: "unsupported"}},
	} {
		docker(t, "exec", c.name, "sh", "-c", `rm -f /etc/os-release /usr/lib/os-release && printf '%s\n' "$1" >/etc/os-release`, "sh", tc.osRelease)
		out, errOut, code := c.run(t, "sh", scriptPath, "check", "services")
		if code != 0 {
			t.Fatalf("%q: exit %d\n%s\n%s", tc.osRelease, code, out, errOut)
		}
		tc.want.Container = "docker"
		if got := parseScriptResult(t, out, []string{"services"}).Platform; got != tc.want {
			t.Errorf("%q: platform %+v, want %+v", tc.osRelease, got, tc.want)
		}
	}
	if _, _, code := c.run(t, "test", "-e", "/tmp/ran"); code == 0 {
		t.Error("os-release was run, not read")
	}
}

// scriptCheckAll runs check on every module with each shell the image has, and
// checks that nothing but /run/sshd changed on the container's filesystem.
func scriptCheckAll(t *testing.T, c *scriptContainer) {
	before := c.diff(t)
	out, errOut, code := c.run(t, "sh", scriptPath, "check", "all")
	if code != 0 {
		t.Fatalf("check all: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	r := parseScriptResult(t, out, HardeningModules)
	c.platform(t, r.Platform)

	for _, name := range containerNotApplicable {
		if m := scriptModule(t, r, name); m.State != "not_applicable" || m.Reason == "" {
			t.Errorf("%s in a container: %+v", name, m)
		}
	}
	// The kernel's network settings are the container's own; nothing else
	// of the kernel's is reported.
	k := scriptModule(t, r, "kernel")
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
			if m := scriptModule(t, r, name); m.State != "not_applicable" {
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

// scriptUsageErrors: a bad mode, module or option exits 2 with a message on
// stderr and no result; not being root exits 3.
func scriptUsageErrors(t *testing.T, c *scriptContainer) {
	for _, args := range [][]string{
		{},
		{"check"},
		{"undo", "all", "allow-tcp=22"},
		{"undo", "ssh", "password-off"},
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
		if code != 2 || strings.TrimSpace(errOut) == "" || strings.Contains(out, HardeningResultPrefix) {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want exit 2 with a message", args, code, out, errOut)
		}
	}
	for _, mode := range []string{"check", "apply", "undo"} {
		out, errOut, code := c.runAs(t, "65534:65534", "sh", scriptPath, mode, "all")
		if code != 3 || strings.TrimSpace(errOut) == "" || strings.Contains(out, HardeningResultPrefix) {
			t.Errorf("%s, not root: exit %d, stdout %q, stderr %q; want exit 3 with a message", mode, code, out, errOut)
		}
	}
}

// scriptOptions: every option in its valid forms is accepted, and the firewall
// lists the operator's ports as ones apply would leave open. The chosen
// modules come back in the script's order, once each.
func scriptOptions(t *testing.T, c *scriptContainer) {
	out, errOut, code := c.run(t, "sh", scriptPath, "check", "integrity,firewall,fail2ban,firewall",
		"allow-tcp=8080,9000-9100", "allow-udp=53", "allow-tcp=443",
		"trusted=10.0.0.0/8,2001:db8::/32,192.0.2.7,::1,fe80::1/64",
		"root-password-off", "password-off", "epel")
	if code != 0 {
		t.Fatalf("options: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	r := parseScriptResult(t, out, []string{"firewall", "fail2ban", "integrity"})
	fw := scriptModule(t, r, "firewall")
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

// scriptListeningPorts: sockets listening outside loopback are ports apply would
// leave open; loopback ones are not, nor the client socket dhclient binds to
// a random port besides 68 (a stand-in named dhclient binds both). Needs
// perl or python3 in the image to listen with.
func scriptListeningPorts(t *testing.T, c *scriptContainer) {
	type sock struct {
		addr string
		port int
		tcp  bool
	}
	var interpreter string
	var listen func(sockets []sock) []string
	switch {
	case c.has(t, "perl"):
		interpreter = "perl"
		listen = func(sockets []sock) []string {
			var s []string
			for _, k := range sockets {
				kind := `Proto => "udp"`
				if k.tcp {
					kind = "Listen => 5"
				}
				s = append(s, fmt.Sprintf(`IO::Socket::INET->new(LocalAddr => "%s:%d", %s)`, k.addr, k.port, kind))
			}
			return []string{"-MIO::Socket::INET", "-e", "my @s = (" + strings.Join(s, ", ") + "); grep { !defined } @s and die; sleep 600"}
		}
	case c.has(t, "python3"):
		interpreter = "python3"
		listen = func(sockets []sock) []string {
			var s []string
			for _, k := range sockets {
				kind := "socket.SOCK_DGRAM"
				if k.tcp {
					kind = "socket.SOCK_STREAM"
				}
				s = append(s, fmt.Sprintf("(%q, %d, %s)", k.addr, k.port, kind))
			}
			return []string{"-c", "import socket, time\nkeep = []\n" +
				"for a, p, kind in (" + strings.Join(s, ", ") + ",):\n" +
				"    s = socket.socket(socket.AF_INET, kind); s.bind((a, p))\n" +
				"    s.listen() if kind == socket.SOCK_STREAM else None\n" +
				"    keep.append(s)\n" +
				"time.sleep(600)\n"}
		}
	default:
		t.Log("no perl or python3 in this image to listen with: listening ports not tested here")
		return
	}
	// The kernel names a process after the file it runs: here a link named
	// dhclient.
	c.sh(t, `ln -sf "$(command -v `+interpreter+`)" /tmp/dhclient`)
	for _, l := range []struct {
		run, table string
		ready      int
		socks      []sock
	}{
		{interpreter, "tcp", 8443, []sock{{"0.0.0.0", 8443, true}, {"127.0.0.1", 9999, true}, {"0.0.0.0", 5355, false}, {"127.0.0.1", 5356, false}}},
		{"/tmp/dhclient", "udp", 41234, []sock{{"0.0.0.0", 68, false}, {"0.0.0.0", 41234, false}}},
	} {
		docker(t, append([]string{"exec", "-d", c.name, l.run}, listen(l.socks)...)...)
		deadline := time.Now().Add(10 * time.Second)
		for !strings.Contains(docker(t, "exec", c.name, "cat", "/proc/net/"+l.table), fmt.Sprintf(":%04X ", l.ready)) {
			if time.Now().After(deadline) {
				t.Fatalf("%s did not start listening", l.run)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	out, errOut, code := c.run(t, "sh", scriptPath, "check", "firewall")
	if code != 0 {
		t.Fatalf("firewall: exit %d\n%s\n%s", code, out, errOut)
	}
	fw := scriptModule(t, parseScriptResult(t, out, []string{"firewall"}), "firewall")
	if fw.Ports == nil || !slices.Contains(fw.Ports.TCP, "8443") || slices.Contains(fw.Ports.TCP, "9999") ||
		!slices.Contains(fw.Ports.UDP, "5355") || slices.Contains(fw.Ports.UDP, "5356") ||
		!slices.Contains(fw.Ports.UDP, "68") || slices.Contains(fw.Ports.UDP, "41234") {
		t.Errorf("listening ports: %+v", fw.Ports)
	}
}

// scriptJournal: a module whose apply or undo was interrupted (an intent without a
// done mark) is half applied; one that finished is not.
func scriptJournal(t *testing.T, c *scriptContainer) {
	docker(t, "exec", c.name, "sh", "-c",
		"mkdir -p /var/lib/easyrmm-hardening/modules/ssh /var/lib/easyrmm-hardening/modules/kernel && "+
			"touch /var/lib/easyrmm-hardening/modules/ssh/intent /var/lib/easyrmm-hardening/modules/kernel/intent "+
			"/var/lib/easyrmm-hardening/modules/kernel/done")
	out, errOut, code := c.run(t, "sh", scriptPath, "check", "ssh,kernel")
	if code != 0 {
		t.Fatalf("journal: exit %d\n%s\n%s", code, out, errOut)
	}
	r := parseScriptResult(t, out, []string{"ssh", "kernel"})
	if m := scriptModule(t, r, "ssh"); m.State != "half_applied" || m.Reason == "" {
		t.Errorf("ssh with an intent and no done mark: %+v", m)
	}
	if m := scriptModule(t, r, "kernel"); m.State == "half_applied" {
		t.Errorf("kernel with an intent and a done mark: %+v", m)
	}
}

// The record apply keeps, and the copy of the script undo can run without
// the agent.
const (
	stateDir   = "/var/lib/easyrmm-hardening"
	scriptCopy = stateDir + "/easyrmm-hardening.sh"
)

// scriptApplyUndo: apply and undo every module in a container, where most
// are not applicable and the network is off, so that only permissions has
// something to apply. What apply changes is recorded with a copy of the
// script; a second apply changes nothing; undo, run from that copy, puts
// back what is still as apply left it, leaves what an administrator
// changed since, and removes the record.
func scriptApplyUndo(t *testing.T, c *scriptContainer) {
	c.sh(t, "rm -rf "+stateDir+" && chmod 0666 /etc/passwd /etc/group")
	sum := sha256.Sum256([]byte(hardeningScript))
	scriptSum := hex.EncodeToString(sum[:]) + "  -\n"
	out := c.script(t, "apply", "all")
	r := parseScriptOutcome(t, out, HardeningApply, HardeningModules)
	for _, m := range r.Modules {
		switch {
		case m.Module == "permissions":
			if m.Outcome != HardeningApplied || m.State != HardeningInPlace || !m.Recorded ||
				!slices.Contains(m.Done, "/etc/passwd: mode 0666 to 0644") || !slices.Contains(m.Done, "/etc/group: mode 0666 to 0644") {
				t.Errorf("permissions: %+v", m)
			}
		case m.Module == "firewall":
			// No systemd in the container to load the rules at boot.
			if m.Outcome != HardeningRefused || !strings.Contains(m.OutcomeReason, "systemd is not running") {
				t.Errorf("firewall: %+v", m)
			}
		case m.Module == "integrity":
			// AIDE cannot be installed without a network; the installation
			// is put back.
			if m.Outcome != HardeningOutcomeFailed || !strings.Contains(m.OutcomeReason, "put back") || m.Recorded {
				t.Errorf("integrity: %+v", m)
			}
		case m.Module == "kernel":
			// /proc/sys is read-only in a Docker container.
			if m.Outcome != HardeningUnchanged && (m.Outcome != HardeningRefused || !strings.Contains(m.OutcomeReason, "read-only")) {
				t.Errorf("kernel: %+v", m)
			}
		case slices.Contains(containerNotApplicable, m.Module):
			if m.Outcome != HardeningSkipped {
				t.Errorf("%s in a container: %+v", m.Module, m)
			}
		case m.Outcome == HardeningApplied || m.Recorded:
			t.Errorf("%s applied in a container without a network: %+v", m.Module, m)
		}
	}
	c.wantModes(t, "644 /etc/passwd", "644 /etc/group")
	if got := c.sh(t, "stat -c '%a' "+stateDir+" && ls "+stateDir+" "+stateDir+"/modules && sha256sum <"+scriptPath+" && sha256sum <"+scriptCopy); got !=
		"700\n"+stateDir+":\neasyrmm-hardening.sh\nmodules\n\n"+stateDir+"/modules:\npermissions\n"+scriptSum+scriptSum {
		t.Errorf("the record after apply:\n%s", got)
	}

	// Applying again changes nothing; check sees the record.
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "apply", "permissions"), HardeningApply, []string{"permissions"}), "permissions")
	if m.Outcome != HardeningUnchanged || len(m.Done) != 0 || !m.Recorded {
		t.Errorf("permissions applied again: %+v", m)
	}
	m = scriptModule(t, parseScriptResult(t, c.script(t, "check", "permissions"), []string{"permissions"}), "permissions")
	if m.State != HardeningInPlace || !m.Recorded {
		t.Errorf("permissions checked after apply: %+v", m)
	}

	// An administrator narrows /etc/group further: undo leaves it.
	c.sh(t, "chmod 0600 /etc/group")
	out, errOut, code := c.run(t, "sh", scriptCopy, "undo", "all")
	if code != 0 {
		t.Fatalf("undo from the copy: exit %d\n%s\n%s", code, out, errOut)
	}
	r = parseScriptOutcome(t, out, HardeningUndo, HardeningModules)
	for _, m := range r.Modules {
		if m.Module == "permissions" {
			if m.Outcome != HardeningPartlyUndone || m.Recorded || !slices.Contains(m.Done, "/etc/passwd: mode 0644 back to 0666") ||
				!slices.Contains(m.Done, "Left as it is: the mode of /etc/group, changed since apply") {
				t.Errorf("permissions undone: %+v", m)
			}
		} else if m.Outcome != HardeningNothingToUndo {
			t.Errorf("%s undone without a record: %+v", m.Module, m)
		}
	}
	c.wantModes(t, "666 /etc/passwd", "600 /etc/group")
	c.wantGone(t, stateDir)
	r = parseScriptOutcome(t, c.script(t, "undo", "all"), HardeningUndo, HardeningModules)
	for _, m := range r.Modules {
		if m.Outcome != HardeningNothingToUndo {
			t.Errorf("%s undone twice: %+v", m.Module, m)
		}
	}
	c.wantGone(t, stateDir)
	c.sh(t, "chmod 0644 /etc/passwd /etc/group")
}

// slowChmod makes chmod in the container wait five minutes before it
// changes /etc/passwd, so that a run can be caught in the middle of a
// module; failChmod makes it fail for /etc/group. The script's PATH puts
// /usr/local/sbin first.
const (
	slowChmod = "printf '%s\\n' '#!/bin/sh' 'case \"$*\" in *\" /etc/passwd\") : >/tmp/slow; sleep 300 ;; esac' 'exec /bin/chmod \"$@\"' " +
		">/usr/local/sbin/chmod && /bin/chmod 0755 /usr/local/sbin/chmod && rm -f /tmp/slow"
	failChmod = "printf '%s\\n' '#!/bin/sh' 'case \"$*\" in *\" /etc/group\") echo refused by the test >&2; exit 1 ;; esac' 'exec /bin/chmod \"$@\"' " +
		">/usr/local/sbin/chmod && /bin/chmod 0755 /usr/local/sbin/chmod"
)

// interrupt starts `apply permissions` in a process group of its own, waits
// until it is changing /etc/passwd, and sends the group SIGNAL, as a job's
// timeout or cancel does (SIGTERM, then SIGKILL ten seconds later).
func (c *scriptContainer) interrupt(t *testing.T, signal string) {
	t.Helper()
	c.sh(t, slowChmod)
	docker(t, "exec", "-d", c.name, "setsid", "sh", "-c", "echo $$ >/tmp/pgid; exec sh "+scriptPath+" apply permissions")
	c.waitFor(t, "/tmp/slow")
	c.sh(t, "kill -"+signal+" -$(cat /tmp/pgid)")
	// Ended: gone, or a zombie (the container's PID 1, sleep, reaps
	// nothing).
	c.waitUntil(t, `p=$(cat /tmp/pgid); test ! -e /proc/$p || test "$(cut -d' ' -f3 /proc/$p/stat)" = Z`, "the run to end")
	c.sh(t, "rm -f /usr/local/sbin/chmod /tmp/slow /tmp/pgid")
}

// scriptInterrupted: a run killed in the middle of a module leaves it half
// applied; the lock a killed run left does not stop the next; apply then
// finishes the module, and undo reverses it to the state before the first,
// interrupted apply. Undo of a module whose only run was killed puts back
// what it recorded.
func scriptInterrupted(t *testing.T, c *scriptContainer) {
	c.sh(t, "rm -rf "+stateDir+" && chmod 0666 /etc/passwd")
	for _, signal := range []string{"KILL", "TERM"} {
		c.interrupt(t, signal)
		m := scriptModule(t, parseScriptResult(t, c.script(t, "check", "permissions"), []string{"permissions"}), "permissions")
		if m.State != HardeningHalfApplied || !m.Recorded {
			t.Errorf("after SIG%s: %+v", signal, m)
		}
		if signal == "TERM" {
			// The run released its lock as it ended.
			c.wantGone(t, stateDir+"/lock")
		}
	}
	c.wantModes(t, "666 /etc/passwd")

	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "apply", "permissions"), HardeningApply, []string{"permissions"}), "permissions")
	if m.Outcome != HardeningApplied || m.State != HardeningInPlace {
		t.Errorf("apply after the interruptions: %+v", m)
	}
	c.wantModes(t, "644 /etc/passwd")
	m = scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "permissions"), HardeningUndo, []string{"permissions"}), "permissions")
	if m.Outcome != HardeningUndone || !slices.Contains(m.Done, "/etc/passwd: mode 0644 back to 0666") {
		t.Errorf("undo after the interruptions: %+v", m)
	}
	c.wantModes(t, "666 /etc/passwd")
	c.wantGone(t, stateDir)

	c.interrupt(t, "KILL")
	m = scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "permissions"), HardeningUndo, []string{"permissions"}), "permissions")
	if m.Outcome != HardeningUndone || m.State == HardeningHalfApplied || m.Recorded {
		t.Errorf("undo of an interrupted apply: %+v", m)
	}
	c.wantModes(t, "666 /etc/passwd")
	c.wantGone(t, stateDir)
	c.sh(t, "chmod 0644 /etc/passwd")
}

// scriptFailures: a module that fails part way is put back as it was before
// the run; another run holding the lock refuses every module; a record from
// a later release of the script is refused, not misread.
func scriptFailures(t *testing.T, c *scriptContainer) {
	c.sh(t, "rm -rf "+stateDir+" && chmod 0666 /etc/passwd /etc/group && "+failChmod)
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "apply", "permissions"), HardeningApply, []string{"permissions"}), "permissions")
	if m.Outcome != HardeningOutcomeFailed || !strings.Contains(m.OutcomeReason, "/etc/group") || !strings.Contains(m.OutcomeReason, "put back") ||
		m.Recorded || len(m.Done) != 0 {
		t.Errorf("a failed apply: %+v", m)
	}
	c.sh(t, "rm -f /usr/local/sbin/chmod")
	// /etc/passwd, changed before /etc/group failed, is put back.
	c.wantModes(t, "666 /etc/passwd", "666 /etc/group")
	c.wantGone(t, stateDir)

	// Another run holds the lock (PID 1 runs as long as the container).
	c.sh(t, "mkdir -p "+stateDir+"/lock && echo 1 $(cut -d' ' -f22 /proc/1/stat) >"+stateDir+"/lock/pid")
	r := parseScriptOutcome(t, c.script(t, "apply", "permissions,services"), HardeningApply, []string{"permissions", "services"})
	for _, m := range r.Modules {
		if m.Outcome != HardeningRefused || !strings.Contains(m.OutcomeReason, "Another EasyRMM hardening run") {
			t.Errorf("%s while another run holds the lock: %+v", m.Module, m)
		}
	}
	c.wantModes(t, "666 /etc/passwd")
	c.sh(t, "rm -rf "+stateDir)

	// A record of format 2.
	c.sh(t, "mkdir -p "+stateDir+"/modules/permissions && printf 'format 2\\nmode\\t/etc/passwd\\t600\\troot:root\\t666\\n' >"+stateDir+
		"/modules/permissions/manifest && date >"+stateDir+"/modules/permissions/done")
	m = scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "permissions"), HardeningUndo, []string{"permissions"}), "permissions")
	if m.Outcome != HardeningRefused || !strings.Contains(m.OutcomeReason, "format 2") || !m.Recorded {
		t.Errorf("undo of a later format: %+v", m)
	}
	c.wantModes(t, "666 /etc/passwd")
	c.sh(t, "rm -rf "+stateDir+" && chmod 0644 /etc/passwd /etc/group")
}

// scriptPackagesLeft: undo removes a package apply installed only when
// that removes nothing else, and says why it left one. A record names a
// package others need, then one the package manager fails to remove (a
// stand-in, first in the script's PATH, refuses). Both stay installed.
func scriptPackagesLeft(t *testing.T, c *scriptContainer) {
	const left = "Left as it is: the packages it installed ("
	// name prints a package's name as the script records it.
	manager, name := "apt-get", "dpkg-query -W -f='${binary:Package}' "
	cases := []struct{ pkg, refuse, why string }{
		// apt-get refuses to simulate it: essential packages need it.
		{"libc6", "", "): the package manager could not remove them: E: "},
		{"e2fsprogs", `*" -s "*) ;; *" remove "*) echo 'E: refused by the test' >&2; exit 100 ;;`,
			"): the package manager could not remove them: E: refused by the test"},
	}
	if !c.has(t, "dpkg-query") {
		manager, name = "rpm", "rpm -q --qf '%{NAME}.%{ARCH}' "
		cases = []struct{ pkg, refuse, why string }{
			{"glibc", "", "), because removing them would remove other packages too"},
			{"tar", `*" --test "*) ;; *" -e "*) echo 'error: refused by the test' >&2; exit 1 ;;`,
				"): the package manager could not remove them: error: refused by the test"},
		}
	}
	for _, tc := range cases {
		pkg := strings.TrimSpace(c.sh(t, name+tc.pkg))
		c.sh(t, "rm -rf "+stateDir+" && mkdir -p "+stateDir+"/modules/sudo && printf 'format 1\\npkg\\t%s\\n' "+pkg+" >"+stateDir+
			"/modules/sudo/manifest && date >"+stateDir+"/modules/sudo/done")
		if tc.refuse != "" {
			c.sh(t, "printf '%s\\n' '#!/bin/sh' 'case \" $* \" in "+strings.ReplaceAll(tc.refuse, "'", `'"'"'`)+" esac' 'exec /usr/bin/"+manager+
				" \"$@\"' >/usr/local/sbin/"+manager+" && chmod 0755 /usr/local/sbin/"+manager)
		}
		m := scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "sudo"), HardeningUndo, []string{"sudo"}), "sudo")
		c.sh(t, "rm -f /usr/local/sbin/"+manager)
		want := left + pkg + tc.why
		if m.Outcome != HardeningPartlyUndone || m.Recorded || !slices.ContainsFunc(m.Done, func(d string) bool { return strings.HasPrefix(d, want) }) {
			t.Errorf("undo with %s recorded: %+v, want %q", pkg, m, want)
		}
		if got := strings.TrimSpace(c.sh(t, name+tc.pkg)); got != pkg {
			t.Errorf("%s after undo: %q", pkg, got)
		}
		c.wantGone(t, stateDir)
	}
}

// scriptRollbackLeaves: a module that fails after installing a package,
// whose rollback cannot remove it, says the package stays and why rather
// than that everything was put back. A stand-in apt-get, first in the
// script's PATH, installs a package built in the container in place of
// AIDE, fails, and refuses to remove it. Only where dpkg-deb can build one
// offline (Debian and Ubuntu).
func scriptRollbackLeaves(t *testing.T, c *scriptContainer) {
	if !c.has(t, "dpkg-deb") {
		return
	}
	c.sh(t, "rm -rf "+stateDir+" /tmp/easyrmm-test-pkg && mkdir -p /tmp/easyrmm-test-pkg/DEBIAN && "+
		"printf 'Package: easyrmm-test-pkg\\nVersion: 1\\nArchitecture: all\\nMaintainer: EasyRMM tests <tests@example.invalid>\\nDescription: a stand-in\\n' "+
		">/tmp/easyrmm-test-pkg/DEBIAN/control && dpkg-deb --build /tmp/easyrmm-test-pkg /tmp/easyrmm-test-pkg.deb >/dev/null && "+
		"printf '%s\\n' '#!/bin/sh' 'case \" $* \" in' "+
		`'*" -s "*) exec /usr/bin/apt-get "$@" ;;' `+
		`'*" update "*) exit 0 ;;' `+
		`'*" install "*) dpkg -i /tmp/easyrmm-test-pkg.deb >/dev/null; echo "E: stopped by the test" >&2; exit 100 ;;' `+
		`'*" remove "*) echo "E: refused by the test" >&2; exit 100 ;;' `+
		"'esac' 'exec /usr/bin/apt-get \"$@\"' >/usr/local/sbin/apt-get && chmod 0755 /usr/local/sbin/apt-get")
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "apply", "integrity"), HardeningApply, []string{"integrity"}), "integrity")
	c.sh(t, "rm -f /usr/local/sbin/apt-get")
	const want = "AIDE could not be installed: E: stopped by the test; what this run changed was put back, but the packages it installed " +
		"(easyrmm-test-pkg) stay: the package manager could not remove them: E: refused by the test."
	if m.Outcome != HardeningOutcomeFailed || m.OutcomeReason != want || m.Recorded {
		t.Errorf("a failed apply whose package stays: %+v, want %q", m, want)
	}
	if got := strings.TrimSpace(c.sh(t, "dpkg-query -W -f='${Status}' easyrmm-test-pkg")); got != "install ok installed" {
		t.Errorf("the package the stand-in installed: %q", got)
	}
	c.sh(t, "dpkg --purge easyrmm-test-pkg >/dev/null && rm -rf "+stateDir+" /tmp/easyrmm-test-pkg /tmp/easyrmm-test-pkg.deb")
}

// scriptModuleStream: a dnf module stream a package step enabled (RHEL 8's
// python36, for fail2ban from EPEL) goes with the rollback of a module that
// fails. A stand-in dnf, first in the script's PATH, writes a module
// stream's file as dnf does when it enables one, and fails to install AIDE.
// Only where dnf is the package manager.
func scriptModuleStream(t *testing.T, c *scriptContainer) {
	if !c.has(t, "dnf") {
		return
	}
	const stream = "/etc/dnf/modules.d/easyrmm-test.module"
	c.sh(t, "rm -rf "+stateDir+" && test ! -e "+stream+" && "+
		"printf '%s\\n' '#!/bin/sh' "+
		`'mkdir -p /etc/dnf/modules.d && printf "[easyrmm-test]\\nname=easyrmm-test\\nstream=1\\nprofiles=\\nstate=enabled\\n" >`+stream+`' `+
		`'case " $* " in *" install "*) echo "Error: stopped by the test" >&2; exit 1 ;; esac' `+
		">/usr/local/sbin/dnf && chmod 0755 /usr/local/sbin/dnf")
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "apply", "integrity"), HardeningApply, []string{"integrity"}), "integrity")
	c.sh(t, "rm -f /usr/local/sbin/dnf")
	const want = "AIDE could not be installed: Error: stopped by the test; what this run changed was put back."
	if m.Outcome != HardeningOutcomeFailed || m.OutcomeReason != want || m.Recorded {
		t.Errorf("a failed apply that enabled a module stream: %+v, want %q", m, want)
	}
	c.wantGone(t, stream)
	c.sh(t, "rm -rf "+stateDir)
}

// scriptPackageRecovery: a package step that finds the package database
// left unusable by one stopped part way recovers it first, unless another
// process still uses it, which is waited for and never touched (ADR-0051).
// Undo of a record naming a package runs while a process uses the
// database, in a copy of the script that waits 6 seconds for it rather
// than 300, and is refused; then, once that process is gone, it recovers
// the database and removes the package. Where dpkg-deb can build a package
// offline (Debian and Ubuntu), apply recovers before installing, too; where
// rpm keeps its database in Berkeley DB (RHEL 8), an rpm killed while it
// writes leaves it unusable. Elsewhere nothing needs recovering.
func scriptPackageRecovery(t *testing.T, c *scriptContainer) {
	switch {
	case c.has(t, "dpkg-deb"):
		scriptDpkgRecovery(t, c)
	case c.has(t, "rpm") && strings.TrimSpace(c.sh(t, "test -e /var/lib/rpm/Packages && echo bdb; true")) == "bdb":
		scriptRpmRecovery(t, c)
	default:
		t.Log("rpm keeps its database in SQLite here: no package database to recover")
	}
}

// recoveryUndo records PKG as installed by the sudo module, and runs undo
// of it with SCRIPT (the script, or the copy that waits less).
func (c *scriptContainer) recoveryUndo(t *testing.T, script, pkg string) HardeningModuleResult {
	t.Helper()
	c.sh(t, "rm -rf "+stateDir+" && mkdir -p "+stateDir+"/modules/sudo && printf 'format 1\\npkg\\t%s\\n' "+pkg+" >"+stateDir+
		"/modules/sudo/manifest && date >"+stateDir+"/modules/sudo/done")
	out, errOut, code := c.run(t, "sh", script, "undo", "sudo")
	if code != 0 {
		t.Fatalf("undo sudo: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	return scriptModule(t, parseScriptOutcome(t, out, HardeningUndo, []string{"sudo"}), "sudo")
}

// shortWait is a copy of the script that waits 6 seconds for a process
// using the package database.
const shortWait = "/tmp/easyrmm-short-wait.sh"

func (c *scriptContainer) writeShortWait(t *testing.T) {
	t.Helper()
	c.sh(t, "sed 's/^PKG_LOCK_WAIT=300$/PKG_LOCK_WAIT=6/' "+scriptPath+" >"+shortWait+" && grep -q '^PKG_LOCK_WAIT=6$' "+shortWait)
}

// wantRefused: undo while PID, named NAME, used the package database.
func wantRefused(t *testing.T, m HardeningModuleResult, pkg, what, name, pid, use string) {
	t.Helper()
	want := "the packages it installed (" + pkg + ") could not be removed: " + what + ", and " + name + " (PID " + pid + ") still " + use + " after "
	if m.Outcome != HardeningOutcomeFailed || !strings.HasPrefix(m.OutcomeReason, want) ||
		!strings.HasSuffix(m.OutcomeReason, " seconds; it was left to finish; what this run changed was put back.") ||
		!m.Recorded || m.PackageRecovery != nil {
		t.Errorf("undo while %s used the package database: %+v, want a failure starting %q", name, m, want)
	}
}

// wantRecovered: undo that recovered the database and removed PKG.
func wantRecovered(t *testing.T, m HardeningModuleResult, pkg, why string) {
	t.Helper()
	if m.Outcome != HardeningUndone || m.Recorded || m.PackageRecovery == nil ||
		*m.PackageRecovery != (HardeningPackageRecovery{Outcome: HardeningRecovered, Reason: why}) ||
		!slices.Contains(m.Done, why) || !slices.Contains(m.Done, "Removed the packages it installed: "+pkg) {
		t.Errorf("undo after the package database was left unusable: %+v", m)
	}
}

func scriptDpkgRecovery(t *testing.T, c *scriptContainer) {
	// The package's postinst waits while /tmp/easyrmm-test-hold exists.
	c.sh(t, "rm -rf "+stateDir+" /tmp/easyrmm-test-pkg && mkdir -p /tmp/easyrmm-test-pkg/DEBIAN && "+
		"printf 'Package: easyrmm-test-pkg\\nVersion: 1\\nArchitecture: all\\nMaintainer: EasyRMM tests <tests@example.invalid>\\nDescription: a stand-in\\n' "+
		">/tmp/easyrmm-test-pkg/DEBIAN/control && "+
		"printf '#!/bin/sh\\nwhile [ -e /tmp/easyrmm-test-hold ]; do sleep 1; done\\n' >/tmp/easyrmm-test-pkg/DEBIAN/postinst && "+
		"chmod 0755 /tmp/easyrmm-test-pkg/DEBIAN/postinst && dpkg-deb --build /tmp/easyrmm-test-pkg /tmp/easyrmm-test-pkg.deb >/dev/null && "+
		"dpkg -i /tmp/easyrmm-test-pkg.deb >/dev/null")
	pkg := strings.TrimSpace(c.sh(t, "dpkg-query -W -f='${binary:Package}' easyrmm-test-pkg"))
	// hold starts installing the package again, stopped in its postinst:
	// dpkg runs, holding its locks; the PID of that dpkg. (The pattern
	// [.] keeps grep from finding its own command line.)
	hold := func() string {
		c.sh(t, "touch /tmp/easyrmm-test-hold")
		docker(t, "exec", "-d", c.name, "dpkg", "-i", "/tmp/easyrmm-test-pkg.deb")
		c.waitUntil(t, "grep -qs 'easyrmm-test-pkg[.]postinst' /proc/[0-9]*/cmdline", "the postinst to run")
		return strings.TrimSpace(c.sh(t, `for p in /proc/[0-9]*; do [ "$(cat $p/stat 2>/dev/null | cut -d' ' -f2-3)" != "(dpkg) S" ] || echo ${p#/proc/}; done`))
	}
	// interrupt kills that dpkg part way, as a time limit does, and lets
	// its postinst end: dpkg is interrupted, and apt refuses every step.
	interrupt := func(pid string) {
		c.sh(t, "kill -9 "+pid+" && rm -f /tmp/easyrmm-test-hold")
		c.waitUntil(t, "! grep -qs 'easyrmm-test-pkg[.]postinst' /proc/[0-9]*/cmdline", "the postinst to end")
		if out, errOut, code := c.run(t, "apt-get", "check"); code == 0 || !strings.Contains(out+errOut, "dpkg was interrupted") {
			t.Fatalf("apt-get check after dpkg was killed: exit %d\n%s%s", code, out, errOut)
		}
	}
	const why = "dpkg was interrupted: dpkg --configure -a put it right before the package step"

	pid := hold()
	c.writeShortWait(t)
	wantRefused(t, c.recoveryUndo(t, shortWait, pkg), pkg, "dpkg was interrupted", "dpkg", pid, "held its lock")
	// The dpkg that held the lock still runs, in its postinst.
	c.sh(t, "grep -qs 'easyrmm-test-pkg[.]postinst' /proc/[0-9]*/cmdline && test \"$(cut -d' ' -f3 /proc/"+pid+"/stat)\" = S")
	interrupt(pid)
	wantRecovered(t, c.recoveryUndo(t, scriptPath, pkg), pkg, why)
	c.sh(t, "! dpkg-query -W easyrmm-test-pkg >/dev/null 2>&1 && apt-get check >/dev/null")
	c.wantGone(t, stateDir)

	// Apply recovers before it installs: a stand-in apt-get, first in the
	// script's PATH, then fails to install AIDE.
	interrupt(hold())
	c.sh(t, "printf '%s\\n' '#!/bin/sh' 'case \" $* \" in' "+
		`'*" update "*) exit 0 ;;' '*" install "*) echo "E: stopped by the test" >&2; exit 100 ;;' `+
		"'esac' 'exec /usr/bin/apt-get \"$@\"' >/usr/local/sbin/apt-get && chmod 0755 /usr/local/sbin/apt-get")
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "apply", "integrity"), HardeningApply, []string{"integrity"}), "integrity")
	c.sh(t, "rm -f /usr/local/sbin/apt-get")
	if m.Outcome != HardeningOutcomeFailed || m.OutcomeReason != "AIDE could not be installed: E: stopped by the test; what this run changed was put back." ||
		m.PackageRecovery == nil || *m.PackageRecovery != (HardeningPackageRecovery{Outcome: HardeningRecovered, Reason: why}) || m.Recorded {
		t.Errorf("apply after dpkg was interrupted: %+v", m)
	}
	c.sh(t, "apt-get check >/dev/null && dpkg --purge easyrmm-test-pkg >/dev/null && rm -rf "+stateDir+" "+shortWait+
		" /tmp/easyrmm-test-pkg /tmp/easyrmm-test-pkg.deb")
}

func scriptRpmRecovery(t *testing.T, c *scriptContainer) {
	// rootfiles: a package nothing needs, of five files.
	const pkg = "rootfiles.noarch"
	c.sh(t, "rpm -q rootfiles >/dev/null && rpm -e --test rootfiles")
	// An rpm removing tzdata (some 1,900 files) is killed as soon as it
	// has its database open, as a time limit does: every rpm and dnf
	// command fails after it.
	c.sh(t, `rpm -e --nodeps tzdata >/dev/null 2>&1 & p=$!; i=0
		until grep -qs '/var/lib/rpm/__db\.' /proc/$p/maps; do i=$((i + 1)); [ $i -lt 20000 ] || exit 1; done
		kill -9 $p; wait $p; true`)
	if out, errOut, code := c.run(t, "rpm", "-q", "rpm"); code == 0 || !strings.Contains(out+errOut, "DB_RUNRECOVERY") {
		t.Fatalf("rpm -q after rpm was killed: exit %d\n%s%s", code, out, errOut)
	}
	// Another process has the database's environment open.
	docker(t, "exec", "-d", c.name, "/usr/libexec/platform-python", "-c",
		"import mmap, time; f = open('/var/lib/rpm/__db.001', 'rb'); m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ); time.sleep(600)")
	c.waitUntil(t, "grep -qs '/var/lib/rpm/__db\\.001' /proc/[0-9]*/maps", "the environment to be mapped")
	pid := strings.TrimSpace(c.sh(t, "grep -l '/var/lib/rpm/__db\\.001' /proc/[0-9]*/maps | cut -d/ -f3"))
	c.writeShortWait(t)
	const what = "rpm's database needed recovering (DB_RUNRECOVERY)"
	wantRefused(t, c.recoveryUndo(t, shortWait, pkg), pkg, what, "platform-python", pid, "had it open")
	c.sh(t, "kill -9 "+pid)
	c.waitUntil(t, "! grep -qs '/var/lib/rpm/__db\\.001' /proc/[0-9]*/maps", "the environment to be let go")
	wantRecovered(t, c.recoveryUndo(t, scriptPath, pkg), pkg, what+": removing /var/lib/rpm/__db.* put it right before the package step")
	c.sh(t, "! rpm -q rootfiles >/dev/null && rpm -q tzdata >/dev/null && dnf -q -C check && rm -f "+shortWait)
	c.wantGone(t, stateDir)
}

// scriptDanglingUnitLink: undo of a unit that was not there before apply,
// and went with the package undo removed, removes a link systemctl enable
// made for it, which points nowhere now (Ubuntu 22.04's fail2ban). Another
// such link, to a unit that was there before apply, stays.
func scriptDanglingUnitLink(t *testing.T, c *scriptContainer) {
	const wants = "/etc/systemd/system/multi-user.target.wants/"
	c.sh(t, "rm -rf "+stateDir+" && mkdir -p "+stateDir+"/modules/sudo "+wants+" && "+
		"ln -s /usr/lib/systemd/system/easyrmm-test.service "+wants+"easyrmm-test.service && "+
		"ln -s /usr/lib/systemd/system/easyrmm-test-kept.service "+wants+"easyrmm-test-kept.service && "+
		"printf 'format 1\\nunit\\teasyrmm-test.service\\tnot-found\\tinactive\\tenabled\\tactive\\n"+
		"unit\\teasyrmm-test-kept.service\\tenabled\\tactive\\tenabled\\tactive\\n' >"+stateDir+"/modules/sudo/manifest && "+
		"date >"+stateDir+"/modules/sudo/done")
	m := scriptModule(t, parseScriptOutcome(t, c.script(t, "undo", "sudo"), HardeningUndo, []string{"sudo"}), "sudo")
	const want = "Removed " + wants + "easyrmm-test.service, a link to easyrmm-test.service, gone with its package"
	if m.Outcome != HardeningUndone || !slices.Equal(m.Done, []string{want}) || m.Recorded {
		t.Errorf("undo of units gone with their packages: %+v, want done %q", m, want)
	}
	c.sh(t, "! test -L "+wants+"easyrmm-test.service && test -L "+wants+"easyrmm-test-kept.service && rm -rf "+stateDir+" "+wants+"easyrmm-test-kept.service")
}

type scriptContainer struct {
	name  string
	cache map[string]bool
}

// startScriptContainer runs IMAGE with no network and the script mounted
// read-only, removed when the test ends.
func startScriptContainer(t *testing.T, image, script string) *scriptContainer {
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
	c := &scriptContainer{name: "easyrmm-testhardening-" + hex.EncodeToString(b), cache: map[string]bool{}}
	docker(t, "run", "-d", "--rm", "--network", "none", "--name", c.name,
		"-v", script+":"+scriptPath+":ro", image, "sleep", "infinity")
	t.Cleanup(func() { _, _, _ = dockerRun(time.Minute, "rm", "-f", c.name) })
	return c
}

// run runs a command in the container as root: its stdout, stderr and exit
// status.
func (c *scriptContainer) run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	return c.runAs(t, "0:0", args...)
}

func (c *scriptContainer) runAs(t *testing.T, user string, args ...string) (string, string, int) {
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

// sh runs a shell script in the container as root; it must succeed.
func (c *scriptContainer) sh(t *testing.T, script string) string {
	t.Helper()
	out, errOut, code := c.run(t, "sh", "-c", script)
	if code != 0 {
		t.Fatalf("%s: exit %d\n%s\n%s", script, code, out, errOut)
	}
	return out
}

// script runs the hardening script; it must exit 0.
func (c *scriptContainer) script(t *testing.T, args ...string) string {
	t.Helper()
	out, errOut, code := c.run(t, append([]string{"sh", scriptPath}, args...)...)
	if code != 0 {
		t.Fatalf("%q: exit %d\nstdout:\n%s\nstderr:\n%s", args, code, out, errOut)
	}
	return out
}

// wantModes checks files' modes, each given as "MODE PATH".
func (c *scriptContainer) wantModes(t *testing.T, want ...string) {
	t.Helper()
	for _, w := range want {
		_, path, _ := strings.Cut(w, " ")
		if got := strings.TrimSpace(c.sh(t, "stat -c '%a %n' "+path)); got != w {
			t.Errorf("mode %q, want %q", got, w)
		}
	}
}

func (c *scriptContainer) wantGone(t *testing.T, path string) {
	t.Helper()
	if _, _, code := c.run(t, "test", "-e", path); code == 0 {
		t.Errorf("%s is still there", path)
	}
}

// waitFor waits for a path to appear.
func (c *scriptContainer) waitFor(t *testing.T, path string) {
	t.Helper()
	c.waitUntil(t, "test -e "+path, path+" to appear")
}

// waitUntil waits for a shell test to succeed.
func (c *scriptContainer) waitUntil(t *testing.T, test, what string) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		if _, _, code := c.run(t, "sh", "-c", test); code == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited a minute for %s", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// has reports whether the container has a command.
func (c *scriptContainer) has(t *testing.T, cmd string) bool {
	t.Helper()
	if v, ok := c.cache[cmd]; ok {
		return v
	}
	_, _, code := c.run(t, "sh", "-c", `command -v "$1" >/dev/null`, "sh", cmd)
	c.cache[cmd] = code == 0
	return code == 0
}

// diff lists what changed in the container's filesystem since it started.
func (c *scriptContainer) diff(t *testing.T) []string {
	t.Helper()
	out := strings.TrimSpace(docker(t, "diff", c.name))
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

// platform checks the reported platform against the container's
// os-release, read here independently of the script.
func (c *scriptContainer) platform(t *testing.T, p HardeningPlatform) {
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
	want := HardeningPlatform{ID: id, VersionID: version, Family: families[id], Container: "docker", Support: "full"}
	if want.Family == "" {
		t.Fatalf("no expectations for %s in this test", id)
	}
	if !fullySupported(id, version) {
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
