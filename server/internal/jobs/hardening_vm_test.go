//go:build vm

package jobs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/paulmataruso/easyrmm/internal/vmtest"
)

// TestHardeningOnMachines runs the hardening script this package embeds as
// root on each distribution's cloud image chosen by EASYRMM_VM_IMAGE
// (internal/vmtest; ADR-0051), and reads each result as the server does.
//
//   - check all: for the machine's own platform with full support, no
//     module failed, none that a container rules out is not applicable, and
//     nothing under /etc, /usr/local or the script's state changed.
//   - Each module, one at a time: apply, then check; apply again, which
//     changes nothing. What each reports must match its case in
//     machineCases.
//   - fail2ban bans real failed sign-ins from outside (QEMU's 10.0.2.2),
//     and with that address trusted does not.
//   - A restart: every module checks as it did after apply.
//   - Undo of each module, last first; a restart; then every file under
//     /etc and /usr/local, the kernel's parameters, units, packages, rules
//     and mounts as they were before apply (machineState).
//
// Run it with `make test-vm`.
func TestHardeningOnMachines(t *testing.T) {
	for _, image := range vmtest.Selected(t) {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			hardenMachine(t, image)
		})
	}
}

// What check may read but must never change: configuration, what an
// administrator installed by hand, and the record apply and undo keep.
const machineListing = `find /etc /usr/local /var/lib/easyrmm-hardening -xdev ` +
	`\( -type f -o -type l -o -type d \) -printf '%p %M %u:%g %s %T@\n' 2>/dev/null | LC_ALL=C sort`

// The kernel parameters the kernel module sets, and forwarding, which it
// never sets: an independent copy of the script's list.
var machineSysctls = []string{
	"net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects",
	"net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects",
	"net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.default.accept_source_route",
	"net.ipv6.conf.all.accept_redirects", "net.ipv6.conf.default.accept_redirects",
	"net.ipv6.conf.all.accept_source_route", "net.ipv6.conf.default.accept_source_route",
	"net.ipv4.tcp_syncookies", "net.ipv4.conf.all.log_martians", "net.ipv4.conf.default.log_martians",
	"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter",
	"kernel.dmesg_restrict", "kernel.kptr_restrict", "kernel.yama.ptrace_scope", "kernel.unprivileged_bpf_disabled",
	"fs.protected_hardlinks", "fs.protected_symlinks", "fs.protected_fifos", "fs.protected_regular",
	"net.ipv4.ip_forward",
}

// The units modules start, stop, enable or write.
var machineUnits = []string{
	"ssh.service", "ssh.socket", "sshd.service", "easyrmm-firewall.service", "nftables.service", "fail2ban.service",
	"auditd.service", "chronyd.service", "chrony.service", "systemd-timesyncd.service", "easyrmm-aide-check.timer",
	"dailyaidecheck.timer", "aidecheck.timer",
}

// machineState lists what apply may change and undo must put back, one
// item a line, sorted: every file, link and directory under /etc and
// /usr/local with its mode and owner, and each file's content; the kernel
// parameters; the units' states; the packages installed; nftables, the
// audit rules, /dev/shm's options, SELinux's mode; whether an initramfs
// carries EasyRMM's files; the script's state.
func machineState() string {
	var b strings.Builder
	// Emulated, systemd can be too busy to list its unit files just after
	// a restart: it is asked again for up to two minutes.
	b.WriteString(`n=0
until units=$(systemctl list-unit-files --no-legend --no-pager 2>/dev/null) && [ -n "$units" ] || [ "$n" -ge 12 ]; do
	n=$((n + 1))
	sleep 10
done
{
find /etc /usr/local -xdev \( -type f -o -type l -o -type d \) -printf 'path %y %p %M %u:%g %l\n'
find /etc /usr/local -xdev -type f -exec sha256sum {} + | grep -v ' /etc/selinux/[^/]*/policy/policy\.[0-9]*$' | sed 's/^/content /'
# SELinux's policy, rebuilt when a package adds a module and again when it
# goes (fail2ban's), is not the same bytes as the image's: its modules and
# booleans are compared instead.
! command -v semodule >/dev/null || semodule -l 2>/dev/null | sed 's/^/selinux-module /'
! command -v getsebool >/dev/null || getsebool -a 2>/dev/null | sed 's/^/selinux-boolean /'
`)
	for _, p := range machineSysctls {
		fmt.Fprintf(&b, "printf 'sysctl %s %%s\\n' \"$(sysctl -n %s 2>&1)\"\n", p, p)
	}
	for _, u := range machineUnits {
		fmt.Fprintf(&b, "printf 'unit %s %%s %%s\\n' \"$(systemctl is-enabled %s 2>/dev/null)\" \"$(systemctl is-active %s 2>/dev/null)\"\n", u, u, u)
	}
	b.WriteString(`printf '%s\n' "$units" | awk 'NF { print "unit-file", $1, $2 }'
if command -v dpkg-query >/dev/null; then
	dpkg-query -W -f='package ${db:Status-Abbrev} ${binary:Package} ${Version}\n'
else
	rpm -qa --qf 'package %{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'
fi
nft list ruleset 2>&1 | sed 's/^/nft /'
auditctl -l 2>&1 | sed 's/^/audit /'
printf 'shm %s\n' "$(findmnt -no OPTIONS /dev/shm)"
printf 'selinux %s\n' "$(getenforce 2>/dev/null)"
for i in /boot/initrd.img-* /boot/initramfs-*.img; do
	[ -f "$i" ] || continue
	case $i in *kdump*) continue ;; esac
	if command -v lsinitramfs >/dev/null; then lsinitramfs "$i"; else lsinitrd "$i"; fi 2>/dev/null | grep -c easyrmm | sed "s|^|initramfs $i |"
done
printf 'state %s\n' "$(ls -A /var/lib/easyrmm-hardening 2>&1)"
printf 'shared %s\n' "$(ls -A /var/lib/easyrmm 2>&1)"
awk -F: '{ print "account", $1, $3, $7 }' /etc/passwd
awk -F: '{ print "group", $1, $3 }' /etc/group
} | LC_ALL=C sort`)
	return b.String()
}

// volatile reports whether a line of machineState's difference is one
// that changes whatever hardening does: the content of a cache rebuilt
// when packages come and go, and of the account files and their backups
// (whose accounts leftAccount compares).
func volatile(line string) bool {
	f := strings.Fields(line)
	var path string
	switch {
	case len(f) == 4 && f[1] == "content":
		path = f[3]
	case len(f) >= 4 && f[0] == "+" && f[1] == "path" && f[2] == "f":
		// A backup the account tools made.
		path = strings.TrimSuffix(f[3], "-")
		if path == f[3] {
			return false
		}
	default:
		return false
	}
	return slices.Contains([]string{"/etc/ld.so.cache", "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"}, strings.TrimSuffix(path, "-"))
}

// leftAccount reports whether a line of machineState's difference is a
// system account or group that a package apply installed created: Debian
// and RHEL keep those when the package is removed, so that files they
// owned are never given to a later account.
func leftAccount(line string) bool {
	f := strings.Fields(line)
	if len(f) < 4 || f[0] != "+" {
		return false
	}
	id, err := strconv.Atoi(f[3])
	switch {
	case err != nil || id >= 1000:
		return false
	case f[1] == "group":
		return len(f) == 4
	case f[1] == "account":
		return len(f) == 5 && (strings.HasSuffix(f[4], "/nologin") || strings.HasSuffix(f[4], "/false"))
	}
	return false
}

// hardenMachine is TestHardeningOnMachines on one image.
func hardenMachine(t *testing.T, image string) {
	vm := vmtest.Boot(t, image, vmtest.Options{Forward: []int{22}})
	m := &hardeningMachine{t: t, vm: vm}
	if state, err := vm.WaitBooted(t.Context()); err != nil {
		t.Fatal(err)
	} else if state != "running" {
		// The smoke test fails on this; here it is only context for what
		// the check reports.
		t.Logf("systemd: %s", state)
	}
	if err := vm.WriteFile(t.Context(), machineScript, []byte(hardeningScript), 0o700); err != nil {
		t.Fatal(err)
	}
	osRelease := m.run("cat /etc/os-release", time.Minute)
	id, version := osReleaseField(osRelease, "ID"), osReleaseField(osRelease, "VERSION_ID")
	m.family = families[id]
	// Password sign-in on, as on many servers (cloud-init turns it off):
	// with no account that has a key, password-off is then refused. First
	// in sshd_config, whose first value wins. And where sshd has penalties
	// of its own for failed sign-ins (OpenSSH 9.8 and later), those off, so
	// that what cuts the test's wrong sign-ins off is fail2ban alone
	// (OpenSSH 10.5 prints the keyword as PerSourcePenalties, earlier
	// releases in lower case).
	m.run(`sed -i '1i PasswordAuthentication yes' /etc/ssh/sshd_config
if sshd -T 2>/dev/null | grep -qi '^persourcepenalties '; then sed -i '1i PerSourcePenalties no' /etc/ssh/sshd_config; fi
for u in ssh.service sshd.service; do systemctl try-reload-or-restart "$u" 2>/dev/null; done; true`, time.Minute)
	// Debian 13's apt-listchanges.timer turns itself off once its service
	// has run, within the hour: run it now, so that it is off in both
	// snapshots rather than changing between them.
	m.run(`! systemctl is-enabled apt-listchanges.timer >/dev/null 2>&1 || systemctl start apt-listchanges.service; true`, 15*time.Minute)

	// Check changes nothing.
	before := m.run(machineState(), 10*time.Minute)
	listing := m.run(machineListing, 5*time.Minute)
	first := m.script(HardeningCheck, HardeningModules)
	if after := m.run(machineListing, 5*time.Minute); after != listing {
		for _, line := range lineDiff(listing, after) {
			t.Errorf("check changed the machine: %s", line)
		}
	}
	if !fullySupported(id, version) {
		t.Errorf("%s %s is not in the table of fully supported releases: test it, then add it to the script's table and this test's", id, version)
	}
	want := HardeningPlatform{ID: id, VersionID: version, Family: m.family, Container: "none", Support: "full"}
	if first.Platform != want {
		t.Fatalf("platform %+v, want %+v", first.Platform, want)
	}
	for _, r := range first.Modules {
		t.Logf("check %-14s %-17s %s", r.Module, r.State, r.Reason)
		m.want(r, HardeningCheck, r.State)
	}

	// Apply, check and apply again, module by module.
	auditdBefore := m.hasAuditd()
	applied := map[string]string{}
	for _, module := range HardeningModules {
		r := scriptModule(t, m.script(HardeningApply, []string{module}, machineOptions(module, m.family)...), module)
		t.Logf("apply %-14s %-9s -> %-14s %s %q", module, r.Outcome, r.State, r.OutcomeReason, r.Done)
		m.want(r, HardeningApply, r.Outcome)
		m.wantAfter(r, HardeningApply)
		if r.Outcome == HardeningApplied && !r.Recorded {
			t.Errorf("%s applied without a record", module)
		}
		if module == "audit" && m.marked() == auditdBefore {
			t.Errorf("audit applied with auditd installed before: %v, but the marker %s: %v", auditdBefore, auditdMarker, !auditdBefore)
		}
		again := scriptModule(t, m.script(HardeningApply, []string{module}, machineOptions(module, m.family)...), module)
		// What was refused stays refused; the rest is in place.
		wantAgain := r.Outcome
		if r.Outcome == HardeningApplied {
			wantAgain = HardeningUnchanged
			if slices.ContainsFunc(r.Done, func(d string) bool { return strings.HasPrefix(d, "Refused: ") }) {
				wantAgain = HardeningRefused
			}
		}
		if again.Outcome != wantAgain || len(again.Done) > 0 && again.Outcome != HardeningRefused || again.State != r.State {
			t.Errorf("%s applied again: %s (%s) %q, state %s; want %s, state %s", module, again.Outcome, again.OutcomeReason, again.Done, again.State, wantAgain, r.State)
		}
		applied[module] = r.State
	}
	if _, ok := applied["integrity"]; ok {
		m.waitAIDE()
	}
	afterApply := m.script(HardeningCheck, HardeningModules)
	m.bans()

	// Everything persists across a restart.
	m.restart()
	for _, r := range m.script(HardeningCheck, HardeningModules).Modules {
		if was := scriptModule(t, afterApply, r.Module); r.State != was.State || !slices.Equal(r.Missing, was.Missing) {
			t.Errorf("%s after a restart: %s %q, was %s %q", r.Module, r.State, r.Missing, was.State, was.Missing)
		}
	}

	// Undo, last module first.
	for i := len(HardeningModules) - 1; i >= 0; i-- {
		module := HardeningModules[i]
		if module == "audit" {
			m.keepsAuditd(auditdBefore)
		}
		r := scriptModule(t, m.script(HardeningUndo, []string{module}), module)
		t.Logf("undo  %-14s %-15s -> %-14s %s %q", module, r.Outcome, r.State, r.OutcomeReason, r.Done)
		m.want(r, HardeningUndo, r.Outcome)
		if r.Recorded {
			t.Errorf("%s: a record is left after undo", module)
		}
	}
	for _, r := range m.script(HardeningUndo, HardeningModules).Modules {
		if r.Outcome != HardeningNothingToUndo {
			t.Errorf("%s undone twice: %s %q", r.Module, r.Outcome, r.Done)
		}
	}
	if has, marked := m.hasAuditd(), m.marked(); has != auditdBefore || marked {
		t.Errorf("after undo auditd installed: %v, the marker: %v; before apply auditd installed: %v", has, marked, auditdBefore)
	}

	// After a restart, everything as it was before apply.
	m.restart()
	after := m.run(machineState(), 10*time.Minute)
	for _, line := range lineDiff(before, after) {
		switch {
		case leftAccount(line):
			t.Logf("left by a package: %s", line)
		case !volatile(line):
			t.Errorf("not as before apply: %s", line)
		}
	}
	for _, r := range m.script(HardeningCheck, HardeningModules).Modules {
		if was := scriptModule(t, first, r.Module); r.State != was.State {
			t.Errorf("%s checks %s after undo, %s before apply", r.Module, r.State, was.State)
		}
	}
}

// Where the test puts the script on each machine.
const machineScript = "/root/easyrmm-hardening.sh"

// machineOptions are the options each module is applied with: password
// sign-in off, which is refused where no account has a key (the seed gives
// none one), and EPEL on RHEL and its rebuilds.
func machineOptions(module, family string) []string {
	switch {
	case module == "ssh":
		return []string{"root-password-off", "password-off"}
	case module == "fail2ban" && family == "rhel":
		return []string{"epel"}
	}
	return nil
}

type hardeningMachine struct {
	t      *testing.T
	vm     *vmtest.VM
	family string
}

// run runs a shell script as root, which must succeed within timeout.
func (m *hardeningMachine) run(script string, timeout time.Duration) string {
	m.t.Helper()
	ctx, cancel := context.WithTimeout(m.t.Context(), timeout)
	defer cancel()
	stdout, stderr, exit, err := m.vm.Run(ctx, script)
	if err != nil || exit != 0 {
		m.t.Fatalf("%s: exit %d, %v\n%s\n%s", script, exit, err, stdout, stderr)
	}
	return strings.TrimSpace(string(stdout))
}

// script runs the hardening script; it must exit 0 with a result the
// server accepts. Emulated machines install packages slowly: an hour.
func (m *hardeningMachine) script(mode string, modules []string, options ...string) *hardeningResult {
	m.t.Helper()
	args := append([]string{"sh", machineScript, mode, strings.Join(modules, ",")}, options...)
	return parseScriptOutcome(m.t, m.run(strings.Join(args, " "), time.Hour), mode, modules)
}

// want checks a state or outcome against the module's case for MODE on
// this family.
func (m *hardeningMachine) want(r HardeningModuleResult, mode, got string) {
	m.t.Helper()
	c, ok := machineCases[r.Module][mode][m.family]
	if !ok {
		m.t.Errorf("%s: no case for %s on %s", r.Module, mode, m.family)
		return
	}
	if !slices.Contains(c.Want, got) {
		m.t.Errorf("%s: %s %s (%s %s; %q), want one of %q", r.Module, mode, got, r.Reason, r.OutcomeReason, r.Done, c.Want)
	}
}

// wantAfter checks the state the check found after MODE.
func (m *hardeningMachine) wantAfter(r HardeningModuleResult, mode string) {
	m.t.Helper()
	c := machineCases[r.Module][mode][m.family]
	if !slices.Contains(c.After, r.State) {
		m.t.Errorf("%s after %s: %s (%s; missing %q), want one of %q", r.Module, mode, r.State, r.Reason, r.Missing, c.After)
	}
}

// waitAIDE waits for AIDE's baseline, which apply starts outside the job,
// to finish: emulated, it can take an hour.
func (m *hardeningMachine) waitAIDE() {
	m.t.Helper()
	m.run(`n=0
while systemctl is-active --quiet easyrmm-aide-init.service; do
	n=$((n + 1)); [ "$n" -le 1800 ] || { echo 'the baseline did not finish in 90 minutes' >&2; exit 1; }
	sleep 3
done
systemctl show -p Result --value easyrmm-aide-init.service | grep -qx success`, 95*time.Minute)
}

// The marker the audit module writes when it installs auditd, shared with
// log collection (ADR-0060).
const auditdMarker = "/var/lib/easyrmm/auditd-installed"

func (m *hardeningMachine) hasAuditd() bool {
	m.t.Helper()
	return m.run(`if [ -x /usr/sbin/auditd ] || [ -x /sbin/auditd ]; then echo yes; fi`, time.Minute) == "yes"
}

func (m *hardeningMachine) marked() bool {
	m.t.Helper()
	return m.run("if [ -f "+auditdMarker+" ]; then echo yes; fi", time.Minute) == "yes"
}

// keepsAuditd undoes audit while another rules file is in
// /etc/audit/rules.d: auditd stays installed and running, and so does the
// marker where there is one. Then, with that file gone, audit is applied
// again over the auditd that is now installed, which writes no marker, so
// that the undo that follows removes auditd by the first one alone.
func (m *hardeningMachine) keepsAuditd(before bool) {
	m.t.Helper()
	const foreign = "/etc/audit/rules.d/70-machine-test.rules"
	m.run("echo '-w /etc/hosts -p wa -k machine-test' >"+foreign+" && augenrules --load >/dev/null", time.Minute)
	r := scriptModule(m.t, m.script(HardeningUndo, []string{"audit"}), "audit")
	m.t.Logf("undo  audit with %s: %s %q", foreign, r.Outcome, r.Done)
	want := HardeningUndone
	if !before {
		want = HardeningPartlyUndone
	}
	if r.Outcome != want || r.Recorded {
		m.t.Errorf("audit undone with %s: %s %q, want %s", foreign, r.Outcome, r.Done, want)
	}
	active := m.run("systemctl is-active auditd.service || true", time.Minute)
	if has, marked := m.hasAuditd(), m.marked(); !has || marked == before || active != "active" {
		m.t.Errorf("audit undone with %s: auditd installed %v, the marker %v, auditd %s", foreign, has, marked, active)
	}
	// augenrules makes audit.rules.prev, which undo took away: this
	// load's is the test's, and goes too.
	m.run("rm "+foreign+" && augenrules --load >/dev/null && rm -f /etc/audit/audit.rules.prev", time.Minute)
	r = scriptModule(m.t, m.script(HardeningApply, []string{"audit"}), "audit")
	if marked := m.marked(); r.Outcome != HardeningApplied || marked == before {
		m.t.Errorf("audit applied again over the auditd it installed: %s %q, the marker %v", r.Outcome, r.Done, marked)
	}
}

func (m *hardeningMachine) restart() {
	m.t.Helper()
	if err := m.vm.Restart(m.t.Context()); err != nil {
		m.t.Fatal(err)
	}
}

// bans signs in wrongly from outside, through the forwarded SSH port,
// until fail2ban bans the address the machine sees (QEMU's 10.0.2.2), and
// checks that the ban cuts that address off. Then it applies fail2ban again
// with the address trusted, lifts the ban, signs in wrongly as many times
// without being cut off, and waits until fail2ban has read those failures
// and ignored them. Emulated, fail2ban reads sshd's log minutes late: the
// address is trusted before the ban is lifted, so that failures it has yet
// to read cannot ban it again.
func (m *hardeningMachine) bans() {
	m.t.Helper()
	const outside = "10.0.2.2"
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(m.vm.HostPort(22)))
	for i := 0; i < 12; i++ {
		if cut, _ := wrongSignIn(addr); cut {
			break
		}
	}
	if status := m.run(`n=0
until fail2ban-client status sshd | grep -q 'Banned IP list:.*\b`+outside+`\b'; do
	n=$((n + 1)); [ "$n" -le 60 ] || break
	sleep 10
done
fail2ban-client status sshd`, 15*time.Minute); !strings.Contains(status, outside) {
		m.t.Errorf("fail2ban did not ban %s after wrong sign-ins:\n%s", outside, status)
	} else {
		// fail2ban lists a ban before its action has run (and, the first
		// time, made its nftables table): emulated, that takes a while.
		cut, err := false, error(nil)
		for i := 0; i < 12 && !cut; i++ {
			if i > 0 {
				time.Sleep(10 * time.Second)
			}
			if cut, err = wrongSignIn(addr); cut {
				m.t.Logf("%s cut off at sign-in %d after the ban was listed", outside, i+1)
			}
		}
		if !cut {
			m.t.Errorf("%s, banned, still reached sshd two minutes later: %v", outside, err)
		}
	}

	r := scriptModule(m.t, m.script(HardeningApply, []string{"fail2ban"}, append(machineOptions("fail2ban", m.family), "trusted="+outside+"/32")...), "fail2ban")
	if r.Outcome != HardeningApplied || r.State != HardeningInPlace {
		m.t.Errorf("fail2ban with %s trusted: %s %s %q", outside, r.Outcome, r.OutcomeReason, r.Done)
	}
	// Where fail2ban logs that it ignored a trusted address: its own file,
	// or the journal.
	const ignored = `{ cat /var/log/fail2ban.log 2>/dev/null; journalctl -q -u fail2ban.service 2>/dev/null; } | grep -c '\] Ignore ` + outside + ` by' || true`
	seen := m.run(ignored, time.Minute)
	m.run("fail2ban-client set sshd unbanip "+outside+" >/dev/null 2>&1; true", time.Minute)
	for i := 0; i < 12; i++ {
		if cut, err := wrongSignIn(addr); cut {
			m.t.Errorf("sign-in %d from the trusted %s was cut off: %v", i+1, outside, err)
			break
		}
	}
	if now := m.run(`n=0
while [ "$(`+ignored+`)" -le `+seen+` ] && [ "$n" -lt 60 ]; do n=$((n + 1)); sleep 10; done
`+ignored, 15*time.Minute); now == seen {
		m.t.Errorf("fail2ban did not log that it ignored the trusted %s within 10 minutes", outside)
	}
	if status := m.run("fail2ban-client status sshd", time.Minute); strings.Contains(status, outside) {
		m.t.Errorf("fail2ban banned the trusted %s:\n%s", outside, status)
	}
}

// wrongSignIn signs in as an account that does not exist, with a wrong
// password. It reports whether the machine cut the connection off, as a
// ban does, rather than sshd refusing the password; and the error.
func wrongSignIn(addr string) (bool, error) {
	conf := &ssh.ClientConfig{
		User:            "easyrmm-nobody",
		Auth:            []ssh.AuthMethod{ssh.Password("wrong")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // a test machine's sshd, signed in to wrongly on purpose
	}
	conn, err := net.DialTimeout("tcp", addr, time.Minute)
	if err != nil {
		return true, err
	}
	defer func() { _ = conn.Close() }()
	// Emulated machines answer slowly, but they answer.
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	c, _, _, err := ssh.NewClientConn(conn, addr, conf)
	if err == nil {
		_ = c.Close()
		return false, nil
	}
	// QEMU accepts the connection on the host's side; a ban rejects or
	// drops what reaches the machine, so the handshake ends, is reset
	// (QEMU passes a rejection on as a reset) or never answers.
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, syscall.ECONNRESET) ||
		strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "unable to authenticate"), err
}

// lineDiff lists the lines only one of two listings has, marked - and +.
func lineDiff(before, after string) []string {
	b, a := strings.Split(before, "\n"), strings.Split(after, "\n")
	var d []string
	for _, l := range b {
		if !slices.Contains(a, l) {
			d = append(d, "- "+l)
		}
	}
	for _, l := range a {
		if !slices.Contains(b, l) {
			d = append(d, "+ "+l)
		}
	}
	return d
}

// osReleaseField is a field of os-release, unquoted.
func osReleaseField(osRelease, key string) string {
	for _, line := range strings.Split(osRelease, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}
