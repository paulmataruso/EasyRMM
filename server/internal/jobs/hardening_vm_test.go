//go:build vm

package jobs

import (
	"slices"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/vmtest"
)

// TestHardeningCheckOnMachines runs the hardening script this package
// embeds, `check all`, as root on each distribution's cloud image chosen by
// EASYRMM_VM_IMAGE (internal/vmtest; ADR-0051). The result must be one the
// server accepts, for the machine's own platform with full support; every
// module the container test finds not applicable applies here; none fails;
// and nothing under /etc, /usr/local or the script's own state changed.
// Run it with `make test-vm`.
func TestHardeningCheckOnMachines(t *testing.T) {
	for _, image := range vmtest.Selected(t) {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			checkOnMachine(t, image)
		})
	}
}

// What check may read but must never change: configuration, what an
// administrator installed by hand, and the record apply and undo keep.
const machineListing = `find /etc /usr/local /var/lib/easyrmm-hardening -xdev ` +
	`\( -type f -o -type l -o -type d \) -printf '%p %M %u:%g %s %T@\n' 2>/dev/null | LC_ALL=C sort`

func checkOnMachine(t *testing.T, image string) {
	vm := vmtest.Boot(t, image, vmtest.Options{})
	ctx := t.Context()
	if state, err := vm.WaitBooted(ctx); err != nil {
		t.Fatal(err)
	} else if state != "running" {
		// The smoke test fails on this; here it is only context for what
		// the check reports.
		t.Logf("systemd: %s", state)
	}
	const script = "/root/easyrmm-hardening.sh"
	if err := vm.WriteFile(ctx, script, []byte(hardeningScript), 0o700); err != nil {
		t.Fatal(err)
	}

	before := machineRun(t, vm, machineListing)
	stdout, stderr, exit, err := vm.Run(ctx, "sh "+script+" check all")
	if err != nil || exit != 0 {
		t.Fatalf("check all: exit %d, %v\nstdout:\n%s\nstderr:\n%s", exit, err, stdout, stderr)
	}
	after := machineRun(t, vm, machineListing)
	for _, line := range lineDiff(before, after) {
		t.Errorf("check changed the machine: %s", line)
	}

	r := parseScriptResult(t, string(stdout), HardeningModules)
	osRelease := machineRun(t, vm, "cat /etc/os-release")
	id, version := osReleaseField(osRelease, "ID"), osReleaseField(osRelease, "VERSION_ID")
	if !fullySupported(id, version) {
		t.Errorf("%s %s is not in the table of fully supported releases: test it, then add it to the script's table and this test's", id, version)
	}
	want := HardeningPlatform{ID: id, VersionID: version, Family: families[id], Container: "none", Support: "full"}
	if r.Platform != want {
		t.Errorf("platform %+v, want %+v", r.Platform, want)
	}
	for _, m := range r.Modules {
		t.Logf("%-14s %-17s %s", m.Module, m.State, m.Reason)
		switch {
		case m.State == HardeningFailed:
			t.Errorf("%s failed on a machine: %s (missing %q)", m.Module, m.Reason, m.Missing)
		case m.State == HardeningNotApplicable && (slices.Contains(containerNotApplicable, m.Module) || m.Module == "ssh"):
			t.Errorf("%s is not applicable on a machine with sshd: %s", m.Module, m.Reason)
		}
	}
}

func machineRun(t *testing.T, vm *vmtest.VM, script string) string {
	t.Helper()
	stdout, stderr, exit, err := vm.Run(t.Context(), script)
	if err != nil || exit != 0 {
		t.Fatalf("%s: exit %d, %v\n%s", script, exit, err, stderr)
	}
	return strings.TrimSpace(string(stdout))
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
