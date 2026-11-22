//go:build integration || vm

package jobs

import (
	"slices"
	"strings"
	"testing"
)

// What the container and machine tests of the hardening script share.

// What a container's kernel, clock and devices make not applicable there.
var containerNotApplicable = []string{"kernel-modules", "usb-storage", "time", "audit", "mac", "shared-memory"}

// The family the script reports for each os-release ID tested.
var families = map[string]string{
	"debian": "debian", "ubuntu": "debian",
	"rocky": "rhel", "almalinux": "rhel", "rhel": "rhel",
	"fedora": "fedora",
}

// The platforms the script reports full support for, by os-release ID: an
// independent copy of the script's table, for the images and machines tested
// here. It is exactly the releases CI's machine tests apply and undo every
// module on (internal/vmtest's images); the rest are checked only.
var fullSupport = map[string][]string{
	"debian": {"12", "13"}, "ubuntu": {"22.04", "24.04", "26.04"},
	"rocky": {"8", "9", "10"}, "almalinux": {"9", "10"},
	"fedora": {"45"},
}

// fullySupported reports whether the table above lists a release, whole
// (Ubuntu's 24.04) or by its major version (Rocky Linux 9.6 is 9).
func fullySupported(id, version string) bool {
	major, _, _ := strings.Cut(version, ".")
	return slices.Contains(fullSupport[id], version) || slices.Contains(fullSupport[id], major)
}

// scriptModule is the result's report of one module.
func scriptModule(t *testing.T, r *hardeningResult, name string) HardeningModuleResult {
	t.Helper()
	for _, m := range r.Modules {
		if m.Module == name {
			return m
		}
	}
	t.Fatalf("no %s in the result", name)
	return HardeningModuleResult{}
}

// parseScriptResult reads a check's result as the server does; see
// parseScriptOutcome.
func parseScriptResult(t *testing.T, stdout string, wantModules []string) *hardeningResult {
	t.Helper()
	return parseScriptOutcome(t, stdout, HardeningCheck, wantModules)
}

// parseScriptOutcome reads the result of MODE as the server does, and
// checks what the server's parser leaves to the script: empty values left
// out, the container's kind, a reason where the state or the outcome needs
// one, what apply did where it applied, and the modules in the script's
// order.
func parseScriptOutcome(t *testing.T, stdout, mode string, wantModules []string) *hardeningResult {
	t.Helper()
	r, err := parseHardeningResult(stdout, Hardening{Mode: mode, Modules: wantModules})
	if err != nil {
		t.Fatalf("the server would refuse the result: %v\n%s", err, stdout)
	}
	raw := strings.TrimPrefix(lastLine(stdout), HardeningResultPrefix)
	for _, empty := range []string{`:""`, `:[]`, `:{}`} {
		if strings.Contains(raw, empty) {
			t.Errorf("the result has an empty value (%s): %s", empty, raw)
		}
	}
	if !slices.Contains([]string{"none", "lxc", "docker", "podman", "other"}, r.Platform.Container) {
		t.Errorf("platform %+v", r.Platform)
	}
	var got []string
	for _, m := range r.Modules {
		got = append(got, m.Module)
		switch m.State {
		case HardeningNotApplicable, HardeningManagedElsewhere, HardeningNotSupported, HardeningFailed, HardeningHalfApplied:
			if m.Reason == "" {
				t.Errorf("%s is %s without a reason", m.Module, m.State)
			}
		case HardeningPartly:
			if len(m.Missing) == 0 {
				t.Errorf("%s is partly in place with nothing missing", m.Module)
			}
		}
		switch m.Outcome {
		case HardeningSkipped, HardeningRefused, HardeningOutcomeFailed, HardeningNothingToUndo, HardeningNotRun:
			if m.OutcomeReason == "" {
				t.Errorf("%s: %s without a reason", m.Module, m.Outcome)
			}
		case HardeningApplied, HardeningUndone, HardeningPartlyUndone:
			if len(m.Done) == 0 {
				t.Errorf("%s: %s, and nothing said what", m.Module, m.Outcome)
			}
		}
		// Skipped exactly when the check rules the module out.
		notHere := slices.Contains([]string{HardeningNotApplicable, HardeningManagedElsewhere, HardeningNotSupported}, m.State)
		if mode == HardeningApply && m.Outcome != HardeningNotRun && notHere != (m.Outcome == HardeningSkipped) {
			t.Errorf("%s: %s, and apply's outcome is %s", m.Module, m.State, m.Outcome)
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
