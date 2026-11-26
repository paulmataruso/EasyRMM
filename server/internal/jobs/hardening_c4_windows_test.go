//go:build windows

package jobs

import "testing"

// ADR-0078's C4 checks on a real domain controller, as LocalSystem (see
// hardeningSystemTest). They only read, so the test plants nothing. It
// skips where the computer is not a domain controller, where the module is
// not applicable by design.

func TestWindowsC4ChecksAsSystem(t *testing.T) {
	hardeningSystemTest(t)
	r := checkAll(t)
	if r.Platform.Windows == nil || r.Platform.Windows.Role != "domain_controller" {
		t.Skip("this computer is not a domain controller")
	}
	var dc *HardeningModuleResult
	for i := range r.Modules {
		if r.Modules[i].Module == "dc" {
			dc = &r.Modules[i]
		}
	}
	if dc == nil {
		t.Fatal("the dc module is not in the result")
	}
	if dc.State == HardeningFailed || dc.State == HardeningNotSupported || dc.State == HardeningNotApplicable {
		t.Fatalf("module dc: %s (%s)", dc.State, dc.Reason)
	}
	for _, s := range dc.Settings {
		// The backup date needs a repadmin answer in a form this test has
		// not recorded; every other reader must answer.
		if s.State == "unknown" && s.ID != "dc-backup" {
			t.Errorf("setting %s could not be read: %s", s.ID, s.Note)
		}
		t.Logf("%s: %s %q (%s)", s.ID, s.State, s.Value, s.Note)
	}
}
