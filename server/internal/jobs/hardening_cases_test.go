package jobs

import (
	"slices"
	"testing"
)

// machineCase is what the machine test (hardening_vm_test.go) expects of a
// module in one mode on one distribution family, on the cloud image as it
// boots: for check, the states it may report before apply; for apply and
// undo, the outcomes, and for apply the states the check may report after
// it (and after a restart).
type machineCase struct {
	Want  []string
	After []string
}

// Families the machine test boots: Debian and Ubuntu, Rocky Linux and
// AlmaLinux, Fedora.
var machineFamilies = []string{"debian", "rhel", "fedora"}

// same is a case that holds for every family.
func same(c machineCase) map[string]machineCase {
	return map[string]machineCase{"debian": c, "rhel": c, "fedora": c}
}

// machineCases: module, then mode, then family.
var machineCases = map[string]map[string]map[string]machineCase{
	"ssh": {
		// Password sign-in off is refused: no account has a key.
		HardeningCheck: same(machineCase{Want: []string{HardeningPartly}}),
		HardeningApply: same(machineCase{Want: []string{HardeningApplied}, After: []string{HardeningPartly}}),
		HardeningUndo:  same(machineCase{Want: []string{HardeningUndone}}),
	},
	"firewall": {
		HardeningCheck: same(machineCase{Want: []string{HardeningNotInPlace}}),
		HardeningApply: same(machineCase{Want: []string{HardeningApplied}, After: []string{HardeningInPlace}}),
		HardeningUndo:  same(machineCase{Want: []string{HardeningUndone}}),
	},
	"fail2ban": {
		// On RHEL's rebuilds only with the epel option, which check is not
		// given.
		HardeningCheck: {
			"debian": {Want: []string{HardeningNotInPlace}},
			"rhel":   {Want: []string{HardeningNotApplicable}},
			"fedora": {Want: []string{HardeningNotInPlace}},
		},
		HardeningApply: same(machineCase{Want: []string{HardeningApplied}, After: []string{HardeningInPlace}}),
		HardeningUndo:  same(machineCase{Want: []string{HardeningUndone}}),
	},
	"kernel": {
		HardeningCheck: same(machineCase{Want: []string{HardeningPartly}}),
		HardeningApply: same(machineCase{Want: []string{HardeningApplied}, After: []string{HardeningInPlace}}),
		HardeningUndo:  same(machineCase{Want: []string{HardeningUndone}}),
	},
	"audit": {
		// Debian's and Ubuntu's cloud images have no auditd.
		HardeningCheck: {
			"debian": {Want: []string{HardeningNotInPlace}},
			"rhel":   {Want: []string{HardeningPartly}},
			"fedora": {Want: []string{HardeningPartly, HardeningNotInPlace}},
		},
		HardeningApply: same(machineCase{Want: []string{HardeningApplied}, After: []string{HardeningInPlace}}),
		HardeningUndo:  same(machineCase{Want: []string{HardeningUndone}}),
	},
	"permissions": {
		// Fedora 45's cloud image has every mode as strict already.
		HardeningCheck: {
			"debian": {Want: []string{HardeningPartly}},
			"rhel":   {Want: []string{HardeningPartly}},
			"fedora": {Want: []string{HardeningInPlace}},
		},
		HardeningApply: {
			"debian": {Want: []string{HardeningApplied}, After: []string{HardeningInPlace}},
			"rhel":   {Want: []string{HardeningApplied}, After: []string{HardeningInPlace}},
			"fedora": {Want: []string{HardeningUnchanged}, After: []string{HardeningInPlace}},
		},
		HardeningUndo: {
			"debian": {Want: []string{HardeningUndone}},
			"rhel":   {Want: []string{HardeningUndone}},
			"fedora": {Want: []string{HardeningNothingToUndo}},
		},
	},
	"services": {
		// None of the services is on in a cloud image.
		HardeningCheck: same(machineCase{Want: []string{HardeningInPlace}}),
		HardeningApply: same(machineCase{Want: []string{HardeningUnchanged}, After: []string{HardeningInPlace}}),
		HardeningUndo:  same(machineCase{Want: []string{HardeningNothingToUndo}}),
	},
	"kernel-modules": {
		HardeningCheck: same(machineCase{Want: []string{HardeningPartly, HardeningNotInPlace}}),
		HardeningApply: same(machineCase{Want: []string{HardeningApplied}, After: []string{HardeningInPlace}}),
		HardeningUndo:  same(machineCase{Want: []string{HardeningUndone}}),
	},
	"sudo": {
		HardeningCheck: same(machineCase{Want: []string{HardeningPartly, HardeningNotInPlace}}),
		HardeningApply: same(machineCase{Want: []string{HardeningApplied}, After: []string{HardeningInPlace}}),
		HardeningUndo:  same(machineCase{Want: []string{HardeningUndone}}),
	},
	"time": {
		HardeningCheck: same(machineCase{Want: []string{HardeningInPlace}}),
		HardeningApply: same(machineCase{Want: []string{HardeningUnchanged}, After: []string{HardeningInPlace}}),
		HardeningUndo:  same(machineCase{Want: []string{HardeningNothingToUndo}}),
	},
	"shared-memory": {
		HardeningCheck: same(machineCase{Want: []string{HardeningNotInPlace, HardeningPartly}}),
		HardeningApply: same(machineCase{Want: []string{HardeningApplied}, After: []string{HardeningInPlace}}),
		HardeningUndo:  same(machineCase{Want: []string{HardeningUndone}}),
	},
	"usb-storage": {
		HardeningCheck: same(machineCase{Want: []string{HardeningNotInPlace}}),
		HardeningApply: same(machineCase{Want: []string{HardeningApplied}, After: []string{HardeningInPlace}}),
		HardeningUndo:  same(machineCase{Want: []string{HardeningUndone}}),
	},
	"mac": {
		// AppArmor on Debian and Ubuntu, SELinux enforcing elsewhere.
		// Debian 13's apparmor ships profiles in complain mode (Xorg,
		// plasmashell, sbuild): the check lists them and apply leaves them.
		HardeningCheck: {
			"debian": {Want: []string{HardeningInPlace, HardeningPartly}},
			"rhel":   {Want: []string{HardeningInPlace}},
			"fedora": {Want: []string{HardeningInPlace}},
		},
		HardeningApply: {
			"debian": {Want: []string{HardeningUnchanged}, After: []string{HardeningInPlace, HardeningPartly}},
			"rhel":   {Want: []string{HardeningUnchanged}, After: []string{HardeningInPlace}},
			"fedora": {Want: []string{HardeningUnchanged}, After: []string{HardeningInPlace}},
		},
		HardeningUndo: same(machineCase{Want: []string{HardeningNothingToUndo}}),
	},
	"integrity": {
		HardeningCheck: same(machineCase{Want: []string{HardeningNotInPlace}}),
		HardeningApply: same(machineCase{Want: []string{HardeningApplied}, After: []string{HardeningPartly, HardeningInPlace}}),
		HardeningUndo:  same(machineCase{Want: []string{HardeningUndone}}),
	},
}

// TestEveryModuleHasMachineCases fails when a module, mode and family has
// no case in the machine test (ADR-0051), or a case names a state or
// outcome the script does not report.
func TestEveryModuleHasMachineCases(t *testing.T) {
	for _, module := range HardeningModules {
		for _, mode := range []string{HardeningCheck, HardeningApply, HardeningUndo} {
			for _, family := range machineFamilies {
				c, ok := machineCases[module][mode][family]
				if !ok || len(c.Want) == 0 {
					t.Errorf("%s: no machine case for %s on %s", module, mode, family)
					continue
				}
				known := hardeningOutcomes[mode]
				if mode == HardeningCheck {
					known = hardeningStates
				}
				for _, w := range c.Want {
					if !slices.Contains(known, w) {
						t.Errorf("%s, %s on %s: %q is not one of %s's", module, mode, family, w, mode)
					}
				}
				if (mode == HardeningApply) != (len(c.After) > 0) {
					t.Errorf("%s, %s on %s: states after are for apply, and apply needs them", module, mode, family)
				}
				for _, s := range c.After {
					if !slices.Contains(hardeningStates, s) {
						t.Errorf("%s, %s on %s: %q is not a state", module, mode, family, s)
					}
				}
			}
		}
	}
	for module := range machineCases {
		if !slices.Contains(HardeningModules, module) {
			t.Errorf("machine cases for %q, which is not a module", module)
		}
	}
}
