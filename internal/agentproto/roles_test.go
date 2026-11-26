package agentproto

import "testing"

func TestRoleValidation(t *testing.T) {
	for _, n := range RoleNames {
		if !ValidRoleName(n) {
			t.Errorf("%s is not valid", n)
		}
	}
	for _, n := range []string{"", "AD_DS", "bogus"} {
		if ValidRoleName(n) {
			t.Errorf("%q is valid", n)
		}
	}
	for _, s := range []string{RolePresent, RoleUnconfigured, RoleUnknown, RolePassive} {
		if !ValidRoleState(s) {
			t.Errorf("state %s is not valid", s)
		}
	}
	if ValidRoleState("") || ValidRoleState("absent") {
		t.Error("an unknown state is valid")
	}
}
