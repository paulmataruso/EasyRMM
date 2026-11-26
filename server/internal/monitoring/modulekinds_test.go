package monitoring

import (
	"encoding/json"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
)

func okKind(name string) ModuleKind {
	return ModuleKind{Name: name, Label: "x", Module: modules.DNS, Action: "dns.status",
		Eval: func(json.RawMessage, *int) (Verdict, error) { return Verdict{}, nil }}
}

func TestRegisterModuleAlertsRefusesWhatIsNotValid(t *testing.T) {
	three := 3
	cases := map[string]ModuleAlerts{
		"a built-in name":  {Module: modules.DNS, Kinds: []ModuleKind{okKind("offline")}},
		"a bad name":       {Module: modules.DNS, Kinds: []ModuleKind{okKind("DNS Down")}},
		"the repair kind":  {Module: modules.DNS, Kinds: []ModuleKind{okKind(KindRepairFailed)}},
		"another module's": {Module: modules.DNS, Kinds: []ModuleKind{func() ModuleKind { k := okKind("dns_x"); k.Module = modules.DHCP; return k }()}},
		"no evaluator":     {Module: modules.DNS, Kinds: []ModuleKind{{Name: "dns_x", Label: "x", Module: modules.DNS, Action: "dns.status"}}},
		"a bad threshold": {Module: modules.DNS, Kinds: []ModuleKind{func() ModuleKind {
			k := okKind("dns_x")
			k.Threshold = ThresholdSpec{Used: true, Min: 5, Max: 1}
			return k
		}()}},
		"two of one name":      {Module: modules.DNS, Kinds: []ModuleKind{okKind("dns_x"), okKind("dns_x")}},
		"a default of no kind": {Module: modules.DNS, Kinds: []ModuleKind{okKind("dns_x")}, Defaults: []DefaultPolicy{{Key: "a", Kind: "dns_y", Severity: SeverityWarning}}},
		"a default with a threshold the kind does not take": {Module: modules.DNS, Kinds: []ModuleKind{okKind("dns_x")},
			Defaults: []DefaultPolicy{{Key: "a", Kind: "dns_x", Severity: "loud", Threshold: &three}}},
		"not a module": {Module: "nope"},
	}
	for name, m := range cases {
		if err := RegisterModuleAlerts(m); err == nil {
			t.Errorf("%s was registered", name)
		}
	}
	if _, ok := ModuleKindOf("dns_x"); ok {
		t.Error("a refused registration left a kind behind")
	}
}

func TestModuleKindPolicyValidation(t *testing.T) {
	k := ModuleKind{Name: "dns_old", Label: "x", Module: modules.DNS, Action: "dns.status", Threshold: ThresholdSpec{Used: true, Min: 1, Max: 30, Unit: "days"},
		Grace: true, Eval: func(json.RawMessage, *int) (Verdict, error) { return Verdict{}, nil }}
	if err := RegisterModuleAlerts(ModuleAlerts{Module: modules.DNS, Kinds: []ModuleKind{k}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = RegisterModuleAlerts(ModuleAlerts{Module: modules.DNS}) })
	ten, forty := 10, 40
	bad := func(cd condition) bool { return cd.validate() != nil }
	base := condition{name: "n", kind: "dns_old", severity: SeverityWarning, threshold: &ten, minutes: 5}
	if bad(base) {
		t.Error("a valid module policy was refused")
	}
	if c := base; func() bool { c.threshold = &forty; return !bad(c) }() {
		t.Error("a threshold above the kind's range was accepted")
	}
	if c := base; func() bool { c.threshold = nil; return !bad(c) }() {
		t.Error("a missing threshold was accepted")
	}
	if c := base; func() bool { c.minutes = 0; return !bad(c) }() {
		t.Error("a grace of 0 minutes was accepted")
	}
	if !validKind("dns_old") || validKind("dns_nope") {
		t.Error("validKind does not follow the registry")
	}
}
