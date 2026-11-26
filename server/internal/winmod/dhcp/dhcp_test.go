package dhcp

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

func catalog(t *testing.T) *winmod.Catalog {
	t.Helper()
	c, err := winmod.NewCatalog(Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogPinsAndScripts(t *testing.T) {
	c := catalog(t)
	files, err := os.ReadDir("scripts")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		name := "dhcp." + strings.TrimSuffix(f.Name(), ".ps1")
		a, ok := c.Lookup(name)
		if !ok {
			t.Errorf("%s is not in the catalog", f.Name())
			continue
		}
		if agentproto.HashScript(a.Script) != a.ScriptSHA256 {
			t.Errorf("%s: pin does not match", name)
		}
	}
	if len(files) != len(c.Actions()) || len(pins) != len(files) {
		t.Errorf("%d scripts, %d actions, %d pins", len(files), len(c.Actions()), len(pins))
	}
}

func TestTiers(t *testing.T) {
	tier3 := map[string]bool{"dhcp.scope_deactivate": true, "dhcp.scope_remove": true, "dhcp.scope_range_set": true, "dhcp.option_set_network": true}
	for _, a := range catalog(t).Actions() {
		switch {
		case tier3[a.Name]:
			if !a.Destructive || a.Subject != "scopeId" || a.Permission != "dhcp.manage" {
				t.Errorf("%s must be destructive on its scope", a.Name)
			}
		case a.Changes:
			if a.Destructive || a.Permission != "dhcp.manage" {
				t.Errorf("%s: a tier 2 change is dhcp.manage and not destructive", a.Name)
			}
		default:
			if a.Permission != "dhcp.view" || a.Destructive {
				t.Errorf("%s: a read is dhcp.view", a.Name)
			}
		}
	}
	a, _ := catalog(t).Lookup("dhcp.lease_list")
	if !a.Sensitive || a.SensitivePermission != "dhcp.manage" || a.Keep != LeaseKeep || a.Freshness != 0 {
		t.Errorf("lease_list is sensitive, kept 15 minutes and never a snapshot: %+v", a)
	}
}

func run(t *testing.T, action, params string) error {
	t.Helper()
	a, ok := catalog(t).Lookup(action)
	if !ok {
		t.Fatalf("no action %s", action)
	}
	_, err := a.Validate(json.RawMessage(params))
	return err
}

func code(err error) string {
	var e *apperr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestScopeCreate(t *testing.T) {
	good := `{"name":"Office","startRange":"192.168.10.10","endRange":"192.168.10.200","subnetMask":"255.255.255.0","leaseHours":8}`
	if err := run(t, "dhcp.scope_create", good); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"reversed":      `{"name":"x","startRange":"192.168.10.200","endRange":"192.168.10.10","subnetMask":"255.255.255.0","leaseHours":8}`,
		"two subnets":   `{"name":"x","startRange":"192.168.10.10","endRange":"192.168.11.200","subnetMask":"255.255.255.0","leaseHours":8}`,
		"mask holes":    `{"name":"x","startRange":"192.168.10.10","endRange":"192.168.10.20","subnetMask":"255.0.255.0","leaseHours":8}`,
		"mask all":      `{"name":"x","startRange":"192.168.10.10","endRange":"192.168.10.20","subnetMask":"255.255.255.255","leaseHours":8}`,
		"mask none":     `{"name":"x","startRange":"192.168.10.10","endRange":"192.168.10.20","subnetMask":"0.0.0.0","leaseHours":8}`,
		"bad address":   `{"name":"x","startRange":"192.168.10.300","endRange":"192.168.10.310","subnetMask":"255.255.255.0","leaseHours":8}`,
		"injection":     `{"name":"x","startRange":"192.168.10.1; calc","endRange":"192.168.10.9","subnetMask":"255.255.255.0","leaseHours":8}`,
		"no lease":      `{"name":"x","startRange":"192.168.10.1","endRange":"192.168.10.9","subnetMask":"255.255.255.0"}`,
		"zero lease":    `{"name":"x","startRange":"192.168.10.1","endRange":"192.168.10.9","subnetMask":"255.255.255.0","leaseHours":0}`,
		"state chosen":  `{"name":"x","startRange":"192.168.10.1","endRange":"192.168.10.9","subnetMask":"255.255.255.0","leaseHours":8,"state":"Active"}`,
		"unnamed scope": `{"startRange":"192.168.10.1","endRange":"192.168.10.9","subnetMask":"255.255.255.0","leaseHours":8}`,
	} {
		if run(t, "dhcp.scope_create", p) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// Options 3 and 6 reach every client: option_set refuses them and the
// network action takes only them, at every level, behind a step-up.
func TestOptionSplit(t *testing.T) {
	for _, p := range []string{`{"scopeId":"server","optionId":3,"value":"192.168.1.1"}`, `{"scopeId":"192.168.1.0","optionId":6,"value":"192.168.1.2"}`} {
		if got := code(run(t, "dhcp.option_set", p)); got != "use_network_option" {
			t.Errorf("option_set %s: %q", p, got)
		}
		if err := run(t, "dhcp.option_set_network", p); err != nil {
			t.Errorf("option_set_network %s: %v", p, err)
		}
	}
	for _, p := range []string{
		`{"scopeId":"server","optionId":15,"value":"corp.example.com"}`,
		`{"scopeId":"192.168.1.0","optionId":42,"value":"192.168.1.1, 192.168.1.2"}`,
		`{"scopeId":"192.168.1.0","optionId":51,"value":"28800"}`,
		`{"scopeId":"192.168.1.0","optionId":66,"value":"boot.example.com"}`,
		`{"scopeId":"192.168.1.0","optionId":67,"value":"pxe/boot.wim"}`,
	} {
		if err := run(t, "dhcp.option_set", p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{
		`{"scopeId":"server","optionId":15,"value":"a b"}`,
		`{"scopeId":"server","optionId":43,"value":"x"}`,
		`{"scopeId":"server","optionId":51,"value":"10"}`,
		`{"scopeId":"everything","optionId":15,"value":"x.com"}`,
		`{"scopeId":"server","optionId":67,"value":"a;b"}`,
		`{"scopeId":"server","optionId":42,"value":"1.1.1.1,nope"}`,
	} {
		if run(t, "dhcp.option_set", p) == nil {
			t.Errorf("accepted %s", p)
		}
	}
	if run(t, "dhcp.option_set_network", `{"scopeId":"server","optionId":15,"value":"x.com"}`) == nil {
		t.Error("the network action took option 15")
	}
	if run(t, "dhcp.option_set_network", `{"scopeId":"server","optionId":6,"value":"1.1.1.1,1.1.1.2,1.1.1.3,1.1.1.4,1.1.1.5,1.1.1.6,1.1.1.7,1.1.1.8,1.1.1.9"}`) == nil {
		t.Error("nine addresses were accepted")
	}
}

func TestReservationsAndRanges(t *testing.T) {
	for _, mac := range []string{"00-11-22-33-44-55", "00:11:22:33:44:55", "001122334455", "AA-bb-CC-dd-EE-ff"} {
		if err := run(t, "dhcp.reservation_add", `{"scopeId":"192.168.1.0","ipAddress":"192.168.1.50","clientId":"`+mac+`"}`); err != nil {
			t.Errorf("%s: %v", mac, err)
		}
	}
	for _, mac := range []string{"00-11-22-33-44", "00-11-22-33-44-5g", "00-11:22-33:44-55", "0011223344556", "$(calc)xxxxxxxx"} {
		if run(t, "dhcp.reservation_add", `{"scopeId":"192.168.1.0","ipAddress":"192.168.1.50","clientId":"`+mac+`"}`) == nil {
			t.Errorf("accepted %q", mac)
		}
	}
	if run(t, "dhcp.exclusion_add", `{"scopeId":"192.168.1.0","startRange":"192.168.1.20","endRange":"192.168.1.10"}`) == nil {
		t.Error("a reversed range was accepted")
	}
	if run(t, "dhcp.scope_range_set", `{"scopeId":"192.168.1.0","startRange":"192.168.1.200","endRange":"192.168.1.100"}`) == nil {
		t.Error("a reversed scope range was accepted")
	}
	if err := run(t, "dhcp.scope_range_set", `{"scopeId":"192.168.1.0","startRange":"192.168.1.100","endRange":"192.168.1.200"}`); err != nil {
		t.Error(err)
	}
	if run(t, "dhcp.scope_set", `{"scopeId":"192.168.1.0"}`) == nil {
		t.Error("scope_set with nothing to set was accepted")
	}
	if err := run(t, "dhcp.scope_set", `{"scopeId":"192.168.1.0","description":"x"}`); err != nil {
		t.Error(err)
	}
	if run(t, "dhcp.lease_remove", `{"scopeId":"192.168.1.0","ipAddress":"not-an-ip"}`) == nil {
		t.Error("a lease address that is not one was accepted")
	}
	if err := run(t, "dhcp.option_list", `{}`); err != nil {
		t.Error(err)
	}
	if run(t, "dhcp.option_list", `{"scopeId":"x.x.x.x"}`) == nil {
		t.Error("a scope that is not an address was accepted")
	}
}

func TestConfirmationNamesTheScope(t *testing.T) {
	a, _ := catalog(t).Lookup("dhcp.scope_remove")
	chk, err := a.Validate(json.RawMessage(`{"scopeId":"192.168.1.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := a.ConfirmText(chk.Subject); got != "dhcp.scope_remove:192.168.1.0" {
		t.Errorf("confirmation %q", got)
	}
}
