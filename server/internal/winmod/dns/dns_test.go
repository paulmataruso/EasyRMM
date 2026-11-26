package dns

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
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

// Every catalog entry's pin matches its script, and every script file is in
// the catalog (a script that nothing runs is dead code).
func TestCatalogPinsAndScripts(t *testing.T) {
	c := catalog(t)
	files, err := os.ReadDir("scripts")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		name := "dns." + strings.TrimSuffix(f.Name(), ".ps1")
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

// The tiers of ADR-0076 section 4: what is tier 3 (confirmed and behind a
// step-up), what changes the server, and what only reads.
func TestTiers(t *testing.T) {
	c := catalog(t)
	tier3 := []string{"dns.record_remove_all", "dns.zone_remove", "dns.zone_allow_nonsecure"}
	for _, a := range c.Actions() {
		switch {
		case slices.Contains(tier3, a.Name):
			if !a.Destructive || a.Subject == "" || !a.Changes {
				t.Errorf("%s must be destructive with a subject", a.Name)
			}
		case a.Changes:
			if a.Destructive || a.Permission != "dns.manage" {
				t.Errorf("%s: a tier 2 change is dns.manage and not destructive", a.Name)
			}
		default:
			if a.Permission != "dns.view" || a.Destructive || a.Changes {
				t.Errorf("%s: a read is dns.view and changes nothing", a.Name)
			}
		}
	}
	for _, n := range tier3 {
		if _, ok := c.Lookup(n); !ok {
			t.Errorf("%s is missing", n)
		}
	}
}

func TestProtectedRecords(t *testing.T) {
	for _, tc := range []struct {
		zone, rel string
		want      bool
	}{
		{"corp.example.com", "_ldap._tcp", true},
		{"corp.example.com", "_ldap._tcp.dc._msdcs", true},
		{"corp.example.com", "_kerberos._udp", true},
		{"corp.example.com", "_kpasswd._tcp", true},
		{"corp.example.com", "_gc._tcp.Default-First-Site-Name._sites", true},
		{"corp.example.com", "_ldap.Default-First-Site-Name._sites", true},
		{"corp.example.com", "gc._msdcs", true},
		{"_msdcs.corp.example.com", "@", true},
		{"_msdcs.corp.example.com", "anything", true},
		{"corp.example.com", "DomainDnsZones", true},
		{"corp.example.com", "ForestDnsZones", true},
		{"corp.example.com", "a._msdcs", true},
		{"corp.example.com", "_LDAP._TCP", true},
		// Non-AD underscore records are editable (ADR-0076, amended).
		{"example.com", "_dmarc", false},
		{"example.com", "_acme-challenge", false},
		{"example.com", "selector._domainkey", false},
		{"example.com", "_sip._tcp", false},
		{"example.com", "_spf", false},
		{"example.com", "www", false},
		{"example.com", "@", false},
		{"example.com", "_ldapish", false},
	} {
		if got := ProtectedRecord(tc.zone, tc.rel); got != tc.want {
			t.Errorf("ProtectedRecord(%q, %q) = %v, want %v", tc.zone, tc.rel, got, tc.want)
		}
	}
	for z, want := range map[string]bool{"_msdcs.corp.example.com": true, "DomainDnsZones.corp.example.com": true,
		"forestdnszones.corp.example.com": true, "corp.example.com": false, "example.com": false, "msdcs.example.com": false} {
		if got := ProtectedZone(z); got != want {
			t.Errorf("ProtectedZone(%q) = %v, want %v", z, got, want)
		}
	}
}

func TestRelName(t *testing.T) {
	for _, tc := range [][3]string{
		{"example.com", "@", "@"}, {"example.com", "www", "www"}, {"example.com", "example.com.", "@"},
		{"example.com", "www.example.com.", "www"}, {"Example.com.", "WWW.example.COM.", "www"},
		{"example.com", "www.other.org.", ""}, {"example.com", "notexample.com.", ""},
	} {
		if got := RelName(tc[0], tc[1]); got != tc[2] {
			t.Errorf("RelName(%q, %q) = %q, want %q", tc[0], tc[1], got, tc[2])
		}
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

// The guard refuses before any job exists, by its own code, whatever
// spelling the name takes.
func TestGuardRefusesProtectedNames(t *testing.T) {
	for _, p := range []string{
		`{"zone":"corp.example.com","name":"_ldap._tcp","type":"SRV","data":"0 100 389 dc1.corp.example.com"}`,
		`{"zone":"corp.example.com","name":"_ldap._tcp.corp.example.com.","type":"SRV","data":"0 100 389 dc1.corp.example.com"}`,
		`{"zone":"_msdcs.corp.example.com","name":"@","type":"NS","data":"dc1.corp.example.com"}`,
		`{"zone":"corp.example.com","name":"gc._msdcs","type":"CNAME","data":"dc1.corp.example.com"}`,
	} {
		for _, action := range []string{"dns.record_add", "dns.record_remove"} {
			if got := code(run(t, action, p)); got != "protected_record" {
				t.Errorf("%s %s: code %q", action, p, got)
			}
		}
		if got := code(run(t, "dns.record_set", strings.TrimSuffix(p, "}")+`,"newData":"dc2.corp.example.com"}`)); got != "protected_record" {
			// newData is not a valid SRV for the SRV cases: either refusal is fine, an accept is not.
			if got == "" {
				t.Errorf("record_set accepted %s", p)
			}
		}
	}
	if got := code(run(t, "dns.record_remove_all", `{"zone":"example.com","name":"@"}`)); got != "protected_record" {
		t.Errorf("remove_all of the apex: %q", got)
	}
	if got := code(run(t, "dns.record_remove_all", `{"zone":"corp.example.com","name":"_kerberos._tcp"}`)); got != "protected_record" {
		t.Errorf("remove_all of a locator name: %q", got)
	}
	for _, a := range []string{"dns.zone_remove"} {
		for _, z := range []string{"_msdcs.corp.example.com", "DomainDnsZones.corp.example.com", "ForestDnsZones.corp.example.com"} {
			if got := code(run(t, a, `{"zone":"`+z+`"}`)); got != "protected_zone" {
				t.Errorf("%s %s: %q", a, z, got)
			}
		}
	}
	if got := code(run(t, "dns.zone_create", `{"zone":"_msdcs.corp.example.com","storage":"ad_forest","dynamicUpdate":"Secure"}`)); got != "protected_zone" {
		t.Errorf("zone_create of _msdcs: %q", got)
	}
}

func TestGuardAcceptsEditableRecords(t *testing.T) {
	for _, p := range []string{
		`{"zone":"example.com","name":"www","type":"A","data":"192.0.2.10","ttl":300}`,
		`{"zone":"example.com","name":"_dmarc","type":"TXT","data":"v=DMARC1; p=none"}`,
		`{"zone":"example.com","name":"_sip._tcp","type":"SRV","data":"10 60 5060 sip.example.com"}`,
		`{"zone":"example.com","name":"mail","type":"MX","data":"10 mx.example.com."}`,
		`{"zone":"example.com","name":"*.apps","type":"CNAME","data":"lb.example.com"}`,
		`{"zone":"example.com","name":"host.example.com.","type":"AAAA","data":"2001:db8::1"}`,
		`{"zone":"1.168.192.in-addr.arpa","name":"10","type":"PTR","data":"host.example.com."}`,
	} {
		if err := run(t, "dns.record_add", p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func TestGuardRefusesBadValues(t *testing.T) {
	for _, p := range []string{
		`{"zone":"example.com","name":"www","type":"A","data":"999.1.1.1"}`,
		`{"zone":"example.com","name":"www","type":"A","data":"192.0.2.1; Remove-Item *"}`,
		`{"zone":"example.com","name":"www","type":"A","data":"::1"}`,
		`{"zone":"example.com","name":"www","type":"MX","data":"mx.example.com"}`,
		`{"zone":"example.com","name":"www","type":"SRV","data":"1 2 70000 h.example.com"}`,
		`{"zone":"example.com","name":"@","type":"CNAME","data":"h.example.com"}`,
		`{"zone":"example.com","name":"www.other.org.","type":"A","data":"192.0.2.1"}`,
		`{"zone":"example.com","name":"a b","type":"A","data":"192.0.2.1"}`,
		`{"zone":"exa mple.com","name":"www","type":"A","data":"192.0.2.1"}`,
		`{"zone":"example.com","name":"$(calc)","type":"A","data":"192.0.2.1"}`,
		`{"zone":"example.com","name":"www","type":"SOA","data":"x"}`,
		`{"zone":"example.com","name":"www","type":"A","data":"192.0.2.1","ttl":0}`,
		`{"zone":"example.com","name":"www","type":"A","data":"192.0.2.1","ttl":99999999}`,
		`{"zone":"example.com","name":"www","type":"A"}`,
	} {
		if err := run(t, "dns.record_add", p); err == nil {
			t.Errorf("accepted %s", p)
		}
	}
	if err := run(t, "dns.zone_create", `{"zone":"example.com","storage":"file","dynamicUpdate":"Secure"}`); err == nil {
		t.Error("secure updates on a file zone were accepted")
	}
	if err := run(t, "dns.zone_create", `{"zone":"example.com","storage":"file","dynamicUpdate":"NonsecureAndSecure"}`); err == nil {
		t.Error("a zone was created allowing unauthenticated updates")
	}
	if err := run(t, "dns.zone_set_update", `{"zone":"example.com","mode":"NonsecureAndSecure"}`); err == nil {
		t.Error("the tier 2 action accepted unauthenticated updates")
	}
	if err := run(t, "dns.zone_create", `{"zone":"example.com","storage":"file","dynamicUpdate":"None"}`); err != nil {
		t.Errorf("a plain zone: %v", err)
	}
}

func TestConfirmation(t *testing.T) {
	a, _ := catalog(t).Lookup("dns.zone_remove")
	chk, err := a.Validate(json.RawMessage(`{"zone":"old.example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := a.ConfirmText(chk.Subject); got != "dns.zone_remove:old.example.com" {
		t.Errorf("confirmation %q", got)
	}
}

func FuzzGuards(f *testing.F) {
	for _, s := range []string{"@", "a.b.", "_ldap._tcp", "*.x", "..", "a..b", strings.Repeat("a", 300), "\x00", "é.com"} {
		f.Add("example.com", s, "A", s)
	}
	f.Fuzz(func(t *testing.T, zone, name, typ, data string) {
		_ = RelName(zone, name)
		_ = ProtectedRecord(zone, name)
		_ = ProtectedZone(zone)
		_ = checkData(typ, data)
		_ = guardRecord(true)(map[string]any{"zone": zone, "name": name, "type": typ, "data": data, "newData": data})
	})
}
