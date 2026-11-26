//go:build integration

package jobs

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/roles"
)

// The DNS and DHCP actions through the real winmod path: permissions, the
// protected-name refusals before any job exists, confirmation and step-up.
func TestWinmodDNSAndDHCP(t *testing.T) {
	f := newFixture(t)
	cat, err := winmod.NewCatalog(roles.Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	sealer, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f.svc.SetWinmod(cat, modules.New(f.db, audit.New(f.db, time.Now), log), sealer)
	f.svc.SetStepUp(stepUpStub{})

	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	siteAdmin := f.user("sa@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	ro := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme, SiteID: f.hq})
	dev := f.winmodDevice("HQ-DC", "windows")
	jobs := func() int { return f.count(`SELECT count(*) FROM jobs`) }
	run := func(c access.Caller, action, params, confirm string) error {
		_, err := f.svc.RunWinmod(f.ctx, c, WinmodInput{DeviceID: dev, Action: action, Params: json.RawMessage(params), Confirm: confirm})
		return err
	}
	code := func(err error) string {
		if e, ok := apperr.As(err); ok {
			return e.Code
		}
		return ""
	}

	// A protected record is refused before a job exists, in every spelling.
	for _, a := range []string{"dns.record_add", "dns.record_remove"} {
		for _, name := range []string{"_ldap._tcp", "_ldap._tcp.corp.example.com.", "x._msdcs"} {
			err := run(siteAdmin, a, `{"zone":"corp.example.com","name":"`+name+`","type":"SRV","data":"0 100 389 dc1.corp.example.com"}`, "")
			if code(err) != "protected_record" {
				t.Errorf("%s %s: %v", a, name, err)
			}
		}
	}
	if got := code(run(siteAdmin, "dns.zone_remove", `{"zone":"_msdcs.corp.example.com"}`, "dns.zone_remove:_msdcs.corp.example.com")); got != "protected_zone" {
		t.Errorf("zone_remove of _msdcs: %q", got)
	}
	if jobs() != 0 {
		t.Fatalf("%d jobs were created by refused requests", jobs())
	}

	// Permissions: a Technician reads DHCP but cannot change it or touch DNS;
	// Read-Only holds none of them.
	fieldErr(t, run(tech, "dns.zone_list", ``, ""), "deviceIds", "cannot")
	fieldErr(t, run(tech, "dhcp.scope_create", `{"name":"x","startRange":"10.0.0.10","endRange":"10.0.0.20","subnetMask":"255.255.255.0","leaseHours":8}`, ""), "deviceIds", "cannot")
	fieldErr(t, run(ro, "dhcp.scope_list", ``, ""), "deviceIds", "cannot")
	if err := run(tech, "dhcp.scope_list", ``, ""); err != nil {
		t.Errorf("a Technician reads DHCP scopes: %v", err)
	}
	if err := run(siteAdmin, "dns.record_add", `{"zone":"example.com","name":"www","type":"A","data":"192.0.2.10"}`, ""); err != nil {
		t.Errorf("a plain record: %v", err)
	}

	// Tier 3 needs the confirmation by name, and a step-up.
	before := jobs()
	fieldErr(t, run(siteAdmin, "dhcp.scope_remove", `{"scopeId":"10.0.0.0"}`, ""), "confirm", "dhcp.scope_remove:10.0.0.0")
	fieldErr(t, run(siteAdmin, "dns.record_remove_all", `{"zone":"example.com","name":"old"}`, "dns.record_remove_all:other"), "confirm", "dns.record_remove_all:old")
	f.svc.SetStepUp(stepUpStub{err: errors.New("step up required")})
	if err := run(siteAdmin, "dhcp.option_set_network", `{"scopeId":"server","optionId":6,"value":"10.0.0.2"}`, "dhcp.option_set_network:server"); err == nil {
		t.Error("a gateway or DNS server option changed without a step-up")
	}
	if jobs() != before {
		t.Error("a refused tier 3 action left a job")
	}
	f.svc.SetStepUp(stepUpStub{})
	if err := run(siteAdmin, "dhcp.option_set_network", `{"scopeId":"server","optionId":6,"value":"10.0.0.2"}`, "dhcp.option_set_network:server"); err != nil {
		t.Errorf("with the step-up: %v", err)
	}
	// Tier 2 needs neither.
	f.svc.SetStepUp(nil)
	if err := run(siteAdmin, "dhcp.option_set", `{"scopeId":"10.0.0.0","optionId":15,"value":"corp.example.com"}`, ""); err != nil {
		t.Errorf("a tier 2 change: %v", err)
	}
}
