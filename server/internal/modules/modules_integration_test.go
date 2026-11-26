//go:build integration

package modules_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t         *testing.T
	ctx       context.Context
	db        *database.DB
	svc       *modules.Service
	acme, hq  uuid.UUID
	plant     uuid.UUID
	globex    uuid.UUID
	gsite     uuid.UUID
	dev       uuid.UUID
	orgAdmin  access.Caller
	siteAdmin access.Caller
	tech      access.Caller
	readOnly  access.Caller
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB}
	f.svc = modules.New(inst.DB, audit.New(inst.DB, nil), slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.plant = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.gsite = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Main') RETURNING id`, f.globex)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	f.dev = f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, 'dc1', 'dc1', 'windows', $3, now(), now()) RETURNING id`, f.acme, f.hq, key)
	f.orgAdmin = f.user("oa@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	f.siteAdmin = f.user("sa@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	f.tech = f.user("t@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	f.readOnly = f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	return f
}

func (f *fixture) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fixture) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

// report stores a heartbeat's roles the way the heartbeat does.
func (f *fixture) report(dev, org uuid.UUID, roles []agentproto.Role) (rescan bool) {
	f.t.Helper()
	err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) (err error) {
		rescan, err = f.svc.StoreRoles(f.ctx, tx, dev, org, roles)
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return rescan
}

func present(names ...string) []agentproto.Role {
	out := []agentproto.Role{}
	for _, n := range names {
		out = append(out, agentproto.Role{Name: n, State: agentproto.RolePresent})
	}
	return out
}

func roleNames(r *modules.DeviceRoles) []string {
	out := []string{}
	for _, x := range r.Roles {
		out = append(out, x.Name)
	}
	return out
}

func TestRolesAreStoredCleanedAndRead(t *testing.T) {
	f := newFixture(t)
	// Never reported: unknown, not absent.
	got, err := f.svc.Roles(f.ctx, f.tech, f.dev)
	if err != nil || got.Known || len(got.Roles) != 0 || got.ReportedAt != nil {
		t.Fatalf("before any report: %+v, %v", got, err)
	}
	// An agent that sends none leaves it unknown.
	f.report(f.dev, f.acme, nil)
	if got, _ := f.svc.Roles(f.ctx, f.tech, f.dev); got.Known {
		t.Fatal("a nil report made the roles known")
	}
	rep := append(present("dns", "ad_ds"), agentproto.Role{Name: "made_up", State: "present"},
		agentproto.Role{Name: "dhcp", State: "bogus"}, agentproto.Role{Name: "dns", State: "present"})
	f.report(f.dev, f.acme, rep)
	got, err = f.svc.Roles(f.ctx, f.tech, f.dev)
	if err != nil || !got.Known || got.ReportedAt == nil {
		t.Fatalf("after a report: %+v, %v", got, err)
	}
	if n := roleNames(got); len(n) != 2 || n[0] != "ad_ds" || n[1] != "dns" {
		t.Errorf("roles = %v, want [ad_ds dns]: unknown names and states dropped, no duplicates", n)
	}
	// A nil report keeps the last known list...
	f.report(f.dev, f.acme, nil)
	if got, _ := f.svc.Roles(f.ctx, f.tech, f.dev); !got.Known || len(got.Roles) != 2 {
		t.Errorf("a nil report changed the list: %+v", got)
	}
	// ...for 7 days, then it reads as unknown.
	f.exec(`UPDATE devices SET roles_at = now() - interval '8 days' WHERE id = $1`, f.dev)
	if got, _ := f.svc.Roles(f.ctx, f.tech, f.dev); got.Known || len(got.Roles) != 0 {
		t.Errorf("after 8 days: %+v", got)
	}
	// Someone who may not see the device gets not found.
	outsider := f.user("o@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.globex})
	if _, err := f.svc.Roles(f.ctx, outsider, f.dev); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("outsider: %v", err)
	}
}

func TestRoleRemovalRunsHooksAndDropsTheRole(t *testing.T) {
	f := newFixture(t)
	var cleared []modules.Module
	f.svc.OnRoleRemoved(func(_ context.Context, _ pgx.Tx, dev, org uuid.UUID, m modules.Module) error {
		if dev != f.dev || org != f.acme {
			t.Errorf("hook for %v in %v", dev, org)
		}
		cleared = append(cleared, m)
		return nil
	})
	f.report(f.dev, f.acme, present("ad_ds", "dns", "defender"))
	f.report(f.dev, f.acme, present("dns", "defender"))
	if len(cleared) != 1 || cleared[0] != modules.ActiveDirectory {
		t.Fatalf("cleared = %v, want [active_directory]", cleared)
	}
	got, _ := f.svc.Roles(f.ctx, f.tech, f.dev)
	if n := roleNames(got); len(n) != 2 {
		t.Errorf("roles = %v", n)
	}
	// An unchanged report, and a nil one, remove nothing.
	f.report(f.dev, f.acme, present("dns", "defender"))
	f.report(f.dev, f.acme, nil)
	if len(cleared) != 1 {
		t.Errorf("cleared again: %v", cleared)
	}
	// A report with none left clears the rest.
	f.report(f.dev, f.acme, []agentproto.Role{})
	if len(cleared) != 3 {
		t.Errorf("cleared = %v, want all three", cleared)
	}
	if got, _ := f.svc.Roles(f.ctx, f.tech, f.dev); !got.Known || len(got.Roles) != 0 {
		t.Errorf("an empty report must read as known and empty: %+v", got)
	}
}

func TestRescanIsAskedForOnceAndAudited(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.RequestRescan(f.ctx, f.readOnly, f.dev); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only: %v", err)
	}
	if err := f.svc.RequestRescan(f.ctx, f.tech, f.dev); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.roles_rescan'`); n != 1 {
		t.Errorf("%d audit rows", n)
	}
	if !f.report(f.dev, f.acme, nil) {
		t.Error("the heartbeat did not carry the rescan request")
	}
	if f.report(f.dev, f.acme, nil) {
		t.Error("the rescan request was asked twice")
	}
}

func TestNothingIsStoredOutsideTheDevScope(t *testing.T) {
	f := newFixture(t)
	t.Cleanup(devscope.Set(f.globex))
	f.report(f.dev, f.acme, present("dns"))
	if got, _ := f.svc.Roles(f.ctx, f.tech, f.dev); got.Known {
		t.Error("roles of an organization outside the dev scope were stored")
	}
	if err := f.svc.RequestRescan(f.ctx, f.tech, f.dev); err == nil {
		t.Error("a rescan was accepted outside the dev scope")
	}
	if f.svc.Allowed(f.ctx, f.acme, f.hq, modules.DNS) {
		t.Error("Allowed said yes outside the dev scope")
	}
	if !f.svc.Allowed(f.ctx, f.globex, f.gsite, modules.DNS) {
		t.Error("Allowed said no inside the dev scope")
	}
}

func TestTogglesResolveAndAreAudited(t *testing.T) {
	f := newFixture(t)
	dns := modules.DNS
	if !f.svc.Allowed(f.ctx, f.acme, f.hq, dns) {
		t.Fatal("no row must mean on")
	}
	// Organization off: both sites follow.
	if err := f.svc.SetEnabled(f.ctx, f.orgAdmin, modules.AtOrganization, f.acme, dns, false); err != nil {
		t.Fatal(err)
	}
	if f.svc.Allowed(f.ctx, f.acme, f.hq, dns) || f.svc.Allowed(f.ctx, f.acme, f.plant, dns) {
		t.Error("an organization-wide off did not reach its sites")
	}
	if !f.svc.Allowed(f.ctx, f.acme, f.hq, modules.DHCP) {
		t.Error("turning DNS off turned DHCP off")
	}
	// A site row wins over the organization's.
	if err := f.svc.SetEnabled(f.ctx, f.orgAdmin, modules.AtSite, f.hq, dns, true); err != nil {
		t.Fatal(err)
	}
	if !f.svc.Allowed(f.ctx, f.acme, f.hq, dns) || f.svc.Allowed(f.ctx, f.acme, f.plant, dns) {
		t.Error("the site override did not win, or leaked to a sibling")
	}
	// Setting twice keeps one row; the settings list shows level and effect.
	if err := f.svc.SetEnabled(f.ctx, f.orgAdmin, modules.AtOrganization, f.acme, dns, false); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM windows_module_settings WHERE module = 'dns'`); n != 2 {
		t.Errorf("%d rows, want one per level", n)
	}
	list, err := f.svc.Settings(f.ctx, f.tech, modules.AtSite, f.hq)
	if err != nil || len(list) != len(modules.Catalog) {
		t.Fatalf("settings: %v, %v", list, err)
	}
	for _, s := range list {
		switch s.Module {
		case dns:
			if !s.Enabled || s.Override == nil || !*s.Override {
				t.Errorf("dns at the site: %+v", s)
			}
		default:
			if !s.Enabled || s.Override != nil {
				t.Errorf("%s at the site: %+v", s.Module, s)
			}
		}
	}
	// Clearing the override returns the site to its organization.
	if err := f.svc.ClearOverride(f.ctx, f.orgAdmin, f.hq, dns); err != nil {
		t.Fatal(err)
	}
	if f.svc.Allowed(f.ctx, f.acme, f.hq, dns) {
		t.Error("the site did not follow its organization after the override was cleared")
	}
	// Three changes, three audit rows, with old and new.
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'windows_module.set'`); n != 4 {
		t.Errorf("%d audit rows, want 4", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'windows_module.set' AND details->>'module' = 'dns'
		AND details->>'scope' = 'organization' AND details->>'old' = 'true' AND details->>'new' = 'false'`); n != 1 {
		t.Errorf("the organization's change is not audited with old and new: %d", n)
	}
}

func TestTogglePermissions(t *testing.T) {
	f := newFixture(t)
	dns := modules.DNS
	// A technician sees the toggles but changes neither level.
	if _, err := f.svc.Settings(f.ctx, f.tech, modules.AtOrganization, f.acme); err != nil {
		t.Errorf("technician reading: %v", err)
	}
	if err := f.svc.SetEnabled(f.ctx, f.tech, modules.AtOrganization, f.acme, dns, false); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("technician at the organization: %v", err)
	}
	if err := f.svc.SetEnabled(f.ctx, f.tech, modules.AtSite, f.hq, dns, false); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("technician at a site: %v", err)
	}
	// A site administrator may override their own site but not the
	// organization, nor a site of another scope.
	if err := f.svc.SetEnabled(f.ctx, f.siteAdmin, modules.AtSite, f.hq, dns, false); err != nil {
		t.Errorf("site administrator at their site: %v", err)
	}
	if err := f.svc.SetEnabled(f.ctx, f.siteAdmin, modules.AtOrganization, f.acme, dns, false); err == nil {
		t.Error("site administrator changed the organization")
	}
	if err := f.svc.SetEnabled(f.ctx, f.siteAdmin, modules.AtSite, f.plant, dns, false); err == nil {
		t.Error("site administrator changed a site that is not theirs")
	}
	// Nobody reaches another organization.
	if _, err := f.svc.Settings(f.ctx, f.orgAdmin, modules.AtOrganization, f.globex); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization: %v", err)
	}
	if err := f.svc.SetEnabled(f.ctx, f.orgAdmin, modules.AtOrganization, f.acme, "bogus", false); err == nil {
		t.Error("an unknown module was accepted")
	}
}

func TestOfferedAnswersNotFoundNeverForbidden(t *testing.T) {
	f := newFixture(t)
	notFound := func(who string, c access.Caller, m modules.Module) {
		t.Helper()
		if _, err := f.svc.Offered(f.ctx, c, f.dev, m); !errors.Is(err, apperr.ErrNotFound) {
			t.Errorf("%s, %s: %v, want not found", who, m, err)
		}
	}
	offered := func(who string, c access.Caller, m modules.Module) {
		t.Helper()
		if d, err := f.svc.Offered(f.ctx, c, f.dev, m); err != nil || d.ID != f.dev {
			t.Errorf("%s, %s: %v, want offered", who, m, err)
		}
	}
	// Roles unknown: nothing is offered.
	notFound("org admin, no roles reported", f.orgAdmin, modules.DNS)
	f.report(f.dev, f.acme, present("dns", "ad_cs", "defender"))
	offered("org admin", f.orgAdmin, modules.DNS)
	offered("technician", f.tech, modules.Defender)
	// The role is not there.
	notFound("org admin, no DHCP role", f.orgAdmin, modules.DHCP)
	// The caller lacks the view permission: technicians hold neither
	// dns.view nor ca.view; Read-Only holds none.
	notFound("technician", f.tech, modules.DNS)
	notFound("technician", f.tech, modules.CertificateAuthority)
	notFound("read-only", f.readOnly, modules.Defender)
	offered("site administrator", f.siteAdmin, modules.DNS)
	offered("site administrator", f.siteAdmin, modules.CertificateAuthority)
	// The toggle is off for the site.
	if err := f.svc.SetEnabled(f.ctx, f.orgAdmin, modules.AtSite, f.hq, modules.DNS, false); err != nil {
		t.Fatal(err)
	}
	notFound("org admin, toggled off", f.orgAdmin, modules.DNS)
	offered("org admin, other module", f.orgAdmin, modules.CertificateAuthority)
	// Not a module at all.
	notFound("org admin", f.orgAdmin, "bogus")
	// The device's roles are unknown again after a week of silence.
	f.exec(`UPDATE devices SET roles_at = now() - interval '8 days' WHERE id = $1`, f.dev)
	notFound("org admin, stale roles", f.orgAdmin, modules.Defender)
}
