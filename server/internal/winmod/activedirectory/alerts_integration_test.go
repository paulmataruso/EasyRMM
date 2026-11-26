//go:build integration

package activedirectory_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/modsnap"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/activedirectory"
)

// Active Directory's replication alert, from the snapshot of health_read, through the real
// monitoring evaluator, module gate and role-removal hook, on real
// PostgreSQL. Snapshots are put in as the winmod result path writes them.

type fx struct {
	t            *testing.T
	ctx          context.Context
	db           *database.DB
	mods         *modules.Service
	mon          *monitoring.Service
	acme, hq     uuid.UUID
	globex, main uuid.UUID
	admin        access.Caller
}

func newFx(t *testing.T) *fx {
	t.Helper()
	inst := testdb.New(t)
	f := &fx{t: t, ctx: context.Background(), db: inst.DB}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	au := audit.New(inst.DB, nil)
	f.mods = modules.New(inst.DB, au, log)
	f.mon = monitoring.New(inst.DB, au, 30*24*time.Hour, 7*24*time.Hour, log)
	f.mon.FollowServing(func() (time.Time, bool) { return time.Now().Add(-24 * time.Hour), true })
	if err := monitoring.RegisterModuleAlerts(activedirectory.AlertKinds()); err != nil {
		t.Fatal(err)
	}
	f.mods.OnRoleRemoved(modsnap.OnRoleRemoved)
	f.mods.OnRoleRemoved(monitoring.RoleRemovedHook)
	f.mods.OnEnabled(monitoring.EnsureDefaults)
	f.mon.UseModules(f.mods)
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.main = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Main') RETURNING id`, f.globex)
	uid := f.id(`INSERT INTO users (email, display_name) VALUES ('oa@example.com', 'oa') RETURNING id`)
	p, err := rbac.NewPrincipal(uid, []rbac.Assignment{{Role: rbac.RoleSuperAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	f.admin = access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: uid, Label: "oa@example.com"})
	return f
}

func (f *fx) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) str(sql string, args ...any) string {
	f.t.Helper()
	var s string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&s) }); err != nil {
		f.t.Fatal(err)
	}
	return s
}

// device enrolls a Windows device with a domain controller role.
func (f *fx) device(org, site uuid.UUID, name string) uuid.UUID {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at, roles, roles_at)
		VALUES ($1, $2, $3, $3, 'windows', $4, now() - interval '1 day', now(), '[{"name":"ad_ds","state":"present"}]', now()) RETURNING id`,
		org, site, name, key)
}

// snapshot stores an active_directory.health_read result taken ago minutes ago.
func (f *fx) snapshot(dev uuid.UUID, ago int, state string, failures int) {
	f.t.Helper()
	h := activedirectory.Health{Controller: "dc1.corp.test", Domain: "corp.test", Checks: []activedirectory.Check{{Name: "replication", State: state, Detail: "x"}},
		Replication: activedirectory.Replication{FailureCount: failures, Partners: []activedirectory.Partner{}}}
	b, err := json.Marshal(h)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, data)
		VALUES ($1, 'active_directory', 'active_directory.health_read', '', now() - make_interval(mins => $2), $3)
		ON CONFLICT (device_id, action, params_hash) DO UPDATE SET taken_at = excluded.taken_at, data = excluded.data`, dev, ago, b)
}

func (f *fx) evaluate() monitoring.Result {
	f.t.Helper()
	r, err := f.mon.Evaluate(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// open names the policies with an unresolved alert on the device.
func (f *fx) open(dev uuid.UUID) string {
	return f.str(`SELECT coalesce(string_agg(name, ' | ' ORDER BY name), '') FROM alerts WHERE device_id = $1 AND status <> 'resolved'`, dev)
}

func (f *fx) resolution(dev uuid.UUID) string {
	return f.str(`SELECT coalesce((SELECT resolution FROM alerts WHERE device_id = $1 AND kind = $2 ORDER BY seq DESC LIMIT 1), '')`, dev, activedirectory.KindReplicationFailed)
}

func mustInt(s string) int {
	var n int
	_, _ = fmt.Sscan(s, &n)
	return n
}

const replicationFailing = "Directory: replication failing"

func TestReplicationPolicyIsCreatedOnceAndStaysQuiet(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "dc1")
	f.device(f.globex, f.main, "member-server-less-org")
	f.exec(`UPDATE devices SET roles = '[]' WHERE organization_id = $1`, f.globex)
	f.evaluate()
	f.evaluate()
	count := func(org uuid.UUID) int {
		return mustInt(f.str(`SELECT count(*)::text FROM alert_policies WHERE organization_id = $1 AND module = 'active_directory'`, org))
	}
	if n := count(f.acme); n != 4 {
		t.Errorf("%d default policies after two evaluations, want 4", n)
	}
	if n := count(f.globex); n != 0 {
		t.Errorf("an organization with no domain controller has %d", n)
	}
	if got := f.str(`SELECT enabled::text || ' ' || severity || ' ' || minutes::text FROM alert_policies WHERE default_key = 'replication_failing'`); got != "true warning 120" {
		t.Errorf("the default is %q", got)
	}
	// A healthy domain, and a domain of one controller (no partners), open nothing.
	f.snapshot(dev, 1, "ok", 0)
	f.evaluate()
	f.snapshot(dev, 1, "not_applicable", 0)
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Errorf("a quiet week opened %q", got)
	}
}

func TestReplicationAlertOpensAfterTheGraceAndResolves(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "dc1")
	f.evaluate()
	f.snapshot(dev, 1, "critical", 2)
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Fatalf("opened before the two hour grace: %q", got)
	}
	f.exec(`UPDATE windows_module_conditions SET since = now() - interval '3 hours'`)
	f.snapshot(dev, 0, "critical", 2)
	f.evaluate()
	if got := f.open(dev); got != replicationFailing {
		t.Fatalf("open alerts %q", got)
	}
	// A check that could not run is unknown, never healthy: the alert stays.
	f.snapshot(dev, 0, "could_not_run", 0)
	f.evaluate()
	if got := f.open(dev); got != replicationFailing {
		t.Errorf("an unknown reading changed the alert: %q", got)
	}
	f.snapshot(dev, 0, "ok", 0)
	f.evaluate()
	if got := f.open(dev); got != "" || f.resolution(dev) != "cleared" {
		t.Errorf("open %q, resolution %q", got, f.resolution(dev))
	}
	// An alert is not raised from a snapshot too old to trust.
	f.snapshot(dev, 24*60, "critical", 2)
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Errorf("a day-old snapshot opened %q", got)
	}
}

func TestReplicationAlertFollowsTheModuleRoleAndScope(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "dc1")
	f.evaluate()
	// The condition is first seen, then has held for the grace.
	open := func() {
		f.snapshot(dev, 0, "critical", 1)
		f.evaluate()
		f.exec(`UPDATE windows_module_conditions SET since = now() - interval '3 hours'`)
		f.evaluate()
	}
	open()
	if got := f.open(dev); got != replicationFailing {
		t.Fatalf("open alerts %q", got)
	}
	// Module off: resolved with that reason, and nothing opens while it is off.
	if err := f.mods.SetEnabled(f.ctx, f.admin, modules.AtOrganization, f.acme, modules.ActiveDirectory, false); err != nil {
		t.Fatal(err)
	}
	f.evaluate()
	if got := f.open(dev); got != "" || f.resolution(dev) != "module_off" {
		t.Errorf("module off: open %q, resolution %q", got, f.resolution(dev))
	}
	if err := f.mods.SetEnabled(f.ctx, f.admin, modules.AtOrganization, f.acme, modules.ActiveDirectory, true); err != nil {
		t.Fatal(err)
	}
	open()
	if got := f.open(dev); got != replicationFailing {
		t.Fatalf("open alerts %q", got)
	}
	// The role goes (the server is demoted): resolved, snapshots cleared.
	err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := f.mods.StoreRoles(f.ctx, tx, dev, f.acme, []agentproto.Role{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.open(dev); got != "" || f.resolution(dev) != "role_removed" {
		t.Errorf("open %q, resolution %q", got, f.resolution(dev))
	}
	if n := mustInt(f.str(`SELECT count(*)::text FROM windows_module_snapshots WHERE device_id = $1`, dev)); n != 0 {
		t.Errorf("%d snapshots left after the role was removed", n)
	}
}

func TestReplicationAlertSkipsOrganizationsOutsideTheScope(t *testing.T) {
	f := newFx(t)
	t.Cleanup(devscope.Set(f.acme))
	out := f.device(f.globex, f.main, "out-of-scope")
	f.snapshot(out, 0, "critical", 3)
	f.evaluate()
	f.exec(`UPDATE windows_module_conditions SET since = now() - interval '3 hours'`)
	f.evaluate()
	if got := f.open(out); got != "" {
		t.Errorf("an organization outside the scope has alerts %q", got)
	}
	if n := mustInt(f.str(`SELECT count(*)::text FROM alert_policies WHERE organization_id = $1`, f.globex)); n != 0 {
		t.Errorf("an organization outside the scope has %d policies", n)
	}
}

func TestDomainsAreGroupedBySIDAndThePinIsKept(t *testing.T) {
	f := newFx(t)
	svc := activedirectory.New(f.db, f.mods, audit.New(f.db, nil))
	status := func(dev uuid.UUID, host string, ro bool) {
		st := activedirectory.Status{Domain: "corp.test", DomainSID: "S-1-5-21-1-2-3", Controller: host, PDCEmulator: "dc1.corp.test", ReadOnly: ro}
		b, _ := json.Marshal(st)
		f.exec(`INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, data) VALUES ($1, 'active_directory', 'active_directory.status', '', now(), $2)`, dev, b)
	}
	d1, d2, d3 := f.device(f.acme, f.hq, "dc1"), f.device(f.acme, f.hq, "dc2"), f.device(f.acme, f.hq, "rodc")
	status(d1, "dc1.corp.test", false)
	status(d2, "dc2.corp.test", false)
	status(d3, "rodc.corp.test", true)
	f.snapshot(d1, 0, "critical", 2)
	f.snapshot(d2, 0, "ok", 0)
	out, err := svc.Read(f.ctx, f.admin, f.acme)
	if err != nil || len(out.Domains) != 1 || len(out.Domains[0].Controllers) != 3 {
		t.Fatalf("%+v, %v", out, err)
	}
	// dc1 holds the PDC role but is unhealthy; the healthy dc2 is chosen, never the read-only one.
	if d := out.Domains[0]; d.Chosen == nil || *d.Chosen != d2 {
		t.Errorf("chosen %v (%s)", d.Chosen, d.Why)
	}
	if err := svc.Pin(f.ctx, f.admin, f.acme, "S-1-5-21-1-2-3", &d3); err != nil {
		t.Fatal(err)
	}
	out, _ = svc.Read(f.ctx, f.admin, f.acme)
	if d := out.Domains[0]; d.Pinned == nil || *d.Pinned != d3 || *d.Chosen != d2 {
		t.Errorf("a read-only pin is kept but not chosen: %+v", d)
	}
	if err := svc.Pin(f.ctx, f.admin, f.acme, "S-1-5-21-1-2-3", &d1); err != nil {
		t.Fatal(err)
	}
	if err := svc.Pin(f.ctx, f.admin, f.acme, "not a sid", nil); err == nil {
		t.Error("a bad SID was accepted")
	}
	other := f.device(f.globex, f.main, "other")
	if err := svc.Pin(f.ctx, f.admin, f.acme, "S-1-5-21-1-2-3", &other); err == nil {
		t.Error("another organization's computer was pinned")
	}
	if err := svc.Pin(f.ctx, f.admin, f.acme, "S-1-5-21-1-2-3", nil); err != nil {
		t.Fatal(err)
	}
	if n := mustInt(f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'active_directory.pin'`)); n != 3 {
		t.Errorf("%d pin audit rows", n)
	}
	// A module that is off hides the domain; a caller without ad.view finds nothing.
	if err := f.mods.SetEnabled(f.ctx, f.admin, modules.AtOrganization, f.acme, modules.ActiveDirectory, false); err != nil {
		t.Fatal(err)
	}
	if out, _ := svc.Read(f.ctx, f.admin, f.acme); out.Enabled || len(out.Domains) != 0 {
		t.Errorf("module off: %+v", out)
	}
}
