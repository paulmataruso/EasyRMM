//go:build integration

package defender_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/modsnap"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/defender"
)

// Defender's alerts, from the snapshot of defender.status, through the real
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
	if err := monitoring.RegisterModuleAlerts(defender.AlertKinds()); err != nil {
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

// device enrolls a Windows device with Defender detected.
func (f *fx) device(org, site uuid.UUID, name string) uuid.UUID {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at, roles, roles_at)
		VALUES ($1, $2, $3, $3, 'windows', $4, now() - interval '1 day', now(), '[{"name":"defender","state":"present"}]', now()) RETURNING id`,
		org, site, name, key)
}

// snapshot stores a defender.status result taken ago minutes ago.
func (f *fx) snapshot(dev uuid.UUID, ago int, mut func(*defender.Status)) {
	f.t.Helper()
	on, off := true, false
	st := defender.Status{RealTimeProtectionEnabled: &on, TamperProtected: &on, RunningMode: "Normal", SignatureAgeDays: ptr(0), QuickScanAgeDays: ptr(1)}
	_ = off
	if mut != nil {
		mut(&st)
	}
	b, err := json.Marshal(st)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, data)
		VALUES ($1, 'defender', 'defender.status', '', now() - make_interval(mins => $2), $3)
		ON CONFLICT (device_id, action, params_hash) DO UPDATE SET taken_at = excluded.taken_at, data = excluded.data`, dev, ago, b)
}

func ptr[T any](v T) *T { return &v }

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

func (f *fx) resolution(dev uuid.UUID, kind string) string {
	return f.str(`SELECT coalesce((SELECT resolution FROM alerts WHERE device_id = $1 AND kind = $2 ORDER BY seq DESC LIMIT 1), '')`, dev, kind)
}

func (f *fx) policyID(org uuid.UUID, key string) uuid.UUID {
	return f.id(`SELECT id FROM alert_policies WHERE organization_id = $1 AND default_key = $2`, org, key)
}

const (
	protectionOff = "Defender: real-time protection off"
	tamperOff     = "Defender: Tamper Protection off"
)

func TestDefaultPoliciesAreCreatedOnce(t *testing.T) {
	f := newFx(t)
	count := func(org uuid.UUID) int {
		return mustInt(f.str(`SELECT count(*)::text FROM alert_policies WHERE organization_id = $1 AND module = 'defender'`, org))
	}
	f.device(f.acme, f.hq, "dc1")
	if n := count(f.acme); n != 0 {
		t.Fatalf("%d defaults before any evaluation", n)
	}
	f.evaluate()
	f.evaluate()
	if n := count(f.acme); n != 4 {
		t.Errorf("%d default policies after two evaluations, want 4", n)
	}
	if n := count(f.globex); n != 0 {
		t.Errorf("an organization with no Defender computer has %d defaults", n)
	}
	// The age rules start off.
	if got := f.str(`SELECT enabled::text FROM alert_policies WHERE default_key = 'signatures_old_7'`); got != "false" {
		t.Errorf("signature age default enabled = %s", got)
	}

	// Turning the module off and on again, an administrator's setting on a
	// default stays and nothing is duplicated.
	admin := f.admin
	f.exec(`UPDATE alert_policies SET enabled = false WHERE default_key = 'tamper_off'`)
	if err := f.mods.SetEnabled(f.ctx, admin, modules.AtOrganization, f.acme, modules.Defender, false); err != nil {
		t.Fatal(err)
	}
	if err := f.mods.SetEnabled(f.ctx, admin, modules.AtOrganization, f.acme, modules.Defender, true); err != nil {
		t.Fatal(err)
	}
	f.evaluate()
	if n := count(f.acme); n != 4 {
		t.Errorf("%d default policies after off and on, want 4", n)
	}
	if got := f.str(`SELECT enabled::text FROM alert_policies WHERE default_key = 'tamper_off'`); got != "false" {
		t.Errorf("re-enabling the module turned a default back on (%s)", got)
	}

	// A default is turned on or off, never changed or deleted.
	id := f.policyID(f.acme, "protection_off")
	name := "Mine"
	if _, err := f.mon.UpdatePolicy(f.ctx, admin, id, monitoring.PolicyPatch{Name: &name}); !errors.Is(err, apperr.Conflict("default_policy", "")) {
		t.Errorf("renaming a default: %v", err)
	}
	off := false
	if p, err := f.mon.UpdatePolicy(f.ctx, admin, id, monitoring.PolicyPatch{Enabled: &off}); err != nil || p.Enabled || !p.Default || p.Module != "defender" {
		t.Errorf("turning a default off: %+v, %v", p, err)
	}
	if err := f.mon.DeletePolicy(f.ctx, admin, id); !errors.Is(err, apperr.Conflict("default_policy", "")) {
		t.Errorf("deleting a default: %v", err)
	}
}

func mustInt(s string) int {
	var n int
	_, _ = fmt.Sscan(s, &n)
	return n
}

func TestAlertsOpenAndResolveFromTheSnapshot(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "dc1")
	f.evaluate() // creates the defaults
	f.snapshot(dev, 1, func(s *defender.Status) { s.RealTimeProtectionEnabled = ptr(false); s.TamperProtected = ptr(false) })
	f.evaluate()

	// Tamper Protection off opens at once; real-time protection off waits
	// out its five-minute grace (the reading is one minute old).
	if got := f.open(dev); got != tamperOff {
		t.Fatalf("open alerts %q", got)
	}
	if n := mustInt(f.str(`SELECT count(*)::text FROM windows_module_conditions WHERE device_id = $1`, dev)); n != 1 {
		t.Errorf("%d grace conditions recorded", n)
	}
	// Six minutes after the first reading, the condition has held for the
	// grace.
	f.exec(`UPDATE windows_module_conditions SET since = now() - interval '6 minutes'`)
	f.snapshot(dev, 0, func(s *defender.Status) { s.RealTimeProtectionEnabled = ptr(false); s.TamperProtected = ptr(false) })
	f.evaluate()
	if got := f.open(dev); got != tamperOff+" | "+protectionOff {
		t.Fatalf("open alerts %q", got)
	}
	if sev := f.str(`SELECT severity FROM alerts WHERE name = $1`, protectionOff); sev != "critical" {
		t.Errorf("severity %s", sev)
	}

	// An unreadable value changes nothing; a reading that clears resolves.
	f.snapshot(dev, 0, func(s *defender.Status) { s.RealTimeProtectionEnabled = nil; s.TamperProtected = nil })
	f.evaluate()
	if got := f.open(dev); got != tamperOff+" | "+protectionOff {
		t.Errorf("an unknown reading changed the alerts: %q", got)
	}
	f.snapshot(dev, 0, nil)
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Errorf("still open after a clear reading: %q", got)
	}
	if got := f.resolution(dev, defender.KindTamperOff); got != "cleared" {
		t.Errorf("resolution %q", got)
	}
	if n := mustInt(f.str(`SELECT count(*)::text FROM windows_module_conditions WHERE device_id = $1`, dev)); n != 0 {
		t.Errorf("%d grace conditions left after the condition cleared", n)
	}

	// A passive Defender is not the active antivirus: not applicable.
	f.snapshot(dev, 0, func(s *defender.Status) { s.TamperProtected = ptr(false) })
	f.evaluate()
	if got := f.open(dev); got != tamperOff {
		t.Fatalf("open alerts %q", got)
	}
	f.snapshot(dev, 0, func(s *defender.Status) { s.TamperProtected = ptr(false); s.RunningMode = "Passive" })
	f.evaluate()
	if got := f.open(dev); got != "" || f.resolution(dev, defender.KindTamperOff) != "not_applicable" {
		t.Errorf("passive mode: open %q, resolution %q", got, f.resolution(dev, defender.KindTamperOff))
	}

	// A snapshot too old to trust judges nothing.
	f.snapshot(dev, 24*60, func(s *defender.Status) { s.TamperProtected = ptr(false) })
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Errorf("a day-old snapshot opened %q", got)
	}
}

func TestBestMatchOpensTheHighestThreshold(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "dc1")
	f.evaluate()
	on := true
	if _, err := f.mon.UpdatePolicy(f.ctx, f.admin, f.policyID(f.acme, "signatures_old_7"), monitoring.PolicyPatch{Enabled: &on}); err != nil {
		t.Fatal(err)
	}
	three := 3
	if _, err := f.mon.CreatePolicy(f.ctx, f.admin, monitoring.PolicyInput{
		OrganizationID: &f.acme, Name: "Signatures 3 days", Kind: defender.KindSignaturesOld, Threshold: &three, Severity: "warning",
	}); err != nil {
		t.Fatal(err)
	}
	// Created through the API: a minutes value the kind does not use is set aside.
	f.snapshot(dev, 0, func(s *defender.Status) { s.SignatureAgeDays = ptr(9) })
	f.evaluate()
	if got := f.open(dev); got != "Defender: signatures out of date (7 days)" {
		t.Errorf("open alerts %q, want only the 7-day policy", got)
	}
	// Four days old: only the 3-day policy holds. The 7-day alert resolves.
	f.snapshot(dev, 0, func(s *defender.Status) { s.SignatureAgeDays = ptr(4) })
	f.evaluate()
	if got := f.open(dev); got != "Signatures 3 days" {
		t.Errorf("open alerts %q", got)
	}
}

func TestAModuleThatIsOffRaisesNothingAndResolves(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "dc1")
	f.evaluate()
	f.snapshot(dev, 0, func(s *defender.Status) { s.TamperProtected = ptr(false) })
	f.evaluate()
	if got := f.open(dev); got != tamperOff {
		t.Fatalf("open alerts %q", got)
	}
	if err := f.mods.SetEnabled(f.ctx, f.admin, modules.AtOrganization, f.acme, modules.Defender, false); err != nil {
		t.Fatal(err)
	}
	f.evaluate()
	if got := f.open(dev); got != "" || f.resolution(dev, defender.KindTamperOff) != "module_off" {
		t.Errorf("module off: open %q, resolution %q", got, f.resolution(dev, defender.KindTamperOff))
	}
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Errorf("an alert opened while the module is off: %q", got)
	}
	// A site that overrides the organization turns it back on for itself.
	if err := f.mods.SetEnabled(f.ctx, f.admin, modules.AtSite, f.hq, modules.Defender, true); err != nil {
		t.Fatal(err)
	}
	f.evaluate()
	if got := f.open(dev); got != tamperOff {
		t.Errorf("site override on: open %q", got)
	}
}

func TestRoleRemovalResolvesAlertsAndClearsSnapshots(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "dc1")
	f.evaluate()
	f.snapshot(dev, 0, func(s *defender.Status) { s.TamperProtected = ptr(false) })
	f.evaluate()
	if got := f.open(dev); got != tamperOff {
		t.Fatalf("open alerts %q", got)
	}
	// The agent reports a known, empty role list: the role is gone.
	err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := f.mods.StoreRoles(f.ctx, tx, dev, f.acme, []agentproto.Role{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.open(dev); got != "" || f.resolution(dev, defender.KindTamperOff) != "role_removed" {
		t.Errorf("open %q, resolution %q", got, f.resolution(dev, defender.KindTamperOff))
	}
	if n := mustInt(f.str(`SELECT count(*)::text FROM windows_module_snapshots WHERE device_id = $1`, dev)); n != 0 {
		t.Errorf("%d snapshots left after the role was removed", n)
	}
	// And nothing is raised for it afterwards.
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Errorf("alerts after the role was removed: %q", got)
	}
}

func TestOutOfScopeOrganizationsAreSkipped(t *testing.T) {
	f := newFx(t)
	restore := devscope.Set(f.acme)
	t.Cleanup(restore)
	in := f.device(f.acme, f.hq, "in-scope")
	out := f.device(f.globex, f.main, "out-of-scope")
	for _, d := range []uuid.UUID{in, out} {
		f.snapshot(d, 0, func(s *defender.Status) { s.TamperProtected = ptr(false) })
	}
	f.evaluate()
	if got := f.open(in); got != tamperOff {
		t.Errorf("the organization in scope: open %q", got)
	}
	if got := f.open(out); got != "" {
		t.Errorf("an organization outside the scope has alerts %q", got)
	}
	if n := mustInt(f.str(`SELECT count(*)::text FROM alert_policies WHERE organization_id = $1`, f.globex)); n != 0 {
		t.Errorf("an organization outside the scope has %d policies", n)
	}
	// An alert it had before the guard resolves.
	restore()
	f.evaluate()
	if got := f.open(out); got != tamperOff {
		t.Fatalf("without a scope: open %q", got)
	}
	t.Cleanup(devscope.Set(f.acme))
	f.evaluate()
	if got := f.open(out); got != "" {
		t.Errorf("alerts of an organization that left the scope: %q", got)
	}
}
