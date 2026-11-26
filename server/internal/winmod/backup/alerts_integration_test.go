//go:build integration

package backup_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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
	"github.com/paulmataruso/easyrmm/server/internal/winmod/backup"
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
	if err := monitoring.RegisterModuleAlerts(backup.AlertKinds()); err != nil {
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

// device enrolls a Windows device with Windows Backup detected.
func (f *fx) device(org, site uuid.UUID, name string) uuid.UUID {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at, roles, roles_at)
		VALUES ($1, $2, $3, $3, 'windows', $4, now() - interval '1 day', now(), '[{"name":"windows_backup","state":"present"}]', now()) RETURNING id`,
		org, site, name, key)
}

// snapshot stores a backup.status result taken ago minutes ago.
func (f *fx) snapshot(dev uuid.UUID, ago int, mut func(*backup.Status)) {
	f.t.Helper()
	last := time.Now().Add(-6 * time.Hour).UTC().Truncate(time.Second)
	total, free := int64(1000), int64(500)
	st := backup.Status{Installed: true, Configured: true, LastSuccess: &last, LastSuccessAgeDays: ptr(0), VersionCount: ptr(3),
		Schedule: []string{"21:00"}, Targets: []backup.Target{{Kind: "volume", FreeBytes: &free, TotalBytes: &total, Online: true}}}
	if mut != nil {
		mut(&st)
	}
	b, err := json.Marshal(st)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, data)
		VALUES ($1, 'windows_backup', 'windows_backup.status', '', now() - make_interval(mins => $2), $3)
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

func mustInt(s string) int {
	var n int
	_, _ = fmt.Sscan(s, &n)
	return n
}

const (
	failed     = "Backup: last backup failed"
	missing    = "Backup: target not found"
	overdue    = "Backup: no successful backup in 2 days"
	lowSpace   = "Backup: target nearly full (under 10% free)"
	stuck      = "Backup: running too long"
	notConfigd = "Backup: not configured on a server"
)

func TestDefaultPoliciesAreCreatedOnceAndSomeStartOff(t *testing.T) {
	f := newFx(t)
	f.device(f.acme, f.hq, "srv1")
	f.evaluate()
	f.evaluate()
	if n := mustInt(f.str(`SELECT count(*)::text FROM alert_policies WHERE organization_id = $1 AND module = 'windows_backup'`, f.acme)); n != 6 {
		t.Errorf("%d default policies, want 6", n)
	}
	if got := f.str(`SELECT enabled::text FROM alert_policies WHERE default_key = 'not_configured'`); got != "false" {
		t.Errorf("the not-configured default is enabled = %s", got)
	}
	if got := f.str(`SELECT enabled::text FROM alert_policies WHERE default_key = 'failed'`); got != "true" {
		t.Errorf("the failure default is enabled = %s", got)
	}
	if n := mustInt(f.str(`SELECT count(*)::text FROM alert_policies WHERE organization_id = $1`, f.globex)); n != 0 {
		t.Errorf("an organization with no such computer has %d policies", n)
	}
	if err := f.mods.SetEnabled(f.ctx, f.admin, modules.AtOrganization, f.acme, modules.WindowsBackup, false); err != nil {
		t.Fatal(err)
	}
	if err := f.mods.SetEnabled(f.ctx, f.admin, modules.AtOrganization, f.acme, modules.WindowsBackup, true); err != nil {
		t.Fatal(err)
	}
	if n := mustInt(f.str(`SELECT count(*)::text FROM alert_policies WHERE organization_id = $1 AND module = 'windows_backup'`, f.acme)); n != 6 {
		t.Errorf("%d default policies after off and on, want 6", n)
	}
}

func TestFailureOpensAndASuccessResolves(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "srv1")
	f.evaluate()
	ok := time.Now().Add(-30 * time.Hour).UTC()
	bad := time.Now().Add(-6 * time.Hour).UTC()
	f.snapshot(dev, 1, func(s *backup.Status) {
		s.LastSuccess, s.LastFailure, s.LastResultHR = &ok, &bad, ptr(int64(-2147024891))
		s.LastSuccessAgeDays = ptr(1)
	})
	f.evaluate()
	if got := f.open(dev); got != failed {
		t.Fatalf("open alerts %q", got)
	}
	if sev := f.str(`SELECT severity FROM alerts WHERE name = $1`, failed); sev != "critical" {
		t.Errorf("severity %s", sev)
	}
	// A success after the failure clears it.
	later := time.Now().Add(-time.Hour).UTC()
	f.snapshot(dev, 0, func(s *backup.Status) { s.LastSuccess, s.LastFailure = &later, &bad })
	f.evaluate()
	if got := f.open(dev); got != "" || f.resolution(dev, backup.KindFailed) != "cleared" {
		t.Errorf("open %q, resolution %q", got, f.resolution(dev, backup.KindFailed))
	}
}

func TestOverdueLowSpaceStuckAndMissingTarget(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "srv1")
	f.evaluate()
	started := time.Now().Add(-13 * time.Hour).UTC()
	total, free := int64(1000), int64(50)
	f.snapshot(dev, 0, func(s *backup.Status) {
		s.LastSuccessAgeDays = ptr(3)
		s.Running = true
		s.Job = &backup.Job{Type: "Backup", State: "Running", StartTime: &started}
		s.Targets = []backup.Target{{Kind: "volume", FreeBytes: &free, TotalBytes: &total, Online: false}}
	})
	f.evaluate()
	// The missing target waits out its 60-minute grace; the others open now.
	if got := f.open(dev); got != overdue+" | "+stuck+" | "+lowSpace {
		t.Fatalf("open alerts %q", got)
	}
	f.exec(`UPDATE windows_module_conditions SET since = now() - interval '2 hours'`)
	f.snapshot(dev, 0, func(s *backup.Status) {
		s.LastSuccessAgeDays = ptr(3)
		s.Running = true
		s.Job = &backup.Job{Type: "Backup", State: "Running", StartTime: &started}
		s.Targets = []backup.Target{{Kind: "volume", FreeBytes: &free, TotalBytes: &total, Online: false}}
	})
	f.evaluate()
	if got := f.open(dev); got != overdue+" | "+stuck+" | "+lowSpace+" | "+missing {
		t.Fatalf("open alerts %q", got)
	}
	f.snapshot(dev, 0, nil)
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Errorf("still open after a clear reading: %q", got)
	}
}

func TestNotApplicableWithoutTheFeatureOrAPolicy(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "srv1")
	f.evaluate()
	f.snapshot(dev, 0, func(s *backup.Status) { s.LastSuccess, s.LastSuccessAgeDays = nil, nil })
	f.evaluate()
	if got := f.open(dev); got != overdue {
		t.Fatalf("a never-run backup: open %q", got)
	}
	// The policy goes: nothing about backups applies, and the alert resolves.
	f.snapshot(dev, 0, func(s *backup.Status) { s.Configured, s.LastSuccess, s.LastSuccessAgeDays = false, nil, nil })
	f.evaluate()
	if got := f.open(dev); got != "" || f.resolution(dev, backup.KindOverdue) != "not_applicable" {
		t.Errorf("no policy: open %q, resolution %q", got, f.resolution(dev, backup.KindOverdue))
	}
	// Not configured is an alert of its own, off until an organization wants it.
	on := true
	if _, err := f.mon.UpdatePolicy(f.ctx, f.admin, f.policyID(f.acme, "not_configured"), monitoring.PolicyPatch{Enabled: &on}); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE windows_module_conditions SET since = now() - interval '2 days'`)
	f.snapshot(dev, 0, func(s *backup.Status) { s.Configured, s.LastSuccess, s.LastSuccessAgeDays = false, nil, nil })
	f.evaluate()
	f.exec(`UPDATE windows_module_conditions SET since = now() - interval '2 days'`)
	f.evaluate()
	if got := f.open(dev); got != notConfigd {
		t.Errorf("not configured: open %q", got)
	}
	// Without the feature: not applicable, nothing open.
	f.snapshot(dev, 0, func(s *backup.Status) { *s = backup.Status{} })
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Errorf("without the feature: open %q", got)
	}
}

func TestAModuleThatIsOffRaisesNothing(t *testing.T) {
	f := newFx(t)
	dev := f.device(f.acme, f.hq, "srv1")
	f.evaluate()
	bad := time.Now().Add(-time.Hour).UTC()
	f.snapshot(dev, 0, func(s *backup.Status) { s.LastSuccess, s.LastFailure, s.LastResultHR = nil, &bad, ptr(int64(-1)) })
	f.evaluate()
	if got := f.open(dev); !strings.Contains(got, failed) {
		t.Fatalf("open alerts %q", got)
	}
	if err := f.mods.SetEnabled(f.ctx, f.admin, modules.AtOrganization, f.acme, modules.WindowsBackup, false); err != nil {
		t.Fatal(err)
	}
	f.evaluate()
	if got := f.open(dev); got != "" || f.resolution(dev, backup.KindFailed) != "module_off" {
		t.Errorf("module off: open %q, resolution %q", got, f.resolution(dev, backup.KindFailed))
	}
}

func TestOutOfScopeOrganizationsAreSkipped(t *testing.T) {
	f := newFx(t)
	restore := devscope.Set(f.acme)
	t.Cleanup(restore)
	in := f.device(f.acme, f.hq, "in-scope")
	out := f.device(f.globex, f.main, "out-of-scope")
	bad := time.Now().Add(-time.Hour).UTC()
	for _, d := range []uuid.UUID{in, out} {
		f.snapshot(d, 0, func(s *backup.Status) { s.LastSuccess, s.LastFailure, s.LastResultHR = nil, &bad, ptr(int64(-1)) })
	}
	f.evaluate()
	if got := f.open(in); !strings.Contains(got, failed) {
		t.Errorf("the organization in scope: open %q", got)
	}
	if got := f.open(out); got != "" {
		t.Errorf("an organization outside the scope has alerts %q", got)
	}
}

func TestFleetCardCountsFromSnapshotsAndHonoursTheToggleAndPermission(t *testing.T) {
	f := newFx(t)
	cards := backup.NewCards(f.db, f.mods)
	good, bad, never, nodata := f.device(f.acme, f.hq, "a-ok"), f.device(f.acme, f.hq, "b-failed"), f.device(f.acme, f.hq, "c-never"), f.device(f.acme, f.hq, "d-unread")
	other := f.device(f.globex, f.main, "other-org")
	_ = nodata
	failedAt := time.Now().Add(-time.Hour).UTC()
	f.snapshot(good, 0, nil)
	f.snapshot(bad, 0, func(s *backup.Status) { s.LastFailure, s.LastResultHR = &failedAt, ptr(int64(-1)) })
	f.snapshot(never, 0, func(s *backup.Status) { s.LastSuccess = nil })
	f.snapshot(other, 0, nil)
	f.evaluate()

	got, err := cards.Read(f.ctx, f.admin, backup.AtOrganization, f.acme)
	if err != nil {
		t.Fatal(err)
	}
	want := backup.FleetCounts{BackedUp: 1, Failed: 1, Overdue: 1, NoData: 1}
	if !got.Enabled || got.Counts != want || len(got.Devices) != 4 {
		t.Fatalf("org card: %+v", got)
	}
	if got.Devices[1].Name != "b-failed" || got.Devices[1].OpenAlerts != 1 {
		t.Errorf("the failed computer: %+v", got.Devices[1])
	}
	if s, err := cards.Read(f.ctx, f.admin, backup.AtSite, f.hq); err != nil || len(s.Devices) != 4 {
		t.Errorf("site card: %+v, %v", s, err)
	}

	// Read-only holds no backup permission: not found. So does another
	// organization's administrator.
	ro := f.id(`INSERT INTO users (email, display_name) VALUES ('ro@example.com', 'ro') RETURNING id`)
	p, err := rbac.NewPrincipal(ro, []rbac.Assignment{{Role: rbac.RoleReadOnly, OrganizationID: f.acme}})
	if err != nil {
		t.Fatal(err)
	}
	reader := access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: ro, Label: "ro@example.com"})
	if _, err := cards.Read(f.ctx, reader, backup.AtOrganization, f.acme); !errors.Is(err, apperr.NotFound()) {
		t.Errorf("read-only: %v", err)
	}

	// A module that is off shows nothing.
	if err := f.mods.SetEnabled(f.ctx, f.admin, modules.AtOrganization, f.acme, modules.WindowsBackup, false); err != nil {
		t.Fatal(err)
	}
	if off, err := cards.Read(f.ctx, f.admin, backup.AtOrganization, f.acme); err != nil || off.Enabled || len(off.Devices) != 0 {
		t.Errorf("module off: %+v, %v", off, err)
	}
}
