//go:build integration

package roles_test

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
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/modsnap"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/dhcp"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/dns"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/roles"
)

// The DNS and DHCP alerts, from the snapshots of dns.status, dhcp.status and
// dhcp.scope_list, through the real monitoring evaluator, module gate and
// role-removal hook, on real PostgreSQL.

type fx struct {
	t        *testing.T
	ctx      context.Context
	db       *database.DB
	mods     *modules.Service
	mon      *monitoring.Service
	acme, hq uuid.UUID
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
	if err := roles.Register(); err != nil {
		t.Fatal(err)
	}
	f.mods.OnRoleRemoved(modsnap.OnRoleRemoved)
	f.mods.OnRoleRemoved(monitoring.RoleRemovedHook)
	f.mods.OnEnabled(monitoring.EnsureDefaults)
	f.mon.UseModules(f.mods)
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
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

func (f *fx) num(sql string, args ...any) int {
	f.t.Helper()
	var n int
	_, _ = fmt.Sscan(f.str(sql, args...), &n)
	return n
}

// server enrolls a Windows server with the given roles detected.
func (f *fx) server(name string, roleNames ...string) uuid.UUID {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	var rs []map[string]string
	for _, r := range roleNames {
		rs = append(rs, map[string]string{"name": r, "state": "present"})
	}
	b, _ := json.Marshal(rs)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at, roles, roles_at)
		VALUES ($1, $2, $3, $3, 'windows', $4, now() - interval '1 day', now(), $5, now()) RETURNING id`, f.acme, f.hq, name, key, b)
}

func (f *fx) snapshot(dev uuid.UUID, module, action string, ago int, data any) {
	f.t.Helper()
	b, err := json.Marshal(data)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, data)
		VALUES ($1, $2, $3, '', now() - make_interval(mins => $4), $5)
		ON CONFLICT (device_id, action, params_hash) DO UPDATE SET taken_at = excluded.taken_at, data = excluded.data`, dev, module, action, ago, b)
}

func (f *fx) evaluate() {
	f.t.Helper()
	if _, err := f.mon.Evaluate(f.ctx); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) open(dev uuid.UUID) string {
	return f.str(`SELECT coalesce(string_agg(name, ' | ' ORDER BY name), '') FROM alerts WHERE device_id = $1 AND status <> 'resolved'`, dev)
}

func (f *fx) resolution(dev uuid.UUID, kind string) string {
	return f.str(`SELECT coalesce((SELECT resolution FROM alerts WHERE device_id = $1 AND kind = $2 ORDER BY seq DESC LIMIT 1), '')`, dev, kind)
}

func ptr[T any](v T) *T { return &v }

func TestDefaultPoliciesAreCreatedOnce(t *testing.T) {
	f := newFx(t)
	f.server("dc1", agentproto.RoleDNS, agentproto.RoleDHCP)
	f.evaluate()
	f.evaluate()
	for module, want := range map[string]int{"dns": 1, "dhcp": 3} {
		if n := f.num(`SELECT count(*)::text FROM alert_policies WHERE organization_id = $1 AND module = $2`, f.acme, module); n != want {
			t.Errorf("%s: %d default policies, want %d", module, n, want)
		}
	}
	// All three DHCP defaults and the DNS one are on (ADR-0076 section 9).
	if n := f.num(`SELECT count(*)::text FROM alert_policies WHERE organization_id = $1 AND module IN ('dns','dhcp') AND NOT enabled`, f.acme); n != 0 {
		t.Errorf("%d defaults start off", n)
	}
	if got := f.str(`SELECT severity || ' ' || minutes::text FROM alert_policies WHERE default_key = 'service_stopped' AND module = 'dns'`); got != "critical 10" {
		t.Errorf("DNS service stopped: %s", got)
	}
	if got := f.str(`SELECT threshold::text || ' ' || minutes::text FROM alert_policies WHERE default_key = 'scope_nearly_full'`); got != "95 60" {
		t.Errorf("scope nearly full: %s", got)
	}
}

func TestDHCPAlertsFromSnapshots(t *testing.T) {
	f := newFx(t)
	dev := f.server("dhcp1", agentproto.RoleDHCP)
	f.evaluate() // creates the defaults

	scopes := func(pct int, state string) dhcp.ScopeList {
		return dhcp.ScopeList{Scopes: []dhcp.Scope{{ScopeID: "10.0.0.0", State: state, Free: int64(200 - 2*pct), InUse: int64(2 * pct), PercentageInUse: pct}}}
	}
	status := func(joined, authorized *bool, state string) dhcp.Status {
		return dhcp.Status{ServiceState: state, DomainJoined: joined, Authorized: authorized}
	}
	f.snapshot(dev, "dhcp", "dhcp.scope_list", 1, scopes(98, "Active"))
	f.snapshot(dev, "dhcp", "dhcp.status", 1, status(ptr(true), ptr(false), "running"))
	f.evaluate()

	// Not authorized opens at once; a full scope waits out its hour.
	if got := f.open(dev); got != "DHCP: not authorized" {
		t.Fatalf("open alerts %q", got)
	}
	f.exec(`UPDATE windows_module_conditions SET since = now() - interval '61 minutes'`)
	f.snapshot(dev, "dhcp", "dhcp.scope_list", 0, scopes(98, "Active"))
	f.evaluate()
	if got := f.open(dev); got != "DHCP: not authorized | DHCP: scope nearly full" {
		t.Fatalf("open alerts %q", got)
	}

	// Authorized and below the threshold resolves both.
	f.snapshot(dev, "dhcp", "dhcp.scope_list", 0, scopes(40, "Active"))
	f.snapshot(dev, "dhcp", "dhcp.status", 0, status(ptr(true), ptr(true), "running"))
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Errorf("still open: %q", got)
	}
	if got := f.resolution(dev, dhcp.KindNotAuthorized); got != "cleared" {
		t.Errorf("resolution %q", got)
	}

	// A workgroup server needs no authorization; an inactive scope is ignored.
	f.snapshot(dev, "dhcp", "dhcp.status", 0, status(ptr(false), nil, "running"))
	f.snapshot(dev, "dhcp", "dhcp.scope_list", 0, scopes(100, "InActive"))
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Errorf("alerts for a workgroup server with an inactive scope: %q", got)
	}

	// A stopped service opens after its ten minutes.
	f.snapshot(dev, "dhcp", "dhcp.status", 0, status(nil, nil, "stopped"))
	f.evaluate()
	f.exec(`UPDATE windows_module_conditions SET since = now() - interval '11 minutes'`)
	f.snapshot(dev, "dhcp", "dhcp.status", 0, status(nil, nil, "stopped"))
	f.evaluate()
	if got := f.open(dev); got != "DHCP: service stopped" {
		t.Errorf("open alerts %q", got)
	}
}

func TestDNSServiceStoppedAndRoleRemoval(t *testing.T) {
	f := newFx(t)
	dev := f.server("dns1", agentproto.RoleDNS)
	f.evaluate()
	f.snapshot(dev, "dns", "dns.status", 1, dns.Status{ServiceState: "stopped"})
	f.evaluate()
	if got := f.open(dev); got != "" {
		t.Fatalf("opened before the grace: %q", got)
	}
	f.exec(`UPDATE windows_module_conditions SET since = now() - interval '11 minutes'`)
	f.snapshot(dev, "dns", "dns.status", 0, dns.Status{ServiceState: "stopped"})
	f.evaluate()
	if got := f.open(dev); got != "DNS: service stopped" {
		t.Fatalf("open alerts %q", got)
	}
	if sev := f.str(`SELECT severity FROM alerts WHERE device_id = $1`, dev); sev != "critical" {
		t.Errorf("severity %s", sev)
	}

	// The role goes: the alert resolves and the snapshots go.
	err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := f.mods.StoreRoles(f.ctx, tx, dev, f.acme, []agentproto.Role{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.open(dev); got != "" || f.resolution(dev, dns.KindServiceStopped) != "role_removed" {
		t.Errorf("open %q, resolution %q", got, f.resolution(dev, dns.KindServiceStopped))
	}
	if n := f.num(`SELECT count(*)::text FROM windows_module_snapshots WHERE device_id = $1`, dev); n != 0 {
		t.Errorf("%d snapshots left", n)
	}
}
