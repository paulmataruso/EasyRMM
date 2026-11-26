//go:build integration

package agentsettings_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agentsettings"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

const hb = agentsettings.HeartbeatKey

type world struct {
	t                *testing.T
	db               *database.DB
	svc              *agentsettings.Service
	acme, globex     uuid.UUID
	hq, branch, main uuid.UUID
	dev, branchDev   uuid.UUID
	bare             uuid.UUID // a device without the agent
	globexDev        uuid.UUID
}

func newWorld(t *testing.T) *world {
	t.Helper()
	inst := testdb.New(t)
	w := &world{t: t, db: inst.DB}
	w.svc = agentsettings.New(inst.DB, audit.New(inst.DB, nil), nil)
	w.acme = w.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	w.globex = w.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	w.hq = w.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, w.acme)
	w.branch = w.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Branch') RETURNING id`, w.acme)
	w.main = w.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Main') RETURNING id`, w.globex)
	w.dev = w.device("hq-1", w.acme, w.hq, true)
	w.branchDev = w.device("br-1", w.acme, w.branch, true)
	w.bare = w.device("bare-1", w.acme, w.hq, false)
	w.globexDev = w.device("gx-1", w.globex, w.main, true)
	return w
}

func (w *world) id(sql string, args ...any) uuid.UUID {
	w.t.Helper()
	var id uuid.UUID
	err := w.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&id)
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return id
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	err := w.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	})
	if err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) device(name string, org, site uuid.UUID, agent bool) uuid.UUID {
	if !agent {
		return w.id(`INSERT INTO devices (organization_id, site_id, name, platform) VALUES ($1, $2, $3, 'linux') RETURNING id`, org, site, name)
	}
	return w.id(`INSERT INTO devices (organization_id, site_id, name, platform, agent_last_seen_at, agent_public_key, enrolled_at)
		VALUES ($1, $2, $3, 'linux', now(), sha256($3::text::bytea), now()) RETURNING id`, org, site, name)
}

// user makes a caller with a real user row, since a setting names who set it.
func (w *world) user(as ...rbac.Assignment) access.Caller {
	w.t.Helper()
	uid := w.id(`INSERT INTO users (email, display_name) VALUES ($1, 'T') RETURNING id`, uuid.NewString()+"@example.com")
	p, err := rbac.NewPrincipal(uid, as)
	if err != nil {
		w.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: uid, Label: "who@example.com"})
}

func (w *world) target(c access.Caller, scope agentsettings.Scope, id uuid.UUID) agentsettings.Target {
	w.t.Helper()
	tg, err := w.svc.Resolve(context.Background(), c, scope, id)
	if err != nil {
		w.t.Fatalf("resolving %s: %v", scope, err)
	}
	return tg
}

func (w *world) put(c access.Caller, scope agentsettings.Scope, id uuid.UUID, v int, enforced bool) error {
	w.t.Helper()
	tg, err := w.svc.Resolve(context.Background(), c, scope, id)
	if err != nil {
		return err
	}
	_, err = w.svc.Put(context.Background(), c, tg, hb, agentsettings.PutInput{Value: json.RawMessage(fmt.Sprint(v)), Enforced: enforced})
	return err
}

func (w *world) effective(c access.Caller, scope agentsettings.Scope, id uuid.UUID) agentsettings.Entry {
	w.t.Helper()
	l, err := w.svc.List(context.Background(), c, w.target(c, scope, id))
	if err != nil {
		w.t.Fatal(err)
	}
	return l.Items[0]
}

func (w *world) interval(dev uuid.UUID) int {
	w.t.Helper()
	var org, site uuid.UUID
	var n int
	err := w.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		if err := tx.QueryRow(context.Background(), `SELECT organization_id, site_id FROM devices WHERE id = $1`, dev).Scan(&org, &site); err != nil {
			return err
		}
		var err error
		n, err = agentsettings.EffectiveHeartbeat(context.Background(), tx, org, site, dev)
		return err
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return n
}

func (w *world) count(sql string, args ...any) int {
	w.t.Helper()
	var n int
	_ = w.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&n)
	})
	return n
}

func wantErr(t *testing.T, err error, kind apperr.Kind, code, what string) {
	t.Helper()
	ae, ok := apperr.As(err)
	if !ok || ae.Kind != kind || (code != "" && ae.Code != code) {
		t.Fatalf("%s: got %v, want kind %d code %q", what, err, kind, code)
	}
}

func asInt(t *testing.T, raw json.RawMessage) int {
	t.Helper()
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPrecedenceOverFourScopes(t *testing.T) {
	w := newWorld(t)
	sa := w.user(rbac.Assignment{Role: rbac.RoleSuperAdmin})
	if got := w.interval(w.dev); got != 60 {
		t.Fatalf("nothing set: %d", got)
	}
	steps := []struct {
		scope agentsettings.Scope
		id    uuid.UUID
		v     int
		want  int
		from  agentsettings.Scope
	}{
		{agentsettings.ScopePlatform, uuid.Nil, 120, 120, agentsettings.ScopePlatform},
		{agentsettings.ScopeOrganization, w.acme, 90, 90, agentsettings.ScopeOrganization},
		{agentsettings.ScopeSite, w.hq, 45, 45, agentsettings.ScopeSite},
		{agentsettings.ScopeDevice, w.dev, 300, 300, agentsettings.ScopeDevice},
	}
	for _, s := range steps {
		if err := w.put(sa, s.scope, s.id, s.v, false); err != nil {
			t.Fatalf("%s: %v", s.scope, err)
		}
		if got := w.interval(w.dev); got != s.want {
			t.Fatalf("after %s: %d, want %d", s.scope, got, s.want)
		}
		e := w.effective(sa, agentsettings.ScopeDevice, w.dev)
		if e.Effective.From == nil || e.Effective.From.Scope != s.from {
			t.Fatalf("after %s the value comes from %+v", s.scope, e.Effective.From)
		}
	}
	// Other devices follow their own chain: the branch device has no site or
	// device value, so the organization's applies; Globex's, the platform's.
	if got := w.interval(w.branchDev); got != 90 {
		t.Fatalf("branch: %d", got)
	}
	if got := w.interval(w.globexDev); got != 120 {
		t.Fatalf("globex: %d", got)
	}
	// Clearing goes back to inheriting.
	if err := w.svc.Delete(context.Background(), sa, w.target(sa, agentsettings.ScopeDevice, w.dev), hb); err != nil {
		t.Fatal(err)
	}
	if got := w.interval(w.dev); got != 45 {
		t.Fatalf("after clearing the device: %d", got)
	}
	wantErr(t, w.svc.Delete(context.Background(), sa, w.target(sa, agentsettings.ScopeDevice, w.dev), hb), apperr.KindNotFound, "", "clearing twice")
	// The inherited value is what the list says for the device.
	e := w.effective(sa, agentsettings.ScopeDevice, w.dev)
	if asInt(t, e.Inherited.Value) != 45 || e.Inherited.From.Scope != agentsettings.ScopeSite || e.Set != nil {
		t.Fatalf("inherited: %+v set %+v", e.Inherited, e.Set)
	}
}

func TestEnforcement(t *testing.T) {
	w := newWorld(t)
	sa := w.user(rbac.Assignment{Role: rbac.RoleSuperAdmin})
	orgAdmin := w.user(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.acme})
	// A site and a device set earlier.
	for _, s := range []struct {
		scope agentsettings.Scope
		id    uuid.UUID
		v     int
	}{{agentsettings.ScopeSite, w.hq, 45}, {agentsettings.ScopeDevice, w.dev, 100}} {
		if err := w.put(sa, s.scope, s.id, s.v, false); err != nil {
			t.Fatal(err)
		}
	}
	// A device has nothing below it to enforce over, and a site is not
	// among this key's enforcing scopes.
	wantErr(t, w.put(sa, agentsettings.ScopeDevice, w.dev, 100, true), apperr.KindInvalid, "setting_scope", "device enforcing")
	wantErr(t, w.put(sa, agentsettings.ScopeSite, w.hq, 45, true), apperr.KindInvalid, "setting_scope", "site enforcing")
	// The organization enforces: it wins over the site and the device, the
	// values below are kept but not in effect, and nothing can be set there.
	if err := w.put(orgAdmin, agentsettings.ScopeOrganization, w.acme, 200, true); err != nil {
		t.Fatal(err)
	}
	if got := w.interval(w.dev); got != 200 {
		t.Fatalf("enforced: %d", got)
	}
	wantErr(t, w.put(sa, agentsettings.ScopeSite, w.hq, 50, false), apperr.KindConflict, "setting_enforced", "site under the org")
	wantErr(t, w.put(sa, agentsettings.ScopeDevice, w.dev, 50, false), apperr.KindConflict, "setting_enforced", "device under the org")
	e := w.effective(sa, agentsettings.ScopeDevice, w.dev)
	if e.Set == nil || e.Set.InEffect || asInt(t, e.Set.Value) != 100 || e.EnforcedBy == nil || e.EnforcedBy.Scope != agentsettings.ScopeOrganization || e.CanWrite {
		t.Fatalf("device entry under enforcement: %+v set %+v", e, e.Set)
	}
	// The platform enforces over the organization: the highest wins.
	if err := w.put(sa, agentsettings.ScopePlatform, uuid.Nil, 150, true); err != nil {
		t.Fatal(err)
	}
	if got := w.interval(w.dev); got != 150 {
		t.Fatalf("platform enforced: %d", got)
	}
	wantErr(t, w.put(orgAdmin, agentsettings.ScopeOrganization, w.acme, 210, false), apperr.KindConflict, "setting_enforced", "org under the platform")
	// Lifting both brings the earlier values back.
	if err := w.put(sa, agentsettings.ScopePlatform, uuid.Nil, 150, false); err != nil {
		t.Fatal(err)
	}
	if err := w.put(orgAdmin, agentsettings.ScopeOrganization, w.acme, 200, false); err != nil {
		t.Fatal(err)
	}
	if got := w.interval(w.dev); got != 100 {
		t.Fatalf("after lifting: %d, want the device's own 100", got)
	}
}

func TestPermissionAtEachScope(t *testing.T) {
	w := newWorld(t)
	sa := w.user(rbac.Assignment{Role: rbac.RoleSuperAdmin})
	orgAdmin := w.user(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.acme})
	siteAdmin := w.user(rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.acme, SiteID: w.hq})
	orgSiteAdmin := w.user(rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.acme})
	tech := w.user(rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: w.acme})
	ro := w.user(rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: w.acme})
	globex := w.user(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.globex})

	type try struct {
		who  access.Caller
		name string
		sc   agentsettings.Scope
		id   uuid.UUID
		ok   bool
	}
	for _, c := range []try{
		{sa, "super admin, platform", agentsettings.ScopePlatform, uuid.Nil, true},
		{orgAdmin, "org admin, platform", agentsettings.ScopePlatform, uuid.Nil, false},
		{orgAdmin, "org admin, org", agentsettings.ScopeOrganization, w.acme, true},
		{orgAdmin, "org admin, other site's device", agentsettings.ScopeDevice, w.branchDev, true},
		{orgSiteAdmin, "site admin on the whole org, org", agentsettings.ScopeOrganization, w.acme, true},
		{siteAdmin, "site admin of HQ, own site", agentsettings.ScopeSite, w.hq, true},
		{siteAdmin, "site admin of HQ, own device", agentsettings.ScopeDevice, w.dev, true},
		{siteAdmin, "site admin of HQ, the org", agentsettings.ScopeOrganization, w.acme, false},
		{tech, "technician, a device", agentsettings.ScopeDevice, w.dev, false},
		{tech, "technician, a site", agentsettings.ScopeSite, w.hq, false},
		{ro, "read only, a device", agentsettings.ScopeDevice, w.dev, false},
	} {
		err := w.put(c.who, c.sc, c.id, 90, false)
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case !c.ok && err == nil:
			t.Errorf("%s: allowed", c.name)
		case !c.ok:
			wantErr(t, err, apperr.KindForbidden, "", c.name)
		}
	}
	// Another organization's people cannot even see these, and a site admin
	// of another site cannot see HQ's device.
	if _, err := w.svc.Resolve(context.Background(), globex, agentsettings.ScopeDevice, w.dev); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("globex sees Acme's device: %v", err)
	}
	if _, err := w.svc.Resolve(context.Background(), siteAdmin, agentsettings.ScopeDevice, w.branchDev); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("HQ's admin sees the branch's device: %v", err)
	}
	// Everyone who can see reads, and the entry says whether they may write.
	if e := w.effective(ro, agentsettings.ScopeDevice, w.dev); e.CanWrite {
		t.Error("read only may write")
	}
	if e := w.effective(siteAdmin, agentsettings.ScopePlatform, uuid.Nil); e.CanWrite || asInt(t, e.Effective.Value) != 90 {
		t.Errorf("a site admin reading the platform: %+v", e)
	}
	// A site admin sees the organization's value on their device, not the
	// other site's.
	if e := w.effective(siteAdmin, agentsettings.ScopeDevice, w.dev); e.Inherited.From == nil || e.Inherited.From.Scope != agentsettings.ScopeSite {
		t.Errorf("inherited as the site admin sees it: %+v", e.Inherited)
	}
	// A device without the agent has nothing to receive a setting.
	_, err := w.svc.Resolve(context.Background(), sa, agentsettings.ScopeDevice, w.bare)
	wantErr(t, err, apperr.KindInvalid, "setting_scope", "device without the agent")
	// A key that is not in the catalog.
	_, err = w.svc.Put(context.Background(), sa, w.target(sa, agentsettings.ScopePlatform, uuid.Nil), "agent.nothing", agentsettings.PutInput{Value: json.RawMessage("60")})
	wantErr(t, err, apperr.KindNotFound, "", "unknown key")
}

func TestRowLevelSecurityAndDeviceRows(t *testing.T) {
	w := newWorld(t)
	sa := w.user(rbac.Assignment{Role: rbac.RoleSuperAdmin})
	for _, s := range []struct {
		scope agentsettings.Scope
		id    uuid.UUID
	}{{agentsettings.ScopePlatform, uuid.Nil}, {agentsettings.ScopeOrganization, w.acme}, {agentsettings.ScopeSite, w.hq}, {agentsettings.ScopeSite, w.branch}, {agentsettings.ScopeDevice, w.dev}} {
		if err := w.put(sa, s.scope, s.id, 80, false); err != nil {
			t.Fatal(err)
		}
	}
	count := func(scope access.Caller) int {
		n := 0
		_ = w.db.ReadTx(context.Background(), scope.Scope, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT count(*) FROM agent_settings`).Scan(&n)
		})
		return n
	}
	for _, c := range []struct {
		name string
		who  access.Caller
		want int
	}{
		{"super admin", sa, 5},
		{"acme org admin", w.user(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.acme}), 5},
		{"globex org admin", w.user(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.globex}), 1},
		{"HQ site admin: platform, the org, HQ and its device", w.user(rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.acme, SiteID: w.hq}), 4},
		{"Branch technician: platform, the org, Branch", w.user(rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: w.acme, SiteID: w.branch}), 3},
	} {
		if got := count(c.who); got != c.want {
			t.Errorf("%s sees %d rows, want %d", c.name, got, c.want)
		}
	}
	// Writes below the service: a site admin cannot write the organization's
	// or the platform's rows, nor another site's, whatever the permission.
	hq := w.user(rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.acme, SiteID: w.hq})
	write := func(c access.Caller, sql string, args ...any) error {
		return w.db.InTx(context.Background(), c.Scope, func(tx pgx.Tx) error {
			tag, err := tx.Exec(context.Background(), sql, args...)
			if err == nil && tag.RowsAffected() == 0 {
				return errors.New("no rows")
			}
			return err
		})
	}
	if write(hq, `UPDATE agent_settings SET value = '61' WHERE scope = 'organization'`) == nil {
		t.Error("a site admin changed the organization's row")
	}
	if write(hq, `DELETE FROM agent_settings WHERE scope = 'platform'`) == nil {
		t.Error("a site admin deleted the platform's row")
	}
	if write(hq, `UPDATE agent_settings SET value = '61' WHERE site_id = $1 AND scope = 'site'`, w.branch) == nil {
		t.Error("a site admin changed another site's row")
	}
	if err := write(hq, `UPDATE agent_settings SET value = '61' WHERE site_id = $1 AND scope = 'site'`, w.hq); err != nil {
		t.Errorf("a site admin could not change their site's row: %v", err)
	}
	if write(hq, `INSERT INTO agent_settings (key, scope, organization_id, value) VALUES ('agent.other_key', 'organization', $1, '1')`, w.acme) == nil {
		t.Error("a site admin inserted an organization row")
	}
	// A device row needs a device with the agent, in the site it names.
	for name, args := range map[string][]any{
		"no agent":   {w.acme, w.hq, w.bare},
		"wrong site": {w.acme, w.branch, w.dev},
		"wrong org":  {w.globex, w.main, w.dev},
	} {
		err := w.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `INSERT INTO agent_settings (key, scope, organization_id, site_id, device_id, value)
				VALUES ('agent.x_key', 'device', $1, $2, $3, '1')`, args...)
			return err
		})
		if err == nil {
			t.Errorf("a device row was accepted: %s", name)
		}
	}
	// Rows go with their device, site and organization.
	w.exec(`DELETE FROM devices WHERE id = $1`, w.dev)
	if n := w.count(`SELECT count(*) FROM agent_settings WHERE device_id = $1`, w.dev); n != 0 {
		t.Errorf("%d device rows left", n)
	}
	w.exec(`DELETE FROM devices WHERE organization_id = $1`, w.acme)
	w.exec(`DELETE FROM sites WHERE id = $1`, w.branch)
	if n := w.count(`SELECT count(*) FROM agent_settings WHERE site_id = $1`, w.branch); n != 0 {
		t.Errorf("%d site rows left", n)
	}
	w.exec(`DELETE FROM sites WHERE organization_id = $1`, w.acme)
	w.exec(`DELETE FROM organizations WHERE id = $1`, w.acme)
	if n := w.count(`SELECT count(*) FROM agent_settings WHERE scope <> 'platform'`); n != 0 {
		t.Errorf("%d rows left after the organization", n)
	}
}

func TestPlatformMinimumRaisesEarlierValues(t *testing.T) {
	w := newWorld(t)
	sa := w.user(rbac.Assignment{Role: rbac.RoleSuperAdmin})
	siteAdmin := w.user(rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.acme, SiteID: w.hq})
	if err := w.put(siteAdmin, agentsettings.ScopeSite, w.hq, 30, false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.SetLimits(context.Background(), sa, agentsettings.Limits{MinHeartbeatSeconds: 120}); err != nil {
		t.Fatal(err)
	}
	if got := w.interval(w.dev); got != 120 {
		t.Fatalf("an earlier 30 under a minimum of 120: %d", got)
	}
	e := w.effective(sa, agentsettings.ScopeDevice, w.dev)
	if !e.Effective.Raised || asInt(t, e.Effective.Value) != 120 || e.Min != 120 {
		t.Fatalf("shown as raised: %+v", e)
	}
	wantErr(t, w.put(siteAdmin, agentsettings.ScopeSite, w.hq, 60, false), apperr.KindInvalid, "setting_invalid", "below the minimum")
	if err := w.put(siteAdmin, agentsettings.ScopeSite, w.hq, 120, false); err != nil {
		t.Fatal(err)
	}
	if got := w.interval(w.branchDev); got != 120 {
		t.Fatalf("a device with nothing set follows the default under the minimum: %d", got)
	}
	// The limits: bounds, and who may set them.
	for _, bad := range []int{29, 301, 0, -5} {
		_, err := w.svc.SetLimits(context.Background(), sa, agentsettings.Limits{MinHeartbeatSeconds: bad})
		wantErr(t, err, apperr.KindInvalid, "setting_invalid", fmt.Sprint("minimum ", bad))
	}
	_, err := w.svc.SetLimits(context.Background(), siteAdmin, agentsettings.Limits{MinHeartbeatSeconds: 30})
	wantErr(t, err, apperr.KindForbidden, "", "a site admin setting the limits")
	// Lowering it brings the earlier value back into effect as it was set.
	if _, err := w.svc.SetLimits(context.Background(), sa, agentsettings.Limits{MinHeartbeatSeconds: 30}); err != nil {
		t.Fatal(err)
	}
	if l, _ := w.svc.Limits(context.Background()); l.MinHeartbeatSeconds != 30 {
		t.Fatalf("limits: %+v", l)
	}
}

func TestValuesAreChecked(t *testing.T) {
	w := newWorld(t)
	sa := w.user(rbac.Assignment{Role: rbac.RoleSuperAdmin})
	tg := w.target(sa, agentsettings.ScopePlatform, uuid.Nil)
	for _, bad := range []string{`29`, `301`, `"60"`, `60.5`, `1e2`, `null`, `true`, `[60]`, `{}`, ``, `-60`, `99999999999`} {
		_, err := w.svc.Put(context.Background(), sa, tg, hb, agentsettings.PutInput{Value: json.RawMessage(bad)})
		wantErr(t, err, apperr.KindInvalid, "setting_invalid", "value "+bad)
	}
	if n := w.count(`SELECT count(*) FROM agent_settings`); n != 0 {
		t.Fatalf("%d rows stored from refused values", n)
	}
	// 30 and 300 are the bounds, inside.
	for _, ok := range []int{30, 300} {
		if err := w.put(sa, agentsettings.ScopePlatform, uuid.Nil, ok, false); err != nil {
			t.Fatalf("%d: %v", ok, err)
		}
	}
}

func TestWritesAreRateLimitedPerCallerAndPerTarget(t *testing.T) {
	w := newWorld(t)
	sa := w.user(rbac.Assignment{Role: rbac.RoleSuperAdmin})
	// One target: 30 a minute, then 429.
	var err error
	n := 0
	for ; n < 40; n++ {
		if err = w.put(sa, agentsettings.ScopeSite, w.hq, 60+n%3, false); err != nil {
			break
		}
	}
	if n != 30 {
		t.Fatalf("%d writes to one site before the limit", n)
	}
	wantErr(t, err, apperr.KindTooMany, "rate_limited", "per target")
	// Another target is untouched by that limit.
	if err := w.put(sa, agentsettings.ScopeSite, w.branch, 60, false); err != nil {
		t.Fatalf("another site: %v", err)
	}
	// A caller spread over 100 sites is held to 60 a minute across all of
	// them.
	sites := make([]uuid.UUID, 100)
	for i := range sites {
		sites[i] = w.id(`INSERT INTO sites (organization_id, name) VALUES ($1, $2) RETURNING id`, w.acme, fmt.Sprintf("S%d", i))
	}
	spread := w.user(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.acme})
	done := 0
	for _, s := range sites {
		if err = w.put(spread, agentsettings.ScopeSite, s, 90, false); err != nil {
			break
		}
		done++
	}
	if done != 60 {
		t.Fatalf("%d writes by one caller across 100 sites", done)
	}
	wantErr(t, err, apperr.KindTooMany, "rate_limited", "per caller")
	// A second caller has a limit of their own.
	other := w.user(rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.acme})
	if err := w.put(other, agentsettings.ScopeSite, sites[99], 90, false); err != nil {
		t.Fatalf("another caller: %v", err)
	}
	// Refused writes (no permission) do not use the limit up.
	ro := w.user(rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: w.acme})
	for i := 0; i < 70; i++ {
		wantErr(t, w.put(ro, agentsettings.ScopeSite, w.hq, 60, false), apperr.KindForbidden, "", "read only")
	}
}

func TestEveryChangeIsAudited(t *testing.T) {
	w := newWorld(t)
	sa := w.user(rbac.Assignment{Role: rbac.RoleSuperAdmin})
	if err := w.put(sa, agentsettings.ScopeSite, w.hq, 90, false); err != nil {
		t.Fatal(err)
	}
	if err := w.put(sa, agentsettings.ScopeSite, w.hq, 120, false); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.Delete(context.Background(), sa, w.target(sa, agentsettings.ScopeSite, w.hq), hb); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.SetLimits(context.Background(), sa, agentsettings.Limits{MinHeartbeatSeconds: 40}); err != nil {
		t.Fatal(err)
	}
	type row struct {
		action  string
		org     *uuid.UUID
		site    *uuid.UUID
		details map[string]any
	}
	var rows []row
	err := w.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		rs, err := tx.Query(context.Background(), `SELECT action, organization_id, site_id, details FROM audit_log WHERE action LIKE 'agent_setting.%' ORDER BY id`)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var r row
			if err := rs.Scan(&r.action, &r.org, &r.site, &r.details); err != nil {
				return err
			}
			rows = append(rows, r)
		}
		return rs.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"agent_setting.set", "agent_setting.set", "agent_setting.cleared", "agent_setting.limits_set"}
	if len(rows) != len(want) {
		t.Fatalf("%d audit rows, want %d: %+v", len(rows), len(want), rows)
	}
	for i, a := range want {
		if rows[i].action != a {
			t.Errorf("row %d: %s, want %s", i, rows[i].action, a)
		}
	}
	if rows[0].site == nil || *rows[0].site != w.hq || rows[0].details["key"] != hb || rows[0].details["new"] != float64(90) || rows[0].details["old"] != nil {
		t.Errorf("first set: %+v", rows[0])
	}
	if rows[1].details["old"] != float64(90) || rows[1].details["new"] != float64(120) {
		t.Errorf("second set keeps the old value: %+v", rows[1].details)
	}
	if rows[2].details["old"] != float64(120) {
		t.Errorf("cleared: %+v", rows[2].details)
	}
	if rows[3].details["minHeartbeatSeconds"] != float64(40) {
		t.Errorf("limits: %+v", rows[3].details)
	}
	// A refused write leaves no row.
	before := w.count(`SELECT count(*) FROM audit_log WHERE action LIKE 'agent_setting.%'`)
	_ = w.put(sa, agentsettings.ScopeSite, w.hq, 5, false)
	if w.count(`SELECT count(*) FROM audit_log WHERE action LIKE 'agent_setting.%'`) != before {
		t.Error("a refused write was audited as a change")
	}
}

func TestDevScopeGatesWritesAndTheInterval(t *testing.T) {
	w := newWorld(t)
	sa := w.user(rbac.Assignment{Role: rbac.RoleSuperAdmin})
	if err := w.put(sa, agentsettings.ScopePlatform, uuid.Nil, 200, false); err != nil {
		t.Fatal(err)
	}
	if err := w.put(sa, agentsettings.ScopeSite, w.hq, 100, false); err != nil {
		t.Fatal(err)
	}
	defer devscope.Set(w.globex)()
	// Acme is outside the scope: nothing is written for it, and its agents
	// keep today's minute; Globex follows the platform's value.
	wantErr(t, w.put(sa, agentsettings.ScopeSite, w.hq, 90, false), apperr.KindForbidden, "", "write outside the dev scope")
	wantErr(t, w.put(sa, agentsettings.ScopeOrganization, w.acme, 90, false), apperr.KindForbidden, "", "organization write outside the dev scope")
	wantErr(t, w.put(sa, agentsettings.ScopeDevice, w.dev, 90, false), apperr.KindForbidden, "", "device write outside the dev scope")
	if got := w.interval(w.dev); got != 60 {
		t.Fatalf("outside the dev scope: %d", got)
	}
	if got := w.interval(w.globexDev); got != 200 {
		t.Fatalf("inside the dev scope: %d", got)
	}
	if e := w.effective(sa, agentsettings.ScopeSite, w.hq); e.CanWrite {
		t.Error("the list offers a write outside the dev scope")
	}
}

func TestDeviceStateInTheListing(t *testing.T) {
	w := newWorld(t)
	sa := w.user(rbac.Assignment{Role: rbac.RoleSuperAdmin})
	l, err := w.svc.List(context.Background(), sa, w.target(sa, agentsettings.ScopeDevice, w.dev))
	if err != nil {
		t.Fatal(err)
	}
	if l.Device == nil || l.Device.HeartbeatSeconds != 60 || l.Device.OnlineUntil == nil || l.Name != "hq-1" {
		t.Fatalf("device state: %+v", l)
	}
	if l.Limits.MinHeartbeatSeconds != 30 || len(l.Items) != 1 || l.Items[0].Key != hb {
		t.Fatalf("listing: %+v", l)
	}
}
