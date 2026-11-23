//go:build integration

package devices_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// world is Acme (sites HQ, Branch; group Servers in HQ) and Globex (site Main).
type world struct {
	db                 *database.DB
	svc                *devices.Service
	sys                access.Caller
	acme, globex       uuid.UUID
	hq, branch, main   uuid.UUID
	servers, mainGroup uuid.UUID
	moved              int
}

func newWorld(t *testing.T) *world {
	t.Helper()
	inst := testdb.New(t)
	w := &world{db: inst.DB, svc: devices.New(inst.DB, false), sys: access.System("test")}
	w.svc.SetAudit(audit.New(inst.DB, nil))
	w.svc.OnMoved(func() { w.moved++ })
	org := func(name string) uuid.UUID {
		return w.insert(t, `INSERT INTO organizations (name) VALUES ($1) RETURNING id`, name)
	}
	site := func(o uuid.UUID, name string) uuid.UUID {
		return w.insert(t, `INSERT INTO sites (organization_id, name) VALUES ($1, $2) RETURNING id`, o, name)
	}
	w.acme, w.globex = org("Acme"), org("Globex")
	w.hq, w.branch, w.main = site(w.acme, "HQ"), site(w.acme, "Branch"), site(w.globex, "Main")
	w.servers = w.insert(t, `INSERT INTO device_groups (organization_id, site_id, name) VALUES ($1, $2, 'Servers') RETURNING id`, w.acme, w.hq)
	w.mainGroup = w.insert(t, `INSERT INTO device_groups (organization_id, site_id, name) VALUES ($1, $2, 'Servers') RETURNING id`, w.globex, w.main)
	return w
}

func (w *world) insert(t *testing.T, sql string, args ...any) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := w.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&id)
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (w *world) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	err := w.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (w *world) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	err := w.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (w *world) device(t *testing.T, name string, org, site uuid.UUID) uuid.UUID {
	t.Helper()
	return w.insert(t, `INSERT INTO devices (organization_id, site_id, name, platform, agent_last_seen_at, agent_public_key, enrolled_at)
		VALUES ($1, $2, $3, 'linux', now(), sha256($3::text::bytea), now()) RETURNING id`, org, site, name)
}

func (w *world) siteOf(t *testing.T, id uuid.UUID) (org, site uuid.UUID) {
	t.Helper()
	err := w.db.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT organization_id, site_id FROM devices WHERE id = $1`, id).Scan(&org, &site)
	})
	if err != nil {
		t.Fatal(err)
	}
	return org, site
}

func user(t *testing.T, as ...rbac.Assignment) access.Caller {
	t.Helper()
	uid := uuid.New()
	p, err := rbac.NewPrincipal(uid, as)
	if err != nil {
		t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: uid, Label: "user@example.com"})
}

func wantKind(t *testing.T, err error, kind apperr.Kind, what string) {
	t.Helper()
	if ae, ok := apperr.As(err); !ok || ae.Kind != kind {
		t.Fatalf("%s: got %v, want apperr kind %d", what, err, kind)
	}
}

func TestMoveRefusals(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	d := w.device(t, "srv-01", w.acme, w.hq)
	one := []uuid.UUID{d}
	// ids builds a list of n distinct device ids.
	tooMany := make([]uuid.UUID, devices.MaxMove+1)
	for i := range tooMany {
		tooMany[i] = uuid.New()
	}

	readOnly := user(t, rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: w.acme})
	if _, err := w.svc.Move(ctx, readOnly, devices.MoveInput{DeviceIDs: one, SiteID: w.hq}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a read-only user moved a device: %v", err)
	}

	admin := w.sys
	for name, in := range map[string]devices.MoveInput{
		"none":    {SiteID: w.hq},
		"limit":   {DeviceIDs: tooMany, SiteID: w.hq},
		"no site": {DeviceIDs: one},
	} {
		wantKind(t, errOf(w.svc.Move(ctx, admin, in)), apperr.KindInvalid, name)
	}
	// Exactly the limit passes validation (the devices do not exist).
	wantKind(t, errOf(w.svc.Move(ctx, admin, devices.MoveInput{DeviceIDs: tooMany[:devices.MaxMove], SiteID: w.hq})), apperr.KindNotFound, "at the limit")

	// Unknown site, group of another site, unknown device.
	wantKind(t, errOf(w.svc.Move(ctx, admin, devices.MoveInput{DeviceIDs: one, SiteID: uuid.New()})), apperr.KindInvalid, "unknown site")
	g := w.mainGroup
	wantKind(t, errOf(w.svc.Move(ctx, admin, devices.MoveInput{DeviceIDs: one, SiteID: w.hq, GroupID: &g})), apperr.KindInvalid, "group of another site")
	wantKind(t, errOf(w.svc.Move(ctx, admin, devices.MoveInput{DeviceIDs: []uuid.UUID{d, uuid.New()}, SiteID: w.hq})), apperr.KindNotFound, "unknown device")

	// A site the caller cannot see does not exist for them, and neither do its devices.
	branchOnly := user(t, rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.acme, SiteID: w.branch})
	wantKind(t, errOf(w.svc.Move(ctx, branchOnly, devices.MoveInput{DeviceIDs: one, SiteID: w.hq})), apperr.KindInvalid, "invisible site")
	wantKind(t, errOf(w.svc.Move(ctx, branchOnly, devices.MoveInput{DeviceIDs: one, SiteID: w.branch})), apperr.KindNotFound, "invisible device")

	tech := user(t, rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: w.acme})
	orgAdminAcme := user(t, rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.acme})
	siteAdminBoth := user(t, rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.acme}, rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.globex})
	orgAcmeSiteGlobex := user(t, rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.acme}, rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.globex})
	siteAcmeOrgGlobex := user(t, rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.acme}, rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: w.globex})
	// A technician of HQ who also administers HQ's device but only views Branch.
	hqAdminBranchTech := user(t,
		rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.acme, SiteID: w.hq},
		rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: w.acme, SiteID: w.branch})
	hqTech := user(t, rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: w.acme, SiteID: w.hq},
		rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.acme, SiteID: w.branch})
	// Edit-less on the device's own site: read-only there, administrator of Branch.
	hqReader := user(t, rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: w.acme, SiteID: w.hq},
		rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: w.acme, SiteID: w.branch})

	for _, c := range []struct {
		name string
		who  access.Caller
		site uuid.UUID
	}{
		{"device.edit missing on the device's site", hqReader, w.branch},
		{"site.manage missing on the source site", tech, w.branch},
		{"site.manage missing on the target site", hqAdminBranchTech, w.branch},
		{"site.manage missing on the source (site tech)", hqTech, w.branch},
		{"org.manage missing on both", siteAdminBoth, w.main},
		{"org.manage missing on the target", orgAcmeSiteGlobex, w.main},
		{"org.manage missing on the source", siteAcmeOrgGlobex, w.main},
		{"target organization not visible", orgAdminAcme, w.main},
	} {
		_, err := w.svc.Move(ctx, c.who, devices.MoveInput{DeviceIDs: one, SiteID: c.site})
		if c.name == "target organization not visible" {
			wantKind(t, err, apperr.KindInvalid, c.name)
		} else if !errors.Is(err, apperr.ErrForbidden) {
			t.Errorf("%s: got %v, want forbidden", c.name, err)
		}
	}
	if org, site := w.siteOf(t, d); org != w.acme || site != w.hq {
		t.Fatalf("a refused move changed the device: %v %v", org, site)
	}
	if w.moved != 0 {
		t.Fatal("OnMoved ran for refused moves")
	}
}

func errOf(_ *devices.MoveResult, err error) error { return err }

func TestMoveBusyAndLeavingOrganization(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	x := w.device(t, "x-01", w.acme, w.hq)
	busy := w.device(t, "busy-01", w.acme, w.hq)
	same := w.device(t, "same-01", w.acme, w.hq)

	user := w.insert(t, `INSERT INTO users (email, display_name) VALUES ('u@example.com', 'U') RETURNING id`)
	session := w.insert(t, `INSERT INTO sessions (token_hash, user_id, state, idle_expires_at, expires_at)
		VALUES (sha256('s'::bytea), $1, 'active', now() + interval '1 hour', now() + interval '1 hour') RETURNING id`, user)
	job := w.insert(t, `INSERT INTO jobs (id, script_name, shell, body, body_sha256, timeout_seconds, expires_at)
		VALUES (gen_random_uuid(), 'Up', 'sh', 'true', sha256('true'::bytea), 60, now() + interval '1 day') RETURNING id`)
	run := func(dev uuid.UUID, status string) {
		w.exec(t, `INSERT INTO job_runs (job_id, organization_id, site_id, device_id, status, expires_at, started_at, deadline_at)
			VALUES ($1, $2, $3, $4, $5, now() + interval '1 day',
				CASE WHEN $5 = 'running' THEN now() END, CASE WHEN $5 = 'running' THEN now() + interval '1 hour' END)`,
			job, w.acme, w.hq, dev, status)
	}
	run(x, "queued")
	run(busy, "running")
	w.exec(t, `INSERT INTO remote_grants (launch_hash, session_id, user_id, device_id, organization_id, site_id, kind, launch_expires_at)
		VALUES (sha256('g'::bytea), $1, $2, $3, $4, $5, 'desktop', now() + interval '1 minute')`, session, user, x, w.acme, w.hq)
	w.exec(t, `INSERT INTO alerts (device_id, name, kind, minutes, severity, value, last_value)
		VALUES ($1, 'Disk', 'disk', 5, 'warning', 96, 96)`, x)

	// A run in progress refuses the move with a conflict; nothing moves.
	for _, ids := range [][]uuid.UUID{{busy}, {x, busy}} {
		err := errOf(w.svc.Move(ctx, w.sys, devices.MoveInput{DeviceIDs: ids, SiteID: w.main}))
		wantKind(t, err, apperr.KindConflict, "busy")
		if ae, _ := apperr.As(err); ae.Code != "device_busy" {
			t.Fatalf("code %q", ae.Code)
		}
	}
	if org, _ := w.siteOf(t, x); org != w.acme {
		t.Fatal("a refused move changed a device")
	}
	if w.count(t, `SELECT count(*) FROM job_runs WHERE device_id = $1 AND status = 'queued'`, x) != 1 {
		t.Fatal("a refused move canceled a run")
	}
	// Within the organization a running job does not matter; the same
	// placement counts as unchanged.
	res, err := w.svc.Move(ctx, w.sys, devices.MoveInput{DeviceIDs: []uuid.UUID{busy, same}, SiteID: w.hq})
	if err != nil || res.Moved != 0 || res.Unchanged != 2 {
		t.Fatalf("unchanged: %+v %v", res, err)
	}
	if w.moved != 0 {
		t.Fatal("OnMoved ran when nothing moved")
	}
	g := w.servers
	if res, err = w.svc.Move(ctx, w.sys, devices.MoveInput{DeviceIDs: []uuid.UUID{busy}, SiteID: w.branch}); err != nil || res.Moved != 1 || res.OtherOrganization != 0 {
		t.Fatalf("within the organization: %+v %v", res, err)
	}
	if res, err = w.svc.Move(ctx, w.sys, devices.MoveInput{DeviceIDs: []uuid.UUID{same}, SiteID: w.hq, GroupID: &g}); err != nil || res.Moved != 1 {
		t.Fatalf("into a group: %+v %v", res, err)
	}

	res, err = w.svc.Move(ctx, w.sys, devices.MoveInput{DeviceIDs: []uuid.UUID{x}, SiteID: w.main})
	if err != nil || res.Moved != 1 || res.OtherOrganization != 1 || res.CanceledRuns != 1 {
		t.Fatalf("across organizations: %+v %v", res, err)
	}
	if org, site := w.siteOf(t, x); org != w.globex || site != w.main {
		t.Fatalf("device is in %v %v", org, site)
	}
	if n := w.count(t, `SELECT count(*) FROM job_runs WHERE device_id = $1 AND status = 'canceled' AND organization_id = $2 AND site_id = $3`, x, w.acme, w.hq); n != 1 {
		t.Fatalf("canceled runs of the old organization: %d", n)
	}
	for table, q := range map[string]string{
		"remote_grants": `SELECT count(*) FROM remote_grants WHERE device_id = $1`,
		"alerts":        `SELECT count(*) FROM alerts WHERE device_id = $1`,
	} {
		if w.count(t, q, x) != 0 {
			t.Errorf("%s stayed with the device", table)
		}
	}
	for action, org := range map[string]uuid.UUID{"device.move_out": w.acme, "device.move": w.globex, "job.cancel": w.acme} {
		if w.count(t, `SELECT count(*) FROM audit_log WHERE action = $1 AND device_id = $2 AND organization_id = $3`, action, x, org) != 1 {
			t.Errorf("no %s record in %v", action, org)
		}
	}
	if w.moved != 3 {
		t.Fatalf("OnMoved ran %d times, want 3", w.moved)
	}
}

func TestMoveManyDevices(t *testing.T) {
	w := newWorld(t)
	ids := make([]uuid.UUID, 0, devices.MaxMove)
	for i := range devices.MaxMove {
		ids = append(ids, w.device(t, fmt.Sprintf("bulk-%03d", i), w.acme, w.hq))
	}
	// A duplicate id counts once.
	res, err := w.svc.Move(context.Background(), w.sys, devices.MoveInput{DeviceIDs: append(ids, ids[0]), SiteID: w.branch})
	if err != nil || res.Moved != devices.MaxMove {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestUpdateStatus(t *testing.T) {
	for _, c := range []struct{ agent, build, state, target, want string }{
		{"", "b", "", "", devices.UpdateUnsupported},
		{"b", "b", "", "", devices.UpdateCurrent},
		{"a", "b", "", "", devices.UpdateAvailable},
		{"a", "b", "sent", "b", devices.UpdateUpdating},
		{"a", "b", "queued", "b", devices.UpdateQueued},
		{"a", "b", "failed", "b", devices.UpdateFailed},
		{"a", "b", "done", "b", devices.UpdateAvailable},
	} {
		if got := devices.UpdateStatus(c.agent, c.build, c.state, c.target); got != c.want {
			t.Errorf("%+v: got %q", c, got)
		}
	}
}

func TestListRefusesUnknownFilters(t *testing.T) {
	w := newWorld(t)
	for name, q := range map[string]devices.Query{
		"status":     {Status: "asleep"},
		"hardening":  {Hardening: "sturdy"},
		"diskHealth": {DiskHealth: "spinning"},
	} {
		_, err := w.svc.List(context.Background(), w.sys, q)
		wantKind(t, err, apperr.KindInvalid, name)
	}
}

func TestLookup(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	d := w.device(t, "srv-01", w.acme, w.hq)
	got, err := devices.Lookup(ctx, w.db, w.sys, d)
	if err != nil || got.ID != d {
		t.Fatalf("%v %v", got, err)
	}
	_, err = devices.Lookup(ctx, w.db, w.sys, uuid.New())
	wantKind(t, err, apperr.KindNotFound, "unknown device")
	other := user(t, rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: w.globex})
	_, err = devices.Lookup(ctx, w.db, other, d)
	wantKind(t, err, apperr.KindNotFound, "another organization's device")
}

// A failure at any step of a move across organizations undoes all of it.
func TestMoveUndoneByFailure(t *testing.T) {
	inst := testdb.New(t)
	w := &world{db: inst.DB, svc: devices.New(inst.DB, false), sys: access.System("test")}
	w.svc.SetAudit(audit.New(inst.DB, nil))
	w.acme = w.insert(t, `INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	w.globex = w.insert(t, `INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	w.hq = w.insert(t, `INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, w.acme)
	w.main = w.insert(t, `INSERT INTO sites (organization_id, name) VALUES ($1, 'Main') RETURNING id`, w.globex)
	d := w.device(t, "x-01", w.acme, w.hq)
	u := w.insert(t, `INSERT INTO users (email, display_name) VALUES ('u@example.com', 'U') RETURNING id`)
	sess := w.insert(t, `INSERT INTO sessions (token_hash, user_id, state, idle_expires_at, expires_at)
		VALUES (sha256('s'::bytea), $1, 'active', now() + interval '1 hour', now() + interval '1 hour') RETURNING id`, u)
	job := w.insert(t, `INSERT INTO jobs (id, script_name, shell, body, body_sha256, timeout_seconds, expires_at)
		VALUES (gen_random_uuid(), 'Up', 'sh', 'true', sha256('true'::bytea), 60, now() + interval '1 day') RETURNING id`)
	w.exec(t, `INSERT INTO job_runs (job_id, organization_id, site_id, device_id, expires_at) VALUES ($1, $2, $3, $4, now() + interval '1 day')`, job, w.acme, w.hq, d)
	w.exec(t, `INSERT INTO remote_grants (launch_hash, session_id, user_id, device_id, organization_id, site_id, kind, launch_expires_at)
		VALUES (sha256('g'::bytea), $1, $2, $3, $4, $5, 'desktop', now() + interval '1 minute')`, sess, u, d, w.acme, w.hq)
	w.exec(t, `INSERT INTO alerts (device_id, name, kind, minutes, severity, value, last_value) VALUES ($1, 'Disk', 'disk', 5, 'warning', 96, 96)`, d)

	ctx := context.Background()
	super, err := pgx.Connect(ctx, inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(ctx)
	if _, err := super.Exec(ctx, `CREATE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$`); err != nil {
		t.Fatal(err)
	}
	for i, f := range []struct{ table, event, when string }{
		{"devices", "UPDATE", ""},
		{"job_runs", "UPDATE", ""},
		{"audit_log", "INSERT", "WHEN (NEW.action = 'job.cancel')"},
		{"remote_grants", "DELETE", ""},
		{"alerts", "DELETE", ""},
		{"audit_log", "INSERT", "WHEN (NEW.action = 'device.move_out')"},
		{"audit_log", "INSERT", "WHEN (NEW.action = 'device.move')"},
	} {
		name := fmt.Sprintf("fault%d", i)
		if _, err := super.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW %s EXECUTE FUNCTION refuse()`, name, f.event, f.table, f.when)); err != nil {
			t.Fatal(err)
		}
		if _, err := w.svc.Move(ctx, w.sys, devices.MoveInput{DeviceIDs: []uuid.UUID{d}, SiteID: w.main}); err == nil {
			t.Errorf("%s %s %s: the move succeeded", f.table, f.event, f.when)
		}
		if org, _ := w.siteOf(t, d); org != w.acme {
			t.Errorf("%s: a failed move changed the device", name)
		}
		if _, err := super.Exec(ctx, fmt.Sprintf(`DROP TRIGGER %s ON %s`, name, f.table)); err != nil {
			t.Fatal(err)
		}
	}
	if w.count(t, `SELECT count(*) FROM alerts WHERE device_id = $1`, d) != 1 || w.count(t, `SELECT count(*) FROM job_runs WHERE status = 'queued'`) != 1 {
		t.Fatal("failed moves left changes behind")
	}
}
