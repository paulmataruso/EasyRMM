//go:build integration

package app_test

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// moveFixture is two organizations: Acme with sites HQ (groups Servers and
// Desks) and Branch (group Tills), and Globex with the site Main.
type moveFixture struct {
	h                                  *harness
	admin                              *client
	acme, globex                       string
	hq, branch, main                   string
	servers, desks, tills, mainServers string
}

func newMoveFixture(t *testing.T) *moveFixture {
	t.Helper()
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	f := &moveFixture{h: h, admin: admin, acme: orgID(t, admin, "Acme")}
	var o idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations", map[string]string{"name": "Globex"}, &o)
	f.globex = o.ID
	site := func(org, name string) string {
		var s idObj
		admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+org+"/sites", map[string]string{"name": name, "timezone": "UTC"}, &s)
		return s.ID
	}
	group := func(site, name string) string {
		var g idObj
		admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+site+"/device-groups", map[string]string{"name": name}, &g)
		return g.ID
	}
	f.hq, f.branch, f.main = site(f.acme, "HQ"), site(f.acme, "Branch"), site(f.globex, "Main")
	f.servers, f.desks, f.tills, f.mainServers = group(f.hq, "Servers"), group(f.hq, "Desks"), group(f.branch, "Tills"), group(f.main, "Servers")
	return f
}

// device inserts an enrolled device.
func (f *moveFixture) device(t *testing.T, name, org, site string, group *string) string {
	t.Helper()
	var id string
	if err := f.h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `INSERT INTO devices (organization_id, site_id, device_group_id, name, platform, agent_last_seen_at, agent_public_key, enrolled_at)
			VALUES ($1, $2, $3, $4, 'linux', now(), sha256($4::text::bytea), now()) RETURNING id`, org, site, group, name).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

type placed struct {
	OrganizationID string  `json:"organizationId"`
	SiteID         string  `json:"siteId"`
	DeviceGroupID  *string `json:"deviceGroupId"`
}

func (f *moveFixture) where(t *testing.T, c *client, id string) placed {
	t.Helper()
	var p placed
	c.expect(http.StatusOK, "GET", "/api/v1/devices/"+id, nil, &p)
	return p
}

func (f *moveFixture) user(t *testing.T, email, role string, scope map[string]any) *client {
	t.Helper()
	a := map[string]any{"role": role}
	for k, v := range scope {
		a[k] = v
	}
	invite(t, f.h, f.admin, email, []map[string]any{a})
	c := f.h.client()
	c.signIn(email, "a long and unusual passphrase", "")
	return c
}

func (f *moveFixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func move(ids []string, site string, group *string) map[string]any {
	return map[string]any{"deviceIds": ids, "siteId": site, "groupId": group}
}

// A move needs device.edit; to another site also site.manage on both sites;
// to another organization also org.manage on both organizations; and it
// moves every device or none (ADR-0069).
func TestMoveDevicesPermissions(t *testing.T) {
	f := newMoveFixture(t)
	srv := f.device(t, "srv-01", f.acme, f.hq, &f.servers)
	desk := f.device(t, "desk-01", f.acme, f.hq, &f.desks)
	till := f.device(t, "till-01", f.acme, f.branch, &f.tills)
	const url = "/api/v1/devices/move"

	tech := f.user(t, "tess@acme.example", "technician", map[string]any{"organizationId": f.acme})
	// Within a site: device.edit.
	var res struct{ Moved, Unchanged int }
	tech.expect(http.StatusOK, "POST", url, move([]string{srv}, f.hq, &f.desks), &res)
	if res.Moved != 1 || res.Unchanged != 0 {
		t.Fatalf("group move: %+v", res)
	}
	if p := f.where(t, tech, srv); p.DeviceGroupID == nil || *p.DeviceGroupID != f.desks {
		t.Fatalf("after the group move: %+v", p)
	}
	// Into no group; a device already there is unchanged.
	tech.expect(http.StatusOK, "POST", url, move([]string{srv, desk}, f.hq, nil), &res)
	if res.Moved != 2 {
		t.Fatalf("into no group: %+v", res)
	}
	tech.expect(http.StatusOK, "POST", url, move([]string{srv}, f.hq, nil), &res)
	if res.Moved != 0 || res.Unchanged != 1 {
		t.Fatalf("again: %+v", res)
	}
	// A technician does not move devices across sites, and nothing moves: the
	// allowed device in the same request stays where it was.
	wantStatus(t, tech.do("POST", url, move([]string{desk, till}, f.hq, &f.servers)), http.StatusForbidden, "forbidden")
	if p := f.where(t, tech, desk); p.DeviceGroupID != nil {
		t.Errorf("a refused move changed a device: %+v", p)
	}
	wantStatus(t, tech.do("POST", url, move([]string{till}, f.hq, nil)), http.StatusForbidden, "forbidden")

	// A site administrator of the organization moves across its sites, not out of it.
	siteAdmin := f.user(t, "sam@acme.example", "site_admin", map[string]any{"organizationId": f.acme})
	siteAdmin.expect(http.StatusOK, "POST", url, move([]string{till}, f.hq, &f.servers), &res)
	if p := f.where(t, siteAdmin, till); p.SiteID != f.hq || p.DeviceGroupID == nil || *p.DeviceGroupID != f.servers {
		t.Fatalf("after the site move: %+v", p)
	}
	wantStatus(t, siteAdmin.do("POST", url, move([]string{till}, f.main, nil)), http.StatusUnprocessableEntity, "validation_failed")
	// An administrator of Acme only does not even see Globex's site.
	orgAdmin := f.user(t, "olga@acme.example", "org_admin", map[string]any{"organizationId": f.acme})
	wantStatus(t, orgAdmin.do("POST", url, move([]string{till}, f.main, nil)), http.StatusUnprocessableEntity, "validation_failed")
	// One who sees Globex's site without managing Globex does not own its side of the move.
	invite(t, f.h, f.admin, "dora@acme.example", []map[string]any{
		{"role": "org_admin", "organizationId": f.acme}, {"role": "technician", "organizationId": f.globex}})
	dual := f.h.client()
	dual.signIn("dora@acme.example", "a long and unusual passphrase", "")
	wantStatus(t, dual.do("POST", url, move([]string{till}, f.main, nil)), http.StatusForbidden, "forbidden")
	// A site administrator of one site does not own the other site.
	hqOnly := f.user(t, "hank@acme.example", "site_admin", map[string]any{"organizationId": f.acme, "siteId": f.hq})
	wantStatus(t, hqOnly.do("POST", url, move([]string{desk}, f.branch, nil)), http.StatusUnprocessableEntity, "validation_failed")
	invite(t, f.h, f.admin, "hope@acme.example", []map[string]any{
		{"role": "site_admin", "organizationId": f.acme, "siteId": f.hq}, {"role": "technician", "organizationId": f.acme, "siteId": f.branch}})
	hqAndSee := f.h.client()
	hqAndSee.signIn("hope@acme.example", "a long and unusual passphrase", "")
	wantStatus(t, hqAndSee.do("POST", url, move([]string{desk}, f.branch, nil)), http.StatusForbidden, "forbidden")

	// A super administrator moves across organizations; the group must be the site's.
	wantStatus(t, f.admin.do("POST", url, move([]string{till}, f.main, &f.servers)), http.StatusUnprocessableEntity, "validation_failed")
	f.admin.expect(http.StatusOK, "POST", url, move([]string{till}, f.main, &f.mainServers), &res)
	if p := f.where(t, f.admin, till); p.OrganizationID != f.globex || p.SiteID != f.main {
		t.Fatalf("after the organization move: %+v", p)
	}
	// ...which Acme's technician no longer sees.
	wantStatus(t, tech.do("GET", "/api/v1/devices/"+till, nil), http.StatusNotFound, "not_found")

	// Bad requests.
	wantStatus(t, f.admin.do("POST", url, move([]string{}, f.hq, nil)), http.StatusUnprocessableEntity, "validation_failed")
	many := make([]string, 501)
	for i := range many {
		many[i] = fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1)
	}
	wantStatus(t, f.admin.do("POST", url, move(many, f.hq, nil)), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, f.admin.do("POST", url, move([]string{"00000000-0000-0000-0000-000000000001"}, f.hq, nil)), http.StatusNotFound, "not_found")
	wantStatus(t, f.admin.do("POST", url, move([]string{srv}, "00000000-0000-0000-0000-000000000001", nil)), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, f.admin.do("POST", url, "x"), http.StatusBadRequest, "")
	// Read-only users cannot move.
	ro := f.user(t, "rae@acme.example", "read_only", map[string]any{"organizationId": f.acme})
	wantStatus(t, ro.do("POST", url, move([]string{srv}, f.hq, &f.desks)), http.StatusForbidden, "forbidden")
}

// The audit log records every device's move, in both organizations when it
// changes organization.
func TestMoveDevicesAuditAndMeshDesiredState(t *testing.T) {
	f := newMoveFixture(t)
	d := f.device(t, "srv-01", f.acme, f.hq, nil)
	exec(t, f.h, `UPDATE devices SET mesh_node_id = 'node//abc', mesh_agent_type = 6 WHERE id = $1`, d)
	mesh := func() (from *string, pending bool, site string) {
		if err := f.h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT mesh_from_site_id::text, mesh_settings_pending, site_id::text FROM devices WHERE id = $1`, d).
				Scan(&from, &pending, &site)
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	var res struct{ Moved int }
	// A group change leaves the node alone.
	f.admin.expect(http.StatusOK, "POST", "/api/v1/devices/move", move([]string{d}, f.hq, &f.desks), &res)
	if from, pending, _ := mesh(); from != nil || pending {
		t.Errorf("group move: from %v pending %v", from, pending)
	}
	// A site move records where the node still is, and that the agent must be told.
	f.admin.expect(http.StatusOK, "POST", "/api/v1/devices/move", move([]string{d}, f.branch, nil), &res)
	if from, pending, site := mesh(); from == nil || *from != f.hq || !pending || site != f.branch {
		t.Errorf("site move: from %v pending %v site %s", from, pending, site)
	}
	// Moved again before the node followed: it is still in HQ's group.
	f.admin.expect(http.StatusOK, "POST", "/api/v1/devices/move", move([]string{d}, f.main, nil), &res)
	if from, _, _ := mesh(); from == nil || *from != f.hq {
		t.Errorf("second move: from %v", from)
	}
	// Back to the site whose group holds the node: nothing to move.
	f.admin.expect(http.StatusOK, "POST", "/api/v1/devices/move", move([]string{d}, f.hq, nil), &res)
	if from, _, _ := mesh(); from != nil {
		t.Errorf("back home: from %v", from)
	}
	// A device without a node has nothing pending.
	n := f.device(t, "plain", f.acme, f.hq, nil)
	f.admin.expect(http.StatusOK, "POST", "/api/v1/devices/move", move([]string{n}, f.branch, nil), &res)
	if c := f.count(t, `SELECT count(*) FROM devices WHERE id = $1 AND mesh_from_site_id IS NULL AND NOT mesh_settings_pending`, n); c != 1 {
		t.Error("a device without a MeshCentral node has a pending move")
	}

	// Audit: one record per device and move; a move out of an organization is also in the old one's log.
	if c := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'device.move' AND device_id = $1`, d); c != 4 {
		t.Errorf("device.move records: %d", c)
	}
	if c := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'device.move_out' AND device_id = $1`, d); c != 2 {
		t.Errorf("device.move_out records: %d", c)
	}
	if c := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'device.move_out' AND device_id = $1 AND organization_id = $2`, d, f.acme); c != 1 {
		t.Error("the move out of Acme is not in Acme's log")
	}
}

// A device that leaves its organization leaves that organization's data
// behind (ADR-0069): queued runs are canceled, a run in progress refuses the
// move, remote sessions end, alerts go; job runs and audit records stay.
func TestMoveDeviceToAnotherOrganization(t *testing.T) {
	f := newMoveFixture(t)
	x := f.device(t, "x-01", f.acme, f.hq, nil)
	busy := f.device(t, "busy-01", f.acme, f.hq, nil)
	var script idObj
	f.admin.expect(http.StatusCreated, "POST", "/api/v1/scripts", map[string]any{"organizationId": f.acme, "name": "Up", "shell": "bash", "body": "true"}, &script)
	var queued, running idObj
	f.admin.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{"scriptId": script.ID, "deviceIds": []string{x}}, &queued)
	f.admin.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{"scriptId": script.ID, "deviceIds": []string{busy}}, &running)
	exec(t, f.h, `UPDATE job_runs SET status = 'running', started_at = now(), deadline_at = now() + interval '1 hour' WHERE device_id = $1`, busy)
	exec(t, f.h, `INSERT INTO remote_grants (launch_hash, session_id, user_id, device_id, organization_id, site_id, kind, launch_expires_at)
		SELECT sha256('g'::bytea), s.id, s.user_id, $1, $2, $3, 'desktop', now() + interval '1 minute' FROM sessions s LIMIT 1`, x, f.acme, f.hq)
	exec(t, f.h, `INSERT INTO device_metric_samples (device_id, at, cpu_percent, memory_percent, swap_percent, disk_percent, load1)
		SELECT $1, now() - make_interval(secs => g * 60 + 10), 5, 30, 0, 96, 0 FROM generate_series(0, 9) g`, x)
	if _, err := f.h.deps.Monitoring.Evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.count(t, `SELECT count(*) FROM alerts WHERE device_id = $1`, x) == 0 || f.count(t, `SELECT count(*) FROM remote_grants WHERE device_id = $1`, x) != 1 {
		t.Fatal("the fixture has no alerts or no remote session")
	}

	// A run in progress refuses the move, and the other device in the request stays.
	wantStatus(t, f.admin.do("POST", "/api/v1/devices/move", move([]string{x, busy}, f.main, nil)), http.StatusConflict, "device_busy")
	if p := f.where(t, f.admin, x); p.OrganizationID != f.acme {
		t.Fatalf("a refused move changed a device: %+v", p)
	}
	if f.count(t, `SELECT count(*) FROM job_runs WHERE device_id = $1 AND status = 'queued'`, x) != 1 {
		t.Fatal("a refused move canceled a run")
	}
	// Within the organization a running job does not matter.
	var res struct{ Moved, OtherOrganization, CanceledRuns int }
	f.admin.expect(http.StatusOK, "POST", "/api/v1/devices/move", move([]string{busy}, f.branch, nil), &res)
	if res.Moved != 1 || res.OtherOrganization != 0 {
		t.Fatalf("within the organization: %+v", res)
	}

	f.admin.expect(http.StatusOK, "POST", "/api/v1/devices/move", move([]string{x}, f.main, nil), &res)
	if res.Moved != 1 || res.OtherOrganization != 1 || res.CanceledRuns != 1 {
		t.Fatalf("result %+v", res)
	}
	if n := f.count(t, `SELECT count(*) FROM job_runs WHERE device_id = $1 AND status = 'canceled' AND organization_id = $2 AND site_id = $3`, x, f.acme, f.hq); n != 1 {
		t.Errorf("the canceled run did not keep its organization and site: %d", n)
	}
	if f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'job.cancel' AND target_id IN (SELECT id::text FROM job_runs WHERE device_id = $1) AND organization_id = $2`, x, f.acme) != 1 {
		t.Error("the canceled run is not audited in the old organization")
	}
	if f.count(t, `SELECT count(*) FROM remote_grants WHERE device_id = $1`, x) != 0 || f.count(t, `SELECT count(*) FROM alerts WHERE device_id = $1`, x) != 0 {
		t.Error("remote sessions or alerts stayed with the device")
	}
	// Acme's people keep the run's history; Globex's do not see it.
	acmeTech := f.user(t, "tess@acme.example", "technician", map[string]any{"organizationId": f.acme})
	globexTech := f.user(t, "gus@globex.example", "technician", map[string]any{"organizationId": f.globex})
	var runs struct{ Items []idObj }
	acmeTech.expect(http.StatusOK, "GET", "/api/v1/jobs", nil, &runs)
	if len(runs.Items) != 2 {
		t.Errorf("Acme's jobs: %d", len(runs.Items))
	}
	globexTech.expect(http.StatusOK, "GET", "/api/v1/jobs", nil, &runs)
	if len(runs.Items) != 0 {
		t.Errorf("Globex sees %d of Acme's jobs", len(runs.Items))
	}
	globexTech.expect(http.StatusOK, "GET", "/api/v1/devices", nil, &struct{ Items []idObj }{})
}

// Every table that holds a device's id, organization or site is accounted
// for: what a move does to it is written down here, and this test fails for a
// table added without a decision (ADR-0069).
func TestMoveDispositionOfEveryTable(t *testing.T) {
	f := newMoveFixture(t)
	type disposition string
	const (
		// the device's own row: it moves.
		moves disposition = "moves"
		// keyed by device_id alone, no organization or site of its own: the
		// rows are the machine's and follow it.
		follows disposition = "follows the device"
		// holds a copy of the organization and site as they were: stays with
		// the old organization.
		stays disposition = "stays with the old organization and site"
		// ends with the move to another organization.
		ends disposition = "ends with a move to another organization"
		// owned by an organization or site, not by a device: untouched.
		owned disposition = "owned by an organization or a site, untouched"
		// the patching engine's links: its reconcile follows the device.
		engine disposition = "follows through the engine's reconcile"
	)
	want := map[string]disposition{
		"devices": moves,
		// follows
		"agent_nonces": follows, "agent_updates": follows, "device_disk_health": follows, "device_disk_health_samples": follows,
		"device_hardening": follows, "device_hardening_checks": follows, "device_inventory": follows, "device_metric_samples": follows,
		"device_metrics": follows, "device_removals": follows, "device_software": follows, "enrollment_requests": follows,
		"retired_agent_nonces": follows,
		// recovery (R1-R3): the machine's own state and repair history
		"agent_conditions": follows, "agent_repairs": ends,
		// ends
		"remote_grants": ends, "alerts": ends,
		"agent_log_records": ends, "agent_log_days": ends, "agent_log_follow": ends,
		// a device's verbose setting ends with any move to another site; a
		// group's is owned by the group.
		"agent_log_verbose": ends,
		// stays
		"job_runs": stays, "audit_log": stays, "retired_devices": stays, "mail_sends": stays,
		// owned
		"alert_policies": owned, "windows_module_settings": owned, "contacts": owned, "device_groups": owned, "enrollment_tokens": owned, "mesh_sites": owned,
		"role_assignments": owned, "scripts": owned, "site_places": owned, "sites": owned, "easypatch_organizations": owned, "easypatch_sites": owned,
		// engine
		"easypatch_devices": engine, "easypatch_install_restarts": engine, "easypatch_installs": engine, "easypatch_opt_outs": engine,
		"easypatch_removals": engine,
	}
	var tables []string
	byTable := map[string][]string{}
	if err := f.h.db.DB.InTx(context.Background(), database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT table_name, column_name FROM information_schema.columns
			WHERE table_schema = 'public' AND column_name IN ('device_id', 'organization_id', 'site_id', 'device_group_id')
			  AND table_name IN (SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE')
			ORDER BY 1, 2`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tbl, col string
			if err := rows.Scan(&tbl, &col); err != nil {
				return err
			}
			byTable[tbl] = append(byTable[tbl], col)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	for tbl := range byTable {
		tables = append(tables, tbl)
	}
	sort.Strings(tables)
	for _, tbl := range tables {
		if _, ok := want[tbl]; !ok {
			t.Errorf("table %s (columns %v) has no decision for a device move; add it to this test and to ADR-0069's list", tbl, byTable[tbl])
		}
	}
	for tbl := range want {
		if _, ok := byTable[tbl]; !ok {
			t.Errorf("table %s is listed here but no longer holds a device, organization or site id", tbl)
		}
	}

	// One device with a row in every table that can be seeded without a long
	// story; the rest are checked by their schema and by their counts.
	d := f.device(t, "table-01", f.acme, f.hq, &f.servers)
	for _, tbl := range tables {
		cols := byTable[tbl]
		hasOrgOrSite := slices.Contains(cols, "organization_id") || slices.Contains(cols, "site_id")
		switch want[tbl] {
		case follows:
			t.Run(tbl, func(t *testing.T) {
				if hasOrgOrSite {
					t.Errorf("%s holds an organization or site of its own (%v); a device's move would leave it wrong", tbl, cols)
				}
				if !slices.Contains(cols, "device_id") {
					t.Errorf("%s is not keyed by device_id", tbl)
				}
			})
		case stays:
			t.Run(tbl, func(t *testing.T) {
				if !hasOrgOrSite {
					t.Errorf("%s keeps no organization or site, so nothing stays", tbl)
				}
			})
		}
	}

	counts := func() map[string]int {
		out := map[string]int{}
		for _, tbl := range tables {
			if want[tbl] == owned || want[tbl] == engine || want[tbl] == stays {
				out[tbl] = f.count(t, "SELECT count(*) FROM "+tbl)
			}
		}
		return out
	}
	before := counts()
	var res struct{ Moved int }
	f.admin.expect(http.StatusOK, "POST", "/api/v1/devices/move", move([]string{d}, f.main, &f.mainServers), &res)
	after := counts()
	for _, tbl := range tables {
		switch want[tbl] {
		case owned, engine:
			t.Run(tbl+" is untouched", func(t *testing.T) {
				if after[tbl] != before[tbl] {
					t.Errorf("%s had %d rows, has %d", tbl, before[tbl], after[tbl])
				}
			})
		case stays:
			if tbl == "audit_log" {
				continue // grows with the move's own records
			}
			t.Run(tbl+" stays", func(t *testing.T) {
				if after[tbl] != before[tbl] {
					t.Errorf("%s had %d rows, has %d", tbl, before[tbl], after[tbl])
				}
			})
		}
	}
	t.Run("devices moves", func(t *testing.T) {
		if p := f.where(t, f.admin, d); p.OrganizationID != f.globex || p.SiteID != f.main {
			t.Errorf("%+v", p)
		}
	})
	t.Run("audit_log keeps its records", func(t *testing.T) {
		if n := f.count(t, `SELECT count(*) FROM audit_log WHERE action = 'device.move_out' AND organization_id = $1 AND site_id = $2`, f.acme, f.hq); n != 1 {
			t.Errorf("the old site's log has %d move-out records", n)
		}
	})
}
