//go:build integration

package monitoring

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

const (
	remoteDown  = "Remote access down"
	agentSilent = "EasyRMM agent silent"
)

// meshFixture gives the fixture's service a MeshCentral link and a device
// group for the HQ site, and turns every other policy off. The clock is at
// 0 when the link opened a day ago.
type meshFixture struct {
	*fixture
	start     time.Time
	connected bool
	since     time.Time
}

func newMeshFixture(t *testing.T) *meshFixture {
	t.Helper()
	m := &meshFixture{fixture: newFixture(t), start: time.Now(), connected: true}
	m.since = m.start.Add(-24 * time.Hour)
	m.svc.FollowMesh(func() (bool, time.Time) { return m.connected, m.since })
	m.exec(`UPDATE alert_policies SET enabled = false WHERE kind NOT IN ('remote_down', 'agent_silent')`)
	m.exec(`INSERT INTO mesh_sites (site_id, organization_id, mesh_id, synced_name) VALUES ($1, $2, 'mesh//g1', 'HQ')`, m.hq, m.acme)
	return m
}

func (m *meshFixture) at(d time.Duration) Result {
	m.t.Helper()
	m.svc.now = func() time.Time { return m.start.Add(d) }
	return m.evaluate()
}

// connect sets MeshCentral's view of a device as it was ago ago.
func (m *meshFixture) connect(device uuid.UUID, online bool, ago time.Duration) {
	m.t.Helper()
	// Two statements: the trigger sets remote_changed_at when remote_online
	// changes, and the second keeps what the test says.
	m.exec(`UPDATE devices SET remote_online = $2 WHERE id = $1`, device, online)
	m.exec(`UPDATE devices SET remote_changed_at = $2 WHERE id = $1`, device, m.start.Add(-ago))
}

// seen sets when a device's agent last checked in.
func (m *meshFixture) seen(device uuid.UUID, ago time.Duration) {
	m.t.Helper()
	m.exec(`UPDATE devices SET agent_last_seen_at = $2 WHERE id = $1`, device, m.start.Add(-ago))
}

func TestRemoteAccessDownOpensAndResolves(t *testing.T) {
	m := newMeshFixture(t)
	d := m.device(m.acme, m.hq, "laptop", 0)
	m.exec(`UPDATE devices SET meshagent_state = '{"installed": true, "running": false}', meshagent_state_at = now() WHERE id = $1`, d)
	m.connect(d, false, 14*time.Minute)
	m.seen(d, 0)
	if r := m.at(0); r.Opened != 0 {
		t.Fatalf("14 minutes: %+v", r)
	}
	if r := m.at(time.Minute); r.Opened != 1 {
		t.Fatalf("15 minutes: %+v", r)
	}
	a := m.alertOn(d, remoteDown)
	if a == nil || a.Kind != KindRemoteDown || a.Severity != SeverityCritical || a.Minutes != 15 || a.Threshold != nil {
		t.Fatalf("alert = %+v", a)
	}
	if a.Detail != "MeshAgent is installed but not running. Not connected for 15 minutes." {
		t.Errorf("detail = %q", a.Detail)
	}
	// Still down later: one alert, its detail follows.
	m.seen(d, -20*time.Minute)
	if r := m.at(20 * time.Minute); r.Opened != 0 {
		t.Fatalf("later: %+v", r)
	}
	if a := m.alertOn(d, remoteDown); a == nil || a.LastValue < 34 || a.Value != 15 {
		t.Fatalf("alert later = %+v", a)
	}
	// MeshCentral sees it connected.
	m.connect(d, true, -30*time.Minute)
	if r := m.at(30 * time.Minute); r.Resolved != 1 {
		t.Fatalf("connected: %+v", r)
	}
	if m.alertOn(d, remoteDown) != nil || m.lastResolution(d) != "cleared" {
		t.Errorf("alert kept, resolution %q", m.lastResolution(d))
	}
}

func TestRemoteAccessDownNeedsTheAgentAndAGroup(t *testing.T) {
	m := newMeshFixture(t)
	silent := m.device(m.acme, m.hq, "silent", 60) // not checking in: offline's business
	m.seen(silent, time.Hour)
	m.connect(silent, false, time.Hour)
	noGroup := m.device(m.acme, m.branch, "branch-pc", 0) // the site has no MeshCentral group
	m.connect(noGroup, false, time.Hour)
	if r := m.at(0); r.Opened != 0 {
		t.Fatalf("%+v", r)
	}
	if m.count(`SELECT count(*) FROM alerts`) != 0 {
		t.Error("alerts opened")
	}
}

func TestRemoteAccessDownWaitsForMeshCentral(t *testing.T) {
	m := newMeshFixture(t)
	d := m.device(m.acme, m.hq, "laptop", 0)
	m.connect(d, false, time.Hour)

	// EasyRMM cannot see MeshCentral: nothing is judged.
	m.connected = false
	if r := m.at(0); r.Opened != 0 {
		t.Fatalf("while down: %+v", r)
	}
	// It returns: still nothing for 15 minutes.
	m.connected, m.since = true, m.start
	if r := m.at(14 * time.Minute); r.Opened != 0 {
		t.Fatalf("14 minutes after it returned: %+v", r)
	}
	m.seen(d, -14*time.Minute)
	if r := m.at(15 * time.Minute); r.Opened != 1 {
		t.Fatalf("15 minutes after it returned: %+v", r)
	}
	// An open alert is neither resolved nor changed while it is down again.
	m.connect(d, true, -16*time.Minute)
	m.connected = false
	if r := m.at(16 * time.Minute); r.Resolved != 0 || m.alertOn(d, remoteDown) == nil {
		t.Fatalf("while down again: %+v", r)
	}
}

func TestRemoteAccessAlertsNeverForADeviceThatIsLeaving(t *testing.T) {
	cases := map[string]string{
		"removal":   `INSERT INTO device_removals (device_id, id) VALUES ($1, gen_random_uuid())`,
		"opted out": `INSERT INTO easypatch_opt_outs (device_id) VALUES ($1)`,
		"easypatch": `INSERT INTO easypatch_removals (endpoint_id, device_id, reason) VALUES (gen_random_uuid(), $1, 'deleted')`,
	}
	for name, leave := range cases {
		t.Run(name, func(t *testing.T) {
			m := newMeshFixture(t)
			d := m.device(m.acme, m.hq, "leaving", 0)
			m.connect(d, false, time.Hour)
			m.exec(leave, d)
			if r := m.at(0); r.Opened != 0 {
				t.Fatalf("opened for a device that leaves: %+v", r)
			}
		})
	}
	// An alert that is open when the device starts to leave is closed, even
	// while MeshCentral is out of sight.
	m := newMeshFixture(t)
	d := m.device(m.acme, m.hq, "laptop", 0)
	m.connect(d, false, time.Hour)
	if r := m.at(0); r.Opened != 1 {
		t.Fatalf("%+v", r)
	}
	m.exec(`INSERT INTO device_removals (device_id, id) VALUES ($1, gen_random_uuid())`, d)
	m.connected = false
	if r := m.at(time.Minute); r.Resolved != 1 || m.lastResolution(d) != "not_covered" {
		t.Fatalf("%+v, resolution %q", r, m.lastResolution(d))
	}
}

func TestAgentSilentOpensAndResolves(t *testing.T) {
	m := newMeshFixture(t)
	d := m.device(m.acme, m.hq, "server", 14)
	m.seen(d, 14*time.Minute)
	m.connect(d, true, 2*time.Hour)
	if r := m.at(0); r.Opened != 0 {
		t.Fatalf("14 minutes: %+v", r)
	}
	if r := m.at(time.Minute); r.Opened != 1 {
		t.Fatalf("15 minutes: %+v", r)
	}
	a := m.alertOn(d, agentSilent)
	if a == nil || a.Kind != KindAgentSilent || a.Detail != "The EasyRMM agent last checked in 15 minutes ago; MeshCentral sees MeshAgent connected." {
		t.Fatalf("alert = %+v", a)
	}
	// MeshAgent dropping does not resolve it: only the agent checking in does.
	m.connect(d, false, -10*time.Minute)
	if r := m.at(20 * time.Minute); r.Resolved != 0 || m.alertOn(d, agentSilent) == nil {
		t.Fatalf("%+v", r)
	}
	m.seen(d, -20*time.Minute)
	if r := m.at(20 * time.Minute); r.Resolved != 1 || m.lastResolution(d) != "cleared" {
		t.Fatalf("checked in: %+v, resolution %q", r, m.lastResolution(d))
	}
}

func TestAgentSilentWaitsAfterTheServerStarts(t *testing.T) {
	m := newMeshFixture(t)
	d := m.device(m.acme, m.hq, "server", 600)
	m.seen(d, 600*time.Minute)
	m.connect(d, true, 2*time.Hour)
	// The server began serving agents just now: its devices have had no
	// chance to check in.
	m.svc.FollowServing(func() (time.Time, bool) { return m.start, true })
	if r := m.at(AgentGrace + 14*time.Minute); r.Opened != 0 {
		t.Fatalf("before the grace and the minutes: %+v", r)
	}
	if r := m.at(AgentGrace + 15*time.Minute); r.Opened != 1 {
		t.Fatalf("after: %+v", r)
	}
}

func TestRemoteAccessPoliciesCanBeTurnedOffAndChanged(t *testing.T) {
	m := newMeshFixture(t)
	d := m.device(m.acme, m.hq, "laptop", 0)
	m.connect(d, false, 10*time.Minute)
	m.exec(`UPDATE alert_policies SET minutes = 5 WHERE kind = 'remote_down'`)
	if r := m.at(0); r.Opened != 1 {
		t.Fatalf("with 5 minutes: %+v", r)
	}
	m.exec(`UPDATE alert_policies SET enabled = false WHERE kind = 'remote_down'`)
	if r := m.at(time.Minute); r.Resolved != 1 || m.lastResolution(d) != "policy_off" {
		t.Fatalf("turned off: %+v, resolution %q", r, m.lastResolution(d))
	}
	list, err := m.svc.ListPolicies(m.ctx, m.super, PolicyQuery{})
	if err != nil {
		t.Fatal(err)
	}
	var p *Policy
	for _, x := range list {
		if x.Kind == KindRemoteDown {
			p = x
		}
	}
	if p == nil || p.Level != LevelShared {
		t.Fatalf("policy = %+v", p)
	}
	// A policy of its own for an organization, with its minutes checked.
	in := PolicyInput{Name: "Remote access (Acme)", Kind: KindAgentSilent, Minutes: 2, Severity: SeverityWarning, OrganizationID: &m.acme}
	if _, err := m.svc.CreatePolicy(m.ctx, m.super, in); err == nil {
		t.Error("2 minutes accepted")
	}
	in.Minutes = 30
	if q, err := m.svc.CreatePolicy(m.ctx, m.super, in); err != nil || q.Kind != KindAgentSilent || q.Threshold != nil {
		t.Errorf("policy = %+v, %v", q, err)
	}
}

func TestRemoteAccessAlertsEndWithoutRemoteAccess(t *testing.T) {
	m := newMeshFixture(t)
	d := m.device(m.acme, m.hq, "laptop", 0)
	m.connect(d, false, time.Hour)
	if r := m.at(0); r.Opened != 1 {
		t.Fatalf("%+v", r)
	}
	m.svc.mesh = nil
	if r := m.at(time.Minute); r.Resolved != 1 || m.lastResolution(d) != "not_covered" {
		t.Fatalf("%+v, resolution %q", r, m.lastResolution(d))
	}
}

func TestAlertCardShowsTheRepairsSinceItOpened(t *testing.T) {
	m := newMeshFixture(t)
	d := m.device(m.acme, m.hq, "laptop", 0)
	m.connect(d, false, time.Hour)
	// One repair before the alert, one after.
	steps := `'[{"id":"a.0","step":"restart","state":"done"},{"id":"a.1","step":"repair","state":"failed","error":"boom"}]'`
	m.exec(`INSERT INTO agent_repairs (device_id, target, carried_by, trigger, state, steps, step, wait_seconds, started_at, ended_at)
		VALUES ($1, 'meshagent', 'easyrmm-agent', 'manual', 'failed', `+steps+`, 1, 120, $2, $2)`, d, m.start.Add(-time.Hour))
	if r := m.at(0); r.Opened != 1 {
		t.Fatalf("%+v", r)
	}
	m.exec(`INSERT INTO agent_repairs (device_id, target, carried_by, trigger, state, steps, step, wait_seconds, started_at, ended_at, error)
		VALUES ($1, 'meshagent', 'easyrmm-agent', 'manual', 'failed', `+steps+`, 1, 120, $2, $2, 'x')`, d, m.start.Add(time.Minute))
	a := m.alertOn(d, remoteDown)
	got, err := m.svc.GetAlert(m.ctx, m.super, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Repairs) != 1 || got.Repairs[0].Target != "meshagent" || len(got.Repairs[0].Steps) != 2 ||
		got.Repairs[0].Steps[1].Error != "boom" || got.Repairs[0].Error != "x" {
		t.Errorf("repairs = %+v", got.Repairs)
	}
	// The list leaves them out.
	if l := m.alerts(FilterAll); len(l) != 1 || len(l[0].Repairs) != 0 {
		t.Errorf("list = %+v", l)
	}
}

// remote_changed_at moves when MeshCentral's view of a device changes, and
// only then (the device sync and a heartbeat's link both write the column
// remote_online).
func TestRemoteChangedAtFollowsRemoteOnline(t *testing.T) {
	m := newMeshFixture(t)
	d := m.device(m.acme, m.hq, "laptop", 0)
	read := func() time.Time {
		t.Helper()
		var at *time.Time
		if err := m.db.ReadTx(m.ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(m.ctx, `SELECT remote_changed_at FROM devices WHERE id = $1`, d).Scan(&at)
		}); err != nil {
			t.Fatal(err)
		}
		if at == nil {
			return time.Time{}
		}
		return *at
	}
	if !read().IsZero() {
		t.Fatal("set before anything changed")
	}
	m.exec(`UPDATE devices SET remote_online = false, mesh_node_id = 'node//x', name = 'renamed' WHERE id = $1`, d)
	if !read().IsZero() {
		t.Error("moved without a change of remote_online")
	}
	m.exec(`UPDATE devices SET remote_online = true WHERE id = $1`, d)
	first := read()
	if first.IsZero() || time.Since(first) > time.Minute {
		t.Fatalf("not set when it went online: %v", first)
	}
	time.Sleep(20 * time.Millisecond)
	m.exec(`UPDATE devices SET remote_online = true, mesh_agent_type = 6 WHERE id = $1`, d)
	if !read().Equal(first) {
		t.Error("moved without a change")
	}
	m.exec(`UPDATE devices SET remote_online = false WHERE id = $1`, d)
	if !read().After(first) {
		t.Error("not moved when it went offline")
	}
}
