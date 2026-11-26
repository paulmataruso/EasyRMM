//go:build integration

package recovery

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// meshDevice is a device whose EasyRMM agent supervises MeshAgent and
// checks in, and whose site has a MeshCentral group; MeshCentral does not
// see MeshAgent connected.
func (f *fixture) meshDevice(name string) uuid.UUID {
	f.t.Helper()
	d := f.device(name)
	f.exec(`INSERT INTO mesh_sites (site_id, organization_id, mesh_id, synced_name) VALUES ($1, $2, 'mesh-1234567890', 'HQ') ON CONFLICT DO NOTHING`, f.hq, f.acme)
	f.exec(`UPDATE devices SET meshagent_state = '{"installed":true,"running":true}'::jsonb, meshagent_state_at = now(), remote_online = false WHERE id = $1`, d)
	return d
}

// eval judges the conditions d after the start, with every agent having
// checked in just now.
func (f *fixture) eval(d time.Duration) {
	f.t.Helper()
	f.svc.now = func() time.Time { return f.start.Add(d) }
	f.exec(`UPDATE devices SET agent_last_seen_at = $1 WHERE agent_public_key IS NOT NULL`, f.start.Add(d))
	if err := f.svc.Evaluate(f.ctx); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) autos(device uuid.UUID, target string) int {
	return f.count(`SELECT count(*) FROM agent_repairs WHERE device_id = $1 AND target = $2 AND trigger = 'automatic'`, device, target)
}

func (f *fixture) alerts(device uuid.UUID, status string) int {
	return f.count(`SELECT count(*) FROM alerts WHERE device_id = $1 AND kind = 'repair_failed' AND status = $2`, device, status)
}

// The condition must have held for ten minutes, as the server saw it.
func TestAMeshAgentThatStaysDownIsRepairedAfterTenMinutes(t *testing.T) {
	f := newFixture(t)
	d := f.meshDevice("pc")
	f.eval(0)
	f.eval(9*time.Minute + 59*time.Second)
	if f.autos(d, "meshagent") != 0 {
		t.Fatal("repaired before the condition held for ten minutes")
	}
	f.eval(10 * time.Minute)
	if f.autos(d, "meshagent") != 1 {
		t.Fatal("not repaired after ten minutes")
	}
	r := f.latest(d)
	if r.Trigger != TriggerAutomatic || r.Target != "meshagent" || r.State != Running || len(r.Steps) != 2 {
		t.Errorf("repair = %+v", r)
	}
	if f.count(`SELECT wait_seconds FROM agent_repairs WHERE id = $1`, r.ID) != 20*60 {
		t.Error("the wait between steps is not 20 minutes")
	}
	if f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.repair_auto' AND device_id = $1`, d) != 1 {
		t.Error("the start was not audited")
	}
	// One at a time.
	f.eval(11 * time.Minute)
	if f.autos(d, "meshagent") != 1 {
		t.Error("a second repair started beside the first")
	}
}

// An attempt that ends with the target still broken raises one warning with
// the last step's diagnostics, and the limits keep the next one away for 6
// hours.
func TestAFailedAttemptRaisesOneWarningAndTheNextWaitsSixHours(t *testing.T) {
	f := newFixture(t)
	d := f.meshDevice("pc")
	f.eval(0)
	f.eval(10 * time.Minute)
	f.svc.now = func() time.Time { return f.start.Add(10 * time.Minute) }
	q := f.beat(d, nil)
	if q == nil || q.Step != "restart" {
		t.Fatalf("first step = %+v", q)
	}
	f.beat(d, &agentproto.RepairReport{ID: q.ID, OK: true})
	// The wait is 20 minutes; the target is not back.
	f.advance(10*time.Minute + AutoWaitMesh - time.Second)
	if f.latest(d).Steps[1].State != StepPending || f.latest(d).State != Running {
		t.Fatalf("moved on before the wait was over: %+v", f.latest(d))
	}
	f.advance(10*time.Minute + AutoWaitMesh)
	q = f.beat(d, nil)
	if q == nil || q.Step != "repair" {
		t.Fatalf("second step = %+v", q)
	}
	if f.alerts(d, "open") != 0 {
		t.Fatal("an alert before the attempt ended")
	}
	f.beat(d, &agentproto.RepairReport{ID: q.ID, OK: false, Error: "MeshAgent's download did not match its hash"})
	r := f.latest(d)
	if r.State != Failed {
		t.Fatalf("repair = %+v", r)
	}
	var severity, detail, name string
	f.row(`SELECT severity, detail, name FROM alerts WHERE device_id = $1 AND kind = 'repair_failed'`, []any{d}, &severity, &detail, &name)
	if severity != "warning" || name != "Repair failed" || !strings.Contains(detail, "did not match its hash") || !strings.Contains(detail, "MeshAgent") {
		t.Errorf("alert = %q %q %q", severity, name, detail)
	}
	// Inside 6 hours of the attempt's start: no other attempt, though the
	// condition holds.
	f.eval(5*time.Hour + 59*time.Minute)
	if f.autos(d, "meshagent") != 1 || f.alerts(d, "open") != 1 {
		t.Errorf("attempts %d, alerts %d", f.autos(d, "meshagent"), f.alerts(d, "open"))
	}
	f.eval(6*time.Hour + 10*time.Minute)
	if f.autos(d, "meshagent") != 2 {
		t.Fatalf("no second attempt after 6 hours: %d", f.autos(d, "meshagent"))
	}
	// It fails too: still one alert, with the newest detail.
	f.svc.now = func() time.Time { return f.start.Add(6*time.Hour + 10*time.Minute) }
	q = f.beat(d, nil)
	f.beat(d, &agentproto.RepairReport{ID: q.ID, OK: false, Error: "service control refused"})
	f.advance(6*time.Hour + 10*time.Minute)
	q = f.beat(d, nil)
	f.beat(d, &agentproto.RepairReport{ID: q.ID, OK: false, Error: "disk full"})
	if f.alerts(d, "open") != 1 {
		t.Errorf("%d alerts after the second failed attempt, want 1", f.alerts(d, "open"))
	}
	f.row(`SELECT detail FROM alerts WHERE device_id = $1 AND kind = 'repair_failed'`, []any{d}, &detail)
	if !strings.Contains(detail, "disk full") {
		t.Errorf("detail = %q", detail)
	}
	// MeshAgent comes back by itself: the alert goes.
	f.exec(`UPDATE devices SET remote_online = true WHERE id = $1`, d)
	f.eval(7 * time.Hour)
	if f.alerts(d, "open") != 0 || f.alerts(d, "resolved") != 1 {
		t.Errorf("open %d, resolved %d", f.alerts(d, "open"), f.alerts(d, "resolved"))
	}
	if f.count(`SELECT count(*) FROM agent_conditions WHERE device_id = $1`, d) != 0 {
		t.Error("the condition's clock was kept after it cleared")
	}
}

func (f *fixture) row(sql string, args []any, dest ...any) {
	f.t.Helper()
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(dest...) }); err != nil {
		f.t.Fatal(err)
	}
}

// At most three attempts in a day, whatever their spacing.
func TestAtMostThreeAttemptsADay(t *testing.T) {
	f := newFixture(t)
	d := f.meshDevice("pc")
	for _, ago := range []string{"7 hours", "13 hours", "19 hours"} {
		f.exec(`INSERT INTO agent_repairs (device_id, target, carried_by, trigger, state, steps, wait_seconds, started_at, ended_at)
			VALUES ($1, 'meshagent', 'easyrmm-agent', 'automatic', 'failed', '[{"id":"x","step":"restart","state":"failed"}]', 1200,
				$2::timestamptz - $3::interval, $2::timestamptz - $3::interval + interval '1 hour')`, d, f.start, ago)
	}
	f.eval(0)
	f.eval(10 * time.Minute)
	if f.autos(d, "meshagent") != 3 {
		t.Fatalf("a fourth attempt in a day: %d", f.autos(d, "meshagent"))
	}
	// The oldest is a day old by now.
	f.eval(5*time.Hour + 10*time.Minute) // 19h + 5h10 > 24h
	if f.autos(d, "meshagent") != 4 {
		t.Errorf("no attempt once one fell out of the day: %d", f.autos(d, "meshagent"))
	}
}

func TestNoAutomaticRepairWhereNothingIsMeantToHappen(t *testing.T) {
	cases := map[string]func(f *fixture, d uuid.UUID){
		"automatic repairs are off": func(f *fixture, d uuid.UUID) {
			f.exec(`UPDATE organizations SET auto_repair = false WHERE id = $1`, f.acme)
		},
		"a device that is being removed": func(f *fixture, d uuid.UUID) {
			f.exec(`INSERT INTO device_removals (device_id, id) VALUES ($1, gen_random_uuid())`, d)
		},
		"a device that is opted out": func(f *fixture, d uuid.UUID) { f.exec(`INSERT INTO easypatch_opt_outs (device_id) VALUES ($1)`, d) },
		"an EasyPatch agent being removed": func(f *fixture, d uuid.UUID) {
			f.exec(`INSERT INTO easypatch_removals (endpoint_id, device_id, reason) VALUES (gen_random_uuid(), $1, 'deleted')`, d)
		},
		"an agent that does not supervise MeshAgent": func(f *fixture, d uuid.UUID) {
			f.exec(`UPDATE devices SET meshagent_state = NULL, meshagent_state_at = NULL WHERE id = $1`, d)
		},
		"a site without a MeshCentral group": func(f *fixture, d uuid.UUID) { f.exec(`DELETE FROM mesh_sites`) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			d := f.meshDevice("pc")
			change(f, d)
			f.eval(0)
			f.eval(time.Hour)
			if n := f.count(`SELECT count(*) FROM agent_repairs`); n != 0 {
				t.Errorf("%d repairs", n)
			}
		})
	}
}

// Turning automatic repairs off stops one that runs, without an alert.
func TestTurningAutomaticRepairsOffStopsARunningOne(t *testing.T) {
	f := newFixture(t)
	d := f.meshDevice("pc")
	f.eval(0)
	f.eval(10 * time.Minute)
	f.exec(`UPDATE organizations SET auto_repair = false WHERE id = $1`, f.acme)
	f.advance(11 * time.Minute)
	if r := f.latest(d); r.State != Failed || !strings.Contains(r.Error, "turned off") {
		t.Errorf("repair = %+v", r)
	}
	if f.alerts(d, "open") != 0 {
		t.Error("an alert for a repair that stopped on purpose")
	}
	// A repair by hand stays available.
	if _, err := f.request(f.tech, d); err != nil {
		t.Errorf("by hand: %v", err)
	}
}

// A device that starts to leave takes its alert and its repair with it.
func TestADeviceThatLeavesLosesItsRepairFailedAlert(t *testing.T) {
	f := newFixture(t)
	d := f.meshDevice("pc")
	f.exec(`INSERT INTO alerts (policy_id, device_id, name, kind, minutes, severity, subject, subject_label, detail, value, last_value)
		VALUES (NULL, $1, 'Repair failed', 'repair_failed', 0, 'warning', 'meshagent', 'MeshAgent', 'x', 0, 0)`, d)
	f.exec(`INSERT INTO device_removals (device_id, id) VALUES ($1, gen_random_uuid())`, d)
	f.eval(0)
	if f.alerts(d, "open") != 0 || f.alerts(d, "resolved") != 1 {
		t.Errorf("open %d, resolved %d", f.alerts(d, "open"), f.alerts(d, "resolved"))
	}
}

// Nothing is judged while EasyRMM cannot see MeshCentral, or for 15 minutes
// after it can: the clock of the condition starts over.
func TestMeshAgentConditionsAreNotJudgedWithoutMeshCentral(t *testing.T) {
	f := newFixture(t)
	d := f.meshDevice("pc")
	f.eval(0)
	if f.count(`SELECT count(*) FROM agent_conditions`) != 1 {
		t.Fatal("the condition was not noted")
	}
	f.connected = false
	f.eval(5 * time.Minute)
	f.eval(time.Hour)
	if f.autos(d, "meshagent") != 0 || f.count(`SELECT count(*) FROM agent_conditions`) != 0 {
		t.Errorf("judged without MeshCentral: %d repairs", f.autos(d, "meshagent"))
	}
	// It returns: the session counts from the start of the hour.
	f.connected = true
	var since time.Time
	f.svc.FollowMesh(func() (bool, time.Time) { return f.connected, since })
	since = f.start.Add(time.Hour)
	f.eval(time.Hour + 14*time.Minute)
	if f.count(`SELECT count(*) FROM agent_conditions`) != 0 {
		t.Error("judged 14 minutes after MeshCentral returned")
	}
	f.eval(time.Hour + 15*time.Minute)
	f.eval(time.Hour + 24*time.Minute)
	if f.autos(d, "meshagent") != 0 {
		t.Error("repaired before the condition held for 10 minutes since it could be judged")
	}
	f.eval(time.Hour + 25*time.Minute)
	if f.autos(d, "meshagent") != 1 {
		t.Errorf("repairs = %d", f.autos(d, "meshagent"))
	}
}

// tick has the engine polled and the conditions judged d after the start.
func (p *patched) tick(d time.Duration) {
	p.t.Helper()
	p.move(d)
	if err := p.patch.PollAgents(p.ctx); err != nil {
		p.t.Fatal(err)
	}
	p.eval(d)
}

func TestASilentEasyPatchAgentIsRepairedAfterThirtyMinutes(t *testing.T) {
	p := newPatched(t)
	d := p.linkedDevice("pc", p.start.Add(-time.Hour))
	// The engine answers for 15 minutes first; then the condition holds for
	// 30.
	for at := -15 * time.Minute; at < 30*time.Minute; at += 5 * time.Minute {
		p.tick(at)
	}
	if p.autos(d, "easypatch-agent") != 0 {
		t.Fatal("repaired before the condition held for 30 minutes")
	}
	// The condition was first judged at minute 0.
	p.tick(30 * time.Minute)
	p.tick(35 * time.Minute)
	if p.autos(d, "easypatch-agent") != 1 {
		t.Fatalf("not repaired: %d", p.autos(d, "easypatch-agent"))
	}
	r := p.latest(d)
	if r.Target != "easypatch-agent" || r.Trigger != TriggerAutomatic || r.CarriedBy != "easyrmm-agent" {
		t.Errorf("repair = %+v", r)
	}
	if p.count(`SELECT wait_seconds FROM agent_repairs WHERE id = $1`, r.ID) != 30*60 {
		t.Error("the wait is not 30 minutes")
	}
}

func TestEasyPatchAgentsAreNotJudgedWhileTheEngineIsDown(t *testing.T) {
	p := newPatched(t)
	d := p.linkedDevice("pc", p.start.Add(-time.Hour))
	for at := -15 * time.Minute; at <= 0; at += 5 * time.Minute {
		p.tick(at)
	}
	if p.count(`SELECT count(*) FROM agent_conditions WHERE device_id = $1`, d) != 1 {
		t.Fatal("the condition was not noted")
	}
	p.ep.Set(func() { p.ep.Down = true })
	for at := 5 * time.Minute; at <= 2*time.Hour; at += 5 * time.Minute {
		p.move(at)
		_ = p.patch.PollAgents(p.ctx) // fails
		p.eval(at)
	}
	if p.autos(d, "easypatch-agent") != 0 || p.count(`SELECT count(*) FROM agent_conditions`) != 0 {
		t.Errorf("judged while the engine was down: %d repairs", p.autos(d, "easypatch-agent"))
	}
	// It returns: nothing for 15 minutes, then the condition's 30.
	p.ep.Set(func() { p.ep.Down = false })
	base := 2*time.Hour + 5*time.Minute
	for at := base; at < base+45*time.Minute; at += 5 * time.Minute {
		p.tick(at)
	}
	if p.autos(d, "easypatch-agent") != 0 {
		t.Fatal("repaired within 45 minutes of the engine's return")
	}
	for at := base + 45*time.Minute; at <= base+50*time.Minute; at += 5 * time.Minute {
		p.tick(at)
	}
	if p.autos(d, "easypatch-agent") != 1 {
		t.Errorf("repairs = %d", p.autos(d, "easypatch-agent"))
	}
}

func TestNoEasyPatchRepairWhereTheAgentIsNotMeantToBe(t *testing.T) {
	cases := map[string]func(p *patched, d uuid.UUID){
		"patching is off for the organization": func(p *patched, d uuid.UUID) { p.exec(`DELETE FROM easypatch_organizations`) },
		"the device is opted out":              func(p *patched, d uuid.UUID) { p.exec(`INSERT INTO easypatch_opt_outs (device_id) VALUES ($1)`, d) },
		"the agent is not linked": func(p *patched, d uuid.UUID) {
			p.exec(`UPDATE easypatch_devices SET state = 'pending' WHERE device_id = $1`, d)
		},
		"the agent keeps checking in": func(p *patched, d uuid.UUID) {},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPatched(t)
			d := p.linkedDevice("pc", p.start.Add(-time.Hour))
			change(p, d)
			for at := -15 * time.Minute; at <= 2*time.Hour; at += 5 * time.Minute {
				if name == "the agent keeps checking in" {
					seen := p.start.Add(at)
					p.ep.Set(func() { p.endpoint.LastCheckIn = &seen })
				}
				p.tick(at)
			}
			if n := p.count(`SELECT count(*) FROM agent_repairs`); n != 0 {
				t.Errorf("%d repairs", n)
			}
		})
	}
}

// Without remote access or patching there is nothing to judge, and what was
// noted is forgotten.
func TestEvaluateWithoutRemoteAccessOrPatchingJudgesNothing(t *testing.T) {
	f := newFixture(t)
	d := f.meshDevice("pc")
	f.eval(0)
	if f.count(`SELECT count(*) FROM agent_conditions`) != 1 {
		t.Fatal("the condition was not noted")
	}
	f.svc.remote = false
	f.eval(time.Hour)
	if f.count(`SELECT count(*) FROM agent_conditions`) != 0 || f.autos(d, "meshagent") != 0 {
		t.Error("judged without remote access")
	}
	if _, err := f.svc.Request(f.ctx, f.tech, uuid.New(), agentproto.TargetMeshAgent); err == nil {
		t.Error("a repair of a device that does not exist")
	}
}

// While a dev scope is set, no automatic repair starts for a device outside
// it, though the same condition has held as long; a repair an administrator
// asks for still runs. Without a scope, both start (as the tests above show).
func TestDevScopePausesAutomaticRepairOutsideTheScope(t *testing.T) {
	f := newFixture(t)
	in := f.meshDevice("pc-in")
	other := f.id(`INSERT INTO organizations (name) VALUES ('Other') RETURNING id`)
	site := f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, other)
	f.exec(`INSERT INTO mesh_sites (site_id, organization_id, mesh_id, synced_name) VALUES ($1, $2, 'mesh-0987654321', 'HQ')`, site, other)
	key := make([]byte, 32)
	out := f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at,
			meshagent_state, meshagent_state_at, remote_online)
		VALUES ($1, $2, 'pc-out', 'pc-out', 'linux', $3, now() - interval '1 day', now(),
			'{"installed":true,"running":true}'::jsonb, now(), false) RETURNING id`, other, site, key)

	t.Cleanup(devscope.Set(f.acme))
	f.eval(0)
	f.eval(10 * time.Minute)
	if f.autos(in, "meshagent") != 1 {
		t.Error("the device in the scope was not repaired")
	}
	if f.autos(out, "meshagent") != 0 {
		t.Fatal("an automatic repair started outside the dev scope")
	}
	f.eval(7 * time.Hour)
	if f.autos(out, "meshagent") != 0 {
		t.Error("an automatic repair started outside the dev scope, later")
	}
	if _, err := f.svc.Request(f.ctx, f.user("tech@other.example", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: other}), out, agentproto.TargetMeshAgent); err != nil {
		t.Errorf("an administrator's repair outside the scope was refused: %v", err)
	}
}

// A recovery copy is checked against the builds of the device's own
// organization: outside the dev scope, only the stable builds count, and a
// signed build only when it was made from one of them.
func TestDevScopeRecoveryAcceptsTheHashesOfTheOrganizationsBuilds(t *testing.T) {
	f := newFixture(t)
	other := uuid.New()
	f.svc.SetBuilds(func(org uuid.UUID, platform, arch string) []string {
		if platform != "linux" || arch != "amd64" {
			return nil
		}
		if devscope.Allowed(org) {
			return []string{"newhash"}
		}
		return []string{"stablehash"}
	})
	t.Cleanup(devscope.Set(f.acme))
	arch := "amd64"
	for _, c := range []struct {
		org  uuid.UUID
		sha  string
		want bool
	}{
		{f.acme, "newhash", true}, {f.acme, "stablehash", false},
		{other, "stablehash", true}, {other, "newhash", false},
	} {
		var got bool
		if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
			got = f.svc.publishes(f.ctx, tx, c.org, "linux", &arch, c.sha)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("publishes(%v, %s) = %v, want %v", c.org == f.acme, c.sha, got, c.want)
		}
	}

	// A signed Windows build counts outside the scope only when it was made
	// from one of the stable builds.
	h := func(c string) string { return strings.Repeat(c, 64) }
	f.svc.SetBuilds(func(org uuid.UUID, platform, arch string) []string {
		if platform == "windows" && arch == "amd64" {
			if devscope.Allowed(org) {
				return []string{h("1")}
			}
			return []string{h("2")}
		}
		return nil
	})
	for i, c := range []struct{ sha, release string }{{h("a"), h("2")}, {h("b"), h("1")}} {
		f.exec(`INSERT INTO signed_agent_builds (id, arch, version, sha256, release_sha256, content, signer_subject, signer_issuer,
				thumbprint, not_before, not_after, timestamped)
			VALUES ($1, 'amd64', $2, $3, $4, 'x', 's', 'i', $5, now(), now(), false)`,
			uuid.New(), "v"+string(rune('1'+i)), c.sha, c.release, strings.Repeat("0", 40))
	}
	for _, c := range []struct {
		org  uuid.UUID
		sha  string
		want bool
	}{
		{other, h("a"), true}, {other, h("b"), false}, {other, h("c"), false},
		{f.acme, h("a"), true}, {f.acme, h("b"), true}, {f.acme, h("c"), false},
	} {
		var got bool
		if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
			got = f.svc.publishes(f.ctx, tx, c.org, "windows", &arch, c.sha)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("signed: publishes(inside=%v, %.1s) = %v, want %v", c.org == f.acme, c.sha, got, c.want)
		}
	}
}
