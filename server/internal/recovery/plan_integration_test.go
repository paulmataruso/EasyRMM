//go:build integration

package recovery

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

// The one Repair button, row by row (ADR-0069, amended 2026-11-26): the plan
// is chosen from the database, the repairs it names are ordinary repairs,
// and the plan is audited with the repairs it started.

// planned is a patched fixture whose site has a MeshCentral group.
func newPlanned(t *testing.T) *patched {
	p := newPatched(t)
	p.exec(`INSERT INTO mesh_sites (site_id, organization_id, mesh_id, synced_name) VALUES ($1, $2, 'mesh-1234567890', 'HQ')`, p.hq, p.acme)
	return p
}

// state puts a linked device in a state: whether the EasyRMM agent checks in,
// MeshCentral sees MeshAgent, and the engine hears the EasyPatch agent.
func (p *patched) state(name string, rmm, mesh, patch bool) uuid.UUID {
	p.t.Helper()
	seen := p.start
	if !patch {
		seen = p.start.Add(-time.Hour)
	}
	d := p.linkedDevice(name, seen)
	p.seenAt(d, seen)
	p.connect(d, mesh, p.start.Add(-time.Hour))
	if !rmm {
		p.exec(`UPDATE devices SET agent_last_seen_at = $2, agent_sha256 = $3 WHERE id = $1`, d, p.start.Add(-time.Hour), recoveryHash)
	}
	return d
}

func (p *patched) press(d uuid.UUID) (*Outcome, error) {
	return p.svc.RepairDevice(p.ctx, p.tech, d)
}

func targets(o *Outcome) map[string]string {
	m := map[string]string{}
	for _, r := range o.Repairs {
		m[r.Target] = r.CarriedBy
	}
	return m
}

func sameTargets(t *testing.T, o *Outcome, want map[string]string) {
	t.Helper()
	got := targets(o)
	if len(got) != len(want) {
		t.Fatalf("repairs = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("repairs = %v, want %v", got, want)
		}
	}
}

func TestRepairWithOnlyMeshAgentDownHasTheEasyRMMAgentRepairIt(t *testing.T) {
	p := newPlanned(t)
	d := p.state("pc", true, false, true)
	o, err := p.press(d)
	if err != nil {
		t.Fatal(err)
	}
	sameTargets(t, o, map[string]string{"meshagent": "easyrmm-agent"})
	// The instruction is the signed one, through the heartbeat, as always.
	if i := p.beat(d, nil); i == nil || i.Target != "meshagent" || i.Step != "restart" {
		t.Errorf("instruction = %+v", i)
	}
}

func TestRepairWithOnlyThePatchingAgentDownHasTheEasyRMMAgentRepairIt(t *testing.T) {
	p := newPlanned(t)
	d := p.state("pc", true, true, false)
	o, err := p.press(d)
	if err != nil {
		t.Fatal(err)
	}
	sameTargets(t, o, map[string]string{"easypatch-agent": "easyrmm-agent"})
}

func TestRepairWithMeshAgentAndThePatchingAgentDownStartsBothThroughTheEasyRMMAgent(t *testing.T) {
	p := newPlanned(t)
	d := p.state("pc", true, false, false)
	o, err := p.press(d)
	if err != nil {
		t.Fatal(err)
	}
	sameTargets(t, o, map[string]string{"meshagent": "easyrmm-agent", "easypatch-agent": "easyrmm-agent"})
	if p.count(`SELECT count(*) FROM agent_repairs WHERE device_id = $1 AND state = 'running' AND trigger = 'manual'`, d) != 2 {
		t.Error("two repairs are not recorded")
	}
}

func TestRepairWithTheEasyRMMAgentDownHasTheRunningPatchingAgentRepairIt(t *testing.T) {
	p := newPlanned(t)
	d := p.state("pc", false, true, true)
	o, err := p.press(d)
	if err != nil {
		t.Fatal(err)
	}
	sameTargets(t, o, map[string]string{"easyrmm-agent": "easypatch-agent"})
	if len(o.Plan.Later) != 0 {
		t.Errorf("later = %v", o.Plan.Later)
	}
	// The repair is the one through patching: the job is the engine's, and the hash is one the server publishes.
	p.dispatch()
	if len(p.companionJobs()) != 1 {
		t.Errorf("engine jobs = %d", len(p.companionJobs()))
	}
}

func TestRepairWithTheEasyRMMAgentAndMeshAgentDownRepairsTheEasyRMMAgentFirstAndSaysWhatWaits(t *testing.T) {
	p := newPlanned(t)
	d := p.state("pc", false, false, true)
	o, err := p.press(d)
	if err != nil {
		t.Fatal(err)
	}
	sameTargets(t, o, map[string]string{"easyrmm-agent": "easypatch-agent"})
	if len(o.Plan.Later) != 1 || o.Plan.Later[0] != agentproto.TargetMeshAgent || !strings.Contains(o.Plan.Summary, "press Repair again") {
		t.Errorf("plan = %+v", o.Plan)
	}
	if p.count(`SELECT count(*) FROM agent_repairs WHERE device_id = $1 AND target = 'meshagent'`, d) != 0 {
		t.Error("MeshAgent was repaired before the EasyRMM agent is back")
	}
}

func TestRepairWithNoRunningAgentThatCanRepairRefusesAndStartsNothing(t *testing.T) {
	for name, s := range map[string][3]bool{
		"the EasyRMM and patching agents down, MeshAgent up": {false, true, false},
		"all three down": {false, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPlanned(t)
			d := p.state("pc", s[0], s[1], s[2])
			if _, err := p.press(d); code(err) != RefuseNoRunning {
				t.Fatalf("error = %v", err)
			}
			if p.count(`SELECT count(*) FROM agent_repairs`) != 0 || p.count(`SELECT count(*) FROM audit_log WHERE action = 'device.repair_plan'`) != 0 {
				t.Error("a refused press left a repair or an audit row")
			}
			pl, err := p.svc.Plan(p.ctx, p.tech, d)
			if err != nil || pl.Refusal != RefuseNoRunning || !strings.Contains(pl.Summary, "Reinstall the EasyRMM agent") {
				t.Errorf("plan = %+v, %v", pl, err)
			}
		})
	}
}

func TestRepairWithNothingDownRefuses(t *testing.T) {
	p := newPlanned(t)
	d := p.state("pc", true, true, true)
	if _, err := p.press(d); code(err) != RefuseNothingDown {
		t.Fatalf("error = %v", err)
	}
}

func TestRepairLeavesWhatAlreadyRunsAloneAndRefusesWhenThatIsAll(t *testing.T) {
	p := newPlanned(t)
	d := p.state("pc", true, false, false)
	if _, err := p.svc.Request(p.ctx, p.tech, d, agentproto.TargetMeshAgent); err != nil {
		t.Fatal(err)
	}
	o, err := p.press(d)
	if err != nil {
		t.Fatal(err)
	}
	sameTargets(t, o, map[string]string{"easypatch-agent": "easyrmm-agent"})
	if len(o.Plan.Running) != 1 || !strings.Contains(o.Plan.Summary, "MeshAgent is being repaired already") {
		t.Errorf("plan = %+v", o.Plan)
	}
	if _, err := p.press(d); code(err) != RefuseRunning {
		t.Errorf("second press: %v", err)
	}
}

func TestRepairRefusesADeviceThatIsLeaving(t *testing.T) {
	p := newPlanned(t)
	d := p.state("pc", true, false, true)
	p.exec(`INSERT INTO device_removals (device_id, id) VALUES ($1, gen_random_uuid())`, d)
	if _, err := p.press(d); code(err) != RefuseLeaving {
		t.Fatalf("error = %v", err)
	}
}

func TestRepairNeedsTheSamePermissionsAsTheRepairsItStarts(t *testing.T) {
	p := newPlanned(t)
	d := p.state("pc", true, false, true)
	if _, err := p.svc.RepairDevice(p.ctx, p.reader, d); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only user: %v", err)
	}
	if _, err := p.svc.Plan(p.ctx, p.reader, d); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only user, plan: %v", err)
	}
	if _, err := p.svc.RepairDevice(p.ctx, p.stranger, d); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization's administrator: %v", err)
	}
	if p.count(`SELECT count(*) FROM agent_repairs`) != 0 {
		t.Error("a refused press left a repair")
	}
}

func TestRepairAuditsThePlanWithTheRepairsItStarted(t *testing.T) {
	p := newPlanned(t)
	d := p.state("pc", false, false, true)
	o, err := p.press(d)
	if err != nil {
		t.Fatal(err)
	}
	if p.count(`SELECT count(*) FROM audit_log WHERE action = 'device.repair_plan' AND device_id = $1
		AND details->>'plan' = $2 AND details->'repairs' ? $3 AND details->'later' ? 'meshagent'`, d, o.ID.String(), o.Repairs[0].ID.String()) != 1 {
		t.Error("the plan was not audited with its repairs")
	}
	if p.count(`SELECT count(*) FROM audit_log WHERE action = 'device.repair_request' AND device_id = $1`, d) != 1 {
		t.Error("the repair itself was not audited")
	}
}

// Automatic repairs read the same table: a target the plan does not name is
// not repaired, whatever its clock says.
func TestAutomaticRepairFollowsTheTable(t *testing.T) {
	f := newFixture(t)
	d := f.meshDevice("pc")
	// Without a way to sign instructions the table names nothing the EasyRMM agent can carry.
	key := f.svc.key
	f.svc.key = nil
	f.eval(0)
	f.eval(11 * time.Minute)
	if f.autos(d, "meshagent") != 0 {
		t.Fatal("an automatic repair started that the table does not name")
	}
	f.svc.key = key
	f.eval(12 * time.Minute)
	if f.autos(d, "meshagent") != 1 {
		t.Error("the automatic repair did not start once the table names it")
	}
}
