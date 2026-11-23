//go:build integration

package recovery

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// patched is the fixture with the patching engine behind it: a real
// EasyPatch service on eptest, Acme patched, and a device whose EasyPatch
// agent is linked to an endpoint.
type patched struct {
	*fixture
	ep       *eptest.Server
	patch    *easypatch.Service
	endpoint *eptest.Endpoint
	epOrg    uuid.UUID
	// at is the time the services judge by.
	at time.Time
}

func newPatched(t *testing.T) *patched {
	t.Helper()
	f := newFixture(t)
	p := &patched{fixture: f, at: f.start}
	key := bytes.Repeat([]byte{7}, 32)
	p.ep = eptest.NewEngine(t, key)
	signer, err := easypatch.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	client, err := easypatch.NewEngineClient(p.ep.URL(), signer, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	p.patch = easypatch.New(f.db, audit.New(f.db, nil), "1.0.0", f.svc.log)
	if err := p.patch.UseEngine(client); err != nil {
		t.Fatal(err)
	}
	p.patch.SetClock(func() time.Time { return p.at })
	f.svc.UsePatching(p.patch)
	p.epOrg = p.ep.Org("Acme Patch")
	f.exec(`INSERT INTO easypatch_organizations (organization_id, easypatch_id, easypatch_name) VALUES ($1, $2, 'Acme Patch')`, f.acme, p.epOrg)
	return p
}

// move sets the time every service judges by to d after the start.
func (p *patched) move(d time.Duration) {
	p.at = p.start.Add(d)
	p.svc.now = func() time.Time { return p.at }
}

// linkedDevice is a Linux device with the EasyPatch agent of the engine's
// current version, linked to an endpoint that last checked in at seen.
func (p *patched) linkedDevice(name string, seen time.Time) uuid.UUID {
	p.t.Helper()
	d := p.device(name)
	p.exec(`UPDATE devices SET agent_arch = 'amd64' WHERE id = $1`, d)
	p.endpoint = p.ep.AddEndpoint(p.epOrg, name, "", "FP-"+name)
	p.ep.Set(func() { p.endpoint.LastCheckIn = &seen })
	p.exec(`INSERT INTO easypatch_devices (device_id, endpoint_id, state, linked_at, easypatch_org_id) VALUES ($1, $2, 'linked', now(), $3)`, d, p.endpoint.ID, p.epOrg)
	p.exec(`INSERT INTO device_inventory (device_id, hash, data) VALUES ($1, repeat('a', 64), $2::jsonb)`, d,
		`{"easyPatch":{"version":"`+eptest.EngineVersion+`","status":"Active"}}`)
	return d
}

// settle has the engine answer polls for long enough that agents are
// judged, ending at the offset d from the start.
func (p *patched) settle(d time.Duration) {
	p.t.Helper()
	for at := d - 15*time.Minute; at <= d; at += 5 * time.Minute {
		p.move(at)
		if err := p.patch.PollAgents(p.ctx); err != nil {
			p.t.Fatal(err)
		}
	}
	if !p.patch.AgentsSettled(p.at) {
		p.t.Fatal("the engine's answers do not settle")
	}
}

func (p *patched) requestPatching(device uuid.UUID) (*Repair, error) {
	return p.svc.Request(p.ctx, p.tech, device, agentproto.TargetEasyPatchAgent)
}

// seenAt sets the EasyPatch agent's last check-in, as the poll would.
func (p *patched) seenAt(device uuid.UUID, at time.Time) {
	p.t.Helper()
	p.exec(`UPDATE easypatch_devices SET agent_seen_at = $2 WHERE device_id = $1`, device, at)
}

func TestRepairingTheEasyPatchAgentNeedsItToBeThereAndLinked(t *testing.T) {
	p := newPatched(t)
	d := p.linkedDevice("pc", p.start)
	if _, err := p.svc.Request(p.ctx, p.reader, d, agentproto.TargetEasyPatchAgent); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only user: %v", err)
	}
	// Not linked.
	p.exec(`UPDATE easypatch_devices SET state = 'pending', reason = '' WHERE device_id = $1`, d)
	if _, err := p.requestPatching(d); code(err) != "no_patching_agent" {
		t.Errorf("an agent that is not linked: %v", err)
	}
	p.exec(`UPDATE easypatch_devices SET state = 'linked' WHERE device_id = $1`, d)
	// Patching is off for the organization.
	p.exec(`DELETE FROM easypatch_organizations WHERE organization_id = $1`, p.acme)
	if _, err := p.requestPatching(d); code(err) != "patching_off" {
		t.Errorf("patching off: %v", err)
	}
	p.exec(`INSERT INTO easypatch_organizations (organization_id, easypatch_id, easypatch_name) VALUES ($1, $2, 'Acme Patch')`, p.acme, p.epOrg)
	// A server without patching.
	p.svc.UsePatching(nil)
	if _, err := p.requestPatching(d); code(err) != "no_patching" {
		t.Errorf("without patching: %v", err)
	}
	p.svc.UsePatching(p.patch)
	for name, leave := range map[string]string{
		"removal":   `INSERT INTO device_removals (device_id, id) VALUES ($1, gen_random_uuid())`,
		"opted out": `INSERT INTO easypatch_opt_outs (device_id) VALUES ($1)`,
		"easypatch": `INSERT INTO easypatch_removals (endpoint_id, device_id, reason) VALUES (gen_random_uuid(), $1, 'deleted')`,
	} {
		p.exec(leave, d)
		if _, err := p.requestPatching(d); code(err) != "device_leaving" {
			t.Errorf("%s: %v", name, err)
		}
		p.exec(`DELETE FROM device_removals WHERE device_id = $1`, d)
		p.exec(`DELETE FROM easypatch_opt_outs WHERE device_id = $1`, d)
		p.exec(`DELETE FROM easypatch_removals WHERE device_id = $1`, d)
	}
	r, err := p.requestPatching(d)
	if err != nil {
		t.Fatal(err)
	}
	if r.Target != "easypatch-agent" || r.CarriedBy != "easyrmm-agent" || len(r.Steps) != 2 || r.Trigger != TriggerManual {
		t.Errorf("repair = %+v", r)
	}
	if got := p.count(`SELECT wait_seconds FROM agent_repairs WHERE id = $1`, r.ID); time.Duration(got)*time.Second != ManualWaitPatching {
		t.Errorf("wait = %ds", got)
	}
	// One repair of a target at a time, but MeshAgent's is another.
	if _, err := p.requestPatching(d); code(err) != "repair_running" {
		t.Errorf("second: %v", err)
	}
	if _, err := p.request(p.tech, d); err != nil {
		t.Errorf("a repair of MeshAgent beside it: %v", err)
	}
}

// Restart, wait for a check-in, repair with the package of the version
// installed, wait, back.
func TestAnEasyPatchAgentRepairRestartsThenReinstallsTheSameVersion(t *testing.T) {
	p := newPatched(t)
	d := p.linkedDevice("pc", p.start.Add(-time.Hour))
	p.seenAt(d, p.start.Add(-time.Hour))
	r, err := p.requestPatching(d)
	if err != nil {
		t.Fatal(err)
	}
	p.move(0)
	q := p.beat(d, nil)
	if q == nil || q.Target != "easypatch-agent" || q.Step != "restart" || q.EasyPatch != nil || q.ID != r.Steps[0].ID {
		t.Fatalf("first instruction = %+v", q)
	}
	p.beat(d, &agentproto.RepairReport{ID: q.ID, OK: true})
	// Still silent when the wait is over: the next step. The engine's
	// answers must be fresh for it to be judged.
	p.settle(ManualWaitPatching + time.Minute)
	if got := p.latest(d); got.State != Running || got.Steps[0].State != StepDone {
		t.Fatalf("repair = %+v", got)
	}
	p.move(ManualWaitPatching + time.Minute)
	if err := p.svc.Advance(p.ctx); err != nil {
		t.Fatal(err)
	}
	q = p.beat(d, nil)
	if q == nil || q.Step != "repair" || q.EasyPatch == nil || q.ID != r.Steps[1].ID {
		t.Fatalf("second instruction = %+v", q)
	}
	if len(q.EasyPatch.Packages) != 2 || q.EasyPatch.Packages[0].Version != eptest.EngineVersion || q.EasyPatch.Packages[0].Format != "deb" {
		t.Errorf("offer = %+v", q.EasyPatch)
	}
	p.beat(d, &agentproto.RepairReport{ID: q.ID, OK: true})
	// The agent checks in with the engine after the step: back.
	seen := p.at.Add(time.Minute)
	p.ep.Set(func() { p.endpoint.LastCheckIn = &seen })
	p.settle(ManualWaitPatching + 21*time.Minute)
	if err := p.svc.Advance(p.ctx); err != nil {
		t.Fatal(err)
	}
	got := p.latest(d)
	if got.State != Succeeded {
		t.Fatalf("repair = %+v", got)
	}
}

// A package that cannot be offered ends the repair with the reason.
func TestARepairThatCannotBeOfferedEndsWithTheReason(t *testing.T) {
	p := newPatched(t)
	d := p.linkedDevice("pc", p.start.Add(-time.Hour))
	p.exec(`UPDATE device_inventory SET data = '{"easyPatch":{"version":"0.9.0","status":"Active"}}'::jsonb WHERE device_id = $1`, d)
	if _, err := p.requestPatching(d); err != nil {
		t.Fatal(err)
	}
	p.move(0)
	q := p.beat(d, nil)
	p.beat(d, &agentproto.RepairReport{ID: q.ID, OK: true})
	p.settle(ManualWaitPatching + time.Minute)
	if err := p.svc.Advance(p.ctx); err != nil {
		t.Fatal(err)
	}
	if got := p.beat(d, nil); got != nil {
		t.Fatalf("an instruction that cannot be built: %+v", got)
	}
	got := p.latest(d)
	if got.State != Failed || !strings.Contains(got.Error, "no longer offers version 0.9.0") {
		t.Errorf("repair = %+v", got)
	}
}

// Nothing is judged while the engine is not answering.
func TestAStepOfTheEasyPatchAgentIsNotJudgedWhileTheEngineIsDown(t *testing.T) {
	p := newPatched(t)
	d := p.linkedDevice("pc", p.start.Add(-time.Hour))
	p.seenAt(d, p.start.Add(-time.Hour))
	if _, err := p.requestPatching(d); err != nil {
		t.Fatal(err)
	}
	p.move(0)
	q := p.beat(d, nil)
	p.beat(d, &agentproto.RepairReport{ID: q.ID, OK: true})
	// The wait is over, but the engine has not answered for 15 minutes.
	p.move(ManualWaitPatching + time.Minute)
	if err := p.svc.Advance(p.ctx); err != nil {
		t.Fatal(err)
	}
	if got := p.latest(d); got.Steps[1].State != StepPending || got.State != Running || p.count(`SELECT step FROM agent_repairs WHERE id = $1`, got.ID) != 0 {
		t.Errorf("the repair moved on without being able to judge: %+v", got)
	}
}

// A repair of the EasyPatch agent ends, quietly, when patching is switched
// off for the organization.
func TestARepairEndsWhenPatchingIsOff(t *testing.T) {
	p := newPatched(t)
	d := p.linkedDevice("pc", p.start)
	if _, err := p.requestPatching(d); err != nil {
		t.Fatal(err)
	}
	p.exec(`DELETE FROM easypatch_organizations WHERE organization_id = $1`, p.acme)
	if p.beat(d, nil) != nil {
		t.Error("an instruction for a device that is not patched")
	}
	if err := p.svc.Advance(p.ctx); err != nil {
		t.Fatal(err)
	}
	if got := p.latest(d); got.State != Failed || !strings.Contains(got.Error, "Patching is off") {
		t.Errorf("repair = %+v", got)
	}
	if p.count(`SELECT count(*) FROM alerts WHERE kind = 'repair_failed'`) != 0 {
		t.Error("an alert for a repair that stopped on purpose")
	}
}

// Where the server cannot offer the package, or the agent would refuse what
// it offers, the repair ends at once with the reason instead of waiting for
// an agent that would never carry it out.
func TestARepairStepNobodyCouldCarryOutEndsWithTheReason(t *testing.T) {
	prepare := func(t *testing.T) (*patched, uuid.UUID) {
		p := newPatched(t)
		d := p.linkedDevice("pc", p.start.Add(-time.Hour))
		if _, err := p.requestPatching(d); err != nil {
			t.Fatal(err)
		}
		p.move(0)
		q := p.beat(d, nil)
		p.beat(d, &agentproto.RepairReport{ID: q.ID, OK: true})
		p.settle(ManualWaitPatching + time.Minute)
		if err := p.svc.Advance(p.ctx); err != nil {
			t.Fatal(err)
		}
		return p, d
	}
	t.Run("without patching", func(t *testing.T) {
		p, d := prepare(t)
		p.svc.UsePatching(nil)
		if got := p.beat(d, nil); got != nil {
			t.Fatalf("instruction = %+v", got)
		}
		if r := p.latest(d); r.State != Failed || !strings.Contains(r.Error, "without patching") {
			t.Errorf("repair = %+v", r)
		}
	})
	t.Run("a package the agent refuses", func(t *testing.T) {
		p, d := prepare(t)
		// Larger than any EasyPatch agent package is.
		p.ep.Set(func() {
			for _, pk := range p.ep.Packages {
				pk["sizeBytes"] = int64(1) << 31
			}
		})
		if got := p.beat(d, nil); got != nil {
			t.Fatalf("instruction = %+v", got)
		}
		if r := p.latest(d); r.State != Failed || !strings.Contains(r.Error, "not in a form the agent accepts") {
			t.Errorf("repair = %+v", r)
		}
	})
	t.Run("an engine that does not answer", func(t *testing.T) {
		p, d := prepare(t)
		p.ep.Set(func() { p.ep.Down = true })
		if got := p.beat(d, nil); got != nil {
			t.Fatalf("instruction = %+v", got)
		}
		if r := p.latest(d); r.State != Failed || r.Error == "" {
			t.Errorf("repair = %+v", r)
		}
	})
}

// A step the agent never takes ends the repair, for the EasyPatch agent as
// for MeshAgent.
func TestAnEasyPatchStepThatIsNeverTakenFailsTheRepair(t *testing.T) {
	p := newPatched(t)
	d := p.linkedDevice("pc", p.start)
	if _, err := p.requestPatching(d); err != nil {
		t.Fatal(err)
	}
	p.move(StepValid + time.Minute)
	if err := p.svc.Advance(p.ctx); err != nil {
		t.Fatal(err)
	}
	if r := p.latest(d); r.State != Failed || !strings.Contains(r.Error, "did not take the instruction") {
		t.Errorf("repair = %+v", r)
	}
}
