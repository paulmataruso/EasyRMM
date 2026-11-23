//go:build integration

package recovery

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
)

// The EasyRMM agent repaired through patching (ADR-0069, slice R3): the
// EasyPatch agent restarts it and repairs it from its recovery copy, through
// the engine's RepairCompanion job.

const recoveryHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// silent is a device whose EasyRMM agent stopped checking in an hour ago and
// whose EasyPatch agent is linked and checked in at the start; the build the
// device runs has a recorded hash.
func (p *patched) silent(name string) uuid.UUID {
	p.t.Helper()
	d := p.linkedDevice(name, p.start)
	p.exec(`UPDATE devices SET agent_last_seen_at = $2, agent_sha256 = $3 WHERE id = $1`, d, p.start.Add(-time.Hour), recoveryHash)
	p.seenAt(d, p.start)
	return d
}

func (p *patched) requestRMM(device uuid.UUID) (*Repair, error) {
	return p.svc.Request(p.ctx, p.tech, device, agentproto.TargetEasyRMMAgent)
}

func (p *patched) dispatch() {
	p.t.Helper()
	if err := p.svc.Dispatch(p.ctx); err != nil {
		p.t.Fatal(err)
	}
}

// companionJobs are the engine's RepairCompanion jobs, oldest first.
func (p *patched) companionJobs() []eptest.Job {
	var out []eptest.Job
	for _, j := range p.ep.Jobs() {
		if j.Type == "RepairCompanion" {
			out = append(out, j)
		}
	}
	return out
}

func TestRepairingTheEasyRMMAgentThroughPatchingNeedsPatchManageAndASilentAgentWithALinkedPatchingAgent(t *testing.T) {
	p := newPatched(t)
	d := p.silent("pc")
	if _, err := p.svc.Request(p.ctx, p.reader, d, agentproto.TargetEasyRMMAgent); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only user: %v", err)
	}
	if _, err := p.svc.Request(p.ctx, p.stranger, d, agentproto.TargetEasyRMMAgent); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization's administrator: %v", err)
	}
	// The EasyRMM agent checks in: there is nothing to repair.
	p.exec(`UPDATE devices SET agent_last_seen_at = now() WHERE id = $1`, d)
	if _, err := p.requestRMM(d); code(err) != "agent_online" {
		t.Errorf("an agent that checks in: %v", err)
	}
	p.exec(`UPDATE devices SET agent_last_seen_at = $2 WHERE id = $1`, d, p.start.Add(-time.Hour))
	// The EasyPatch agent is quiet too: it cannot repair anything.
	p.seenAt(d, p.start.Add(-11*time.Minute))
	if _, err := p.requestRMM(d); code(err) != "patching_agent_silent" {
		t.Errorf("a patching agent that is silent: %v", err)
	}
	p.seenAt(d, p.start)
	p.exec(`UPDATE easypatch_devices SET state = 'pending', reason = '' WHERE device_id = $1`, d)
	if _, err := p.requestRMM(d); code(err) != "no_patching_agent" {
		t.Errorf("a patching agent that is not linked: %v", err)
	}
	p.exec(`UPDATE easypatch_devices SET state = 'linked' WHERE device_id = $1`, d)
	p.exec(`DELETE FROM easypatch_organizations WHERE organization_id = $1`, p.acme)
	if _, err := p.requestRMM(d); code(err) != "patching_off" {
		t.Errorf("patching off: %v", err)
	}
	p.exec(`INSERT INTO easypatch_organizations (organization_id, easypatch_id, easypatch_name) VALUES ($1, $2, 'Acme Patch')`, p.acme, p.epOrg)
	p.svc.UsePatching(nil)
	if _, err := p.requestRMM(d); code(err) != "no_patching" {
		t.Errorf("without patching: %v", err)
	}
	p.svc.UsePatching(p.patch)
	p.exec(`INSERT INTO device_removals (device_id, id) VALUES ($1, gen_random_uuid())`, d)
	if _, err := p.requestRMM(d); code(err) != "device_leaving" {
		t.Errorf("a device that is leaving: %v", err)
	}
	p.exec(`DELETE FROM device_removals WHERE device_id = $1`, d)

	r, err := p.requestRMM(d)
	if err != nil {
		t.Fatal(err)
	}
	if r.Target != "easyrmm-agent" || r.CarriedBy != "easypatch-agent" || len(r.Steps) != 2 || r.Trigger != TriggerManual {
		t.Errorf("repair = %+v", r)
	}
	if got := p.count(`SELECT wait_seconds FROM agent_repairs WHERE id = $1`, r.ID); time.Duration(got)*time.Second != ManualWait {
		t.Errorf("wait = %ds", got)
	}
	if _, err := p.requestRMM(d); code(err) != "repair_running" {
		t.Errorf("a second repair: %v", err)
	}
	if p.count(`SELECT count(*) FROM audit_log WHERE action = 'device.repair_request' AND device_id = $1`, d) != 1 {
		t.Error("the request was not audited")
	}
	// The EasyRMM agent's own heartbeat is never handed this repair.
	if p.beat(d, nil) != nil {
		t.Error("a heartbeat was handed a step the EasyPatch agent carries")
	}
}

func TestAnEasyRMMAgentRepairRestartsThenRepairsFromTheRecoveryCopyAndEndsWhenTheAgentChecksIn(t *testing.T) {
	p := newPatched(t)
	d := p.silent("pc")
	r, err := p.requestRMM(d)
	if err != nil {
		t.Fatal(err)
	}
	p.move(0)
	p.dispatch()
	jobs := p.companionJobs()
	if len(jobs) != 1 || jobs[0].Companion != (eptest.CompanionRequest{Target: "easyrmm-agent", Step: "restart"}) {
		t.Fatalf("jobs after the first dispatch = %+v", jobs)
	}
	if got := p.latest(d); got.Steps[0].State != StepSent || got.Steps[0].JobID != jobs[0].ID.String() {
		t.Fatalf("step = %+v", got.Steps[0])
	}
	// Nothing again while the job runs.
	p.dispatch()
	if len(p.companionJobs()) != 1 {
		t.Fatal("a second job for a step that is under way")
	}
	// The agent restarts the service and returns the logs, with a secret in them.
	p.ep.SetJobResult(jobs[0].ID, "Completed", "Restarted the EasyRMM agent's service (easyrmm-agent.service); it is running.", "",
		"==== easyrmm-agent ====\nenrolled with token=abc123456789 and key=ert_0123456789abcdef\nstarted")
	p.move(time.Minute)
	p.dispatch()
	got := p.latest(d)
	if got.Steps[0].State != StepDone || !strings.Contains(got.Steps[0].Note, "it is running") {
		t.Fatalf("step = %+v", got.Steps[0])
	}
	var diagnostics string
	if err := p.db.ReadTx(p.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(p.ctx, `SELECT diagnostics FROM agent_repairs WHERE id = $1`, r.ID).Scan(&diagnostics)
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diagnostics, "started") || strings.Contains(diagnostics, "abc123456789") || strings.Contains(diagnostics, "ert_0123456789abcdef") {
		t.Errorf("diagnostics = %q", diagnostics)
	}

	// Still silent when the wait is over: the next step, with the hash of the build.
	p.move(time.Minute + ManualWait + time.Second)
	if err := p.svc.Advance(p.ctx); err != nil {
		t.Fatal(err)
	}
	p.dispatch()
	jobs = p.companionJobs()
	if len(jobs) != 2 || jobs[1].Companion != (eptest.CompanionRequest{Target: "easyrmm-agent", Step: "repair", ExpectedSHA256: recoveryHash}) {
		t.Fatalf("jobs after the second step = %+v", jobs)
	}
	p.ep.SetJobResult(jobs[1].ID, "Completed", "Repaired the EasyRMM agent from its recovery copy; its service is running.", "", "==== easyrmm-agent ====\nstarted again")
	p.move(2 * time.Minute)
	p.dispatch()
	// The EasyRMM agent checks in: the repair succeeded.
	p.exec(`UPDATE devices SET agent_last_seen_at = $2 WHERE id = $1`, d, p.at.Add(time.Second))
	p.move(2*time.Minute + 5*time.Second)
	if err := p.svc.Advance(p.ctx); err != nil {
		t.Fatal(err)
	}
	if got := p.latest(d); got.State != Succeeded || got.Steps[1].State != StepDone {
		t.Fatalf("repair = %+v", got)
	}
	if p.count(`SELECT count(*) FROM alerts WHERE kind = 'repair_failed'`) != 0 {
		t.Error("an alert for a repair that worked")
	}
}

// A step the engine refuses, or one that cannot be asked for, ends with the
// reason: nobody could carry it out.
func TestAnEasyRMMAgentRepairStepNobodyCouldCarryOutEndsWithTheReason(t *testing.T) {
	t.Run("an EasyPatch agent that is too old", func(t *testing.T) {
		p := newPatched(t)
		d := p.silent("pc")
		p.ep.Set(func() { p.endpoint.CannotRepairCompanion = true })
		if _, err := p.requestRMM(d); err != nil {
			t.Fatal(err)
		}
		p.move(0)
		p.dispatch() // the restart is refused: straight to the repair
		p.dispatch() // and that is refused too
		got := p.latest(d)
		if got.State != Failed || got.Steps[0].State != StepFailed || !strings.Contains(got.Error, "cannot do that") {
			t.Errorf("repair = %+v", got)
		}
		if len(p.companionJobs()) != 0 {
			t.Error("a job the engine refused")
		}
	})
	t.Run("a device whose build has no recorded hash", func(t *testing.T) {
		p := newPatched(t)
		d := p.silent("pc")
		p.exec(`UPDATE devices SET agent_sha256 = NULL WHERE id = $1`, d)
		if _, err := p.requestRMM(d); err != nil {
			t.Fatal(err)
		}
		p.move(0)
		p.dispatch()
		j := p.companionJobs()[0]
		p.ep.SetJobResult(j.ID, "Completed", "Restarted.", "", "")
		p.move(time.Minute)
		p.dispatch()
		p.move(time.Minute + ManualWait + time.Second)
		if err := p.svc.Advance(p.ctx); err != nil {
			t.Fatal(err)
		}
		p.dispatch() // the repair step needs the hash
		got := p.latest(d)
		if got.State != Failed || !strings.Contains(got.Error, "no record of the build this device runs") || len(p.companionJobs()) != 1 {
			t.Errorf("repair = %+v", got)
		}
	})
	// toRepairStep takes a repair of a silent device through the restart to
	// the repair step.
	toRepairStep := func(p *patched, d uuid.UUID) {
		t.Helper()
		if _, err := p.requestRMM(d); err != nil {
			t.Fatal(err)
		}
		p.move(0)
		p.dispatch()
		p.ep.SetJobResult(p.companionJobs()[0].ID, "Completed", "Restarted.", "", "")
		p.move(time.Minute)
		p.dispatch()
		p.move(time.Minute + ManualWait + time.Second)
		if err := p.svc.Advance(p.ctx); err != nil {
			t.Fatal(err)
		}
		p.dispatch()
	}
	t.Run("a device whose build the server does not publish is restarted but not repaired", func(t *testing.T) {
		p := newPatched(t)
		d := p.silent("pc")
		// The hash is the device's own word: the server publishes another.
		p.exec(`UPDATE devices SET agent_sha256 = $2 WHERE id = $1`, d, strings.Repeat("ab", 32))
		toRepairStep(p, d)
		got := p.latest(d)
		if got.State != Failed || !strings.Contains(got.Error, "not one this server publishes") || len(p.companionJobs()) != 1 {
			t.Errorf("repair = %+v", got)
		}
	})
	t.Run("a Windows device running a signed build the server keeps is repaired from its copy", func(t *testing.T) {
		p := newPatched(t)
		d := p.silent("pc")
		signed := strings.Repeat("cd", 32)
		p.exec(`UPDATE devices SET platform = 'windows', agent_sha256 = $2 WHERE id = $1`, d, signed)
		p.exec(`INSERT INTO signed_agent_builds (id, arch, version, sha256, release_sha256, content, signer_subject,
			signer_issuer, thumbprint, not_before, not_after, timestamped) VALUES (gen_random_uuid(), 'amd64', '1.0.0', $1, $2, '\x00',
			'CN=Test', 'CN=Test', repeat('a', 40), now() - interval '1 day', now() + interval '1 day', true)`, signed, recoveryHash)
		toRepairStep(p, d)
		jobs := p.companionJobs()
		if len(jobs) != 2 || jobs[1].Companion.ExpectedSHA256 != signed {
			t.Errorf("jobs = %+v", jobs)
		}
	})
	t.Run("a refusal by the agent is the step's failure, with its diagnostics", func(t *testing.T) {
		p := newPatched(t)
		d := p.silent("pc")
		r, err := p.requestRMM(d)
		if err != nil {
			t.Fatal(err)
		}
		p.move(0)
		p.dispatch()
		p.ep.SetJobResult(p.companionJobs()[0].ID, "Failed", "The EasyRMM agent's service (EasyRMMAgent) is not installed.", "service_missing", "==== easyrmm-agent ====\nno service")
		p.move(time.Minute)
		p.dispatch()
		got := p.latest(d)
		if got.Steps[0].State != StepFailed || !strings.Contains(got.Steps[0].Error, "is not installed") || got.State != Running {
			t.Fatalf("repair = %+v", got)
		}
		if p.count(`SELECT count(*) FROM agent_repairs WHERE id = $1 AND diagnostics LIKE '%no service%'`, r.ID) != 1 {
			t.Error("the failed step's diagnostics were not kept")
		}
	})
}

// A step the EasyPatch agent does not take in 15 minutes is canceled in the
// engine so that it cannot run after the repair moved on, and fails.
func TestAnEasyRMMAgentStepThatIsNotTakenIsCancelledInTheEngine(t *testing.T) {
	p := newPatched(t)
	d := p.silent("pc")
	if _, err := p.requestRMM(d); err != nil {
		t.Fatal(err)
	}
	p.move(0)
	p.dispatch()
	job := p.companionJobs()[0]
	p.move(StepValid + time.Second)
	p.dispatch()
	if now := p.companionJobs()[0]; now.Status != eptest.StatusCanceled {
		t.Errorf("the job %s is %s, not canceled", job.ID, now.Status)
	}
	got := p.latest(d)
	if got.Steps[0].State != StepFailed || !strings.Contains(got.Steps[0].Error, "within 15 minutes") {
		t.Errorf("step = %+v", got.Steps[0])
	}
}

// An engine that cannot be reached leaves the step waiting; after 15 minutes
// the repair ends as for any carrier that never takes a step.
func TestAnEasyRMMAgentStepWaitsForAnEngineThatDoesNotAnswer(t *testing.T) {
	p := newPatched(t)
	d := p.silent("pc")
	if _, err := p.requestRMM(d); err != nil {
		t.Fatal(err)
	}
	p.ep.Set(func() { p.ep.Down = true })
	p.move(0)
	p.dispatch()
	if got := p.latest(d); got.Steps[0].State != StepPending || got.State != Running {
		t.Fatalf("repair = %+v", got)
	}
	p.ep.Set(func() { p.ep.Down = false })
	p.move(time.Minute)
	p.dispatch()
	if len(p.companionJobs()) != 1 {
		t.Fatal("the step was not asked for once the engine answered")
	}
	// Down for good: it ends after StepValid.
	p2 := newPatched(t)
	d2 := p2.silent("pc2")
	if _, err := p2.requestRMM(d2); err != nil {
		t.Fatal(err)
	}
	p2.ep.Set(func() { p2.ep.Down = true })
	p2.move(StepValid + time.Minute)
	p2.dispatch()
	if err := p2.svc.Advance(p2.ctx); err != nil {
		t.Fatal(err)
	}
	if got := p2.latest(d2); got.State != Failed || !strings.Contains(got.Error, "EasyPatch agent did not take the instruction") {
		t.Errorf("repair = %+v", got)
	}
}

// Nothing is asked of the engine for a device that is leaving, and the
// repair ends without an alert.
func TestNothingIsAskedOfTheEngineForADeviceThatIsLeaving(t *testing.T) {
	p := newPatched(t)
	d := p.silent("pc")
	if _, err := p.requestRMM(d); err != nil {
		t.Fatal(err)
	}
	p.exec(`INSERT INTO easypatch_opt_outs (device_id) VALUES ($1)`, d)
	p.move(0)
	p.dispatch()
	if len(p.companionJobs()) != 0 {
		t.Error("a job for a device that is leaving")
	}
	if err := p.svc.Advance(p.ctx); err != nil {
		t.Fatal(err)
	}
	if got := p.latest(d); got.State != Failed || !strings.Contains(got.Error, "being removed") {
		t.Errorf("repair = %+v", got)
	}
	if p.count(`SELECT count(*) FROM alerts WHERE kind = 'repair_failed'`) != 0 {
		t.Error("an alert for a device that is leaving")
	}
}

// ---- automatic repairs ------------------------------------------------------------------------------------------------------------

// evalRMM judges the conditions d after the start, the engine having
// answered for long enough, the EasyPatch agent checking in at that time.
// patchingAgentSilent keeps evalRMM from having the EasyPatch agent check in.
var patchingAgentSilent bool

func (p *patched) evalRMM(device uuid.UUID, d time.Duration) {
	p.t.Helper()
	p.settle(d)
	if !patchingAgentSilent {
		p.seenAt(device, p.at)
	}
	if err := p.svc.Evaluate(p.ctx); err != nil {
		p.t.Fatal(err)
	}
}

func (p *patched) autoRMM(device uuid.UUID) int {
	return p.autos(device, "easyrmm-agent")
}

func TestASilentEasyRMMAgentIsRepairedThroughPatchingAfterFifteenMinutes(t *testing.T) {
	p := newPatched(t)
	d := p.silent("pc")
	p.evalRMM(d, 20*time.Minute)
	p.evalRMM(d, 34*time.Minute+59*time.Second)
	if p.autoRMM(d) != 0 {
		t.Fatal("repaired before the condition held for 15 minutes")
	}
	p.evalRMM(d, 35*time.Minute)
	if p.autoRMM(d) != 1 {
		t.Fatal("not repaired after 15 minutes")
	}
	r := p.latest(d)
	if r.Trigger != TriggerAutomatic || r.Target != "easyrmm-agent" || r.CarriedBy != "easypatch-agent" || len(r.Steps) != 2 || r.State != Running {
		t.Errorf("repair = %+v", r)
	}
	if p.count(`SELECT wait_seconds FROM agent_repairs WHERE id = $1`, r.ID) != 30*60 {
		t.Error("the wait between steps is not 30 minutes")
	}
	if p.count(`SELECT count(*) FROM audit_log WHERE action = 'device.repair_auto' AND device_id = $1`, d) != 1 {
		t.Error("the start was not audited")
	}
	// One at a time, and the limits count attempts.
	p.evalRMM(d, 36*time.Minute)
	if p.autoRMM(d) != 1 {
		t.Error("a second repair started beside the first")
	}
}

func TestASilentEasyRMMAgentIsNotRepairedWhereTheConditionOrTheRulesDoNotHold(t *testing.T) {
	cases := map[string]func(p *patched, d uuid.UUID){
		"the EasyRMM agent checks in": func(p *patched, d uuid.UUID) {
			p.exec(`UPDATE devices SET agent_last_seen_at = $2 WHERE id = $1`, d, p.start.Add(45*time.Minute))
		},
		"the EasyPatch agent is silent too": func(p *patched, d uuid.UUID) {
			patchingAgentSilent = true
			p.exec(`UPDATE easypatch_devices SET agent_seen_at = $2 WHERE device_id = $1`, d, p.start.Add(-time.Hour))
		},
		"automatic repairs are off": func(p *patched, d uuid.UUID) {
			p.exec(`UPDATE organizations SET auto_repair = false WHERE id = $1`, p.acme)
		},
		"the device is being removed": func(p *patched, d uuid.UUID) {
			p.exec(`INSERT INTO device_removals (device_id, id) VALUES ($1, gen_random_uuid())`, d)
		},
		"the device opted out of patching": func(p *patched, d uuid.UUID) { p.exec(`INSERT INTO easypatch_opt_outs (device_id) VALUES ($1)`, d) },
		"the EasyPatch agent is not linked": func(p *patched, d uuid.UUID) {
			p.exec(`UPDATE easypatch_devices SET state = 'pending', reason = '' WHERE device_id = $1`, d)
		},
		"the EasyRMM agent was never seen": func(p *patched, d uuid.UUID) { p.exec(`UPDATE devices SET agent_last_seen_at = NULL WHERE id = $1`, d) },
		"patching is off for the organization": func(p *patched, d uuid.UUID) {
			p.exec(`DELETE FROM easypatch_organizations WHERE organization_id = $1`, p.acme)
		},
		"the patching engine has not answered yet": nil,
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			patchingAgentSilent = false
			t.Cleanup(func() { patchingAgentSilent = false })
			p := newPatched(t)
			d := p.silent("pc")
			if change != nil {
				change(p, d)
			}
			if change == nil {
				// No polls: the engine's answers do not settle.
				p.move(40 * time.Minute)
				if err := p.svc.Evaluate(p.ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				p.evalRMM(d, 20*time.Minute)
				p.evalRMM(d, 40*time.Minute)
			}
			if p.autoRMM(d) != 0 {
				t.Errorf("a repair started where %s", name)
			}
		})
	}
}

// Where the target is back by the time the repair is judged, its alert goes.
func TestARepairThroughPatchingThatFailsRaisesOneWarningAndItGoesWhenTheAgentIsBack(t *testing.T) {
	p := newPatched(t)
	d := p.silent("pc")
	p.ep.Set(func() { p.endpoint.CannotRepairCompanion = true })
	p.evalRMM(d, 20*time.Minute)
	p.evalRMM(d, 35*time.Minute)
	if p.autoRMM(d) != 1 {
		t.Fatal("no repair")
	}
	p.dispatch()
	p.dispatch()
	if err := p.svc.Advance(p.ctx); err != nil {
		t.Fatal(err)
	}
	if got := p.latest(d); got.State != Failed {
		t.Fatalf("repair = %+v", got)
	}
	if p.alerts(d, "open") != 1 {
		t.Fatalf("alerts = %d", p.alerts(d, "open"))
	}
	// The agent comes back by itself: the warning resolves.
	p.exec(`UPDATE devices SET agent_last_seen_at = $2 WHERE id = $1`, d, p.at.Add(time.Minute))
	p.move(37 * time.Minute)
	p.settle(40 * time.Minute)
	p.seenAt(d, p.at)
	p.exec(`UPDATE devices SET agent_last_seen_at = $2 WHERE id = $1`, d, p.at)
	if err := p.svc.Evaluate(p.ctx); err != nil {
		t.Fatal(err)
	}
	if p.alerts(d, "open") != 0 || p.alerts(d, "resolved") != 1 {
		t.Errorf("alerts open %d, resolved %d", p.alerts(d, "open"), p.alerts(d, "resolved"))
	}
}

// An engine that stops answering while a step is out leaves it where it is.
func TestAStepWhoseJobCannotBeReadIsLeftAloneAndTheEnginesEndingsAreTheStepsReasons(t *testing.T) {
	for status, want := range map[string]string{
		"Expired":             "did not pick the job up",
		eptest.StatusCanceled: "was canceled",
		"Failed":              "reported that the step failed",
	} {
		p := newPatched(t)
		d := p.silent("pc")
		if _, err := p.requestRMM(d); err != nil {
			t.Fatal(err)
		}
		p.move(0)
		p.dispatch()
		job := p.companionJobs()[0]
		// The engine does not answer: the step stays out.
		p.ep.Set(func() { p.ep.Down = true })
		p.move(time.Minute)
		p.dispatch()
		if got := p.latest(d); got.Steps[0].State != StepSent {
			t.Fatalf("%s: step = %+v", status, got.Steps[0])
		}
		p.ep.Set(func() { p.ep.Down = false })
		p.ep.SetJobStatus(job.ID, status)
		p.move(2 * time.Minute)
		p.dispatch()
		if got := p.latest(d); got.Steps[0].State != StepFailed || !strings.Contains(got.Steps[0].Error, want) {
			t.Errorf("%s: step = %+v", status, got.Steps[0])
		}
	}
}

func TestDispatchWithoutPatchingDoesNothingAndDiagnosticsAreKeptShortAndRedacted(t *testing.T) {
	p := newPatched(t)
	p.svc.UsePatching(nil)
	if err := p.svc.Dispatch(p.ctx); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("line of the log\n", 40000) + "token=abc12345678 end"
	got := keepDiagnostics(long)
	if len(got) > MaxDiagnostics || !strings.HasPrefix(got, "line of the log") || strings.Contains(got, "abc12345678") || !strings.HasSuffix(got, "end") {
		t.Errorf("kept %d bytes: %.40q ... %.40q", len(got), got, got[len(got)-40:])
	}
	if keepDiagnostics("a\xffb") != "ab" {
		t.Error("an invalid byte was kept")
	}
	if keepDiagnostics("") != "" {
		t.Error("nothing became something")
	}
}

func TestDiagnosticsGoWithinFourteenDaysOfTheRepairEnding(t *testing.T) {
	p := newPatched(t)
	d := p.silent("pc")
	r, err := p.requestRMM(d)
	if err != nil {
		t.Fatal(err)
	}
	p.exec(`UPDATE agent_repairs SET state = 'failed', ended_at = $2, diagnostics = 'some lines' WHERE id = $1`, r.ID, p.start.Add(-13*24*time.Hour))
	if err := p.svc.purge(p.ctx); err != nil {
		t.Fatal(err)
	}
	if p.count(`SELECT count(*) FROM agent_repairs WHERE id = $1 AND diagnostics <> ''`, r.ID) != 1 {
		t.Error("diagnostics went before 14 days")
	}
	p.exec(`UPDATE agent_repairs SET ended_at = $2 WHERE id = $1`, r.ID, p.start.Add(-15*24*time.Hour))
	if err := p.svc.purge(p.ctx); err != nil {
		t.Fatal(err)
	}
	if p.count(`SELECT count(*) FROM agent_repairs WHERE id = $1 AND diagnostics = ''`, r.ID) != 1 {
		t.Error("diagnostics stayed after 14 days")
	}
}

func TestAnEasyRMMAgentRepairEndsQuietlyWhenPatchingIsOffOrAutomaticRepairsAre(t *testing.T) {
	p := newPatched(t)
	d := p.silent("pc")
	if _, err := p.requestRMM(d); err != nil {
		t.Fatal(err)
	}
	p.exec(`DELETE FROM easypatch_organizations WHERE organization_id = $1`, p.acme)
	p.dispatch() // nothing is asked of the engine for an organization that is not patched
	if len(p.companionJobs()) != 0 {
		t.Error("a job for an organization that is not patched")
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

	// An automatic one stops when automatic repairs are turned off.
	q := newPatched(t)
	e := q.silent("pc")
	q.evalRMM(e, 20*time.Minute)
	q.evalRMM(e, 35*time.Minute)
	if q.autoRMM(e) != 1 {
		t.Fatal("no automatic repair")
	}
	q.exec(`UPDATE organizations SET auto_repair = false WHERE id = $1`, q.acme)
	if err := q.svc.Advance(q.ctx); err != nil {
		t.Fatal(err)
	}
	if got := q.latest(e); got.State != Failed || !strings.Contains(got.Error, "turned off") {
		t.Errorf("repair = %+v", got)
	}
}

// A step that went well but did not bring the agent back moves on, and a
// damaged record is left to Advance.
func TestAStepThatDidNotBringTheEasyRMMAgentBackMovesOnAndADamagedRecordIsSkipped(t *testing.T) {
	p := newPatched(t)
	d := p.silent("pc")
	r, err := p.requestRMM(d)
	if err != nil {
		t.Fatal(err)
	}
	p.move(0)
	p.dispatch()
	p.ep.SetJobResult(p.companionJobs()[0].ID, "Completed", "Restarted.", "", "")
	p.move(time.Minute)
	p.dispatch()
	p.move(time.Minute + ManualWait + time.Second)
	if err := p.svc.Advance(p.ctx); err != nil {
		t.Fatal(err)
	}
	if got := p.latest(d); got.Steps[0].State != StepDone || p.count(`SELECT step FROM agent_repairs WHERE id = $1`, r.ID) != 1 {
		t.Fatalf("repair = %+v", got)
	}
	// The last step goes well too, and the agent is still silent when its wait is over.
	p.dispatch()
	p.ep.SetJobResult(p.companionJobs()[1].ID, "Completed", "Repaired.", "", "")
	p.move(2 * time.Minute)
	p.dispatch()
	p.move(2*time.Minute + ManualWait + time.Second)
	if err := p.svc.Advance(p.ctx); err != nil {
		t.Fatal(err)
	}
	if got := p.latest(d); got.State != Failed || !strings.Contains(got.Error, "did not check in after the last step") {
		t.Errorf("repair = %+v", got)
	}

	q := newPatched(t)
	e := q.silent("pc")
	r2, err := q.requestRMM(e)
	if err != nil {
		t.Fatal(err)
	}
	q.exec(`UPDATE agent_repairs SET step = 5 WHERE id = $1`, r2.ID)
	q.dispatch() // skipped, not an error
	if err := q.svc.Advance(q.ctx); err != nil {
		t.Fatal(err)
	}
	if got := q.latest(e); got.State != Failed || !strings.Contains(got.Error, "damaged") {
		t.Errorf("repair = %+v", got)
	}
}
