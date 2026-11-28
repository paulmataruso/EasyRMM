//go:build integration

package schedule

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func (f *fixture) winDevice(name string) uuid.UUID {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, 'windows', $4, now(), now()) RETURNING id`, f.acme, f.hq, name, key)
}

func (f *fixture) action(kind string, st Step) Input {
	return Input{Name: "Action " + kind, OrganizationID: f.acme, StepKind: kind, Step: st, Schedule: daily()}
}

func (f *fixture) fireAt(at time.Time) {
	f.t.Helper()
	f.at = at
	if err := f.svc.Fire(f.ctx); err != nil {
		f.t.Fatal(err)
	}
}

var due = time.Date(2026, 1, 6, 8, 0, 20, 0, time.UTC) // 03:00 in New York, Tuesday

func TestRestartTaskMakesAJobPerPlatform(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	l1, l2, w1 := f.device("lin-a"), f.device("lin-b"), f.winDevice("win-a")

	task, err := f.svc.Create(f.ctx, tech, f.action(StepRestart, Step{}))
	if err != nil {
		t.Fatal(err)
	}
	if task.StepKind != StepRestart || task.ScriptID != nil || task.ScriptChanged || task.ScriptSHA256 != "" || !task.CanEdit {
		t.Fatalf("task: %+v", task)
	}
	f.fireAt(due)
	r := f.runs(task.ID)
	if len(r) != 1 || r[0].State != RunSucceeded || len(r[0].JobIDs) != 2 {
		t.Fatalf("runs: %+v", r)
	}
	if n := f.count(`SELECT count(*) FROM jobs WHERE id = ANY($1) AND kind = 'maintenance' AND maintenance->>'action' = 'restart'`, r[0].JobIDs); n != 2 {
		t.Fatalf("%d restart jobs", n)
	}
	if n := f.count(`SELECT count(*) FROM job_runs WHERE job_id = ANY($1) AND device_id = ANY($2)`, r[0].JobIDs, []uuid.UUID{l1, l2, w1}); n != 3 {
		t.Fatalf("%d runs", n)
	}
	if n := f.count(`SELECT count(*) FROM jobs j JOIN job_runs r ON r.job_id = j.id WHERE j.id = ANY($1) AND j.shell = 'powershell' AND r.device_id = $2`, r[0].JobIDs, w1); n != 1 {
		t.Fatal("the Windows device did not get the PowerShell script")
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'automation.create' AND details->>'stepKind' = 'restart'`); n != 1 {
		t.Fatalf("%d create records name the step", n)
	}

	// Limited to one platform, only that platform's devices are reached.
	lin, err := f.svc.Create(f.ctx, tech, f.action(StepShutdown, Step{Platform: "linux"}))
	if err != nil {
		t.Fatal(err)
	}
	f.fireAt(due.Add(24 * time.Hour))
	r = f.runs(lin.ID)
	if len(r) != 1 || len(r[0].JobIDs) != 1 {
		t.Fatalf("linux-only runs: %+v", r)
	}
	if n := f.count(`SELECT count(*) FROM job_runs WHERE job_id = $1 AND device_id = $2`, r[0].JobIDs[0], w1); n != 0 {
		t.Fatal("a Windows device was reached by a Linux-only shutdown")
	}
}

func TestStaggeredRestartKeepsPlatformsApart(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	for i := range 3 {
		f.device("lin-" + string(rune('a'+i)))
		f.winDevice("win-" + string(rune('a'+i)))
	}
	w := f.window("tasks", "03:00", 120)
	in := f.action(StepRestart, Step{})
	in.WindowID, in.StaggerMinutes = &w, 30
	task, err := f.svc.Create(f.ctx, tech, in)
	if err != nil {
		t.Fatal(err)
	}
	f.fireAt(due)
	f.fireAt(due.Add(31 * time.Minute))
	r := f.runs(task.ID)
	if len(r) != 1 || r[0].State != RunSucceeded {
		t.Fatalf("runs: %+v", r)
	}
	// Every device got exactly one restart, whichever batch it was in.
	if n := f.count(`SELECT count(*) FROM job_runs WHERE job_id = ANY($1)`, r[0].JobIDs); n != 6 {
		t.Fatalf("%d restarts for 6 devices", n)
	}
	if n := f.count(`SELECT count(DISTINCT device_id) FROM job_runs WHERE job_id = ANY($1)`, r[0].JobIDs); n != 6 {
		t.Fatalf("%d distinct devices", n)
	}
}

func TestSoftwareAndServiceSteps(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	f.device("lin-a")
	f.winDevice("win-a")

	sw, err := f.svc.Create(f.ctx, tech, f.action(StepSoftware, Step{Software: &jobs.Software{Action: jobs.ActionInstall, Manager: jobs.ManagerSystem, Package: "jq"}}))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := f.svc.Create(f.ctx, tech, f.action(StepService, Step{Action: jobs.MaintServiceRestart, Service: "cron", Platform: "linux"}))
	if err != nil {
		t.Fatal(err)
	}
	f.fireAt(due)
	r := f.runs(sw.ID)
	if len(r) != 1 || r[0].State != RunSucceeded || len(r[0].JobIDs) != 1 {
		t.Fatalf("software runs: %+v", r)
	}
	// A Linux package manager reaches the Linux device only.
	if n := f.count(`SELECT count(*) FROM job_runs WHERE job_id = $1`, r[0].JobIDs[0]); n != 1 {
		t.Fatalf("%d devices got the install", n)
	}
	if n := f.count(`SELECT count(*) FROM jobs WHERE id = $1 AND kind = 'software' AND software->>'package' = 'jq'`, r[0].JobIDs[0]); n != 1 {
		t.Fatal("not a software job")
	}
	r = f.runs(svc.ID)
	if len(r) != 1 || r[0].State != RunSucceeded || len(r[0].JobIDs) != 1 {
		t.Fatalf("service runs: %+v", r)
	}
	if n := f.count(`SELECT count(*) FROM jobs WHERE id = $1 AND maintenance->>'service' = 'cron' AND maintenance->>'action' = 'service_restart'`, r[0].JobIDs[0]); n != 1 {
		t.Fatal("not the service job")
	}
	// The install and the service restart on one device went out one after the other.
	if n := f.count(`SELECT count(*) FROM job_runs WHERE status = 'queued'`); n != 2 {
		t.Fatalf("%d queued runs", n)
	}
}

func TestStepChecks(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	sc := f.script(tech, "echo hi\n")
	bad := map[string]Input{
		"unknown kind":          f.action("format", Step{}),
		"software, no action":   f.action(StepSoftware, Step{}),
		"software, bad package": f.action(StepSoftware, Step{Software: &jobs.Software{Action: jobs.ActionInstall, Manager: jobs.ManagerSystem, Package: "-rf"}}),
		"service, no platform":  f.action(StepService, Step{Action: jobs.MaintServiceStop, Service: "x"}),
		"service, bad action":   f.action(StepService, Step{Action: "restart", Service: "x", Platform: "linux"}),
		"service, bad name":     f.action(StepService, Step{Action: jobs.MaintServiceStop, Service: "a b", Platform: "linux"}),
		"restart, bad platform": f.action(StepRestart, Step{Platform: "mac"}),
	}
	withScript := f.action(StepRestart, Step{})
	withScript.ScriptID = sc.ID
	bad["restart with a script"] = withScript
	for name, in := range bad {
		if _, err := f.svc.Create(f.ctx, tech, in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A script task still needs its script.
	if _, err := f.svc.Create(f.ctx, tech, Input{Name: "x", OrganizationID: f.acme, Schedule: daily()}); err == nil {
		t.Error("a script task without a script was accepted")
	}
}

func TestEditingAStep(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	sc := f.script(tech, "echo hi\n")
	script, err := f.svc.Create(f.ctx, tech, f.input(sc, daily()))
	if err != nil {
		t.Fatal(err)
	}
	task, err := f.svc.Create(f.ctx, tech, f.action(StepService, Step{Action: jobs.MaintServiceStart, Service: "cron", Platform: "linux"}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.Update(f.ctx, tech, task.ID, Patch{Step: &Step{Action: jobs.MaintServiceStop, Service: "atd", Platform: "linux"}})
	if err != nil || got.Step.Service != "atd" || got.Step.Action != jobs.MaintServiceStop {
		t.Fatalf("edited: %+v, %v", got, err)
	}
	if _, err := f.svc.Update(f.ctx, tech, task.ID, Patch{Step: &Step{Action: "bad", Service: "atd", Platform: "linux"}}); err == nil {
		t.Error("a bad step was saved")
	}
	if _, err := f.svc.Update(f.ctx, tech, task.ID, Patch{ScriptID: &sc.ID}); err == nil {
		t.Error("a script was put on a service task")
	}
	if _, err := f.svc.Update(f.ctx, tech, script.ID, Patch{Step: &Step{}}); err == nil {
		t.Error("a step was put on a script task")
	}
	// The script task is untouched by all this.
	if again, _ := f.svc.Get(f.ctx, tech, script.ID); again.ScriptID == nil || *again.ScriptID != sc.ID || again.StepKind != StepScript {
		t.Fatalf("script task: %+v", again)
	}
}

// The owner's permission for the step is checked again at each run: software
// needs software.manage, which losing stops the run.
func TestStepPermissionIsRecheckedAtTheRun(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	f.device("lin-a")
	ro := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	if _, err := f.svc.Create(f.ctx, ro, f.action(StepRestart, Step{})); err == nil {
		t.Fatal("a read-only user saved a restart")
	}
	task, err := f.svc.Create(f.ctx, tech, f.action(StepSoftware, Step{Software: &jobs.Software{Action: jobs.ActionUpgrade, Manager: jobs.ManagerSystem, Package: "jq"}}))
	if err != nil {
		t.Fatal(err)
	}
	// The owner is demoted to read-only before the run.
	f.principals[tech.Actor.ID] = ro.Principal
	f.fireAt(due)
	r := f.runs(task.ID)
	if len(r) != 1 || r[0].State != RunFailed || !strings.Contains(r[0].Detail, "manage software") || len(r[0].JobIDs) != 0 {
		t.Fatalf("runs: %+v", r)
	}
}
