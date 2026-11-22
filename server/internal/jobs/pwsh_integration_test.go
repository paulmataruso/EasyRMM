//go:build integration

package jobs

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// TestPwshScripts: the pwsh shell and its fallback setting, which only a
// pwsh script has and which goes when the shell changes (ADR-0064).
func TestPwshScripts(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})

	_, err := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Bad", Shell: "powershell", PwshFallback: true, Body: "x"})
	fieldErr(t, err, "pwshFallback", "Only a PowerShell 7 script")
	strict, err := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Strict", Shell: "pwsh", Body: "$PSVersionTable"})
	if err != nil || strict.Shell != "pwsh" || strict.PwshFallback {
		t.Fatalf("a pwsh script: %+v %v", strict, err)
	}
	both, err := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Both", Shell: "pwsh", PwshFallback: true, Body: "Get-Date"})
	if err != nil || !both.PwshFallback {
		t.Fatalf("a pwsh script that falls back: %+v %v", both, err)
	}
	if d := f.str(`SELECT details->>'pwshFallback' FROM audit_log WHERE action = 'script.create' AND target_id = $1`, both.ID.String()); d != "true" {
		t.Errorf("the create record's fallback = %q", d)
	}
	_, err = f.svc.UpdateScript(f.ctx, super, strict.ID, ScriptPatch{Shell: ptr("cmd"), PwshFallback: ptr(true)})
	fieldErr(t, err, "pwshFallback", "Only a PowerShell 7 script")
	moved, err := f.svc.UpdateScript(f.ctx, super, both.ID, ScriptPatch{Shell: ptr("powershell")})
	if err != nil || moved.Shell != "powershell" || moved.PwshFallback {
		t.Fatalf("changing the shell keeps the fallback: %+v %v", moved, err)
	}
	back, err := f.svc.UpdateScript(f.ctx, super, both.ID, ScriptPatch{Shell: ptr("pwsh"), PwshFallback: ptr(true)})
	if err != nil || !back.PwshFallback {
		t.Fatalf("back to pwsh with the fallback: %+v %v", back, err)
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'script.update' AND details->'changes' ? 'pwshFallback'`); n != "2" {
		t.Errorf("%s updates recorded the fallback, want 2", n)
	}
	if got, _ := f.svc.GetScript(f.ctx, super, both.ID); !got.PwshFallback {
		t.Errorf("read back %+v", got)
	}
}

// TestPwshJobsFollowWhatThePollAccepts: a pwsh job is created only for
// devices whose agent's build said it accepts job.pwsh; its run is
// delivered only to a poll that lists it, waits and says why otherwise, and
// expires with that reason. The program the agent reports is kept on the
// run and shown to everyone who sees it.
func TestPwshJobsFollowWhatThePollAccepts(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	reader := f.user("reader@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme, SiteID: f.hq})
	strict, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Strict", Shell: "pwsh", Body: "$PSVersionTable"})
	both, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Both", Shell: "pwsh", PwshFallback: true, Body: "Get-Date"})
	classic, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Classic", Shell: "powershell", Body: "Get-Date"})
	pc12, pc13, pc14 := f.device(f.hq, "PC-12", "windows"), f.device(f.hq, "PC-13", "windows"), f.device(f.hq, "PC-14", "windows")

	try := func(sc *Script, devices ...uuid.UUID) error {
		_, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: devices})
		return err
	}
	poll := func(dev uuid.UUID, accepts []string) *agentproto.PollResponse {
		t.Helper()
		resp, err := f.svc.Poll(f.ctx, dev, accepts)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	accepts := func(dev uuid.UUID) string {
		return f.str(`SELECT coalesce(array_to_string(agent_accepts, ','), 'null') FROM devices WHERE id = $1`, dev)
	}

	// Not reported yet: refused, one device or several.
	fieldErr(t, try(strict, pc12), "deviceIds", "PC-12's agent has not yet said whether it can run PowerShell 7 scripts; try again in a minute, and update the agent if it still has not.")
	fieldErr(t, try(strict, pc12, pc13), "deviceIds", "The agents of PC-12 and PC-13 have not yet said whether they can run PowerShell 7 scripts")
	// A poll with an empty list says the agent cannot; one without a list
	// leaves that as it was.
	poll(pc12, []string{})
	poll(pc12, nil)
	if a := accepts(pc12); a != "" {
		t.Errorf("PC-12 accepts %q", a)
	}
	fieldErr(t, try(strict, pc12), "deviceIds", "PC-12's agent cannot run PowerShell 7 scripts; update the agent.")
	poll(pc14, []string{})
	fieldErr(t, try(strict, pc12, pc14), "deviceIds", "The agents of PC-12 and PC-14 cannot run PowerShell 7 scripts; update them.")
	// Names are cleaned, sorted and kept once.
	poll(pc13, []string{"job.pwsh", "Bad Name", "job.pwsh", "future.thing", strings.Repeat("x", agentproto.MaxAcceptLen+1)})
	if a := accepts(pc13); a != "future.thing,job.pwsh" {
		t.Errorf("PC-13 accepts %q", a)
	}
	if n := f.str(`SELECT count(*)::text FROM jobs`); n != "0" {
		t.Fatalf("%s refused jobs stored", n)
	}
	// Other shells need nothing.
	if err := try(classic, pc12); err != nil {
		t.Errorf("a Windows PowerShell job for an agent without job.pwsh: %v", err)
	}

	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: both.ID, DeviceIDs: []uuid.UUID{pc13}})
	if err != nil || job.Shell != "pwsh" || !job.PwshFallback {
		t.Fatalf("a pwsh job: %+v %v", job, err)
	}
	if r := f.str(`SELECT array_to_string(requires, ',') FROM jobs WHERE id = $1`, job.ID); r != "job.pwsh" {
		t.Errorf("the job requires %q", r)
	}
	if d := f.str(`SELECT details->>'pwshFallback' FROM audit_log WHERE action = 'device.script_run' AND details->>'jobId' = $1`, job.ID.String()); d != "true" {
		t.Errorf("the run's record says fallback %q", d)
	}
	run := job.Runs[0].ID
	held := func(c access.Caller) string {
		t.Helper()
		r, err := f.svc.GetRun(f.ctx, c, run)
		if err != nil {
			t.Fatal(err)
		}
		return r.Held
	}
	if h := held(reader); h != "" {
		t.Errorf("a run its device can take is held: %q", h)
	}

	// The heartbeat names another build: the list counts as not reported.
	f.exec(`UPDATE devices SET agent_sha256 = $2 WHERE id = $1`, pc13, strings.Repeat("a", 64))
	if h := held(reader); h != HeldUnreported {
		t.Errorf("held = %q, want %q", h, HeldUnreported)
	}
	fieldErr(t, try(strict, pc13), "deviceIds", "PC-13's agent has not yet said")
	// A poll without the list leaves the run queued; an empty list holds it.
	if resp := poll(pc13, nil); len(resp.Jobs) != 0 {
		t.Fatal("a pwsh run went to a poll without job.pwsh")
	}
	if resp := poll(pc13, []string{}); len(resp.Jobs) != 0 {
		t.Fatal("a pwsh run went to a poll that does not accept it")
	}
	if h := held(super); h != HeldUnable {
		t.Errorf("held = %q, want %q", h, HeldUnable)
	}
	resp := poll(pc13, []string{agentproto.CapJobPwsh})
	if len(resp.Jobs) != 1 {
		t.Fatalf("the poll that accepts it got %d jobs", len(resp.Jobs))
	}
	p, err := agentproto.VerifyJob(f.key, resp.Jobs[0], pc13.String(), time.Now())
	if err != nil || p.Shell != "pwsh" || !p.PwshFallback || p.RunID != run.String() {
		t.Fatalf("payload %+v %v", p, err)
	}
	if h := held(reader); h != "" {
		t.Errorf("a delivered run is held: %q", h)
	}

	// The program the agent started is kept, and shown to Read-Only.
	if st, err := f.svc.Start(f.ctx, pc13, run); err != nil || !st.Proceed {
		t.Fatalf("start %+v %v", st, err)
	}
	zero := 0
	desktop := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	if err := f.svc.Result(f.ctx, pc13, run, agentproto.ResultRequest{Status: StatusSucceeded, ExitCode: &zero, Interpreter: &agentproto.Interpreter{
		Edition: agentproto.EditionDesktop, Version: "5.1.26100.7462", Arch: agentproto.ArchX64, Path: desktop, Fallback: true,
	}}); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.GetRun(f.ctx, reader, run)
	if err != nil {
		t.Fatal(err)
	}
	want := Program{Edition: "Desktop", Version: "5.1.26100.7462", Arch: "x64", Path: desktop, Fallback: true}
	if got.Program == nil || *got.Program != want || got.CanViewOutput {
		t.Errorf("program %+v, output visible %v", got.Program, got.CanViewOutput)
	}
	csv, err := f.svc.ResultsCSV(f.ctx, reader, job.ID)
	if err != nil || !strings.Contains(string(csv.Body), "Program,Program version,Program architecture,Program path,Run") ||
		!strings.Contains(string(csv.Body), `,Windows PowerShell (PowerShell 7 was not found),5.1.26100.7462,x64,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,`+run.String()) {
		t.Errorf("results CSV %v:\n%s", err, csv.Body)
	}

	// A result without a program: not reported. One with odd values: cleaned.
	other, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: classic.ID, DeviceIDs: []uuid.UUID{pc12, pc14}})
	if err != nil {
		t.Fatal(err)
	}
	poll(pc12, nil)
	poll(pc14, nil)
	runOn := func(dev uuid.UUID) uuid.UUID {
		return f.id(`SELECT id FROM job_runs WHERE job_id = $1 AND device_id = $2`, other.ID, dev)
	}
	for _, dev := range []uuid.UUID{pc12, pc14} {
		if st, _ := f.svc.Start(f.ctx, dev, runOn(dev)); !st.Proceed {
			t.Fatal("a Windows PowerShell run did not start")
		}
	}
	if err := f.svc.Result(f.ctx, pc12, runOn(pc12), agentproto.ResultRequest{Status: StatusSucceeded, ExitCode: &zero}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Result(f.ctx, pc14, runOn(pc14), agentproto.ResultRequest{Status: StatusSucceeded, ExitCode: &zero, Interpreter: &agentproto.Interpreter{
		Edition: "Core", Version: "7.6.10\x00" + strings.Repeat("9", 100), Arch: "mips", Path: `C:\Program Files\PowerShell\7\pwsh.exe`, Fallback: true,
	}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.svc.GetRun(f.ctx, reader, runOn(pc12)); got.Program != nil {
		t.Errorf("a run without a program: %+v", got.Program)
	}
	if got, _ := f.svc.GetRun(f.ctx, reader, runOn(pc14)); got.Program == nil || got.Program.Arch != "" || got.Program.Fallback ||
		len(got.Program.Version) != agentproto.MaxInterpreterVersion || !strings.HasPrefix(got.Program.Version, "7.6.10999") {
		t.Errorf("a cleaned program: %+v", got.Program)
	}
	csv, _ = f.svc.ResultsCSV(f.ctx, reader, other.ID)
	if !strings.Contains(string(csv.Body), ",Not reported by this agent's version,,,,") || !strings.Contains(string(csv.Body), `,PowerShell,7.6.10999`) {
		t.Errorf("results CSV:\n%s", csv.Body)
	}

	// A run held for job.pwsh expires with that reason.
	poll(pc13, []string{agentproto.CapJobPwsh})
	held2, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: strict.ID, DeviceIDs: []uuid.UUID{pc13}})
	if err != nil {
		t.Fatal(err)
	}
	poll(pc13, []string{})
	plain, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: classic.ID, DeviceIDs: []uuid.UUID{pc12}})
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE job_runs SET expires_at = now() - interval '1 second' WHERE job_id IN ($1, $2)`, held2.ID, plain.ID)
	if swept, err := f.svc.Sweep(f.ctx); err != nil || swept.Expired != 2 {
		t.Fatalf("sweep %+v %v", swept, err)
	}
	if e := f.str(`SELECT error FROM job_runs WHERE job_id = $1`, held2.ID); !strings.Contains(e, "cannot run PowerShell 7 scripts, so the run waited until it expired") {
		t.Errorf("held run expired with %q", e)
	}
	if e := f.str(`SELECT error FROM job_runs WHERE job_id = $1`, plain.ID); e != "The device did not pick up the job before it expired." {
		t.Errorf("another run expired with %q", e)
	}
}

// TestUnreportedListExpires: a run held because the device's build has not
// said what it accepts expires saying so.
func TestUnreportedListExpires(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	strict, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Strict", Shell: "pwsh", Body: "$PSVersionTable"})
	pc := f.device(f.hq, "PC-12", "windows")
	if _, err := f.svc.Poll(f.ctx, pc, []string{agentproto.CapJobPwsh}); err != nil {
		t.Fatal(err)
	}
	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: strict.ID, DeviceIDs: []uuid.UUID{pc}})
	if err != nil {
		t.Fatal(err)
	}
	// An update: the new build has not polled yet.
	f.exec(`UPDATE devices SET agent_version = '1.1.0' WHERE id = $1`, pc)
	f.exec(`UPDATE job_runs SET expires_at = now() - interval '1 second' WHERE job_id = $1`, job.ID)
	if _, err := f.svc.Sweep(f.ctx); err != nil {
		t.Fatal(err)
	}
	if e := f.str(`SELECT error FROM job_runs WHERE job_id = $1`, job.ID); !strings.Contains(e, "did not say whether it can run PowerShell 7 scripts") {
		t.Errorf("expired with %q", e)
	}
}
