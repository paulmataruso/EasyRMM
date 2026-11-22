//go:build integration

package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func windowsFacts(host, version string) agentproto.Facts {
	return agentproto.Facts{Hostname: host, OS: "Microsoft Windows Server 2025 Datacenter", Platform: "windows", Arch: "amd64", AgentVersion: version}
}

// TestPowerShell7API runs a PowerShell 7 script through the console API and
// the agent API with signed requests (ADR-0064): the poll's accepts kept
// for the build that sent it and deciding what is delivered and what may be
// created, the program a run used shown to Read-Only, the PowerShell
// installs an inventory reports, and what the device says of them: usable,
// or blocked and why.
func TestPowerShell7API(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	ctx := context.Background()
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	pc := enrollAt(t, h, admin, hq.ID, "pc-12")
	beat := func(version string) {
		t.Helper()
		if _, err := pc.ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: windowsFacts("pc-12", version)}); err != nil {
			t.Fatal(err)
		}
	}
	poll := func(accepts []string) *agentproto.PollResponse {
		t.Helper()
		resp, err := pc.ac.Poll(ctx, accepts)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	// report polls only to say what the agent accepts: a poll without work
	// is held for agentproto.PollWait, so it is let go after a second.
	report := func(accepts []string) {
		t.Helper()
		short, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if resp, err := pc.ac.Poll(short, accepts); err == nil && len(resp.Jobs) > 0 {
			t.Fatalf("a poll got %+v", resp)
		} else if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	}
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")

	type deviceView struct {
		Agent *struct {
			Accepts            []string `json:"accepts"`
			PowerShell7        *bool    `json:"powerShell7"`
			PowerShell7Blocked string   `json:"powerShell7Blocked"`
		} `json:"agent"`
	}
	device := func() deviceView {
		t.Helper()
		var d deviceView
		viewer.expect(http.StatusOK, "GET", "/api/v1/devices/"+pc.id, nil, &d)
		if d.Agent == nil {
			t.Fatal("no agent")
		}
		return d
	}

	// --- Scripts ---------------------------------------------------------
	type script struct {
		ID           string `json:"id"`
		Shell        string `json:"shell"`
		PwshFallback bool   `json:"pwshFallback"`
	}
	var sc script
	admin.expect(http.StatusCreated, "POST", "/api/v1/scripts", map[string]any{"name": "Seven", "shell": "pwsh", "pwshFallback": true,
		"body": "param($Name)\nWrite-Output \"hello $Name\""}, &sc)
	if sc.Shell != "pwsh" || !sc.PwshFallback {
		t.Fatalf("created %+v", sc)
	}
	r := admin.do("POST", "/api/v1/scripts", map[string]any{"name": "Five", "shell": "powershell", "pwshFallback": true, "body": "x"})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
	if !strings.Contains(string(r.body), "Only a PowerShell 7 script can fall back to Windows PowerShell 5.1.") {
		t.Errorf("a fallback for Windows PowerShell: %s", r.body)
	}
	var strict script
	admin.expect(http.StatusCreated, "POST", "/api/v1/scripts", map[string]any{"name": "Strict", "shell": "pwsh", "body": "exit 3"}, &strict)
	if strict.PwshFallback {
		t.Errorf("the fallback is on by default: %+v", strict)
	}

	// --- Before the agent says what it accepts ---------------------------
	// Its first poll goes out before any heartbeat answer and says nothing.
	report([]string{agentproto.CapJobPwsh})
	beat("1.2.3-test")
	if d := device(); d.Agent.Accepts != nil || d.Agent.PowerShell7 != nil {
		t.Errorf("before any list or inventory: %+v", d.Agent)
	}
	r = admin.do("POST", "/api/v1/jobs", map[string]any{"scriptId": sc.ID, "deviceIds": []string{pc.id}})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
	if !strings.Contains(string(r.body), "pc-12's agent has not yet said whether it can run PowerShell 7 scripts") {
		t.Errorf("before the list: %s", r.body)
	}

	// --- It accepts pwsh jobs -------------------------------------------
	report([]string{agentproto.CapJobPwsh})
	if d := device(); !slices.Equal(d.Agent.Accepts, []string{agentproto.CapJobPwsh}) {
		t.Errorf("accepts %+v", d.Agent.Accepts)
	}
	inv, err := json.Marshal(agentproto.Inventory{OS: agentproto.OSInfo{ID: "windows", Name: "Windows Server 2025"}, PowerShell: []agentproto.PowerShellInstall{
		{Edition: agentproto.EditionDesktop, Version: "5.1.26100.7019", Arch: "x64", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Usable: true},
		{Edition: agentproto.EditionCore, Version: "7.6.10", Arch: "x64", Path: `C:\Program Files\PowerShell\7\pwsh.exe`, Usable: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.ac.Inventory(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if d := device(); d.Agent.PowerShell7 == nil || !*d.Agent.PowerShell7 || d.Agent.PowerShell7Blocked != "" {
		t.Errorf("powerShell7 %v %q", d.Agent.PowerShell7, d.Agent.PowerShell7Blocked)
	}
	var invView struct {
		Inventory struct {
			PowerShell []agentproto.PowerShellInstall `json:"powerShell"`
		} `json:"inventory"`
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/devices/"+pc.id+"/inventory", nil, &invView)
	if ps := invView.Inventory.PowerShell; len(ps) != 2 || ps[1].Version != "7.6.10" || !ps[1].Usable {
		t.Errorf("inventory's PowerShell %+v", ps)
	}

	var job jobView
	admin.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{"scriptId": sc.ID, "deviceIds": []string{pc.id}, "args": []string{"Ada"}}, &job)
	got := poll([]string{agentproto.CapJobPwsh})
	if len(got.Jobs) != 1 {
		t.Fatalf("poll %+v", got)
	}
	p, err := agentproto.VerifyJob(pc.key, got.Jobs[0], pc.id, time.Now())
	if err != nil || p.Shell != agentproto.ShellPwsh || !p.PwshFallback {
		t.Fatalf("payload %+v %v", p, err)
	}
	if st, err := pc.ac.Start(ctx, p.RunID); err != nil || !st.Proceed {
		t.Fatalf("start %+v %v", st, err)
	}
	zero := 0
	if err := pc.ac.Result(ctx, p.RunID, agentproto.ResultRequest{Status: agentproto.RunSucceeded, ExitCode: &zero, Stdout: "hello Ada\n",
		Interpreter: &agentproto.Interpreter{Edition: agentproto.EditionCore, Version: "7.6.10", Arch: agentproto.ArchX64, Path: `C:\Program Files\PowerShell\7\pwsh.exe`}}); err != nil {
		t.Fatal(err)
	}
	type runProgram struct {
		Status  string `json:"status"`
		Held    string `json:"held"`
		Program *struct {
			Edition  string `json:"edition"`
			Version  string `json:"version"`
			Arch     string `json:"arch"`
			Path     string `json:"path"`
			Fallback bool   `json:"fallback"`
		} `json:"program"`
		Job *struct {
			Shell        string `json:"shell"`
			PwshFallback bool   `json:"pwshFallback"`
		} `json:"job"`
	}
	var run runProgram
	viewer.expect(http.StatusOK, "GET", "/api/v1/job-runs/"+p.RunID, nil, &run)
	if run.Status != "succeeded" || run.Program == nil || run.Program.Edition != "Core" || run.Program.Version != "7.6.10" || run.Program.Arch != "x64" ||
		run.Program.Path != `C:\Program Files\PowerShell\7\pwsh.exe` || run.Program.Fallback || run.Held != "" {
		t.Errorf("run for Read-Only %+v %+v", run, run.Program)
	}
	if run.Job == nil || run.Job.Shell != "pwsh" || !run.Job.PwshFallback {
		t.Errorf("the run's job %+v", run.Job)
	}
	var jobRuns struct {
		Runs []runProgram `json:"runs"`
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/jobs/"+job.ID, nil, &jobRuns)
	if len(jobRuns.Runs) != 1 || jobRuns.Runs[0].Program == nil || jobRuns.Runs[0].Program.Version != "7.6.10" {
		t.Errorf("the job's runs %+v", jobRuns.Runs)
	}
	csv := viewer.do("GET", "/api/v1/jobs/"+job.ID+"/runs.csv", nil)
	if csv.status != http.StatusOK || !strings.Contains(string(csv.body), `,PowerShell,7.6.10,x64,C:\Program Files\PowerShell\7\pwsh.exe,`) {
		t.Errorf("results %d %s", csv.status, csv.body)
	}

	// --- A poll with an empty list replaces it; one without leaves it ----
	report([]string{})
	report(nil)
	if d := device(); d.Agent.Accepts == nil || len(d.Agent.Accepts) != 0 {
		t.Errorf("after an empty list: %+v", d.Agent.Accepts)
	}
	r = admin.do("POST", "/api/v1/jobs", map[string]any{"scriptId": strict.ID, "deviceIds": []string{pc.id}})
	wantStatus(t, r, http.StatusUnprocessableEntity, "validation_failed")
	if !strings.Contains(string(r.body), "pc-12's agent cannot run PowerShell 7 scripts; update the agent.") {
		t.Errorf("an agent that cannot: %s", r.body)
	}

	// --- A run waiting for an agent that stopped accepting pwsh ----------
	report([]string{agentproto.CapJobPwsh})
	job = jobView{}
	admin.expect(http.StatusCreated, "POST", "/api/v1/jobs", map[string]any{"scriptId": strict.ID, "deviceIds": []string{pc.id}}, &job)
	report([]string{})
	viewer.expect(http.StatusOK, "GET", "/api/v1/job-runs/"+job.Runs[0].ID, nil, &run)
	if run.Status != "queued" || run.Held != "unable" || run.Program != nil {
		t.Errorf("held run %+v", run)
	}
	// Another build: what the last one said no longer counts.
	beat("1.2.4-test")
	viewer.expect(http.StatusOK, "GET", "/api/v1/job-runs/"+job.Runs[0].ID, nil, &run)
	if d := device(); run.Held != "unreported" || d.Agent.Accepts != nil {
		t.Errorf("after an update: held %q, accepts %+v", run.Held, d.Agent.Accepts)
	}
	// The new build accepts it, and gets it.
	got = poll([]string{agentproto.CapJobPwsh})
	if len(got.Jobs) != 1 {
		t.Fatalf("not delivered once accepted: %+v", got)
	}
	run = runProgram{}
	viewer.expect(http.StatusOK, "GET", "/api/v1/job-runs/"+job.Runs[0].ID, nil, &run)
	if run.Status != "sent" || run.Held != "" {
		t.Errorf("delivered: %+v", run)
	}

	// --- PowerShell 7 found, but what it loads fails the agent's check -----
	why := `PowerShell 7 would load modules from C:\Program Files\PowerShell\Modules, and C:\Program Files\PowerShell\Modules\Tools ` +
		`can be changed by BUILTIN\Users: not used, since what it loads must be changeable by administrators only. ` +
		`Scripts that allow Windows PowerShell 5.1 do not run in it instead.`
	inv, err = json.Marshal(agentproto.Inventory{OS: agentproto.OSInfo{ID: "windows", Name: "Windows Server 2025"}, PowerShell: []agentproto.PowerShellInstall{
		{Edition: agentproto.EditionDesktop, Version: "5.1.26100.7019", Arch: "x64", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Usable: true},
		{Edition: agentproto.EditionCore, Version: "7.6.10", Arch: "x64", Path: `C:\Program Files\PowerShell\7\pwsh.exe`, Blocked: true, Reason: why},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.ac.Inventory(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if d := device(); d.Agent.PowerShell7 == nil || *d.Agent.PowerShell7 || d.Agent.PowerShell7Blocked != why {
		t.Errorf("blocked: powerShell7 %v %q", d.Agent.PowerShell7, d.Agent.PowerShell7Blocked)
	}
	viewer.expect(http.StatusOK, "GET", "/api/v1/devices/"+pc.id+"/inventory", nil, &invView)
	if ps := invView.Inventory.PowerShell; len(ps) != 2 || ps[1].Usable || !ps[1].Blocked || ps[1].Reason != why {
		t.Errorf("inventory's blocked PowerShell %+v", ps)
	}
}
