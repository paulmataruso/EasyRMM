//go:build integration

package jobs

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func TestHardeningJobs(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	outsider := f.user("globex@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.globex})
	lnx := f.device(f.hq, "HQ-LNX", "linux")
	lnx2 := f.device(f.hq, "HQ-LNX2", "linux")
	win := f.device(f.hq, "HQ-WIN", "windows")
	meshOnly := f.device(f.hq, "HQ-MESH", "")

	in := HardeningInput{DeviceIDs: []uuid.UUID{lnx, lnx2}, Hardening: Hardening{
		Mode: HardeningCheck, Modules: []string{"firewall", "ssh"}, Options: HardeningOptions{AllowTCP: []string{"8443"}},
	}}
	job, err := f.svc.CreateHardeningJob(f.ctx, tech, in)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{"check", "ssh,firewall", "allow-tcp=8443"}
	if job.Kind != KindHardening || job.Hardening == nil || !slices.Equal(job.Hardening.Modules, []string{"ssh", "firewall"}) ||
		job.Software != nil || job.ScriptID != nil || job.ScriptName != "Check hardening: ssh, firewall" || job.Shell != agentproto.ShellSh ||
		job.Body != hardeningScript || job.ArgCount != len(wantArgs) || job.TimeoutSeconds != HardeningTimeout || job.Total != 2 {
		t.Errorf("job %+v", job)
	}
	if args, err := f.svc.ReadArguments(f.ctx, tech, job.ID); err != nil || !slices.Equal(args.Args, wantArgs) {
		t.Errorf("arguments %+v, %v", args, err)
	}

	// The agent gets EasyRMM's script, signed, with the choices as
	// arguments.
	resp, err := f.svc.Poll(f.ctx, lnx)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("poll %+v, %v", resp, err)
	}
	p, err := agentproto.VerifyJob(f.key, resp.Jobs[0], lnx.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.Script != hardeningScript || p.Shell != agentproto.ShellSh || !slices.Equal(p.Args, wantArgs) || p.TimeoutSeconds != HardeningTimeout {
		t.Errorf("payload %+v", p)
	}
	audited := f.str(`SELECT details::text FROM audit_log WHERE action = 'device.hardening' AND device_id = $1`, lnx)
	for _, s := range []string{`"mode": "check"`, `"modules": ["ssh", "firewall"]`, `"allowTcp": ["8443"]`, job.ID.String()} {
		if !strings.Contains(audited, s) {
			t.Errorf("audit %s lacks %s", audited, s)
		}
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'device.hardening'`); n != "2" {
		t.Errorf("%s audit records for two devices", n)
	}

	// Nothing is known until a run reports.
	h, err := f.svc.DeviceHardening(f.ctx, viewer, lnx)
	if err != nil || h.Platform != nil || h.CheckedAt != nil || len(h.Modules) != 0 {
		t.Errorf("before a result: %+v, %v", h, err)
	}

	runOf := func(j *Job, device uuid.UUID) uuid.UUID {
		t.Helper()
		got, err := f.svc.GetJob(f.ctx, tech, j.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range got.Runs {
			if r.DeviceID == device {
				return r.ID
			}
		}
		t.Fatalf("no run of job %s on %s", j.ID, device)
		return uuid.Nil
	}
	finish := func(device, run uuid.UUID, stdout string) {
		t.Helper()
		if _, err := f.svc.Start(f.ctx, device, run); err != nil {
			t.Fatal(err)
		}
		if err := f.svc.Result(f.ctx, device, run, agentproto.ResultRequest{
			Status: StatusSucceeded, ExitCode: ptr(0), Stdout: stdout, StartedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	platform := `{"id":"ubuntu","versionId":"24.04","family":"debian","container":"none","support":"full"}`
	line := func(sshState string) string {
		return HardeningResultPrefix + `{"version":1,"mode":"check","platform":` + platform + `,"modules":[` +
			`{"module":"ssh","state":"` + sshState + `","missing":["LoginGraceTime 30"],"changes":["Write 00-easyrmm-hardening.conf"]},` +
			`{"module":"firewall","state":"managed_elsewhere","reason":"ufw is active.","ports":{"tcp":["22","8443"]}}]}`
	}
	run1 := runOf(job, lnx)
	finish(lnx, run1, "Checking ssh\nChecking firewall\n"+line(HardeningPartly)+"\n")
	h, err = f.svc.DeviceHardening(f.ctx, viewer, lnx)
	if err != nil {
		t.Fatal(err)
	}
	if h.Platform == nil || h.Platform.ID != "ubuntu" || h.Platform.Support != "full" || h.JobID == nil || *h.JobID != job.ID || h.CheckedAt == nil ||
		len(h.Modules) != 2 || h.Modules[0].Module != "ssh" || h.Modules[0].State != HardeningPartly ||
		!slices.Equal(h.Modules[0].Missing, []string{"LoginGraceTime 30"}) || h.Modules[1].Module != "firewall" ||
		h.Modules[1].State != HardeningManagedElsewhere || h.Modules[1].Reason != "ufw is active." || h.Modules[1].Ports == nil ||
		!slices.Equal(h.Modules[1].Ports.TCP, []string{"22", "8443"}) || h.Modules[0].JobID == nil || *h.Modules[0].JobID != job.ID {
		t.Errorf("after a result: %+v", h)
	}
	if run, err := f.svc.GetRun(f.ctx, tech, run1); err != nil || run.Status != StatusSucceeded {
		t.Errorf("run %+v, %v", run, err)
	}

	// A later check of one module changes that module only.
	later, err := f.svc.CreateHardeningJob(f.ctx, tech, HardeningInput{DeviceIDs: []uuid.UUID{lnx}, Hardening: Hardening{
		Mode: HardeningCheck, Modules: []string{"ssh"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.now = func() time.Time { return time.Now().Add(time.Minute) }
	finish(lnx, runOf(later, lnx), HardeningResultPrefix+`{"version":1,"mode":"check","platform":`+platform+
		`,"modules":[{"module":"ssh","state":"in_place"}]}`)
	h, _ = f.svc.DeviceHardening(f.ctx, viewer, lnx)
	if len(h.Modules) != 2 || h.Modules[0].State != HardeningInPlace || len(h.Modules[0].Missing) != 0 || *h.Modules[0].JobID != later.ID ||
		h.Modules[1].State != HardeningManagedElsewhere || *h.Modules[1].JobID != job.ID || *h.JobID != later.ID {
		t.Errorf("after a check of ssh: %+v", h)
	}

	// A result that cannot be read fails the run and keeps nothing.
	run2 := runOf(job, lnx2)
	finish(lnx2, run2, "Checking ssh\n"+HardeningResultPrefix+`{"version":1,"mode":"check","platform":`+platform+
		`,"modules":[{"module":"ssh","state":"hardened"}]}`)
	run, err := f.svc.GetRun(f.ctx, tech, run2)
	if err != nil || run.Status != StatusFailed || !strings.Contains(run.Error, "could not be read") || !strings.Contains(run.Error, "unknown state") {
		t.Errorf("run with a bad result %+v, %v", run, err)
	}
	if h, _ := f.svc.DeviceHardening(f.ctx, tech, lnx2); h.Platform != nil || len(h.Modules) != 0 {
		t.Errorf("a bad result was kept: %+v", h)
	}

	// A run that failed reports nothing to keep, even with a result line.
	failing, err := f.svc.CreateHardeningJob(f.ctx, tech, HardeningInput{DeviceIDs: []uuid.UUID{lnx2}, Hardening: Hardening{
		Mode: HardeningCheck, Modules: []string{"ssh", "firewall"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	fr := runOf(failing, lnx2)
	if _, err := f.svc.Start(f.ctx, lnx2, fr); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Result(f.ctx, lnx2, fr, agentproto.ResultRequest{Status: StatusFailed, ExitCode: ptr(2), Stdout: line(HardeningInPlace)}); err != nil {
		t.Fatal(err)
	}
	if h, _ := f.svc.DeviceHardening(f.ctx, tech, lnx2); h.Platform != nil {
		t.Errorf("a failed run's result was kept: %+v", h)
	}

	// Script jobs are not read as hardening results.
	orgAdmin := f.user("orgadmin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	sc, err := f.svc.CreateScript(f.ctx, orgAdmin, ScriptInput{OrganizationID: &f.acme, Name: "Echo", Shell: "sh", Body: "echo", TimeoutSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	sj, err := f.svc.CreateJob(f.ctx, tech, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{lnx2}})
	if err != nil {
		t.Fatal(err)
	}
	sr := runOf(sj, lnx2)
	finish(lnx2, sr, line(HardeningInPlace))
	if run, _ := f.svc.GetRun(f.ctx, tech, sr); run.Status != StatusSucceeded {
		t.Errorf("a script job's run %+v", run)
	}
	if h, _ := f.svc.DeviceHardening(f.ctx, tech, lnx2); h.Platform != nil {
		t.Errorf("a script job's output was read as a hardening result: %+v", h)
	}

	// Who may see and start what.
	if _, err := f.svc.DeviceHardening(f.ctx, outsider, lnx); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization's device: %v", err)
	}
	for _, r := range []struct {
		in   HardeningInput
		want string
	}{
		{HardeningInput{DeviceIDs: []uuid.UUID{win}, Hardening: Hardening{Mode: HardeningCheck, Modules: []string{"ssh"}}},
			"Hardening runs on Linux; HQ-WIN is not a Linux device."},
		{HardeningInput{DeviceIDs: []uuid.UUID{meshOnly}, Hardening: Hardening{Mode: HardeningCheck, Modules: []string{"ssh"}}},
			"HQ-MESH has no EasyRMM agent to check hardening."},
	} {
		_, err := f.svc.CreateHardeningJob(f.ctx, tech, r.in)
		fieldErr(t, err, "deviceIds", r.want)
	}
	_, err = f.svc.CreateHardeningJob(f.ctx, viewer, HardeningInput{DeviceIDs: []uuid.UUID{lnx}, Hardening: Hardening{Mode: HardeningCheck, Modules: []string{"ssh"}}})
	fieldErr(t, err, "deviceIds", "You cannot check hardening on HQ-LNX.")
	// Apply and undo need device.harden: Site Administrators and above.
	for _, mode := range []string{HardeningApply, HardeningUndo} {
		_, err = f.svc.CreateHardeningJob(f.ctx, tech, HardeningInput{DeviceIDs: []uuid.UUID{lnx}, Hardening: Hardening{Mode: mode, Modules: []string{"ssh"}}})
		fieldErr(t, err, "deviceIds", "You cannot "+mode+" hardening on HQ-LNX.")
	}
	_, err = f.svc.CreateHardeningJob(f.ctx, tech, HardeningInput{DeviceIDs: []uuid.UUID{lnx}, Hardening: Hardening{Mode: "harden", Modules: []string{"ssh"}}})
	fieldErr(t, err, "mode", "check, apply or undo")
	_, err = f.svc.CreateHardeningJob(f.ctx, tech, HardeningInput{DeviceIDs: []uuid.UUID{lnx}, Hardening: Hardening{Mode: HardeningCheck, Modules: []string{"ssh"}}, WaitHours: 1000})
	fieldErr(t, err, "waitHours", "")

	list, err := f.svc.ListJobs(f.ctx, tech, JobQuery{Kind: KindHardening})
	if err != nil {
		t.Fatal(err)
	}
	var ids []uuid.UUID
	for _, j := range list {
		ids = append(ids, j.ID)
	}
	if !slices.Equal(ids, []uuid.UUID{failing.ID, later.ID, job.ID}) {
		t.Errorf("hardening jobs %v", ids)
	}

	// A Site Administrator applies and undoes; what each run did is kept
	// with the check that followed it.
	siteAdmin := f.user("siteadmin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	_, err = f.svc.CreateHardeningJob(f.ctx, siteAdmin, HardeningInput{DeviceIDs: []uuid.UUID{meshOnly}, Hardening: Hardening{Mode: HardeningApply, Modules: []string{"ssh"}}})
	fieldErr(t, err, "deviceIds", "HQ-MESH has no EasyRMM agent to apply hardening.")
	applied, err := f.svc.CreateHardeningJob(f.ctx, siteAdmin, HardeningInput{DeviceIDs: []uuid.UUID{lnx}, Hardening: Hardening{
		Mode: HardeningApply, Modules: []string{"firewall", "ssh"}, Options: HardeningOptions{AllowTCP: []string{"443"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if applied.ScriptName != "Apply hardening: ssh, firewall" || applied.ArgCount != 3 {
		t.Errorf("apply job %+v", applied)
	}
	if args, err := f.svc.ReadArguments(f.ctx, siteAdmin, applied.ID); err != nil || !slices.Equal(args.Args, []string{"apply", "ssh,firewall", "allow-tcp=443"}) {
		t.Errorf("apply job's arguments %+v, %v", args, err)
	}
	f.svc.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	finish(lnx, runOf(applied, lnx), HardeningResultPrefix+`{"version":1,"mode":"apply","platform":`+platform+`,"modules":[`+
		`{"module":"ssh","state":"in_place","outcome":"applied","done":["Wrote 00-easyrmm-hardening.conf","Reloaded ssh.service"],"recorded":true},`+
		`{"module":"firewall","state":"managed_elsewhere","reason":"ufw is active.","outcome":"skipped","outcomeReason":"ufw is active."}]}`)
	h, _ = f.svc.DeviceHardening(f.ctx, viewer, lnx)
	if len(h.Modules) != 2 || h.Modules[0].State != HardeningInPlace || h.Modules[0].Outcome != HardeningApplied || !h.Modules[0].Recorded ||
		!slices.Equal(h.Modules[0].Done, []string{"Wrote 00-easyrmm-hardening.conf", "Reloaded ssh.service"}) ||
		h.Modules[1].Outcome != HardeningSkipped || h.Modules[1].OutcomeReason != "ufw is active." || *h.JobID != applied.ID {
		t.Errorf("after apply: %+v", h)
	}
	_, err = f.svc.CreateHardeningJob(f.ctx, siteAdmin, HardeningInput{DeviceIDs: []uuid.UUID{lnx}, Hardening: Hardening{
		Mode: HardeningUndo, Modules: []string{"ssh"}, Options: HardeningOptions{AllowTCP: []string{"443"}},
	}})
	fieldErr(t, err, "options", "no options")
	undone, err := f.svc.CreateHardeningJob(f.ctx, siteAdmin, HardeningInput{DeviceIDs: []uuid.UUID{lnx}, Hardening: Hardening{Mode: HardeningUndo, Modules: []string{"ssh"}}})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.now = func() time.Time { return time.Now().Add(3 * time.Minute) }
	finish(lnx, runOf(undone, lnx), HardeningResultPrefix+`{"version":1,"mode":"undo","platform":`+platform+`,"modules":[`+
		`{"module":"ssh","state":"partly","missing":["LoginGraceTime 30"],"outcome":"undone","done":["Removed 00-easyrmm-hardening.conf"]}]}`)
	h, _ = f.svc.DeviceHardening(f.ctx, viewer, lnx)
	if len(h.Modules) != 2 || h.Modules[0].Outcome != HardeningUndone || h.Modules[0].Recorded || h.Modules[0].State != HardeningPartly ||
		h.Modules[1].Outcome != HardeningSkipped || *h.Modules[1].JobID != applied.ID {
		t.Errorf("after undo: %+v", h)
	}
	audited = f.str(`SELECT details::text FROM audit_log WHERE action = 'device.hardening' AND details->>'jobId' = $1`, undone.ID.String())
	if !strings.Contains(audited, `"mode": "undo"`) {
		t.Errorf("undo audit %s", audited)
	}

	// Removing a device removes what was found on it.
	f.asOwner(`DELETE FROM devices WHERE id = $1`, lnx)
	if n := f.str(`SELECT (SELECT count(*) FROM device_hardening) + (SELECT count(*) FROM device_hardening_checks)`); n != "0" {
		t.Errorf("%s rows left for a removed device", n)
	}
}
