//go:build integration

package jobs

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func TestSoftwareJobs(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	lnx := f.device(f.hq, "HQ-LNX", "linux")
	win := f.device(f.hq, "HQ-WIN", "windows")
	meshOnly := f.device(f.hq, "HQ-MESH", "")
	branch := f.device(f.branch, "BR-LNX", "linux")

	job, err := f.svc.CreateSoftwareJob(f.ctx, tech, SoftwareInput{
		DeviceIDs: []uuid.UUID{lnx}, Software: Software{Action: ActionInstall, Manager: ManagerSystem, Package: "jq", Version: "1.7.1-3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Software{Action: ActionInstall, Manager: ManagerSystem, Package: "jq", Version: "1.7.1-3"}
	if job.Kind != KindSoftware || job.Software == nil || *job.Software != want || job.ScriptID != nil || job.ScriptName != "Install jq 1.7.1-3" ||
		job.Shell != agentproto.ShellSh || job.Body != linuxScript || !slices.Equal(job.Args, []string{"install", "jq", "1.7.1-3"}) ||
		job.TimeoutSeconds != DefaultSoftwareTimeout || job.Total != 1 {
		t.Errorf("job %+v", job)
	}

	// The agent gets EasyRMM's script, signed, with the package as an argument.
	resp, err := f.svc.Poll(f.ctx, lnx)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("poll %+v, %v", resp, err)
	}
	p, err := agentproto.VerifyJob(f.key, resp.Jobs[0], lnx.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.Script != linuxScript || p.Shell != agentproto.ShellSh || !slices.Equal(p.Args, []string{"install", "jq", "1.7.1-3"}) || p.TimeoutSeconds != DefaultSoftwareTimeout {
		t.Errorf("payload %+v", p)
	}
	run, err := f.svc.GetRun(f.ctx, tech, job.Runs[0].ID)
	if err != nil || run.Job.Kind != KindSoftware || run.Job.Software == nil || *run.Job.Software != want || run.ScriptName != "Install jq 1.7.1-3" {
		t.Errorf("run %+v, %v", run, err)
	}
	audited := f.str(`SELECT details::text FROM audit_log WHERE action = 'device.software_action' AND device_id = $1`, lnx)
	for _, s := range []string{`"package": "jq"`, `"manager": "system"`, `"action": "install"`, `"version": "1.7.1-3"`, job.ID.String()} {
		if !strings.Contains(audited, s) {
			t.Errorf("audit %s lacks %s", audited, s)
		}
	}

	// winget on Windows, with a timeout of its own.
	wj, err := f.svc.CreateSoftwareJob(f.ctx, tech, SoftwareInput{
		DeviceIDs: []uuid.UUID{win}, Software: Software{Action: ActionUpgrade, Manager: ManagerWinget, Package: "Mozilla.Firefox"}, TimeoutSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if wj.ScriptName != "Update Mozilla.Firefox (winget)" || wj.Shell != agentproto.ShellPowerShell || wj.Body != adminOnlyScript+wingetScript || wj.TimeoutSeconds != 600 {
		t.Errorf("winget job %+v", wj)
	}

	// Each device must suit the package manager and the caller.
	refused := []struct {
		c    access.Caller
		in   SoftwareInput
		want string
	}{
		{tech, SoftwareInput{DeviceIDs: []uuid.UUID{win}, Software: Software{Action: ActionInstall, Manager: ManagerSystem, Package: "jq"}},
			"Linux package managers run on Linux; HQ-WIN is not a Linux device."},
		{tech, SoftwareInput{DeviceIDs: []uuid.UUID{lnx}, Software: Software{Action: ActionInstall, Manager: ManagerChocolatey, Package: "7zip"}},
			"Chocolatey runs on Windows; HQ-LNX is not a Windows device."},
		{tech, SoftwareInput{DeviceIDs: []uuid.UUID{meshOnly}, Software: Software{Action: ActionInstall, Manager: ManagerSystem, Package: "jq"}},
			"HQ-MESH has no EasyRMM agent to manage software."},
		{tech, SoftwareInput{DeviceIDs: []uuid.UUID{lnx, branch}, Software: Software{Action: ActionInstall, Manager: ManagerSystem, Package: "jq"}},
			"1 device does not exist or is not visible to you."},
		{viewer, SoftwareInput{DeviceIDs: []uuid.UUID{lnx}, Software: Software{Action: ActionUninstall, Manager: ManagerSystem, Package: "jq"}},
			"You cannot manage software on HQ-LNX."},
	}
	for _, r := range refused {
		_, err := f.svc.CreateSoftwareJob(f.ctx, r.c, r.in)
		fieldErr(t, err, "deviceIds", r.want)
	}
	_, err = f.svc.CreateSoftwareJob(f.ctx, tech, SoftwareInput{DeviceIDs: []uuid.UUID{lnx}, Software: Software{Action: ActionInstall, Manager: ManagerSystem, Package: "jq; reboot"}})
	fieldErr(t, err, "package", "letters, digits")
	_, err = f.svc.CreateSoftwareJob(f.ctx, tech, SoftwareInput{DeviceIDs: []uuid.UUID{lnx}, Software: Software{Action: ActionInstall, Manager: ManagerSystem, Package: "jq"}, TimeoutSeconds: 5 * 3600})
	fieldErr(t, err, "timeoutSeconds", "4 hours")
	_, err = f.svc.CreateSoftwareJob(f.ctx, tech, SoftwareInput{Software: Software{Action: ActionInstall, Manager: ManagerSystem, Package: "jq"}})
	fieldErr(t, err, "deviceIds", "at least one")
	if n := f.str(`SELECT count(*)::text FROM jobs`); n != "2" {
		t.Errorf("%s jobs after refusals", n)
	}

	// Script jobs and software jobs are told apart.
	orgAdmin := f.user("orgadmin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	sc, err := f.svc.CreateScript(f.ctx, orgAdmin, ScriptInput{OrganizationID: &f.acme, Name: "Uptime", Shell: "sh", Body: "uptime", TimeoutSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	sj, err := f.svc.CreateJob(f.ctx, tech, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{lnx}})
	if err != nil {
		t.Fatal(err)
	}
	if sj.Kind != KindScript || sj.Software != nil || sj.ScriptID == nil || *sj.ScriptID != sc.ID {
		t.Errorf("script job %+v", sj)
	}
	for kind, wantIDs := range map[string][]uuid.UUID{KindSoftware: {wj.ID, job.ID}, KindScript: {sj.ID}, "": {sj.ID, wj.ID, job.ID}} {
		list, err := f.svc.ListJobs(f.ctx, tech, JobQuery{Kind: kind})
		if err != nil {
			t.Fatal(err)
		}
		var got []uuid.UUID
		for _, j := range list {
			got = append(got, j.ID)
		}
		if !slices.Equal(got, wantIDs) {
			t.Errorf("kind %q: %v, want %v", kind, got, wantIDs)
		}
	}
	if _, err := f.svc.ListJobs(f.ctx, tech, JobQuery{Kind: "patch"}); err == nil {
		t.Error("an unknown kind was accepted")
	}
	got, err := f.svc.GetJob(f.ctx, viewer, job.ID)
	if err != nil || got.Software == nil || got.Software.Package != "jq" || got.CanCancel {
		t.Errorf("viewer's job %+v, %v", got, err)
	}
}
