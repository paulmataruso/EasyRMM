//go:build integration

package jobs

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// testdata/windows-hardening-check.txt is the standard output of the
// script's check of every module, as LocalSystem, on a Windows Server 2025
// Server Core guest (evaluation media) that is a member of a test domain
// with the policies of internal/winpolicy/testdata/domain-gpos.ps1 linked.
func TestWindowsHardeningJobs(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	win := f.device(f.hq, "HQ-WIN", "windows")
	lnx := f.device(f.hq, "HQ-LNX", "linux")

	in := HardeningInput{DeviceIDs: []uuid.UUID{win}, Hardening: Hardening{
		Platform: HardeningWindows, Mode: HardeningCheck, Modules: slices.Clone(WindowsHardeningModules),
		Options: HardeningOptions{WindowsHardeningOptions: WindowsHardeningOptions{LockoutExposed: true}},
	}}
	job, err := f.svc.CreateHardeningJob(f.ctx, tech, in)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{"check", strings.Join(WindowsHardeningModules, ","), "lockout-exposed"}
	if job.Hardening == nil || job.Hardening.Platform != HardeningWindows || job.Shell != agentproto.ShellPowerShell ||
		job.Body != windowsHardeningScript || job.ScriptName != "Check Windows hardening (every module)" || job.ArgCount != len(wantArgs) {
		t.Errorf("job %+v", job)
	}
	resp, err := f.svc.Poll(f.ctx, win)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("poll %+v, %v", resp, err)
	}
	p, err := agentproto.VerifyJob(f.key, resp.Jobs[0], win.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.Script != windowsHardeningScript || p.Shell != agentproto.ShellPowerShell || !slices.Equal(p.Args, wantArgs) {
		t.Errorf("payload %+v", p)
	}
	audited := f.str(`SELECT details::text FROM audit_log WHERE action = 'device.hardening' AND device_id = $1`, win)
	for _, s := range []string{`"platform": "windows"`, `"lockoutExposed": true`} {
		if !strings.Contains(audited, s) {
			t.Errorf("audit %s lacks %s", audited, s)
		}
	}

	out, err := os.ReadFile("testdata/windows-hardening-check.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.GetJob(f.ctx, tech, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	run := got.Runs[0].ID
	if _, err := f.svc.Start(f.ctx, win, run); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Result(f.ctx, win, run, agentproto.ResultRequest{
		Status: StatusSucceeded, ExitCode: ptr(0), Stdout: string(out), StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if r, err := f.svc.GetRun(f.ctx, tech, run); err != nil || r.Status != StatusSucceeded {
		t.Fatalf("run %+v, %v", r, err)
	}
	h, err := f.svc.DeviceHardening(f.ctx, viewer, win)
	if err != nil {
		t.Fatal(err)
	}
	if h.Platform == nil || h.Platform.Family != "windows" || h.Platform.Windows == nil || h.Platform.Windows.Build != 26100 ||
		len(h.Modules) != len(WindowsHardeningModules) || len(h.ControlSources) == 0 {
		t.Fatalf("device hardening %+v", h)
	}
	for i, m := range h.Modules {
		if m.Module != WindowsHardeningModules[i] {
			t.Errorf("module %d is %s, want %s", i, m.Module, WindowsHardeningModules[i])
		}
		if m.Module == "accounts" && (m.Related == nil || len(m.Related.SP80053R5) == 0) {
			t.Errorf("accounts has no related controls: %+v", m.Related)
		}
	}

	// Each platform's modules on its own devices only.
	for _, c := range []struct {
		in   HardeningInput
		want string
	}{
		{HardeningInput{DeviceIDs: []uuid.UUID{lnx}, Hardening: Hardening{Platform: HardeningWindows, Mode: HardeningCheck, Modules: []string{"uac"}}},
			"Windows hardening runs on Windows; HQ-LNX is not a Windows device."},
		{HardeningInput{DeviceIDs: []uuid.UUID{win}, Hardening: Hardening{Mode: HardeningCheck, Modules: []string{"ssh"}}},
			"Hardening runs on Linux; HQ-WIN is not a Linux device."},
	} {
		_, err := f.svc.CreateHardeningJob(f.ctx, tech, c.in)
		fieldErr(t, err, "deviceIds", c.want)
	}

	// A Linux result for a Windows job fails the run and keeps nothing.
	again, err := f.svc.CreateHardeningJob(f.ctx, tech, HardeningInput{DeviceIDs: []uuid.UUID{win}, Hardening: Hardening{
		Platform: HardeningWindows, Mode: HardeningCheck, Modules: []string{"uac"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, err = f.svc.GetJob(f.ctx, tech, again.ID)
	if err != nil {
		t.Fatal(err)
	}
	run = got.Runs[0].ID
	if _, err := f.svc.Start(f.ctx, win, run); err != nil {
		t.Fatal(err)
	}
	linux := HardeningResultPrefix + `{"version":1,"mode":"check","platform":{"id":"ubuntu","versionId":"24.04","family":"debian","container":"none","support":"full"},"modules":[{"module":"uac","state":"in_place"}]}`
	if err := f.svc.Result(f.ctx, win, run, agentproto.ResultRequest{Status: StatusSucceeded, ExitCode: ptr(0), Stdout: linux, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if r, _ := f.svc.GetRun(f.ctx, tech, run); r.Status != StatusFailed || !strings.Contains(r.Error, "platform") {
		t.Errorf("a Linux result for a Windows job: %+v", r)
	}
	if h2, _ := f.svc.DeviceHardening(f.ctx, viewer, win); h2.Modules[slices.Index(WindowsHardeningModules, "uac")].JobID == nil ||
		*h2.Modules[slices.Index(WindowsHardeningModules, "uac")].JobID != job.ID {
		t.Error("a refused result replaced the module's state")
	}
}
