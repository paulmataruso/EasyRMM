//go:build integration

package jobs

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

func TestMaintenanceJobs(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	viewer := f.user("viewer@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	lnx := f.device(f.hq, "HQ-LNX", "linux")
	win := f.device(f.hq, "HQ-WIN", "windows")

	// A service restart on Linux: EasyRMM's script, the action and the unit as arguments.
	job, err := f.svc.CreateMaintenanceJob(f.ctx, tech, MaintenanceInput{DeviceIDs: []uuid.UUID{lnx}, Platform: "linux",
		Maintenance: Maintenance{Action: MaintServiceRestart, Service: "nginx.service"}})
	if err != nil {
		t.Fatal(err)
	}
	if job.Kind != KindMaintenance || job.ScriptName != "Restart service nginx.service" || job.Shell != agentproto.ShellSh ||
		job.Body != maintLinuxScript || job.ArgCount != 2 || job.ScriptID != nil {
		t.Fatalf("job %+v", job)
	}
	resp, err := f.svc.Poll(f.ctx, lnx, nil)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("poll %+v, %v", resp, err)
	}
	p, err := agentproto.VerifyJob(f.key, resp.Jobs[0], lnx.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Args, []string{"service_restart", "nginx.service"}) || p.Script != maintLinuxScript {
		t.Fatalf("payload %+v", p)
	}
	// A service action never marks the device as expected offline.
	run := uuid.MustParse(p.RunID)
	if err := f.svc.Result(f.ctx, lnx, run, agentproto.ResultRequest{Status: StatusSucceeded, ExitCode: ptr(0), StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if n := f.str(`SELECT count(*)::text FROM device_expected_offline`); n != "0" {
		t.Fatalf("%s expected-offline rows after a service restart", n)
	}
	if a := f.str(`SELECT details->>'action' FROM audit_log WHERE action = 'device.maintenance_action' AND device_id = $1`, lnx); a != MaintServiceRestart {
		t.Fatalf("audit action %q", a)
	}

	// Windows gets the PowerShell script.
	wj, err := f.svc.CreateMaintenanceJob(f.ctx, tech, MaintenanceInput{DeviceIDs: []uuid.UUID{win}, Platform: "windows",
		Maintenance: Maintenance{Action: MaintRestart}})
	if err != nil || wj.Shell != agentproto.ShellPowerShell || wj.Body != maintWindowsScript || wj.ScriptName != "Restart" {
		t.Fatalf("windows job %+v, %v", wj, err)
	}

	// The checks: platform, device, action, permission.
	if _, err := f.svc.CreateMaintenanceJob(f.ctx, tech, MaintenanceInput{DeviceIDs: []uuid.UUID{win}, Platform: "linux",
		Maintenance: Maintenance{Action: MaintRestart}}); err == nil {
		t.Error("a Linux job was made for a Windows computer")
	}
	for _, m := range []Maintenance{{Action: "format"}, {Action: MaintServiceStop}, {Action: MaintServiceStop, Service: "-x"}, {Action: MaintRestart, Service: "x"}} {
		if _, err := f.svc.CreateMaintenanceJob(f.ctx, tech, MaintenanceInput{DeviceIDs: []uuid.UUID{lnx}, Platform: "linux", Maintenance: m}); err == nil {
			t.Errorf("%+v was accepted", m)
		}
	}
	if _, err := f.svc.CreateMaintenanceJob(f.ctx, tech, MaintenanceInput{DeviceIDs: []uuid.UUID{lnx}, Maintenance: Maintenance{Action: MaintRestart}}); err == nil {
		t.Error("a job without a platform was accepted")
	}
	if _, err := f.svc.CreateMaintenanceJob(f.ctx, viewer, MaintenanceInput{DeviceIDs: []uuid.UUID{lnx}, Platform: "linux",
		Maintenance: Maintenance{Action: MaintRestart}}); err == nil {
		t.Error("a read-only user restarted a computer")
	}
}

// A successful restart says the device will be offline; a shutdown for longer;
// a failed one says nothing.
func TestMaintenanceExpectsOffline(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	a, b, c := f.device(f.hq, "A", "linux"), f.device(f.hq, "B", "linux"), f.device(f.hq, "C", "linux")

	run := func(dev uuid.UUID, action, status string) {
		t.Helper()
		if _, err := f.svc.CreateMaintenanceJob(f.ctx, tech, MaintenanceInput{DeviceIDs: []uuid.UUID{dev}, Platform: "linux", Maintenance: Maintenance{Action: action}}); err != nil {
			t.Fatal(err)
		}
		resp, err := f.svc.Poll(f.ctx, dev, nil)
		if err != nil || len(resp.Jobs) != 1 {
			t.Fatalf("poll %+v, %v", resp, err)
		}
		p, err := agentproto.VerifyJob(f.key, resp.Jobs[0], dev.String(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		in := agentproto.ResultRequest{Status: status, StartedAt: time.Now()}
		if status == StatusSucceeded {
			in.ExitCode = ptr(0)
		} else {
			in.ExitCode = ptr(1)
		}
		if err := f.svc.Result(f.ctx, dev, uuid.MustParse(p.RunID), in); err != nil {
			t.Fatal(err)
		}
	}
	run(a, MaintRestart, StatusSucceeded)
	run(b, MaintShutdown, StatusSucceeded)
	run(c, MaintRestart, StatusFailed)

	until := func(dev uuid.UUID) time.Duration {
		var n *time.Time
		_ = f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(f.ctx, `SELECT until_at FROM device_expected_offline WHERE device_id = $1`, dev).Scan(&n)
		})
		if n == nil {
			return 0
		}
		return time.Until(*n).Round(time.Minute)
	}
	if d := until(a); d < 19*time.Minute || d > 20*time.Minute {
		t.Errorf("restart expects %v offline", d)
	}
	if d := until(b); d < 11*time.Hour {
		t.Errorf("shutdown expects %v offline", d)
	}
	if d := until(c); d != 0 {
		t.Errorf("a failed restart expects %v offline", d)
	}
	// A second restart never shortens a longer wait.
	run(b, MaintRestart, StatusSucceeded)
	if d := until(b); d < 11*time.Hour {
		t.Errorf("a restart after a shutdown shortened the wait to %v", d)
	}
}

// One change at a time on a device: a restart waits for a software run ahead of
// it, and software queued behind a restart waits for it too.
func TestMaintenanceIsExclusive(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	dev := f.device(f.hq, "A", "linux")
	other := f.device(f.hq, "B", "linux")

	if _, err := f.svc.CreateSoftwareJob(f.ctx, tech, SoftwareInput{DeviceIDs: []uuid.UUID{dev, other}, Software: Software{Action: ActionInstall, Manager: ManagerSystem, Package: "jq"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateMaintenanceJob(f.ctx, tech, MaintenanceInput{DeviceIDs: []uuid.UUID{dev}, Platform: "linux", Maintenance: Maintenance{Action: MaintRestart}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateMaintenanceJob(f.ctx, tech, MaintenanceInput{DeviceIDs: []uuid.UUID{dev}, Platform: "linux", Maintenance: Maintenance{Action: MaintServiceStart, Service: "cron"}}); err != nil {
		t.Fatal(err)
	}
	// The install is ahead: only it goes out, and Waiting says so.
	resp, err := f.svc.Poll(f.ctx, dev, nil)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("first poll %+v, %v", resp, err)
	}
	p, _ := agentproto.VerifyJob(f.key, resp.Jobs[0], dev.String(), time.Now())
	if p.Args[0] != "install" {
		t.Fatalf("first job %+v", p.Args)
	}
	if w, err := f.svc.Waiting(f.ctx, dev); err != nil || w {
		t.Fatalf("waiting %v, %v with the install still running", w, err)
	}
	// Another device is not held by it.
	if resp, err := f.svc.Poll(f.ctx, other, nil); err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("other device poll %+v, %v", resp, err)
	}
	finish := func(run string) {
		t.Helper()
		if err := f.svc.Result(f.ctx, dev, uuid.MustParse(run), agentproto.ResultRequest{Status: StatusSucceeded, ExitCode: ptr(0), StartedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	finish(p.RunID)
	// The restart is next, alone: the service action waits for it.
	resp, err = f.svc.Poll(f.ctx, dev, nil)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("second poll %+v, %v", resp, err)
	}
	p, _ = agentproto.VerifyJob(f.key, resp.Jobs[0], dev.String(), time.Now())
	if p.Args[0] != MaintRestart {
		t.Fatalf("second job %+v", p.Args)
	}
	if resp, _ := f.svc.Poll(f.ctx, dev, nil); len(resp.Jobs) != 0 {
		t.Fatalf("the service action went out beside the restart: %+v", resp.Jobs)
	}
	finish(p.RunID)
	resp, err = f.svc.Poll(f.ctx, dev, nil)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("third poll %+v, %v", resp, err)
	}
	p, _ = agentproto.VerifyJob(f.key, resp.Jobs[0], dev.String(), time.Now())
	if p.Args[0] != MaintServiceStart {
		t.Fatalf("third job %+v", p.Args)
	}
}
