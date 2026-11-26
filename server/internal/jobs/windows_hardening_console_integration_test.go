//go:build integration

package jobs

import (
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// The console's guard (ADR-0054, W3): its listing, and Keep, which queues
// a new confirmation that ends the computer's timer.
func TestWindowsHardeningGuardKeep(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	other := f.user("other@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.globex, SiteID: f.plant})
	win := f.device(f.hq, "HQ-WIN", "windows")

	// No guard: nothing to keep.
	if _, err := f.svc.KeepGuard(f.ctx, admin, win); err == nil {
		t.Fatal("kept a guard that does not exist")
	} else if e, ok := apperr.As(err); !ok || e.Code != "no_armed_guard" {
		t.Errorf("no guard: %v", err)
	}
	job, err := f.svc.CreateHardeningJob(f.ctx, admin, HardeningInput{DeviceIDs: []uuid.UUID{win}, Confirm: HardeningConfirmation{Agreed: true},
		Hardening: Hardening{Platform: HardeningWindows, Mode: HardeningApply, Settings: []string{"autoplay-autorun"}}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := f.svc.GetJob(f.ctx, admin, job.ID)
	if _, err := f.svc.Poll(f.ctx, win, nil); err != nil {
		t.Fatal(err)
	}
	f.finishRun(win, got.Runs[0].ID, applyAutoplay)

	gs, err := f.svc.DeviceGuards(f.ctx, tech, win)
	if err != nil || len(gs) != 1 || gs[0].State != "armed" || gs[0].ApplyJobID != job.ID || gs[0].KeepRequestedAt != nil ||
		len(gs[0].Settings) != 1 || gs[0].Settings[0] != "autoplay-autorun" || !gs[0].RollbackAt.After(gs[0].ArmedAt) {
		t.Fatalf("guards %+v, %v", gs, err)
	}
	if _, err := f.svc.DeviceGuards(f.ctx, other, win); err == nil {
		t.Error("another organization read the guards")
	}

	// A technician cannot keep; the administrator can, once, and the guard
	// then points at the new confirm job.
	if _, err := f.svc.KeepGuard(f.ctx, tech, win); err == nil {
		t.Error("a technician kept a guard")
	}
	before := f.str(`SELECT confirm_job_id::text FROM hardening_guards WHERE apply_job_id = $1`, job.ID)
	g, err := f.svc.KeepGuard(f.ctx, admin, win)
	if err != nil || g.KeepRequestedAt == nil {
		t.Fatalf("keep %+v, %v", g, err)
	}
	after := f.str(`SELECT confirm_job_id::text FROM hardening_guards WHERE apply_job_id = $1`, job.ID)
	if after == before {
		t.Error("the guard still points at the old confirm job")
	}
	if m := f.str(`SELECT hardening->>'mode' FROM jobs WHERE id = $1`, after); m != HardeningConfirm {
		t.Errorf("the new job's mode %q", m)
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'device.hardening.guard_keep' AND actor_type = 'user' AND device_id = $1`, win); n != "1" {
		t.Errorf("keep audit rows %s", n)
	}

	// The new confirmation ends the guard when it runs.
	if _, err := f.svc.Poll(f.ctx, win, nil); err != nil {
		t.Fatal(err)
	}
	run := f.str(`SELECT r.id::text FROM job_runs r WHERE r.job_id = $1`, after)
	f.finishRun(win, uuid.MustParse(run), "The guard was ended: the change stands.\n")
	if gs, _ = f.svc.DeviceGuards(f.ctx, admin, win); gs[0].State != "confirmed" || gs[0].DecidedAt == nil {
		t.Errorf("after the confirmation %+v", gs[0])
	}

	// Too late: the timer is about to fire.
	f.exec(`UPDATE hardening_guards SET state = 'armed', rollback_at = now() + interval '30 seconds' WHERE apply_job_id = $1`, job.ID)
	if _, err := f.svc.KeepGuard(f.ctx, admin, win); err == nil {
		t.Error("kept a guard 30 seconds before its timer")
	} else if e, ok := apperr.As(err); !ok || e.Code != "guard_too_late" {
		t.Errorf("too late: %v", err)
	}
}

// The fleet: Windows computers with an agent, by scope, with the state of
// each module summed; other organizations' computers never show.
func TestWindowsHardeningFleet(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	site := f.user("site@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	w1 := f.device(f.hq, "HQ-WIN-1", "windows")
	w2 := f.device(f.branch, "BR-WIN-1", "windows")
	f.device(f.hq, "HQ-LNX", "linux")
	f.device(f.plant, "PL-WIN", "windows")
	f.exec(`INSERT INTO device_hardening (device_id, module, state, detail, checked_at) VALUES
		($1, 'autoplay', 'in_place', '{}', now()), ($1, 'smb', 'not_in_place', '{}', now()), ($2, 'autoplay', 'not_in_place', '{}', now())`, w1, w2)

	fl, err := f.svc.HardeningFleet(f.ctx, admin, FleetScope{OrganizationID: f.acme})
	if err != nil || len(fl.Devices) != 2 || fl.Truncated {
		t.Fatalf("organization fleet %+v, %v", fl, err)
	}
	// In the order the script runs the modules.
	if len(fl.Modules) != 2 || fl.Modules[1].Module != "autoplay" || fl.Modules[1].States["in_place"] != 1 || fl.Modules[1].States["not_in_place"] != 1 ||
		fl.Modules[0].Module != "smb" || fl.Modules[0].States["not_in_place"] != 1 {
		t.Errorf("modules %+v", fl.Modules)
	}
	if fl.Devices[0].Name != "BR-WIN-1" || fl.Devices[1].States["in_place"] != 1 {
		t.Errorf("devices %+v", fl.Devices)
	}
	fl, err = f.svc.HardeningFleet(f.ctx, admin, FleetScope{SiteID: f.hq})
	if err != nil || len(fl.Devices) != 1 || fl.Devices[0].ID != w1 {
		t.Errorf("site fleet %+v, %v", fl, err)
	}
	// A site administrator sees their site only, even asking for the
	// organization (row security), and another organization is refused.
	if fl, err = f.svc.HardeningFleet(f.ctx, site, FleetScope{SiteID: f.hq}); err != nil || len(fl.Devices) != 1 {
		t.Errorf("site admin %+v, %v", fl, err)
	}
	if _, err := f.svc.HardeningFleet(f.ctx, admin, FleetScope{OrganizationID: f.globex}); err == nil {
		t.Error("another organization's fleet was read")
	}
}

func TestWindowsCatalog(t *testing.T) {
	c := WindowsCatalog()
	if len(c) != len(WindowsHardeningModules) {
		t.Fatalf("%d modules", len(c))
	}
	n, tier3 := 0, 0
	for _, m := range c {
		n += len(m.Settings)
		for _, s := range m.Settings {
			if s.Tier == 3 {
				tier3++
			}
			if s.Cite == "" || s.What == "" {
				t.Errorf("setting %+v", s)
			}
		}
	}
	if n != len(windowsSettings) || tier3 == 0 {
		t.Errorf("%d settings, %d of tier 3", n, tier3)
	}
}
