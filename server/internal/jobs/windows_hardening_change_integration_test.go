//go:build integration

package jobs

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

const applyAutoplay = HardeningResultPrefix + `{"version":1,"mode":"apply","platform":` + windowsPlatform + `,"modules":[{"module":"autoplay","state":"in_place",` +
	`"outcome":"applied","recorded":true,"done":["autoplay-autorun"],"settings":[{"id":"autoplay-autorun","state":"in_place","value":"1",` +
	`"outcome":"applied","before":"0","changedAt":"2026-11-26T10:00:00Z"}],"managed":[],"notes":[]}]}`

// finish runs a device's run to the end with the output.
func (f *fixture) finishRun(device, run uuid.UUID, out string) {
	f.t.Helper()
	if _, err := f.svc.Start(f.ctx, device, run); err != nil {
		f.t.Fatal(err)
	}
	if err := f.svc.Result(f.ctx, device, run, agentproto.ResultRequest{Status: StatusSucceeded, ExitCode: ptr(0), Stdout: out, StartedAt: time.Now()}); err != nil {
		f.t.Fatal(err)
	}
}

// Apply and undo on Windows: agreement, tiers, the development scope, the
// audit, the guard and its confirmation, and one change at a time.
func TestWindowsHardeningApplyUndo(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	win := f.device(f.hq, "HQ-WIN", "windows")
	devs := []uuid.UUID{win}
	apply := func(c access.Caller, h Hardening, in HardeningConfirmation) (*Job, error) {
		h.Platform = HardeningWindows
		return f.svc.CreateHardeningJob(f.ctx, c, HardeningInput{DeviceIDs: devs, Hardening: h, Confirm: in})
	}
	one := Hardening{Mode: HardeningApply, Settings: []string{"autoplay-autorun"}}

	// Who, and the agreement.
	_, err := apply(tech, one, HardeningConfirmation{Agreed: true})
	fieldErr(t, err, "deviceIds", "cannot")
	_, err = apply(admin, one, HardeningConfirmation{})
	fieldErr(t, err, "confirm.agreed", "read what this change does")

	// Tier 3 needs the name and then a step-up, which is not built yet.
	_, err = apply(admin, Hardening{Mode: HardeningApply, Modules: []string{"firewall"}}, HardeningConfirmation{Agreed: true, Typed: "HQ-WIN"})
	if e, ok := apperr.As(err); !ok || e.Code != "step_up_required" {
		t.Errorf("tier 3: %v", err)
	}
	f.svc.SetStepUp(stepUpStub{})
	_, err = apply(admin, Hardening{Mode: HardeningApply, Modules: []string{"firewall"}}, HardeningConfirmation{Agreed: true, Typed: "HQ-OTHER"})
	fieldErr(t, err, "confirm.typed", "not the computer's name")
	f.svc.SetStepUp(nil)

	// The development scope: another organization's scope refuses it.
	restore := devscope.Set(f.globex)
	_, err = apply(admin, one, HardeningConfirmation{Agreed: true})
	restore()
	fieldErr(t, err, "deviceIds", "development scope")

	job, err := apply(admin, one, HardeningConfirmation{Agreed: true})
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{"apply", "--settings", "autoplay-autorun", "guard-minutes=10"}
	resp, err := f.svc.Poll(f.ctx, win, nil)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("poll %+v, %v", resp, err)
	}
	p, err := agentproto.VerifyJob(f.key, resp.Jobs[0], win.String(), time.Now())
	if err != nil || strings.Join(p.Args, " ") != strings.Join(wantArgs, " ") {
		t.Fatalf("payload %+v, %v", p, err)
	}
	audited := f.str(`SELECT details::text FROM audit_log WHERE action = 'device.hardening' AND device_id = $1 ORDER BY id DESC LIMIT 1`, win)
	for _, s := range []string{`"mode": "apply"`, `"tier": 1`, `"confirmed": true`, `"guardMinutes": 10`, `"autoplay-autorun"`} {
		if !strings.Contains(audited, s) {
			t.Errorf("audit %s lacks %s", audited, s)
		}
	}

	// A result for single settings records no module state.
	got, _ := f.svc.GetJob(f.ctx, admin, job.ID)
	run := got.Runs[0].ID
	f.finishRun(win, run, applyAutoplay)
	if n := f.str(`SELECT count(*)::text FROM device_hardening WHERE device_id = $1`, win); n != "0" {
		t.Errorf("a job for one setting stored %s module states", n)
	}

	// The guard: armed, with a confirm job that no one made by hand.
	if st := f.str(`SELECT state FROM hardening_guards WHERE apply_job_id = $1`, job.ID); st != "armed" {
		t.Fatalf("guard %q", st)
	}
	confirmJob := f.str(`SELECT confirm_job_id::text FROM hardening_guards WHERE apply_job_id = $1`, job.ID)
	if m := f.str(`SELECT hardening->>'mode' FROM jobs WHERE id = $1`, confirmJob); m != HardeningConfirm {
		t.Fatalf("the confirm job's mode %q", m)
	}
	if a := f.str(`SELECT actor_type FROM audit_log WHERE action = 'device.hardening' AND details->>'mode' = 'confirm'`); a != "system" {
		t.Errorf("confirm audited as %q", a)
	}
	_, err = apply(admin, Hardening{Mode: HardeningConfirm, Modules: []string{"autoplay"}}, HardeningConfirmation{Agreed: true})
	fieldErr(t, err, "mode", "Choose check, apply or undo")

	// A new apply waits for the confirmation; the confirm job does not wait.
	second, err := apply(admin, Hardening{Mode: HardeningApply, Modules: []string{"wdigest"}}, HardeningConfirmation{Agreed: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err = f.svc.Poll(f.ctx, win, nil)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("poll %+v, %v", resp, err)
	}
	p, _ = agentproto.VerifyJob(f.key, resp.Jobs[0], win.String(), time.Now())
	if len(p.Args) != 1 || p.Args[0] != "confirm" {
		t.Fatalf("the confirm job was not the one delivered: %+v", p.Args)
	}
	f.finishRun(win, uuid.MustParse(p.RunID), "The guard was ended: the change stands.\n")
	if st := f.str(`SELECT state FROM hardening_guards WHERE apply_job_id = $1`, job.ID); st != "confirmed" {
		t.Errorf("guard after the confirmation: %q", st)
	}
	resp, err = f.svc.Poll(f.ctx, win, nil)
	if err != nil || len(resp.Jobs) != 1 {
		t.Fatalf("poll %+v, %v", resp, err)
	}
	if p, _ = agentproto.VerifyJob(f.key, resp.Jobs[0], win.String(), time.Now()); strings.Join(p.Args, " ") == "" || p.Args[0] != "apply" {
		t.Errorf("the second apply was not delivered after: %+v", p.Args)
	}
	_ = second
}

// An apply whose confirmation never comes is recorded as timed out.
func TestWindowsHardeningGuardTimesOut(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	win := f.device(f.hq, "HQ-WIN", "windows")
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
	if s, err := f.svc.Sweep(f.ctx); err != nil || s.GuardsTimedOut != 0 {
		t.Fatalf("sweep %+v, %v", s, err)
	}
	f.asOwner(`UPDATE hardening_guards SET rollback_at = now() - interval '5 minutes' WHERE apply_job_id = $1`, job.ID)
	if s, err := f.svc.Sweep(f.ctx); err != nil || s.GuardsTimedOut != 1 {
		t.Fatalf("sweep %+v, %v", s, err)
	}
	if st := f.str(`SELECT state FROM hardening_guards WHERE apply_job_id = $1`, job.ID); st != "timed_out" {
		t.Errorf("guard %q", st)
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'device.hardening.guard_timed_out' AND device_id = $1`, win); n != "1" {
		t.Errorf("timed-out audit rows: %s", n)
	}
}

// Outside the development scope the guard queues no confirmation, so the
// computer's timer undoes the change.
func TestWindowsHardeningGuardOutsideScope(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	win := f.device(f.hq, "HQ-WIN", "windows")
	job, err := f.svc.CreateHardeningJob(f.ctx, admin, HardeningInput{DeviceIDs: []uuid.UUID{win}, Confirm: HardeningConfirmation{Agreed: true},
		Hardening: Hardening{Platform: HardeningWindows, Mode: HardeningApply, Settings: []string{"autoplay-autorun"}}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := f.svc.GetJob(f.ctx, admin, job.ID)
	if _, err := f.svc.Poll(f.ctx, win, nil); err != nil {
		t.Fatal(err)
	}
	restore := devscope.Set(f.globex)
	defer restore()
	f.finishRun(win, got.Runs[0].ID, applyAutoplay)
	if n := f.str(`SELECT count(*)::text FROM hardening_guards`); n != "0" {
		t.Errorf("a guard outside the scope: %s", n)
	}
}

// The daily check: one a day per device with EasyRMM's values in place, at
// the device's time, never beside a change, and an undo cancels it.
func TestWindowsHardeningDailyCheck(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	win := f.device(f.hq, "HQ-WIN", "windows")
	other := f.device(f.hq, "HQ-NOREC", "windows")
	f.exec(`INSERT INTO device_hardening (device_id, module, state, detail, checked_at)
		VALUES ($1, 'autoplay', 'in_place', '{"recorded": true}', now()), ($2, 'autoplay', 'in_place', '{}', now())`, win, other)
	day := time.Now().UTC().Truncate(24 * time.Hour)
	at := func(d time.Duration) { f.svc.now = func() time.Time { return day.Add(d) } }
	count := func() string {
		return f.str(`SELECT count(*)::text FROM job_runs r JOIN jobs j ON j.id = r.job_id WHERE r.device_id = $1 AND j.batch_id IS NOT NULL`, win)
	}
	off := dailyOffset(win)
	if off == dailyOffset(other) {
		t.Skip("two devices with one time")
	}
	// Before its time, and after its hour: nothing. The device with no
	// record never has one.
	at(off - time.Minute)
	if n, err := f.svc.QueueDailyChecks(f.ctx); err != nil || n != 0 {
		t.Fatalf("before its time: %d, %v", n, err)
	}
	at(off + dailyCheckWindow + time.Minute)
	if n, _ := f.svc.QueueDailyChecks(f.ctx); n != 0 {
		t.Errorf("a missed day was caught up: %d", n)
	}
	at(off + time.Minute)
	if n, err := f.svc.QueueDailyChecks(f.ctx); err != nil || n != 1 {
		t.Fatalf("at its time: %d, %v", n, err)
	}
	if n, _ := f.svc.QueueDailyChecks(f.ctx); n != 0 || count() != "1" {
		t.Errorf("a second check the same day: %d, %s", n, count())
	}
	if m := f.str(`SELECT j.hardening->>'mode' || ' ' || (j.hardening->'modules')::text FROM jobs j WHERE j.batch_id IS NOT NULL`); m != `check ["autoplay"]` {
		t.Errorf("the job: %s", m)
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'device.hardening_daily_check' AND actor_type = 'system'`); n != "1" {
		t.Errorf("audit rows %s", n)
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'device.hardening' AND device_id = $1`, win); n != "0" {
		t.Errorf("a per-run audit row was written: %s", n)
	}

	// An undo cancels it, with the system as its actor.
	if _, err := f.svc.CreateHardeningJob(f.ctx, admin, HardeningInput{DeviceIDs: []uuid.UUID{win}, Confirm: HardeningConfirmation{Agreed: true},
		Hardening: Hardening{Platform: HardeningWindows, Mode: HardeningUndo, Modules: []string{"autoplay"}}}); err != nil {
		t.Fatal(err)
	}
	if st := f.str(`SELECT r.status || ' ' || r.error FROM job_runs r JOIN jobs j ON j.id = r.job_id WHERE j.batch_id IS NOT NULL`); st != "canceled Replaced by an undo." {
		t.Errorf("the check after an undo: %s", st)
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'job.cancel' AND actor_type = 'system'`); n != "1" {
		t.Errorf("cancel audit rows %s", n)
	}

	// Retention: seven days.
	f.asOwner(`UPDATE jobs SET created_at = now() - interval '8 days' WHERE batch_id IS NOT NULL`)
	if p, err := f.svc.Purge(f.ctx); err != nil || p.Jobs != 1 {
		t.Errorf("purge %+v, %v", p, err)
	}
}
