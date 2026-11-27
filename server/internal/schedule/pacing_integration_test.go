//go:build integration

package schedule

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// window makes a weekly window at HQ (the site's zone is New York). 2026-01-06
// is a Tuesday: day 2.
func (f *fixture) window(purpose, start string, length int) uuid.UUID {
	f.exec(`UPDATE sites SET timezone = 'America/New_York' WHERE id = $1`, f.hq)
	return f.id(`INSERT INTO site_maintenance_windows (organization_id, site_id, name, kind, days, start_local, length_minutes, purpose)
		VALUES ($1, $2, 'Night', 'weekly', ARRAY[2]::smallint[], $3::time, $4, $5) RETURNING id`, f.acme, f.hq, start, length, purpose)
}

// offline makes devices miss their heartbeats (new ones count as online).
func (f *fixture) offline(ids ...uuid.UUID) {
	f.exec(`UPDATE devices SET agent_online_until = now() - interval '1 hour' WHERE id = ANY($1)`, ids)
}

func TestWindowGatesTheRun(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	sc := f.script(tech, "echo hi\n")
	f.device("a")

	// A window that only holds notifications cannot hold a task.
	in := f.input(sc, daily())
	w := f.window("notifications", "03:00", 120)
	in.WindowID = &w
	if _, err := f.svc.Create(f.ctx, tech, in); err == nil {
		t.Fatal("a notifications-only window was accepted")
	}
	f.exec(`UPDATE site_maintenance_windows SET purpose = 'tasks' WHERE id = $1`, w)
	open, err := f.svc.Create(f.ctx, tech, in)
	if err != nil {
		t.Fatal(err)
	}
	if open.WindowID == nil || open.WindowName != "Night" {
		t.Fatalf("task: %+v", open)
	}
	// A window at another hour: the task's 03:00 falls outside it.
	other := f.window("both", "22:00", 60)
	in2 := f.input(sc, daily())
	in2.WindowID = &other
	closed, err := f.svc.Create(f.ctx, tech, in2)
	if err != nil {
		t.Fatal(err)
	}
	// A task without a window still runs.
	free, err := f.svc.Create(f.ctx, tech, f.input(sc, daily()))
	if err != nil {
		t.Fatal(err)
	}

	f.at = time.Date(2026, 1, 6, 8, 0, 20, 0, time.UTC) // 03:00 in New York, Tuesday
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	if r := f.runs(open.ID); len(r) != 1 || r[0].State != RunSucceeded || len(r[0].JobIDs) != 1 {
		t.Fatalf("task in its window: %+v", r)
	}
	if r := f.runs(closed.ID); len(r) != 1 || r[0].State != RunSkipped || len(r[0].JobIDs) != 0 {
		t.Fatalf("task outside its window: %+v", r)
	}
	if r := f.runs(free.ID); len(r) != 1 || r[0].State != RunSucceeded {
		t.Fatalf("task without a window: %+v", r)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'automation.run_skipped'`); n != 1 {
		t.Fatalf("%d run_skipped records", n)
	}

	// Deleting a window leaves a finished task without one.
	if _, err := f.svc.Cancel(f.ctx, tech, closed.ID); err != nil {
		t.Fatal(err)
	}
	f.exec(`DELETE FROM site_maintenance_windows WHERE id = $1`, other)
	if got, _ := f.svc.Get(f.ctx, tech, closed.ID); got.WindowID != nil {
		t.Fatalf("window id after delete: %v", got.WindowID)
	}
}

func TestOnlyIfOnline(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	sc := f.script(tech, "echo hi\n")
	f.device("a")
	d2 := f.device("b")
	f.device("c")
	f.offline(d2)

	in := f.input(sc, daily())
	in.OnlyIfOnline = true
	task, err := f.svc.Create(f.ctx, tech, in)
	if err != nil {
		t.Fatal(err)
	}
	f.at = time.Date(2026, 1, 6, 8, 0, 20, 0, time.UTC)
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	r := f.runs(task.ID)
	if len(r) != 1 || r[0].State != RunSucceeded || len(r[0].JobIDs) != 1 {
		t.Fatalf("runs: %+v", r)
	}
	if n := f.count(`SELECT count(*) FROM job_runs WHERE job_id = $1`, r[0].JobIDs[0]); n != 2 {
		t.Fatalf("%d devices got the job, want the 2 online", n)
	}
	if n := f.count(`SELECT count(*) FROM job_runs WHERE job_id = $1 AND device_id = $2`, r[0].JobIDs[0], d2); n != 0 {
		t.Fatal("the offline device got a job")
	}
}

func TestStaggerSpreadsASite(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	sc := f.script(tech, "echo hi\n")
	for i := range 6 {
		f.device(string(rune('a' + i)))
	}
	w := f.window("tasks", "03:00", 120)
	in := f.input(sc, daily())
	in.WindowID, in.StaggerMinutes = &w, 60
	task, err := f.svc.Create(f.ctx, tech, in)
	if err != nil {
		t.Fatal(err)
	}
	// The stagger cannot be longer than the window.
	long := f.input(sc, daily())
	long.WindowID, long.StaggerMinutes = &w, 121
	if _, err := f.svc.Create(f.ctx, tech, long); err == nil {
		t.Fatal("a stagger longer than the window was accepted")
	}

	f.at = time.Date(2026, 1, 6, 8, 0, 20, 0, time.UTC)
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	r := f.runs(task.ID)
	if len(r) != 1 || r[0].State != RunRunning || len(r[0].JobIDs) != 1 {
		t.Fatalf("after the start: %+v", r)
	}
	if n := f.count(`SELECT count(*) FROM job_runs WHERE job_id = $1`, r[0].JobIDs[0]); n != 1 {
		t.Fatalf("%d devices started at once, want 1", n)
	}
	if n := f.count(`SELECT count(*) FROM automation_run_batches WHERE run_id = $1 AND state = 'pending'`, r[0].ID); n != 5 {
		t.Fatalf("%d batches waiting", n)
	}

	// Twenty minutes in: the batches at +10 and +20 minutes have fallen due.
	f.at = f.at.Add(20 * time.Minute)
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	if r = f.runs(task.ID); r[0].State != RunRunning || len(r[0].JobIDs) != 3 {
		t.Fatalf("after 20 minutes: %+v", r[0])
	}
	// The rest.
	f.at = f.at.Add(40 * time.Minute)
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	if r = f.runs(task.ID); r[0].State != RunSucceeded || len(r[0].JobIDs) != 6 || r[0].CompletedAt == nil {
		t.Fatalf("after the stagger: %+v", r[0])
	}
	if n := f.count(`SELECT count(DISTINCT device_id) FROM job_runs WHERE job_id = ANY($1)`, r[0].JobIDs); n != 6 {
		t.Fatalf("%d distinct devices ran, want 6", n)
	}
}

func TestStaggeredStartsStopWhenTheWindowCloses(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	sc := f.script(tech, "echo hi\n")
	for i := range 4 {
		f.device(string(rune('a' + i)))
	}
	w := f.window("tasks", "03:00", 30)
	in := f.input(sc, daily())
	in.WindowID, in.StaggerMinutes = &w, 30
	task, err := f.svc.Create(f.ctx, tech, in)
	if err != nil {
		t.Fatal(err)
	}
	f.at = time.Date(2026, 1, 6, 8, 0, 20, 0, time.UTC)
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	// Edited meanwhile: the window moves away, so the waiting starts are
	// skipped rather than made outside it.
	f.exec(`UPDATE site_maintenance_windows SET start_local = '22:00' WHERE id = $1`, w)
	f.at = f.at.Add(time.Hour)
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	r := f.runs(task.ID)
	if r[0].State != RunSucceeded || len(r[0].JobIDs) != 1 {
		t.Fatalf("run: %+v", r[0])
	}
	if n := f.count(`SELECT count(*) FROM automation_run_batches WHERE run_id = $1 AND state = 'skipped'`, r[0].ID); n != 3 {
		t.Fatalf("%d batches skipped, want 3", n)
	}
}
