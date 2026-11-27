//go:build integration

package schedule

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t          *testing.T
	ctx        context.Context
	db         *database.DB
	jobs       *jobs.Service
	svc        *Service
	at         time.Time
	acme, hq   uuid.UUID
	globex     uuid.UUID
	principals map[uuid.UUID]*rbac.Principal
}

func (f *fixture) LoadPrincipal(_ context.Context, id uuid.UUID) (*rbac.Principal, error) {
	return f.principals[id], nil
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, principals: map[uuid.UUID]*rbac.Principal{},
		at: time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return f.at }
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditLog := audit.New(inst.DB, clock)
	f.jobs = jobs.New(inst.DB, auditLog, jobkeys.Static(priv), 90*24*time.Hour, 30*24*time.Hour, log)
	f.svc = New(inst.DB, auditLog, f.jobs, f, auth.DataScope, log)
	f.svc.now = clock
	f.acme = f.id(`INSERT INTO organizations (name, timezone) VALUES ('Acme', 'America/New_York') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	return f
}

func (f *fixture) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&id) }); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, sql, args...)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) user(email string, as ...rbac.Assignment) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	for _, a := range as {
		var org, site *uuid.UUID
		if a.OrganizationID != uuid.Nil {
			org = &a.OrganizationID
		}
		if a.SiteID != uuid.Nil {
			site = &a.SiteID
		}
		f.exec(`INSERT INTO role_assignments (user_id, role, organization_id, site_id) VALUES ($1, $2, $3, $4)`, id, string(a.Role), org, site)
	}
	p, err := rbac.NewPrincipal(id, as)
	if err != nil {
		f.t.Fatal(err)
	}
	f.principals[id] = p
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

func (f *fixture) device(name string) uuid.UUID {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, 'linux', $4, now(), now()) RETURNING id`, f.acme, f.hq, name, key)
}

func (f *fixture) count(sql string, args ...any) (n int) {
	f.t.Helper()
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fixture) script(c access.Caller, body string) *jobs.Script {
	f.t.Helper()
	org := f.acme
	sc, err := f.jobs.CreateScript(f.ctx, c, jobs.ScriptInput{Name: "Nightly " + uuid.NewString()[:6], Shell: "bash", Body: body, OrganizationID: &org})
	if err != nil {
		f.t.Fatal(err)
	}
	return sc
}

func (f *fixture) input(sc *jobs.Script, s Schedule) Input {
	return Input{Name: "Nightly", OrganizationID: f.acme, ScriptID: sc.ID, Schedule: s}
}

func (f *fixture) runs(id uuid.UUID) []*Run {
	f.t.Helper()
	r, err := f.svc.History(f.ctx, access.System("test"), id, 50)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func daily() Schedule { return Schedule{Kind: KindDaily, At: "03:00"} }

func TestCreateFireAndHistory(t *testing.T) {
	f := newFixture(t)
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	sc := f.script(tech, "echo hi\n")
	d1, d2 := f.device("a"), f.device("b")

	task, err := f.svc.Create(f.ctx, tech, f.input(sc, daily()))
	if err != nil {
		t.Fatal(err)
	}
	// 03:00 in New York in January is 08:00 UTC; now is 12:00 on Jan 5.
	if want := time.Date(2026, 1, 6, 8, 0, 0, 0, time.UTC); !task.NextRunAt.Equal(want) {
		t.Fatalf("next %v, want %v", task.NextRunAt, want)
	}
	if task.Timezone != "America/New_York" || task.ScriptSHA256 != sc.SHA256 || task.OwnerID != tech.Actor.ID {
		t.Fatalf("task: %+v", task)
	}
	up, _ := f.svc.Upcoming(f.ctx, tech, 10)
	if len(up) != 1 {
		t.Fatalf("upcoming %d", len(up))
	}

	// Not due yet.
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(f.runs(task.ID)); n != 0 {
		t.Fatalf("%d runs before the time", n)
	}
	// Due, on time: one run, one job of both devices. A second server firing
	// the same occurrence changes nothing.
	f.at = time.Date(2026, 1, 6, 8, 0, 20, 0, time.UTC)
	for range 2 {
		if err := f.svc.Fire(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	runs := f.runs(task.ID)
	if len(runs) != 1 || runs[0].State != RunSucceeded || len(runs[0].JobIDs) != 1 || runs[0].OccurrenceKey != "2026-01-06T08:00:00Z" {
		t.Fatalf("runs: %+v", runs)
	}
	if n := f.count(`SELECT count(*) FROM job_runs WHERE job_id = $1 AND device_id IN ($2, $3)`, runs[0].JobIDs[0], d1, d2); n != 2 {
		t.Fatalf("%d job runs", n)
	}
	got, _ := f.svc.Get(f.ctx, tech, task.ID)
	if want := time.Date(2026, 1, 7, 8, 0, 0, 0, time.UTC); !got.NextRunAt.Equal(want) {
		t.Fatalf("next after run %v", got.NextRunAt)
	}
	// The job is audited as the owner; the run by the scheduler.
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'automation.run_started'`); n != 1 {
		t.Fatalf("%d run_started records", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'automation.create'`); n != 1 {
		t.Fatalf("%d create records", n)
	}
}

func TestMissedRuns(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	sc := f.script(admin, "echo hi\n")
	f.device("a")
	skip, err := f.svc.Create(f.ctx, admin, f.input(sc, daily()))
	if err != nil {
		t.Fatal(err)
	}
	in := f.input(sc, daily())
	in.MissedRunRule = RuleRunASAP
	in.Name = "Catch up"
	asap, err := f.svc.Create(f.ctx, admin, in)
	if err != nil {
		t.Fatal(err)
	}
	// The server was down for three days.
	f.at = time.Date(2026, 1, 9, 10, 0, 0, 0, time.UTC)
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	r := f.runs(skip.ID)
	if len(r) != 1 || r[0].State != RunSkipped || r[0].OccurrenceKey != "2026-01-09T08:00:00Z" || !strings.Contains(r[0].Detail, "occurrences") {
		t.Fatalf("skip rule: %+v", r)
	}
	r = f.runs(asap.ID)
	if len(r) != 1 || r[0].State != RunSucceeded || len(r[0].JobIDs) != 1 || !strings.Contains(r[0].Detail, "late") {
		t.Fatalf("run-asap rule: %+v", r)
	}
	// Both continue from the next occurrence, with no storm.
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.runs(asap.ID)) != 1 {
		t.Fatal("a second catch-up run")
	}
}

func TestRunTimeChecks(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	f.device("a")
	due := time.Date(2026, 1, 6, 8, 0, 5, 0, time.UTC)

	// The script changed after the task pinned it: the run fails, no job.
	sc := f.script(admin, "echo one\n")
	task, _ := f.svc.Create(f.ctx, admin, f.input(sc, daily()))
	body := "echo two\n"
	if _, err := f.jobs.UpdateScript(f.ctx, admin, sc.ID, jobs.ScriptPatch{Body: &body}); err != nil {
		t.Fatal(err)
	}
	if g, _ := f.svc.Get(f.ctx, admin, task.ID); !g.ScriptChanged {
		t.Fatal("a changed script is not flagged")
	}
	f.at = due
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	r := f.runs(task.ID)
	if len(r) != 1 || r[0].State != RunFailed || !strings.Contains(r[0].Detail, "changed") || len(r[0].JobIDs) != 0 {
		t.Fatalf("hash: %+v", r)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'automation.run_failed'`); n != 1 {
		t.Fatalf("%d failure records", n)
	}
	// Saved again with Repin, the next occurrence runs.
	f.at = time.Date(2026, 1, 6, 9, 0, 0, 0, time.UTC)
	if _, err := f.svc.Update(f.ctx, admin, task.ID, Patch{Repin: true}); err != nil {
		t.Fatal(err)
	}
	f.at = time.Date(2026, 1, 7, 8, 0, 5, 0, time.UTC)
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	if r := f.runs(task.ID); len(r) != 2 || r[0].State != RunSucceeded {
		t.Fatalf("after repin: %+v", r)
	}

	// An owner whose account is disabled, or who lost the role, runs nothing.
	f.at = time.Date(2026, 1, 7, 12, 0, 0, 0, time.UTC)
	owner := f.user("owner@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	t2, err := f.svc.Create(f.ctx, owner, f.input(f.script(admin, "echo x\n"), daily()))
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE users SET status = 'disabled' WHERE id = $1`, owner.Actor.ID)
	f.at = time.Date(2026, 1, 8, 8, 0, 5, 0, time.UTC)
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	if r := f.runs(t2.ID); len(r) != 1 || r[0].State != RunFailed || !strings.Contains(r[0].Detail, "account") {
		t.Fatalf("disabled owner: %+v", r)
	}
	f.exec(`UPDATE users SET status = 'active' WHERE id = $1`, owner.Actor.ID)
	f.principals[owner.Actor.ID], _ = rbac.NewPrincipal(owner.Actor.ID, nil)
	f.at = time.Date(2026, 1, 9, 8, 0, 5, 0, time.UTC)
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	if r := f.runs(t2.ID); len(r) != 2 || r[0].State != RunFailed || !strings.Contains(r[0].Detail, "no longer run") {
		t.Fatalf("lost role: %+v", r)
	}
}

func TestDevScope(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	f.device("a")
	task, err := f.svc.Create(f.ctx, admin, f.input(f.script(admin, "echo\n"), daily()))
	if err != nil {
		t.Fatal(err)
	}
	defer devscope.Set(f.globex)()
	f.at = time.Date(2026, 1, 6, 8, 0, 5, 0, time.UTC)
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(f.runs(task.ID)); n != 0 {
		t.Fatalf("a task outside the dev scope ran: %d", n)
	}
}

func TestLifecycleAndPermissions(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	viewer := f.user("ro@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme})
	other := f.user("globex@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.globex})
	f.device("a")
	sc := f.script(admin, "echo\n")

	if _, err := f.svc.Create(f.ctx, viewer, f.input(sc, daily())); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("read-only create: %v", err)
	}
	if _, err := f.svc.Create(f.ctx, other, f.input(sc, daily())); err == nil {
		t.Fatal("another organization created a task")
	}
	task, err := f.svc.Create(f.ctx, admin, f.input(sc, Schedule{Kind: KindWeekly, At: "22:00", Days: []int{1, 3}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Get(f.ctx, other, task.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("other org get: %v", err)
	}
	if l, _ := f.svc.List(f.ctx, other, Query{}); len(l) != 0 {
		t.Fatal("other org lists it")
	}
	if g, err := f.svc.Get(f.ctx, viewer, task.ID); err != nil || g.CanEdit {
		t.Fatalf("viewer: %+v %v", g, err)
	}
	if _, err := f.svc.Pause(f.ctx, viewer, task.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("viewer pause: %v", err)
	}

	p, err := f.svc.Pause(f.ctx, admin, task.ID)
	if err != nil || p.State != StatePaused || p.NextRunAt != nil {
		t.Fatalf("pause: %+v %v", p, err)
	}
	if up, _ := f.svc.Upcoming(f.ctx, admin, 10); len(up) != 0 {
		t.Fatal("a paused task is upcoming")
	}
	// A paused task does not fire, and resuming does not catch up.
	f.at = f.at.Add(30 * 24 * time.Hour)
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.runs(task.ID)) != 0 {
		t.Fatal("a paused task ran")
	}
	r, err := f.svc.Resume(f.ctx, admin, task.ID)
	if err != nil || r.State != StateActive || !r.NextRunAt.After(f.at) {
		t.Fatalf("resume: %+v %v", r, err)
	}
	name := "Weekly"
	u, err := f.svc.Update(f.ctx, admin, task.ID, Patch{Name: &name, Schedule: &Schedule{Kind: KindDaily, At: "01:00"}})
	if err != nil || u.Name != name || u.Schedule.Kind != KindDaily {
		t.Fatalf("update: %+v %v", u, err)
	}
	c, err := f.svc.Cancel(f.ctx, admin, task.ID)
	if err != nil || c.State != StateCanceled || c.NextRunAt != nil {
		t.Fatalf("cancel: %+v %v", c, err)
	}
	if _, err := f.svc.Resume(f.ctx, admin, task.ID); err == nil {
		t.Fatal("a canceled task resumed")
	}
	if _, err := f.svc.Update(f.ctx, admin, task.ID, Patch{Name: &name}); err == nil {
		t.Fatal("a canceled task was edited")
	}
	for _, a := range []string{"create", "update", "pause", "resume", "cancel"} {
		if n := f.count(`SELECT count(*) FROM audit_log WHERE action = $1`, "automation."+a); n != 1 {
			t.Errorf("%d automation.%s records", n, a)
		}
	}
}

func TestOnceCompletes(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	f.device("a")
	task, err := f.svc.Create(f.ctx, admin, f.input(f.script(admin, "echo\n"), Schedule{Kind: KindOnce, Date: "2026-01-06", At: "09:00"}))
	if err != nil {
		t.Fatal(err)
	}
	f.at = time.Date(2026, 1, 6, 14, 0, 30, 0, time.UTC) // 09:00 New York
	if err := f.svc.Fire(f.ctx); err != nil {
		t.Fatal(err)
	}
	g, _ := f.svc.Get(f.ctx, admin, task.ID)
	if g.State != StateCompleted || g.NextRunAt != nil || len(f.runs(task.ID)) != 1 {
		t.Fatalf("once: %+v", g)
	}
	if _, err := f.svc.Create(f.ctx, admin, f.input(f.script(admin, "echo\n"), Schedule{Kind: KindOnce, Date: "2026-01-01", At: "09:00"})); err == nil {
		t.Fatal("a past one-off was saved")
	}
}
