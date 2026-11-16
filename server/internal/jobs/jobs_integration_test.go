//go:build integration

package jobs

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

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type fixture struct {
	t      *testing.T
	super  string
	ctx    context.Context
	db     *database.DB
	svc    *Service
	key    ed25519.PublicKey
	sys    access.Caller
	acme   uuid.UUID
	hq     uuid.UUID
	branch uuid.UUID
	globex uuid.UUID
	plant  uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, sys: access.System("test"), super: inst.SuperDSN}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f.key = pub
	f.svc = New(inst.DB, audit.New(inst.DB, nil), priv, 90*24*time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.svc.pollWait = 200 * time.Millisecond
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.branch = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Branch') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.plant = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'Plant') RETURNING id`, f.globex)
	return f
}

func (f *fixture) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, sql, args...).Scan(&id)
	}); err != nil {
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

// asOwner runs SQL the runtime role may not, such as backdating a job.
func (f *fixture) asOwner(sql string, args ...any) {
	f.t.Helper()
	c, err := pgx.Connect(f.ctx, f.super)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = c.Close(f.ctx) }()
	if _, err := c.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) str(sql string, args ...any) string {
	f.t.Helper()
	var s string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, sql, args...).Scan(&s)
	}); err != nil {
		f.t.Fatal(err)
	}
	return s
}

// user creates a user with the assignments and returns them as a caller.
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
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

// device adds an enrolled Linux device (or, with platform "", one known
// only through remote access).
func (f *fixture) device(site uuid.UUID, name, platform string) uuid.UUID {
	f.t.Helper()
	var org uuid.UUID
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT organization_id FROM sites WHERE id = $1`, site).Scan(&org)
	}); err != nil {
		f.t.Fatal(err)
	}
	if platform == "" {
		return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform) VALUES ($1, $2, $3, $3, 'linux') RETURNING id`, org, site, name)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, $4, $5, now(), now()) RETURNING id`, org, site, name, platform, key)
}

func ptr[T any](v T) *T { return &v }

func fieldErr(t *testing.T, err error, field, contains string) {
	t.Helper()
	e, ok := apperr.As(err)
	if !ok || e.Kind != apperr.KindInvalid || !strings.Contains(e.Fields[field], contains) {
		t.Fatalf("want %s error containing %q, got %v (%+v)", field, contains, err, e)
	}
}

func TestSigningKeyIsSealedAndKept(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	sealer, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	a, err := LoadKey(ctx, inst.DB, sealer)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadKey(ctx, inst.DB, sealer)
	if err != nil || !a.Equal(b) {
		t.Fatalf("key not kept: %v", err)
	}
	var value string
	if err := inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT value::text FROM settings WHERE key = 'jobs.signing_key'`).Scan(&value)
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(value, `"sealed"`) || strings.Contains(value, agentproto.EncodeKey(a.Public().(ed25519.PublicKey))) {
		t.Errorf("stored key is not sealed: %s", value)
	}
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	wrong, _ := secrets.NewSealer(secrets.Key{ID: "k1", Raw: other})
	if _, err := LoadKey(ctx, inst.DB, wrong); err == nil {
		t.Error("opened with another secret key")
	}
}

func TestScriptLevelsAndPermissions(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	orgAdmin := f.user("orgadmin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	hqAdmin := f.user("hqadmin@example.com", rbac.Assignment{Role: rbac.RoleSiteAdmin, OrganizationID: f.acme, SiteID: f.hq})
	hqTech := f.user("hqtech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	globexTech := f.user("globex@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.globex})

	shared, err := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Disk usage", Shell: "bash", Body: "df -h\r\n"})
	if err != nil {
		t.Fatal(err)
	}
	if shared.Level != LevelShared || shared.Body != "df -h\n" || shared.TimeoutSeconds != DefaultTimeout || shared.SHA256 != bodyHash("df -h\n") {
		t.Errorf("shared script %+v", shared)
	}
	org, err := f.svc.CreateScript(f.ctx, orgAdmin, ScriptInput{OrganizationID: &f.acme, Name: "Acme inventory", Shell: "sh", Body: "uname -a", TimeoutSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	site, err := f.svc.CreateScript(f.ctx, hqAdmin, ScriptInput{OrganizationID: &f.acme, SiteID: &f.hq, Name: "HQ printers", Shell: "python3", Body: "print('ok')"})
	if err != nil {
		t.Fatal(err)
	}
	if org.Level != LevelOrganization || org.OrganizationName != "Acme" || site.Level != LevelSite || site.SiteName != "HQ" {
		t.Errorf("levels %+v %+v", org, site)
	}

	// A site administrator writes only their site's scripts.
	for name, in := range map[string]ScriptInput{
		"shared":       {Name: "x", Shell: "sh", Body: "true"},
		"organization": {OrganizationID: &f.acme, Name: "x", Shell: "sh", Body: "true"},
		"other site":   {OrganizationID: &f.acme, SiteID: &f.branch, Name: "x", Shell: "sh", Body: "true"},
		"wrong org":    {OrganizationID: &f.globex, SiteID: &f.hq, Name: "x", Shell: "sh", Body: "true"},
	} {
		if _, err := f.svc.CreateScript(f.ctx, hqAdmin, in); !errors.Is(err, apperr.ErrForbidden) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.svc.CreateScript(f.ctx, hqTech, ScriptInput{OrganizationID: &f.acme, SiteID: &f.hq, Name: "x", Shell: "sh", Body: "true"}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("technician wrote a script: %v", err)
	}
	// Names are unique within a level, not across levels.
	_, err = f.svc.CreateScript(f.ctx, orgAdmin, ScriptInput{OrganizationID: &f.acme, Name: "ACME INVENTORY", Shell: "sh", Body: "true"})
	fieldErr(t, err, "name", "already exists")
	if _, err := f.svc.CreateScript(f.ctx, orgAdmin, ScriptInput{OrganizationID: &f.acme, SiteID: &f.branch, Name: "Acme inventory", Shell: "sh", Body: "true"}); err != nil {
		t.Errorf("same name on a site: %v", err)
	}
	// Validation.
	_, err = f.svc.CreateScript(f.ctx, super, ScriptInput{Name: " ", Shell: "zsh", Body: "a\x00b", TimeoutSeconds: 99999})
	e, _ := apperr.As(err)
	if e == nil || e.Fields["name"] == "" || e.Fields["shell"] == "" || e.Fields["body"] == "" || e.Fields["timeoutSeconds"] == "" {
		t.Errorf("validation %+v", e)
	}
	_, err = f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "big", Shell: "sh", Body: strings.Repeat("x", MaxBody+1)})
	fieldErr(t, err, "body", "64 KiB")

	// Reading: the HQ technician sees the shared, organization and HQ
	// scripts, but not the branch's; Globex sees only the shared library.
	names := func(c access.Caller, q ScriptQuery) []string {
		t.Helper()
		list, err := f.svc.ListScripts(f.ctx, c, q)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range list {
			out = append(out, s.Name)
		}
		return out
	}
	if got := strings.Join(names(hqTech, ScriptQuery{}), ","); got != "Acme inventory,Disk usage,HQ printers" {
		t.Errorf("HQ technician sees %s", got)
	}
	if got := strings.Join(names(globexTech, ScriptQuery{}), ","); got != "Disk usage" {
		t.Errorf("Globex sees %s", got)
	}
	if got := strings.Join(names(orgAdmin, ScriptQuery{OrganizationID: f.acme}), ","); got != "Acme inventory,Acme inventory,HQ printers" {
		t.Errorf("org filter %s", got)
	}
	if got := strings.Join(names(super, ScriptQuery{Shared: true}), ","); got != "Disk usage" {
		t.Errorf("shared filter %s", got)
	}
	if _, err := f.svc.GetScript(f.ctx, globexTech, org.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("Globex read Acme's script: %v", err)
	}
	got, err := f.svc.GetScript(f.ctx, hqTech, site.ID)
	if err != nil || got.CanEdit || !got.CanRun || got.Body != "print('ok')" {
		t.Errorf("technician's view %+v %v", got, err)
	}
	// Scripts that can run on a device.
	branchPC := f.device(f.branch, "BRANCH-PC", "linux")
	if got := strings.Join(names(orgAdmin, ScriptQuery{DeviceID: branchPC}), ","); got != "Acme inventory,Acme inventory,Disk usage" {
		t.Errorf("scripts for a branch device %s", got)
	}

	// Changing and deleting. An edit moves updatedAt; deleting its author
	// (created_by and updated_by become NULL) does not.
	f.asOwner(`UPDATE scripts SET updated_at = now() - interval '1 day' WHERE id IN ($1, $2)`, site.ID, org.ID)
	updated, err := f.svc.UpdateScript(f.ctx, hqAdmin, site.ID, ScriptPatch{Body: ptr("print('changed')\r\n"), TimeoutSeconds: ptr(120)})
	if err != nil || updated.Body != "print('changed')\n" || updated.TimeoutSeconds != 120 || updated.Name != "HQ printers" {
		t.Fatalf("update %+v %v", updated, err)
	}
	if time.Since(updated.UpdatedAt) > time.Hour {
		t.Errorf("an edit left updatedAt at %s", updated.UpdatedAt)
	}
	f.asOwner(`DELETE FROM users WHERE id = $1`, orgAdmin.Actor.ID)
	if got := f.str(`SELECT (now() - updated_at > interval '23 hours' AND created_by IS NULL AND updated_by IS NULL)::text FROM scripts WHERE id = $1`, org.ID); got != "true" {
		t.Errorf("deleting the author touched the script: %s", got)
	}
	if _, err := f.svc.UpdateScript(f.ctx, hqTech, site.ID, ScriptPatch{Name: ptr("x")}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("technician changed a script: %v", err)
	}
	if _, err := f.svc.UpdateScript(f.ctx, hqAdmin, org.ID, ScriptPatch{Name: ptr("x")}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("site admin changed an organization script: %v", err)
	}
	details := f.str(`SELECT details::text FROM audit_log WHERE action = 'script.update' AND target_id = $1`, site.ID.String())
	if !strings.Contains(details, bodyHash("print('changed')\n")) || !strings.Contains(details, `"timeoutSeconds"`) {
		t.Errorf("update audit %s", details)
	}
	if err := f.svc.DeleteScript(f.ctx, hqTech, site.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("technician deleted a script: %v", err)
	}
	if err := f.svc.DeleteScript(f.ctx, hqAdmin, site.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.GetScript(f.ctx, super, site.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("deleted script still there: %v", err)
	}
	if f.str(`SELECT count(*)::text FROM audit_log WHERE action IN ('script.create', 'script.update', 'script.delete')`) != "6" {
		t.Errorf("script audit events missing")
	}
}

func TestJobFromCreationToResult(t *testing.T) {
	f := newFixture(t)
	orgAdmin := f.user("orgadmin@example.com", rbac.Assignment{Role: rbac.RoleOrgAdmin, OrganizationID: f.acme})
	tech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	sc, err := f.svc.CreateScript(f.ctx, orgAdmin, ScriptInput{OrganizationID: &f.acme, Name: "Report", Shell: "bash", Body: "echo $1", TimeoutSeconds: 90})
	if err != nil {
		t.Fatal(err)
	}
	pc := f.device(f.hq, "HQ-PC-01", "linux")

	// A poll that is waiting is woken by the new job.
	polled := make(chan *agentproto.PollResponse, 1)
	f.svc.pollWait = 10 * time.Second
	go func() {
		resp, err := f.svc.Poll(f.ctx, pc)
		if err != nil {
			t.Error(err)
		}
		polled <- resp
	}()
	time.Sleep(200 * time.Millisecond)
	job, err := f.svc.CreateJob(f.ctx, tech, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{pc, pc}, Args: []string{"hello world"}})
	if err != nil {
		t.Fatal(err)
	}
	if job.Total != 1 || job.Counts[StatusQueued] != 1 || job.Body != "echo $1" || job.TimeoutSeconds != 90 || job.CreatedBy != "tech@example.com" || !job.CanCancel {
		t.Errorf("job %+v", job)
	}
	if d := time.Until(job.ExpiresAt); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("default wait %v", d)
	}
	var resp *agentproto.PollResponse
	select {
	case resp = <-polled:
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting poll was not woken")
	}
	f.svc.pollWait = 200 * time.Millisecond
	if len(resp.Jobs) != 1 {
		t.Fatalf("poll %+v", resp)
	}
	p, err := agentproto.VerifyJob(f.key, resp.Jobs[0], pc.String(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	run := job.Runs[0]
	if p.RunID != run.ID.String() || p.JobID != job.ID.String() || p.Script != "echo $1" || p.Args[0] != "hello world" || p.TimeoutSeconds != 90 {
		t.Errorf("payload %+v", p)
	}
	audited := f.str(`SELECT details::text FROM audit_log WHERE action = 'device.script_run' AND device_id = $1`, pc)
	if !strings.Contains(audited, `"argCount": 1`) || strings.Contains(audited, "hello world") || !strings.Contains(audited, sc.SHA256) {
		t.Errorf("audit %s", audited)
	}

	// Not delivered again while it is fresh; another device gets nothing.
	if again, _ := f.svc.Poll(f.ctx, pc); len(again.Jobs) != 0 {
		t.Error("delivered twice at once")
	}
	if other, _ := f.svc.Poll(f.ctx, f.device(f.hq, "HQ-PC-02", "linux")); len(other.Jobs) != 0 {
		t.Error("another device got the job")
	}
	// Delivered again when it was not started in time.
	f.exec(`UPDATE job_runs SET sent_at = now() - interval '3 minutes' WHERE id = $1`, run.ID)
	if again, _ := f.svc.Poll(f.ctx, pc); len(again.Jobs) != 1 {
		t.Error("not delivered again")
	}

	if _, err := f.svc.Start(f.ctx, uuid.New(), run.ID); !errors.Is(err, ErrRunNotFound) {
		t.Errorf("another device started the run: %v", err)
	}
	st, err := f.svc.Start(f.ctx, pc, run.ID)
	if err != nil || !st.Proceed {
		t.Fatalf("start %+v %v", st, err)
	}
	if st, _ := f.svc.Start(f.ctx, pc, run.ID); !st.Proceed {
		t.Error("a repeated start was refused")
	}
	got, _ := f.svc.GetRun(f.ctx, tech, run.ID)
	if got.Status != StatusRunning || got.StartedAt == nil || got.Deliveries != 2 {
		t.Errorf("running %+v", got)
	}
	deadline := f.str(`SELECT (deadline_at - started_at)::text FROM job_runs WHERE id = $1`, run.ID)
	if deadline != "00:06:30" {
		t.Errorf("deadline after %s", deadline)
	}

	code := 0
	if err := f.svc.Result(f.ctx, pc, run.ID, agentproto.ResultRequest{Status: StatusSucceeded}); !errors.Is(err, ErrBadResult) {
		t.Errorf("success without exit code: %v", err)
	}
	if err := f.svc.Result(f.ctx, pc, run.ID, agentproto.ResultRequest{Status: "exploded"}); !errors.Is(err, ErrBadResult) {
		t.Errorf("unknown status: %v", err)
	}
	if err := f.svc.Result(f.ctx, pc, run.ID, agentproto.ResultRequest{
		Status: StatusSucceeded, ExitCode: &code, Stdout: "hello world\n\x00", Stderr: strings.Repeat("e", agentproto.MaxStreamBytes+10), Error: "x\x01y",
	}); err != nil {
		t.Fatal(err)
	}
	// The first result wins.
	failed := 1
	if err := f.svc.Result(f.ctx, pc, run.ID, agentproto.ResultRequest{Status: StatusFailed, ExitCode: &failed}); err != nil {
		t.Errorf("repeat result: %v", err)
	}
	if err := f.svc.Result(f.ctx, pc, uuid.New(), agentproto.ResultRequest{Status: StatusFailed}); !errors.Is(err, ErrRunNotFound) {
		t.Errorf("unknown run: %v", err)
	}
	got, err = f.svc.GetRun(f.ctx, tech, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusSucceeded || *got.ExitCode != 0 || *got.Stdout != "hello world\n" || len(*got.Stderr) != agentproto.MaxStreamBytes ||
		!got.StderrTruncated || got.StdoutTruncated || got.Error != "xy" || got.FinishedAt == nil || got.Job.Body != "echo $1" || got.CanCancel {
		t.Errorf("finished run %+v", got)
	}
	if st, _ := f.svc.Start(f.ctx, pc, run.ID); st.Proceed {
		t.Error("a finished run started again")
	}
	job, _ = f.svc.GetJob(f.ctx, tech, job.ID)
	if !job.Finished || job.Counts[StatusSucceeded] != 1 || job.CanCancel {
		t.Errorf("finished job %+v", job)
	}
	list, _ := f.svc.ListJobs(f.ctx, tech, JobQuery{DeviceID: pc})
	if len(list) != 1 || !list[0].Finished || list[0].Total != 1 {
		t.Errorf("job list %+v", list)
	}
	if open, _ := f.svc.ListJobs(f.ctx, tech, JobQuery{Status: "open"}); len(open) != 0 {
		t.Errorf("open jobs %+v", open)
	}
	runs, _ := f.svc.ListRuns(f.ctx, tech, RunQuery{DeviceID: pc})
	if len(runs) != 1 || runs[0].Stdout != nil {
		t.Errorf("device runs %+v", runs)
	}
}

func TestJobsRefuseDevicesTheScriptOrCallerCannotReach(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	hqTech := f.user("tech@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq})
	branchViewer := f.user("viewer@example.com",
		rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme, SiteID: f.hq},
		rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme, SiteID: f.branch})
	hqScript, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{OrganizationID: &f.acme, SiteID: &f.hq, Name: "HQ only", Shell: "sh", Body: "true"})
	shared, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Anywhere", Shell: "sh", Body: "true"})
	globexScript, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{OrganizationID: &f.globex, Name: "Globex", Shell: "sh", Body: "true"})

	hqPC := f.device(f.hq, "HQ-PC", "linux")
	branchPC := f.device(f.branch, "BRANCH-PC", "linux")
	plantPC := f.device(f.plant, "PLANT-PC", "linux")
	winPC := f.device(f.hq, "HQ-WIN", "windows")
	discovered := f.device(f.hq, "HQ-MESH", "")

	try := func(c access.Caller, in JobInput) error {
		_, err := f.svc.CreateJob(f.ctx, c, in)
		return err
	}
	fieldErr(t, try(super, JobInput{ScriptID: hqScript.ID, DeviceIDs: []uuid.UUID{hqPC, branchPC}}), "deviceIds", "only on devices in its site, not on BRANCH-PC")
	fieldErr(t, try(super, JobInput{ScriptID: globexScript.ID, DeviceIDs: []uuid.UUID{hqPC}}), "deviceIds", "in its organization")
	fieldErr(t, try(super, JobInput{ScriptID: shared.ID, DeviceIDs: []uuid.UUID{discovered}}), "deviceIds", "HQ-MESH has no EasyRMM agent")
	fieldErr(t, try(super, JobInput{ScriptID: shared.ID, DeviceIDs: []uuid.UUID{winPC, hqPC}}), "deviceIds", "HQ-WIN is not a Linux device")
	fieldErr(t, try(hqTech, JobInput{ScriptID: shared.ID, DeviceIDs: []uuid.UUID{hqPC, plantPC}}), "deviceIds", "1 device does not exist")
	fieldErr(t, try(branchViewer, JobInput{ScriptID: shared.ID, DeviceIDs: []uuid.UUID{hqPC, branchPC}}), "deviceIds", "cannot run scripts on BRANCH-PC")
	fieldErr(t, try(hqTech, JobInput{ScriptID: globexScript.ID, DeviceIDs: []uuid.UUID{hqPC}}), "scriptId", "does not exist")
	fieldErr(t, try(hqTech, JobInput{DeviceIDs: []uuid.UUID{hqPC}}), "scriptId", "Choose a script")
	fieldErr(t, try(hqTech, JobInput{ScriptID: shared.ID}), "deviceIds", "at least one")
	many := make([]uuid.UUID, MaxDevices+1)
	for i := range many {
		many[i] = uuid.New()
	}
	fieldErr(t, try(hqTech, JobInput{ScriptID: shared.ID, DeviceIDs: many}), "deviceIds", "at most 500")
	fieldErr(t, try(hqTech, JobInput{ScriptID: shared.ID, DeviceIDs: []uuid.UUID{hqPC}, Args: make([]string, MaxArgs+1)}), "args", "at most 32")
	fieldErr(t, try(hqTech, JobInput{ScriptID: shared.ID, DeviceIDs: []uuid.UUID{hqPC}, Args: []string{strings.Repeat("a", MaxArgBytes+1)}}), "args", "Argument 1")
	fieldErr(t, try(hqTech, JobInput{ScriptID: shared.ID, DeviceIDs: []uuid.UUID{hqPC}, Args: []string{"ok", "a\x00"}}), "args", "Argument 2")
	fieldErr(t, try(hqTech, JobInput{ScriptID: shared.ID, DeviceIDs: []uuid.UUID{hqPC}, TimeoutSeconds: MaxTimeout + 1}), "timeoutSeconds", "4 hours")
	fieldErr(t, try(hqTech, JobInput{ScriptID: shared.ID, DeviceIDs: []uuid.UUID{hqPC}, WaitHours: MaxWaitHours + 1}), "waitHours", "7 days")
	if f.str(`SELECT count(*)::text FROM jobs`) != "0" {
		t.Error("a refused job was stored")
	}
	if _, err := f.svc.CreateJob(f.ctx, hqTech, JobInput{ScriptID: hqScript.ID, DeviceIDs: []uuid.UUID{hqPC}, TimeoutSeconds: 5, WaitHours: 2}); err != nil {
		t.Errorf("an allowed job: %v", err)
	}
}

func TestJobsAreSeenOnlyWhereTheirRunsAre(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	acmeTech := f.user("acme@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.acme})
	hqViewer := f.user("hq@example.com", rbac.Assignment{Role: rbac.RoleReadOnly, OrganizationID: f.acme, SiteID: f.hq})
	globexTech := f.user("globex@example.com", rbac.Assignment{Role: rbac.RoleTechnician, OrganizationID: f.globex})
	sc, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Everywhere", Shell: "sh", Body: "true"})
	hqPC, branchPC, plantPC := f.device(f.hq, "HQ", "linux"), f.device(f.branch, "BR", "linux"), f.device(f.plant, "PL", "linux")
	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{hqPC, branchPC, plantPC}})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		c     access.Caller
		total int
	}{"acme": {acmeTech, 2}, "hq": {hqViewer, 1}, "globex": {globexTech, 1}, "super": {super, 3}} {
		j, err := f.svc.GetJob(f.ctx, tc.c, job.ID)
		if err != nil || j.Total != tc.total || len(j.Runs) != tc.total {
			t.Errorf("%s sees %+v %v", name, j, err)
			continue
		}
		list, _ := f.svc.ListJobs(f.ctx, tc.c, JobQuery{})
		if len(list) != 1 || list[0].Total != tc.total {
			t.Errorf("%s list %+v", name, list)
		}
	}
	plantRun := f.id(`SELECT id FROM job_runs WHERE device_id = $1`, plantPC)
	if _, err := f.svc.GetRun(f.ctx, acmeTech, plantRun); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("Acme read Globex's run: %v", err)
	}
	if _, err := f.svc.CancelRun(f.ctx, acmeTech, plantRun); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("Acme canceled Globex's run: %v", err)
	}
	// A read-only viewer sees but cannot cancel.
	if j, _ := f.svc.GetJob(f.ctx, hqViewer, job.ID); j.CanCancel {
		t.Error("read-only viewer may cancel")
	}
	if _, err := f.svc.CancelJob(f.ctx, hqViewer, job.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("read-only cancel: %v", err)
	}
	// Canceling the job from Acme cancels Acme's runs only.
	j, err := f.svc.CancelJob(f.ctx, acmeTech, job.ID)
	if err != nil || j.Counts[StatusCanceled] != 2 {
		t.Fatalf("cancel %+v %v", j, err)
	}
	if st := f.str(`SELECT status FROM job_runs WHERE id = $1`, plantRun); st != StatusQueued {
		t.Errorf("Globex's run became %s", st)
	}
	if _, err := f.svc.CancelJob(f.ctx, acmeTech, job.ID); !errors.Is(err, apperr.Conflict("job_finished", "")) {
		t.Errorf("second cancel: %v", err)
	}
	if n := f.str(`SELECT count(*)::text FROM audit_log WHERE action = 'job.cancel'`); n != "2" {
		t.Errorf("%s cancel events", n)
	}
}

func TestCancelExpireAndLose(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	sc, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "Slow", Shell: "sh", Body: "sleep 100"})
	a, b, c, d := f.device(f.hq, "A", "linux"), f.device(f.hq, "B", "linux"), f.device(f.hq, "C", "linux"), f.device(f.hq, "D", "linux")
	job, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{a, b, c, d}})
	if err != nil {
		t.Fatal(err)
	}
	runOf := func(dev uuid.UUID) uuid.UUID { return f.id(`SELECT id FROM job_runs WHERE device_id = $1`, dev) }
	status := func(dev uuid.UUID) string { return f.str(`SELECT status FROM job_runs WHERE device_id = $1`, dev) }

	// A: running, then canceled: the agent is told and reports.
	_, _ = f.svc.Poll(f.ctx, a)
	if st, _ := f.svc.Start(f.ctx, a, runOf(a)); !st.Proceed {
		t.Fatal("A did not start")
	}
	r, err := f.svc.CancelRun(f.ctx, super, runOf(a))
	if err != nil || r.Status != StatusRunning || !r.CancelRequested || r.CanCancel {
		t.Fatalf("cancel running %+v %v", r, err)
	}
	resp, _ := f.svc.Poll(f.ctx, a)
	if len(resp.Cancel) != 1 || resp.Cancel[0] != runOf(a).String() {
		t.Errorf("cancel not delivered: %+v", resp)
	}
	if resp, _ := f.svc.Poll(f.ctx, a); len(resp.Cancel) != 0 {
		t.Error("cancel repeated at once")
	}
	if st, _ := f.svc.Start(f.ctx, a, runOf(a)); st.Proceed {
		t.Error("a canceled run may start")
	}
	if status(a) != StatusCanceled {
		t.Errorf("A is %s", status(a))
	}

	// B: delivered but not started, then canceled: it never starts.
	_, _ = f.svc.Poll(f.ctx, b)
	if _, err := f.svc.CancelRun(f.ctx, super, runOf(b)); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.svc.Start(f.ctx, b, runOf(b)); st.Proceed || status(b) != StatusCanceled {
		t.Errorf("B %v %s", st.Proceed, status(b))
	}

	// C: never picked up: expires.
	f.exec(`UPDATE job_runs SET expires_at = now() - interval '1 second' WHERE device_id = $1`, c)
	if resp, _ := f.svc.Poll(f.ctx, c); len(resp.Jobs) != 0 {
		t.Error("an expired run was delivered")
	}
	// D: started but silent past its deadline: lost, until a late result.
	_, _ = f.svc.Poll(f.ctx, d)
	_, _ = f.svc.Start(f.ctx, d, runOf(d))
	f.exec(`UPDATE job_runs SET deadline_at = now() - interval '1 second' WHERE device_id = $1`, d)
	swept, err := f.svc.Sweep(f.ctx)
	if err != nil || swept.Expired != 1 || swept.Lost != 1 || status(c) != StatusExpired || status(d) != StatusLost {
		t.Fatalf("sweep %+v %v: %s %s", swept, err, status(c), status(d))
	}
	if err := f.svc.Result(f.ctx, d, runOf(d), agentproto.ResultRequest{Status: StatusTimedOut, Error: "Stopped after 5m0s."}); err != nil {
		t.Fatal(err)
	}
	if status(d) != StatusTimedOut {
		t.Errorf("late result: %s", status(d))
	}
	j, _ := f.svc.GetJob(f.ctx, super, job.ID)
	if !j.Finished || j.Counts[StatusCanceled] != 2 || j.Counts[StatusExpired] != 1 || j.Counts[StatusTimedOut] != 1 {
		t.Errorf("job %+v", j.Counts)
	}

	// Retention removes finished jobs once they are old enough.
	if n, err := f.svc.Purge(f.ctx); err != nil || n != 0 {
		t.Errorf("purged a new job: %d %v", n, err)
	}
	f.asOwner(`UPDATE jobs SET created_at = now() - interval '91 days'`)
	if n, err := f.svc.Purge(f.ctx); err != nil || n != 1 {
		t.Errorf("purge: %d %v", n, err)
	}
	if f.str(`SELECT count(*)::text FROM job_runs`) != "0" {
		t.Error("runs outlived their job")
	}
}

func TestStartingAnExpiredRunAndClosingPolls(t *testing.T) {
	f := newFixture(t)
	super := f.user("super@example.com", rbac.Assignment{Role: rbac.RoleSuperAdmin})
	sc, _ := f.svc.CreateScript(f.ctx, super, ScriptInput{Name: "x", Shell: "sh", Body: "true"})
	pc := f.device(f.hq, "PC", "linux")
	if _, err := f.svc.CreateJob(f.ctx, super, JobInput{ScriptID: sc.ID, DeviceIDs: []uuid.UUID{pc}}); err != nil {
		t.Fatal(err)
	}
	resp, _ := f.svc.Poll(f.ctx, pc)
	run := f.id(`SELECT id FROM job_runs WHERE device_id = $1`, pc)
	f.exec(`UPDATE job_runs SET expires_at = now() - interval '1 second' WHERE id = $1`, run)
	if st, _ := f.svc.Start(f.ctx, pc, run); st.Proceed || f.str(`SELECT status FROM job_runs WHERE id = $1`, run) != StatusExpired {
		t.Error("an expired run started")
	}
	if len(resp.Jobs) != 1 {
		t.Fatal("not delivered")
	}

	// Closing the service ends waiting polls at once.
	f.svc.pollWait = time.Minute
	done := make(chan struct{})
	go func() {
		_, _ = f.svc.Poll(f.ctx, pc)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	f.svc.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not release the poll")
	}
	// A canceled request ends its poll too.
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	f.svc.hub = newHub()
	if _, err := f.svc.Poll(ctx, pc); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled poll: %v", err)
	}
}
