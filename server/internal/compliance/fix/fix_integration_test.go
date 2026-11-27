//go:build integration

package fix_test

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
	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/engine"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/fix"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

const windowsPlatform = `{"id":"windows","versionId":"10.0.26100.4349","family":"windows","container":"none","support":"full",` +
	`"windows":{"build":26100,"ubr":4349,"displayVersion":"24H2","edition":"ServerStandard","installationType":"Server Core",` +
	`"role":"member_server","joined":"domain","mdm":false,"architecture":"amd64","languageMode":"FullLanguage",` +
	`"owners":{"groupPolicyRecord":"read","groupPolicyPreferences":false,"mdm":false,"mdmWinsOverGp":false,` +
	`"defenderForEndpoint":false,"configMgr":false,"dsc":false,"azureMachineConfiguration":false,` +
	`"osConfig":[],"tamperProtected":true},` +
	`"checkOnlyReasons":[],"notes":[],"hardening":{"folder":"absent","copySha256":"","warnings":[],"setAside":[]}}}`

// stepUp is the session's step-up check, which needs a real session: the tests set what it answers.
type stepUp struct{ err error }

func (s *stepUp) VerifyStepUp(context.Context) error { return s.err }

type fixture struct {
	t      *testing.T
	ctx    context.Context
	db     *database.DB
	jobs   *jobs.Service
	eng    *engine.Service
	fix    *fix.Service
	step   *stepUp
	acme   uuid.UUID
	globex uuid.UUID
	hq     uuid.UUID
	win    uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, step: &stepUp{}}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	al := audit.New(inst.DB, time.Now)
	f.jobs = jobs.New(inst.DB, al, jobkeys.Static(priv), 90*24*time.Hour, 30*24*time.Hour, log)
	f.jobs.SetStepUp(f.step)
	f.eng = engine.New(inst.DB, f.jobs, al, log)
	var err error
	if f.fix, err = fix.New(inst.DB, f.jobs, f.eng, al, log); err != nil {
		t.Fatal(err)
	}
	f.fix.SetStepUp(f.step)
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	if err := f.eng.LoadContent(f.ctx, content.FS, compliance.EditionDev); err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO compliance_org_settings (organization_id, enabled) VALUES ($1, true)`, f.acme)
	f.win = f.device("HQ-WIN")
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
	if err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) n(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&n) }); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fixture) str(sql string, args ...any) string {
	f.t.Helper()
	var s string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(f.ctx, sql, args...).Scan(&s) }); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fixture) user(email string, role rbac.Role, org uuid.UUID) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	f.exec(`INSERT INTO role_assignments (user_id, role, organization_id) VALUES ($1, $2, $3)`, id, string(role), org)
	p, err := rbac.NewPrincipal(id, []rbac.Assignment{{Role: role, OrganizationID: org}})
	if err != nil {
		f.t.Fatal(err)
	}
	return access.User(p, auth.DataScope(p), audit.Actor{Type: audit.ActorUser, ID: id, Label: email})
}

func (f *fixture) device(name string) uuid.UUID {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return f.id(`INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
		VALUES ($1, $2, $3, $3, 'windows', $4, now(), now()) RETURNING id`, f.acme, f.hq, name, key)
}

// store keeps a module's check result as the hardening job's ingester does.
func (f *fixture) store(device uuid.UUID, module, state, detail string) {
	f.t.Helper()
	f.exec(`INSERT INTO device_hardening (device_id, module, state, detail, checked_at) VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (device_id, module) DO UPDATE SET state = EXCLUDED.state, detail = EXCLUDED.detail, checked_at = EXCLUDED.checked_at`,
		device, module, state, detail)
}

// seed stores three failing settings on the computer (autoplay: T1, accounts minimum length: T2, Remote Desktop's NLA: T3) and
// scans what is stored, which makes the queue's items.
func (f *fixture) seed(admin access.Caller) {
	f.t.Helper()
	f.store(f.win, "autoplay", "not_in_place", `{"settings":[{"id":"autoplay-autorun","state":"not_in_place","value":"0","want":"1"}]}`)
	f.store(f.win, "accounts", "not_in_place", `{"settings":[{"id":"accounts-min-length","state":"not_in_place","value":"8","want":"14"}]}`)
	f.store(f.win, "rdp", "not_in_place", `{"settings":[{"id":"rdp-nla","state":"not_in_place","value":"0","want":"1"}]}`)
	if _, err := f.eng.StartScan(f.ctx, admin, f.acme, engine.ScanInput{Profile: "win-server-baseline"}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) item(c access.Caller, control string) fix.Item {
	f.t.Helper()
	items, err := f.fix.Queue(f.ctx, c, f.acme, fix.Filter{State: "all"})
	if err != nil {
		f.t.Fatal(err)
	}
	for _, it := range items {
		if it.ControlID == control {
			return it
		}
	}
	f.t.Fatalf("no item for %s among %d", control, len(items))
	return fix.Item{}
}

// get reads an item by id: a control that still fails after a fix has its old item and a new open one.
func (f *fixture) get(c access.Caller, id uuid.UUID) fix.Item {
	f.t.Helper()
	d, err := f.fix.Get(f.ctx, c, f.acme, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return d.Item
}

func code(t *testing.T, err error, want string) {
	t.Helper()
	if e, ok := apperr.As(err); !ok || e.Code != want {
		t.Fatalf("want %s, got %v", want, err)
	}
}

func field(t *testing.T, err error, name string) {
	t.Helper()
	if e, ok := apperr.As(err); !ok || e.Fields[name] == "" {
		t.Fatalf("want a problem with %s, got %v", name, err)
	}
}

// finish runs the device's job to the end with the output.
func (f *fixture) finish(job uuid.UUID, stdout string) {
	f.t.Helper()
	run := uuid.MustParse(f.str(`SELECT id::text FROM job_runs WHERE job_id = $1 AND device_id = $2`, job, f.win))
	if _, err := f.jobs.Start(f.ctx, f.win, run); err != nil {
		f.t.Fatal(err)
	}
	zero := 0
	if err := f.jobs.Result(f.ctx, f.win, run, agentproto.ResultRequest{Status: jobs.StatusSucceeded, ExitCode: &zero, Stdout: stdout, StartedAt: time.Now()}); err != nil {
		f.t.Fatal(err)
	}
}

func line(mode, module, state, setting string) string {
	return jobs.HardeningResultPrefix + `{"version":1,"mode":"` + mode + `","platform":` + windowsPlatform + `,"modules":[{"module":"` + module +
		`","state":"` + state + `",` + setting + `"managed":[],"notes":[]}]}`
}

func applied(module, id, before, after string) string {
	return line("apply", module, "in_place", `"outcome":"applied","recorded":true,"done":["`+id+`"],"settings":[{"id":"`+id+`","state":"in_place","value":"`+after+
		`","outcome":"applied","before":"`+before+`","changedAt":"2026-11-26T10:00:00Z"}],`)
}

func (f *fixture) lastJob(kind string) uuid.UUID {
	return uuid.MustParse(f.str(`SELECT id::text FROM jobs WHERE hardening->>'mode' = $1 ORDER BY created_at DESC LIMIT 1`, kind))
}

const (
	autorun = "win.autoplay.autorun"
	minLen  = "win.accounts.min-length"
	nla     = "win.rdp.nla"
)

// The queue is made from the scan's results, once per computer and control.
func TestScanMakesTheQueue(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.RoleOrgAdmin, f.acme)
	other := f.user("other@example.com", rbac.RoleOrgAdmin, f.globex)
	ro := f.user("ro@example.com", rbac.RoleReadOnly, f.acme)
	f.seed(admin)
	items, err := f.fix.Queue(f.ctx, admin, f.acme, fix.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	tiers := map[string]string{}
	for _, it := range items {
		tiers[it.ControlID] = it.Tier
		if it.State != fix.StateOpen || it.Warning == nil || it.Warning.SHA256 == "" || it.DeviceName != "HQ-WIN" {
			t.Errorf("%s: %+v", it.ControlID, it)
		}
	}
	if tiers[autorun] != "T1" || tiers[minLen] != "T2" || tiers[nla] != "T3" || len(items) != 3 {
		t.Fatalf("tiers %v", tiers)
	}
	if it := f.item(admin, nla); !it.RequiresTyped || !it.RequiresStepUp || len(it.Preconditions) == 0 {
		t.Errorf("the tier 3 item: %+v", it)
	}
	// A second scan does not duplicate.
	if _, err := f.eng.StartScan(f.ctx, admin, f.acme, engine.ScanInput{Profile: "win-server-baseline"}); err != nil {
		t.Fatal(err)
	}
	if n := f.n(`SELECT count(*) FROM compliance_fix_items`); n != 3 {
		t.Errorf("%d items after a second scan", n)
	}
	// Another organization sees nothing; Read-Only holds no compliance permission.
	if _, err := f.fix.Queue(f.ctx, other, f.acme, fix.Filter{}); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization: %v", err)
	}
	if _, err := f.fix.Queue(f.ctx, ro, f.acme, fix.Filter{}); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("read-only: %v", err)
	}
	// The control now meets by itself: the item is resolved, not left open.
	f.store(f.win, "autoplay", "in_place", `{"settings":[{"id":"autoplay-autorun","state":"in_place","value":"1","want":"1"}]}`)
	if _, err := f.eng.StartScan(f.ctx, admin, f.acme, engine.ScanInput{Profile: "win-server-baseline"}); err != nil {
		t.Fatal(err)
	}
	if it := f.item(admin, autorun); it.State != fix.StateResolved {
		t.Errorf("state %s", it.State)
	}
}

// Apply writes an agreement and audit rows; the fix does not change a result until a re-scan; undo.
func TestApplyVerifyAndUndo(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.RoleOrgAdmin, f.acme)
	tech := f.user("tech@example.com", rbac.RoleTechnician, f.acme)
	f.seed(admin)
	it := f.item(admin, autorun)

	if _, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: []uuid.UUID{it.ID}}); err == nil {
		t.Fatal("an apply without the agreement")
	} else {
		field(t, err, "agreed")
	}
	if _, err := f.fix.Apply(f.ctx, tech, f.acme, fix.ApplyInput{ItemIDs: []uuid.UUID{it.ID}, Agreement: fix.Agreement{Agreed: true}}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a technician holds no device.harden: %v", err)
	}
	if f.n(`SELECT count(*) FROM compliance_fix_agreements`) != 0 || f.n(`SELECT count(*) FROM jobs`) != 0 {
		t.Fatal("a refused apply left an agreement or a job")
	}

	out, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: []uuid.UUID{it.ID}, Agreement: fix.Agreement{Agreed: true}})
	if err != nil || len(out) != 1 || out[0].State != fix.StateApplying || out[0].ApplyJobID == nil {
		t.Fatalf("%+v, %v", out, err)
	}
	if f.n(`SELECT count(*) FROM compliance_fix_agreements WHERE item_id = $1 AND act = 'apply' AND warning_id = 'warn.t1.v1' AND length(warning_sha256) = 64`, it.ID) != 1 {
		t.Error("no agreement row with the warning's id and hash")
	}
	for _, a := range []string{"compliance.fix.agreed", "compliance.fix.dispatched"} {
		if f.n(`SELECT count(*) FROM audit_log WHERE action = $1 AND organization_id = $2`, a, f.acme) != 1 {
			t.Errorf("no audit row %s", a)
		}
	}
	// The job changes one setting, named by id, and no module as a whole.
	if got := f.str(`SELECT hardening->>'settings' FROM jobs WHERE id = $1`, *out[0].ApplyJobID); got != `["autoplay-autorun"]` {
		t.Errorf("the job's settings: %s", got)
	}
	// One change at a time on a computer.
	if _, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: []uuid.UUID{f.item(admin, minLen).ID}, Agreement: fix.Agreement{Agreed: true}}); err == nil {
		t.Error("a second change on a computer that is being changed")
	} else {
		code(t, err, "device_busy")
	}

	f.finish(*out[0].ApplyJobID, applied("autoplay", "autoplay-autorun", "0", "1"))
	got, err := f.fix.Queue(f.ctx, admin, f.acme, fix.Filter{State: "all"})
	if err != nil {
		t.Fatal(err)
	}
	var cur fix.Item
	for _, g := range got {
		if g.ControlID == autorun {
			cur = g
		}
	}
	if cur.State != fix.StateApplied || !strings.Contains(string(cur.Outcome), `"before": "0"`) || !strings.Contains(string(cur.Outcome), `"after": "1"`) {
		t.Fatalf("after the job: %s %s", cur.State, cur.Outcome)
	}
	// The requirement's source of truth, the latest result, has not moved: only a re-scan can.
	if st := f.str(`SELECT state FROM compliance_results WHERE device_id = $1 AND control_id = $2`, f.win, autorun); st != "not_in_place" {
		t.Fatalf("the fix changed a result: %s", st)
	}
	if f.n(`SELECT count(*) FROM compliance_scans WHERE trigger = 'verify' AND selection->'controlIds' = '["win.autoplay.autorun"]'::jsonb`) != 1 {
		t.Fatal("no single-control re-scan")
	}
	// The re-scan's check job answers, and the item is verified.
	check := f.lastJob("check")
	f.finish(check, line("check", "autoplay", "in_place", `"settings":[{"id":"autoplay-autorun","state":"in_place","value":"1","want":"1"}],`))
	if err := f.fix.AdvanceOpen(f.ctx); err != nil {
		t.Fatal(err)
	}
	if it := f.item(admin, autorun); it.State != fix.StateVerified || !it.CanUndo {
		t.Fatalf("after the re-scan: %s", it.State)
	}
	if st := f.str(`SELECT state FROM compliance_results WHERE device_id = $1 AND control_id = $2`, f.win, autorun); st != "in_place" {
		t.Errorf("after the re-scan: %s", st)
	}
	// A verified fix stays in the queue for a week, so it can be undone from there; then it is history.
	for filter, want := range map[string]bool{"active": true, "history": false} {
		got, err := f.fix.Queue(f.ctx, admin, f.acme, fix.Filter{State: filter})
		if err != nil {
			t.Fatal(err)
		}
		in := false
		for _, g := range got {
			in = in || g.ID == it.ID
		}
		if in != want {
			t.Errorf("a verified fix in the %s list: %v", filter, in)
		}
	}
	f.exec(`UPDATE compliance_fix_items SET updated_at = now() - interval '8 days' WHERE id = $1`, it.ID)
	if got, _ := f.fix.Queue(f.ctx, admin, f.acme, fix.Filter{State: "history"}); len(got) != 1 || got[0].ID != it.ID {
		t.Errorf("a verified fix after a week is not history: %d", len(got))
	}
	f.exec(`UPDATE compliance_fix_items SET updated_at = now() WHERE id = $1`, it.ID)

	// Undo, agreed to like the fix.
	if _, err := f.fix.Undo(f.ctx, admin, f.acme, it.ID, fix.Agreement{}); err == nil {
		t.Fatal("an undo without the agreement")
	}
	u, err := f.fix.Undo(f.ctx, admin, f.acme, it.ID, fix.Agreement{Agreed: true})
	if err != nil || u.State != fix.StateUndoing || u.UndoJobID == nil {
		t.Fatalf("%+v, %v", u, err)
	}
	if f.n(`SELECT count(*) FROM compliance_fix_agreements WHERE item_id = $1 AND act = 'undo'`, it.ID) != 1 {
		t.Error("no undo agreement")
	}
	f.finish(*u.UndoJobID, line("undo", "autoplay", "not_in_place",
		`"outcome":"undone","done":["autoplay-autorun"],"settings":[{"id":"autoplay-autorun","state":"not_in_place","value":"0","outcome":"restored","before":"1"}],`))
	if err := f.fix.AdvanceOpen(f.ctx); err != nil {
		t.Fatal(err)
	}
	if it := f.item(admin, autorun); it.State != fix.StateUndone {
		t.Fatalf("after the undo: %s", it.State)
	}
	// The undone fix is checked again; the control does not meet, so a new item is in the queue.
	f.finish(f.lastJob("check"), line("check", "autoplay", "not_in_place", `"settings":[{"id":"autoplay-autorun","state":"not_in_place","value":"0","want":"1"}],`))
	if err := f.fix.AdvanceOpen(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.n(`SELECT count(*) FROM compliance_fix_items WHERE control_id = $1 AND state = 'open'`, autorun); n != 1 {
		t.Errorf("%d open items after the undo's re-scan", n)
	}
	// The history keeps every step.
	hist, err := f.fix.Get(f.ctx, admin, f.acme, it.ID)
	if err != nil || len(hist.Agreements) != 2 {
		t.Fatalf("%+v, %v", hist, err)
	}
	for _, a := range []string{"compliance.fix.applied", "compliance.fix.read_back", "compliance.fix.undone"} {
		if f.n(`SELECT count(*) FROM audit_log WHERE action = $1`, a) != 1 {
			t.Errorf("no audit row %s", a)
		}
	}
}

// A change the script could not make stands as failed, with its reason.
func TestFailedApplyIsMarkedFailed(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.RoleOrgAdmin, f.acme)
	f.seed(admin)
	it := f.item(admin, autorun)
	out, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: []uuid.UUID{it.ID}, Agreement: fix.Agreement{Agreed: true}})
	if err != nil {
		t.Fatal(err)
	}
	f.finish(*out[0].ApplyJobID, line("apply", "autoplay", "not_in_place",
		`"outcome":"failed","outcomeReason":"The value was not as intended after the change, so the old one was put back.","done":[],`+
			`"settings":[{"id":"autoplay-autorun","state":"not_in_place","value":"0","outcome":"failed","before":"0"}],`))
	if got := f.item(admin, autorun); got.State != fix.StateFailed || !strings.Contains(got.FailReason, "not as intended") {
		t.Fatalf("%s: %q", got.State, got.FailReason)
	}
	if f.n(`SELECT count(*) FROM audit_log WHERE action = 'compliance.fix.failed' AND outcome = 'failure'`) != 1 {
		t.Error("no failure audit row")
	}
}

// Tier 3: the name typed and a step-up; without them nothing is recorded and no job is made.
func TestTierThreeNeedsTypedNameAndStepUp(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.RoleOrgAdmin, f.acme)
	tech := f.user("tech@example.com", rbac.RoleTechnician, f.acme)
	f.seed(admin)
	it := f.item(admin, nla)
	ids := []uuid.UUID{it.ID}

	if _, err := f.fix.Apply(f.ctx, tech, f.acme, fix.ApplyInput{ItemIDs: ids, Agreement: fix.Agreement{Agreed: true, Typed: "HQ-WIN"}}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a technician holds no compliance.fix_high: %v", err)
	}
	if _, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: ids, Agreement: fix.Agreement{Agreed: true}}); err == nil {
		t.Error("tier 3 without the name")
	} else {
		field(t, err, "typed")
	}
	if _, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: ids, Agreement: fix.Agreement{Agreed: true, Typed: "OTHER"}}); err == nil {
		t.Error("tier 3 with another name")
	} else {
		field(t, err, "typed")
	}
	f.step.err = errors.New("step_up_required")
	if _, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: ids, Agreement: fix.Agreement{Agreed: true, Typed: "hq-win"}}); err == nil || err.Error() != "step_up_required" {
		t.Errorf("tier 3 without a step-up: %v", err)
	}
	if f.n(`SELECT count(*) FROM compliance_fix_agreements`) != 0 || f.n(`SELECT count(*) FROM jobs`) != 0 || f.item(admin, nla).State != fix.StateOpen {
		t.Fatal("a refusal left an agreement, a job or a changed item")
	}
	f.step.err = nil
	out, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: ids, Agreement: fix.Agreement{Agreed: true, Typed: " hq-win "}})
	if err != nil || out[0].State != fix.StateApplying {
		t.Fatalf("%+v, %v", out, err)
	}
	if f.n(`SELECT count(*) FROM compliance_fix_agreements WHERE item_id = $1 AND step_up AND typed_text = 'hq-win'`, it.ID) != 1 {
		t.Error("the agreement does not record the typed text and the step-up")
	}
	if got := f.str(`SELECT details->>'guardMinutes' FROM audit_log WHERE action = 'device.hardening' ORDER BY occurred_at DESC LIMIT 1`); got != "10" {
		t.Errorf("the job carries no guard: %q", got)
	}
}

// There is no bulk path above T1.
func TestNoBulkAboveTierOne(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.RoleOrgAdmin, f.acme)
	f.seed(admin)
	f.store(f.win, "accounts", "not_in_place", `{"settings":[{"id":"accounts-min-length","state":"not_in_place"},{"id":"accounts-complexity","state":"not_in_place"}]}`)
	win2 := f.device("HQ-WIN2")
	f.store(win2, "rdp", "not_in_place", `{"settings":[{"id":"rdp-nla","state":"not_in_place"}]}`)
	f.store(win2, "accounts", "not_in_place", `{"settings":[{"id":"accounts-min-length","state":"not_in_place"}]}`)
	f.store(win2, "autoplay", "not_in_place", `{"settings":[{"id":"autoplay-autorun","state":"not_in_place"}]}`)
	if _, err := f.eng.StartScan(f.ctx, admin, f.acme, engine.ScanInput{Profile: "win-server-baseline"}); err != nil {
		t.Fatal(err)
	}
	ag := fix.Agreement{Agreed: true, Typed: "HQ-WIN"}
	two := func(a, b fix.Item) fix.ApplyInput {
		return fix.ApplyInput{ItemIDs: []uuid.UUID{a.ID, b.ID}, Agreement: ag}
	}
	byDev := func(control string, dev uuid.UUID) fix.Item {
		items, _ := f.fix.Queue(f.ctx, admin, f.acme, fix.Filter{DeviceID: dev})
		for _, it := range items {
			if it.ControlID == control {
				return it
			}
		}
		t.Fatalf("no %s on %s", control, dev)
		return fix.Item{}
	}
	// Tier 3 on two computers; tier 2 and tier 1 together; tier 2 of two controls.
	if _, err := f.fix.Apply(f.ctx, admin, f.acme, two(byDev(nla, f.win), byDev(nla, win2))); err == nil {
		t.Error("a bulk tier 3 request")
	} else {
		field(t, err, "itemIds")
	}
	if _, err := f.fix.Apply(f.ctx, admin, f.acme, two(byDev(minLen, f.win), byDev(autorun, f.win))); err == nil {
		t.Error("items of two tiers")
	}
	if _, err := f.fix.Apply(f.ctx, admin, f.acme, two(byDev(minLen, f.win), byDev("win.accounts.complexity", f.win))); err == nil {
		t.Error("a bulk tier 2 request of two controls")
	}
	if f.n(`SELECT count(*) FROM jobs`) != 0 || f.n(`SELECT count(*) FROM compliance_fix_agreements`) != 0 {
		t.Fatal("a refused bulk request left a job or an agreement")
	}
	// One tier 2 control on two computers is one dialog: two agreements, two jobs.
	out, err := f.fix.Apply(f.ctx, admin, f.acme, two(byDev(minLen, f.win), byDev(minLen, win2)))
	if err != nil || len(out) != 2 {
		t.Fatalf("%v, %v", out, err)
	}
	if f.n(`SELECT count(*) FROM compliance_fix_agreements WHERE act = 'apply'`) != 2 || f.n(`SELECT count(*) FROM jobs WHERE hardening->>'mode' = 'apply'`) != 2 {
		t.Error("each computer gets its own agreement and job")
	}
}

// With approval required, the requester cannot approve their own item; a second person can.
func TestApproval(t *testing.T) {
	f := newFixture(t)
	a := f.user("a@example.com", rbac.RoleOrgAdmin, f.acme)
	b := f.user("b@example.com", rbac.RoleOrgAdmin, f.acme)
	tech := f.user("tech@example.com", rbac.RoleTechnician, f.acme)
	f.seed(a)
	if _, err := f.fix.PutSettings(f.ctx, tech, f.acme, fix.Settings{RequireApproval: []string{"T2"}}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("a technician set approval: %v", err)
	}
	if _, err := f.fix.PutSettings(f.ctx, a, f.acme, fix.Settings{RequireApproval: []string{"T9"}}); err == nil {
		t.Fatal("an unknown tier")
	}
	if _, err := f.fix.PutSettings(f.ctx, a, f.acme, fix.Settings{RequireApproval: []string{"T2"}}); err != nil {
		t.Fatal(err)
	}
	it := f.item(a, minLen)
	if !it.RequiresApproval {
		t.Fatal("the item does not say it needs approval")
	}
	out, err := f.fix.Apply(f.ctx, a, f.acme, fix.ApplyInput{ItemIDs: []uuid.UUID{it.ID}, Agreement: fix.Agreement{Agreed: true}})
	if err != nil || out[0].State != fix.StateAwaiting || f.n(`SELECT count(*) FROM jobs`) != 0 {
		t.Fatalf("%+v, %v", out, err)
	}
	if _, err := f.fix.Approve(f.ctx, a, f.acme, it.ID, fix.Agreement{Agreed: true}); err == nil {
		t.Fatal("the requester approved their own item")
	} else {
		code(t, err, "own_item")
	}
	if _, err := f.fix.Approve(f.ctx, tech, f.acme, it.ID, fix.Agreement{Agreed: true}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a technician approved: %v", err)
	}
	f.step.err = errors.New("step_up_required")
	if _, err := f.fix.Approve(f.ctx, b, f.acme, it.ID, fix.Agreement{Agreed: true}); err == nil {
		t.Fatal("an approval without a step-up")
	}
	f.step.err = nil
	got, err := f.fix.Approve(f.ctx, b, f.acme, it.ID, fix.Agreement{Agreed: true})
	if err != nil || got.State != fix.StateApplying {
		t.Fatalf("%+v, %v", got, err)
	}
	if f.n(`SELECT count(*) FROM compliance_fix_agreements WHERE item_id = $1 AND act = 'approve'`, it.ID) != 1 ||
		f.n(`SELECT count(*) FROM compliance_fix_agreements WHERE item_id = $1 AND act = 'apply'`, it.ID) != 1 {
		t.Error("the requester's and the approver's agreements are two rows")
	}
	if f.str(`SELECT requested_by::text FROM compliance_fix_items WHERE id = $1`, it.ID) == "" {
		t.Error("no requester")
	}
}

// Declining keeps the item visible, with a reason; a deferral comes back on its date.
func TestDeclineAndDefer(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.RoleOrgAdmin, f.acme)
	f.seed(admin)
	it := f.item(admin, minLen)
	if _, err := f.fix.Decline(f.ctx, admin, f.acme, it.ID, fix.DeclineInput{Kind: "accepted_risk"}); err == nil {
		t.Fatal("a decline without a reason")
	}
	soon := time.Now().Add(48 * time.Hour)
	if _, err := f.fix.Decline(f.ctx, admin, f.acme, it.ID, fix.DeclineInput{Kind: "deferred", Reason: "after the audit"}); err == nil {
		t.Fatal("a deferral without a date")
	}
	d, err := f.fix.Decline(f.ctx, admin, f.acme, it.ID, fix.DeclineInput{Kind: "deferred", Reason: "after the audit", ExpiresAt: &soon})
	if err != nil || d.State != fix.StateDeclined || d.Decline == nil || d.Decline.Reason != "after the audit" {
		t.Fatalf("%+v, %v", d, err)
	}
	if _, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: []uuid.UUID{it.ID}, Agreement: fix.Agreement{Agreed: true}}); err == nil {
		t.Error("a declined item was applied")
	}
	if f.n(`SELECT count(*) FROM audit_log WHERE action = 'compliance.fix.declined'`) != 1 {
		t.Error("no audit row")
	}
	// It stays in the queue and is not duplicated by a scan; when the date passes it is open again.
	if _, err := f.eng.StartScan(f.ctx, admin, f.acme, engine.ScanInput{Profile: "win-server-baseline"}); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM compliance_fix_items WHERE control_id = $1`, minLen) != 1 {
		t.Error("a duplicate")
	}
	f.fix.SetClock(func() time.Time { return time.Now().Add(72 * time.Hour) })
	if err := f.fix.Sync(f.ctx, f.acme); err != nil {
		t.Fatal(err)
	}
	if got := f.item(admin, minLen); got.State != fix.StateOpen || got.Decline != nil {
		t.Errorf("after the date: %s", got.State)
	}
}

// Every automatic behavior is refused outside the development scope.
func TestDevScope(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.RoleOrgAdmin, f.acme)
	f.seed(admin)
	it := f.item(admin, autorun)
	restore := devscope.Set(f.globex)
	defer restore()
	if _, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: []uuid.UUID{it.ID}, Agreement: fix.Agreement{Agreed: true}}); err == nil {
		t.Error("a fix in an organization outside the scope")
	} else {
		code(t, err, "not_available")
	}
	if _, err := f.eng.StartVerify(f.ctx, f.acme, f.win, []string{autorun}); err == nil {
		t.Error("a re-scan outside the scope")
	}
	f.exec(`DELETE FROM compliance_fix_items`)
	if err := f.fix.Sync(f.ctx, f.acme); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM compliance_fix_items`) != 0 || f.n(`SELECT count(*) FROM jobs`) != 0 {
		t.Error("the queue made items or jobs outside the scope")
	}
}

// A computer's frameworks view and an organization's summary read stored results only.
func TestResultsViews(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.RoleOrgAdmin, f.acme)
	f.seed(admin)
	s, err := f.eng.Summarize(f.ctx, admin, f.acme, uuid.Nil)
	if err != nil || !s.Enabled || s.Devices != 1 || s.DoesNotMeet < 3 || s.FailingDevices != 1 || s.LastScan == nil {
		t.Fatalf("%+v, %v", s, err)
	}
	if site, err := f.eng.Summarize(f.ctx, admin, f.acme, f.hq); err != nil || site.Devices != 1 {
		t.Fatalf("%+v, %v", site, err)
	}
	if _, err := f.eng.Summarize(f.ctx, admin, f.acme, uuid.New()); err == nil {
		t.Error("a site that is not there")
	}
	fw, err := f.eng.FrameworkForDevice(f.ctx, admin, f.acme, f.win, "nist-800-171r2")
	if err != nil || fw.InScope != 1 || len(fw.OutOfScope) != 0 {
		t.Fatalf("%+v, %v", fw, err)
	}
	if _, err := f.eng.FrameworkForDevice(f.ctx, admin, f.acme, uuid.New(), "nist-800-171r2"); err == nil {
		t.Error("a computer that is not there")
	}
	if f.n(`SELECT count(*) FROM jobs`) != 0 {
		t.Error("reading results made a job")
	}
	// The device list's filter "Compliance: failing" (section 7).
	clean := f.device("HQ-CLEAN")
	svc := devices.New(f.db, false)
	list, err := svc.List(f.ctx, admin, devices.Query{OrganizationID: f.acme, Compliance: devices.ComplianceFailing})
	if err != nil || len(list) != 1 || list[0].ID != f.win {
		t.Fatalf("%v, %v", list, err)
	}
	if all, _ := svc.List(f.ctx, admin, devices.Query{OrganizationID: f.acme}); len(all) != 2 || clean == uuid.Nil {
		t.Errorf("%d devices without the filter", len(all))
	}
	if _, err := svc.List(f.ctx, admin, devices.Query{Compliance: "passing"}); err == nil {
		t.Error("an unknown compliance filter")
	}
}

// The fix tables are walled by organization.
func TestRowLevelSecurity(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.RoleOrgAdmin, f.acme)
	other := f.user("other@example.com", rbac.RoleOrgAdmin, f.globex)
	f.seed(admin)
	it := f.item(admin, autorun)
	if _, err := f.fix.Get(f.ctx, other, f.acme, it.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("another organization read an item: %v", err)
	}
	var n int
	if err := f.db.ReadTx(f.ctx, other.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT count(*) FROM compliance_fix_items`).Scan(&n)
	}); err != nil || n != 0 {
		t.Errorf("another organization's scope sees %d items, %v", n, err)
	}
}

// A set-aside item can be reopened; the background loop advances and syncs, and ends with its context.
func TestReopenAndTheLoop(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.RoleOrgAdmin, f.acme)
	tech := f.user("tech@example.com", rbac.RoleTechnician, f.acme)
	f.seed(admin)
	it := f.item(admin, minLen)
	if _, err := f.fix.Reopen(f.ctx, admin, f.acme, it.ID); err == nil {
		t.Error("an item that was not set aside was reopened")
	}
	if _, err := f.fix.Decline(f.ctx, admin, f.acme, it.ID, fix.DeclineInput{Kind: "accepted_risk", Reason: "the vendor needs it"}); err != nil {
		t.Fatal(err)
	}
	if got, err := f.fix.Get(f.ctx, admin, f.acme, it.ID); err != nil || got.Decline == nil || got.Decline.Kind != "accepted_risk" || got.Decline.ExpiresAt != nil {
		t.Fatalf("%+v, %v", got, err)
	}
	if _, err := f.fix.Reopen(f.ctx, tech, f.acme, uuid.New()); err == nil {
		t.Error("an item that is not there")
	}
	if got, err := f.fix.Reopen(f.ctx, admin, f.acme, it.ID); err != nil || got.State != fix.StateOpen || got.Decline != nil {
		t.Fatalf("%+v, %v", got, err)
	}
	if f.n(`SELECT count(*) FROM audit_log WHERE action = 'compliance.fix.reopened'`) != 1 {
		t.Error("no audit row")
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	done := make(chan struct{})
	go func() { f.fix.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the loop did not end with its context")
	}
	if err := f.fix.SyncAll(f.ctx); err != nil {
		t.Fatal(err)
	}
}

// A change the computer undid because the agent did not report back is failed, with that reason; an item that
// is not applied cannot be undone.
func TestGuardTimeoutFailsTheItem(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.RoleOrgAdmin, f.acme)
	f.seed(admin)
	it := f.item(admin, autorun)
	if _, err := f.fix.Undo(f.ctx, admin, f.acme, it.ID, fix.Agreement{Agreed: true}); err == nil {
		t.Error("an item that was never applied was undone")
	} else {
		code(t, err, "not_undoable")
	}
	out, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: []uuid.UUID{it.ID}, Agreement: fix.Agreement{Agreed: true}})
	if err != nil {
		t.Fatal(err)
	}
	f.finish(*out[0].ApplyJobID, applied("autoplay", "autoplay-autorun", "0", "1"))
	if err := f.fix.AdvanceOpen(f.ctx); err != nil {
		t.Fatal(err)
	}
	if st := f.str(`SELECT state FROM hardening_guards WHERE apply_job_id = $1`, *out[0].ApplyJobID); st != "armed" {
		t.Fatalf("guard %s", st)
	}
	f.exec(`UPDATE hardening_guards SET state = 'timed_out', decided_at = now() WHERE apply_job_id = $1`, *out[0].ApplyJobID)
	if err := f.fix.AdvanceOpen(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.item(admin, autorun); got.State != fix.StateFailed || !strings.Contains(got.FailReason, "undid the change by itself") {
		t.Fatalf("%s: %q", got.State, got.FailReason)
	}
}

// A report that is missing, a job that did not finish well and a re-scan that finds the control still failing
// each leave the item in a state that says so.
func TestUnverifiedAndLostJobs(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin@example.com", rbac.RoleOrgAdmin, f.acme)
	f.seed(admin)
	it := f.item(admin, autorun)
	out, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: []uuid.UUID{it.ID}, Agreement: fix.Agreement{Agreed: true}})
	if err != nil {
		t.Fatal(err)
	}
	f.finish(*out[0].ApplyJobID, applied("autoplay", "autoplay-autorun", "0", "1"))
	if err := f.fix.AdvanceOpen(f.ctx); err != nil {
		t.Fatal(err)
	}
	// The re-scan finds it still does not meet: applied, not verified, and it can be undone.
	f.finish(f.lastJob("check"), line("check", "autoplay", "not_in_place", `"settings":[{"id":"autoplay-autorun","state":"not_in_place","value":"0","want":"1"}],`))
	if err := f.fix.AdvanceOpen(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.get(admin, it.ID); got.State != fix.StateNotVerified || !strings.Contains(got.FailReason, "still does not meet") || !got.CanUndo {
		t.Fatalf("%s: %q", got.State, got.FailReason)
	}
	// An undo job that is lost leaves the item as it was, with the reason.
	u, err := f.fix.Undo(f.ctx, admin, f.acme, it.ID, fix.Agreement{Agreed: true})
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE job_runs SET status = 'lost', finished_at = now() WHERE job_id = $1`, *u.UndoJobID)
	if err := f.fix.AdvanceOpen(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.get(admin, it.ID); got.State != fix.StateNotVerified || !strings.Contains(got.FailReason, "lost") {
		t.Fatalf("%s: %q", got.State, got.FailReason)
	}
	// A Linux control has no fix of its own: the queue lists it, and offers no Apply.
	lnx := f.device("HQ-LNX")
	f.exec(`UPDATE devices SET platform = 'linux' WHERE id = $1`, lnx)
	f.store(lnx, "ssh", "not_in_place", `{"settings":[{"id":"ssh-permit-root-login","state":"not_in_place"}]}`)
	if _, err := f.eng.StartScan(f.ctx, admin, f.acme, engine.ScanInput{Profile: "linux-server-baseline"}); err != nil {
		t.Fatal(err)
	}
	l := f.item(admin, "linux.ssh.permit-root-login")
	if l.ApplyBlocked == "" {
		t.Fatal("a Linux item offers a fix of a whole module")
	}
	if _, err := f.fix.Apply(f.ctx, admin, f.acme, fix.ApplyInput{ItemIDs: []uuid.UUID{l.ID}, Agreement: fix.Agreement{Agreed: true}}); err == nil {
		t.Error("a Linux module's fix was applied as one control's")
	} else {
		code(t, err, "not_offered")
	}
}
