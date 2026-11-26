//go:build integration

package assess_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/engine"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type stepUp struct{ err error }

func (s *stepUp) VerifyStepUp(context.Context) error { return s.err }

type fixture struct {
	t      *testing.T
	ctx    context.Context
	db     *database.DB
	svc    *assess.Service
	step   *stepUp
	now    time.Time
	acme   uuid.UUID
	globex uuid.UUID
	hq     uuid.UUID
	admin  access.Caller
	other  access.Caller
	viewer access.Caller
	dev    uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inst := testdb.New(t)
	f := &fixture{t: t, ctx: context.Background(), db: inst.DB, step: &stepUp{}, now: time.Now()}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	sealer, err := secrets.NewSealer(secrets.Key{ID: "test", Raw: key})
	if err != nil {
		t.Fatal(err)
	}
	al := audit.New(inst.DB, time.Now)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f.svc = assess.New(inst.DB, al, sealer, log)
	f.svc.SetStepUp(f.step)
	f.svc.SetClock(func() time.Time { return f.now })
	eng := engine.New(inst.DB, nil, al, log)
	if err := eng.LoadContent(f.ctx, content.FS, compliance.EditionDev); err != nil {
		t.Fatal(err)
	}
	f.acme = f.id(`INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`)
	f.hq = f.id(`INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, f.acme)
	f.globex = f.id(`INSERT INTO organizations (name) VALUES ('Globex') RETURNING id`)
	f.admin = f.user("admin@acme.test", rbac.RoleOrgAdmin, f.acme)
	f.other = f.user("admin@globex.test", rbac.RoleOrgAdmin, f.globex)
	f.viewer = f.user("tech@acme.test", rbac.RoleTechnician, f.acme)
	f.dev = f.device("HQ-WIN")
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

func (f *fixture) exec(sql string, args ...any) error {
	f.t.Helper()
	return f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error { _, err := tx.Exec(f.ctx, sql, args...); return err })
}

func (f *fixture) must(sql string, args ...any) {
	f.t.Helper()
	if err := f.exec(sql, args...); err != nil {
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

func (f *fixture) user(email string, role rbac.Role, org uuid.UUID) access.Caller {
	f.t.Helper()
	id := f.id(`INSERT INTO users (email, display_name) VALUES ($1, $1) RETURNING id`, email)
	f.must(`INSERT INTO role_assignments (user_id, role, organization_id) VALUES ($1, $2, $3)`, id, string(role), org)
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

func (f *fixture) draft() *assess.Assessment {
	f.t.Helper()
	a, err := f.svc.Create(f.ctx, f.admin, f.acme, assess.CreateInput{Title: "Spring assessment"})
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

func (f *fixture) scopeDevice(a *assess.Assessment, cat string) {
	f.t.Helper()
	d := f.dev
	if _, err := f.svc.PutScope(f.ctx, f.admin, f.acme, a.ID, []assess.ScopeInput{{DeviceID: &d, Category: cat}}); err != nil {
		f.t.Fatal(err)
	}
}

// mapped finds a requirement of the Level 2 framework that a control decides, with the control and its weight.
func (f *fixture) mapped(weight int) (req, nist, control string) {
	f.t.Helper()
	err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT m.req_id, r.flags->>'nist', m.control_id FROM compliance_mappings m
			JOIN compliance_requirements r USING (framework_key, framework_version, req_id)
			WHERE m.framework_key = 'cmmc-l2' AND m.relation = 'satisfies_objective' AND m.obj_id IS NULL AND r.class = 'technical' AND r.weight = $1
			ORDER BY m.req_id, m.control_id LIMIT 1`, weight).Scan(&req, &nist, &control)
	})
	if err != nil {
		f.t.Fatalf("no technical requirement of weight %d with a mapped control: %v", weight, err)
	}
	return
}

// result stores a scan finding for the control on the computer.
func (f *fixture) result(control, state string) {
	f.t.Helper()
	scan := f.id(`INSERT INTO compliance_scans (organization_id, trigger, selection, state, finished_at) VALUES ($1, 'manual', '{}', 'done', now()) RETURNING id`, f.acme)
	f.must(`INSERT INTO compliance_results_history (organization_id, scan_id, device_id, control_id, control_version, state, checked_at) VALUES ($1, $2, $3, $4, 1, $5, now())`,
		f.acme, scan, f.dev, control, state)
}

func code(t *testing.T, err error, want string) {
	t.Helper()
	if e, ok := apperr.As(err); !ok || e.Code != want {
		t.Fatalf("want %s, got %v", want, err)
	}
}

func (f *fixture) req(a *assess.Assessment, nist string) assess.RequirementRow {
	f.t.Helper()
	rows, err := f.svc.Requirements(f.ctx, f.admin, f.acme, a.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, r := range rows {
		if r.NistID == nist {
			return r
		}
	}
	f.t.Fatalf("no requirement %s", nist)
	return assess.RequirementRow{}
}

func (f *fixture) approve(a *assess.Assessment) {
	f.t.Helper()
	for _, to := range []string{assess.InReview, assess.Approved} {
		if _, err := f.svc.Transition(f.ctx, f.admin, f.acme, a.ID, to); err != nil {
			f.t.Fatal(err)
		}
	}
}

func TestNewAssessmentHasEveryRequirementUnassessed(t *testing.T) {
	f := newFixture(t)
	a := f.draft()
	d, err := f.svc.Get(f.ctx, f.admin, f.acme, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Score.Low != 110-313 || d.Score.High != 110 || d.Score.Number != nil || d.Counts[assess.NotAssessed] != 110 {
		t.Errorf("a new assessment: low %d high %d number %v counts %v", d.Score.Low, d.Score.High, d.Score.Number, d.Counts)
	}
	if !strings.Contains(d.Disclaimer, "not an assessment") {
		t.Error("the disclaimer is missing")
	}
	if d.Gate.Outcome != "outside" && d.Gate.Outcome != "possible" {
		t.Errorf("gate %q", d.Gate.Outcome)
	}
	rows, _ := f.svc.Requirements(f.ctx, f.admin, f.acme, a.ID)
	if len(rows) != 110 {
		t.Fatalf("%d requirements", len(rows))
	}
}

func TestScanDecidesObjectivesAndTheRange(t *testing.T) {
	f := newFixture(t)
	a := f.draft()
	_, nist, ctl := f.mapped(5)
	f.scopeDevice(a, "cui")

	f.result(ctl, "not_in_place")
	res, err := f.svc.Refresh(f.ctx, f.admin, f.acme, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.ScanID == nil || res.Updated == 0 {
		t.Fatalf("refresh: %+v", res)
	}
	if r := f.req(a, nist); r.Status != assess.NotMet {
		t.Errorf("a failing control: %s", r.Status)
	}
	d, _ := f.svc.Get(f.ctx, f.admin, f.acme, a.ID)
	if d.Score.High != 110-5 {
		t.Errorf("upper bound %d, want 105 (one 5-point requirement not met)", d.Score.High)
	}
	if d.Score.Low >= d.Score.High {
		t.Errorf("lower bound %d is not below the upper %d", d.Score.Low, d.Score.High)
	}

	// The control now meets: the requirement is met only when every objective is.
	f.result(ctl, "in_place")
	if _, err := f.svc.Refresh(f.ctx, f.admin, f.acme, a.ID); err != nil {
		t.Fatal(err)
	}
	if r := f.req(a, nist); r.Status == assess.NotMet {
		t.Errorf("after the fix: %s", r.Status)
	}
}

func TestScanAloneNeverMakesAPartlyTechnicalRequirementMet(t *testing.T) {
	f := newFixture(t)
	a := f.draft()
	var req, nist, ctl string
	err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT m.req_id, r.flags->>'nist', m.control_id FROM compliance_mappings m JOIN compliance_requirements r USING (framework_key, framework_version, req_id)
			WHERE m.framework_key = 'cmmc-l2' AND m.relation = 'satisfies_objective' AND r.class = 'partly' AND m.obj_id IS NULL ORDER BY 1 LIMIT 1`).Scan(&req, &nist, &ctl)
	})
	if err != nil {
		t.Skip("no partly technical requirement has a mapped control in this content")
	}
	f.scopeDevice(a, "cui")
	f.result(ctl, "in_place")
	if _, err := f.svc.Refresh(f.ctx, f.admin, f.acme, a.ID); err != nil {
		t.Fatal(err)
	}
	if r := f.req(a, nist); r.Status == assess.Met {
		t.Errorf("a scan made a partly technical requirement met")
	}
}

func TestRefreshChecksTheDevelopmentScope(t *testing.T) {
	f := newFixture(t)
	a := f.draft()
	defer devscope.Set(f.globex)()
	_, err := f.svc.Refresh(f.ctx, f.admin, f.acme, a.ID)
	code(t, err, "dev_scope")
	_, err = f.svc.GeneratePOAM(f.ctx, f.admin, f.acme, a.ID)
	code(t, err, "dev_scope")
}

func TestAttestationNeedsStepUpAStatementAndExpires(t *testing.T) {
	f := newFixture(t)
	a := f.draft()
	_, nist, _ := f.mapped(5)
	var req string
	for _, r := range func() []assess.RequirementRow { r, _ := f.svc.Requirements(f.ctx, f.admin, f.acme, a.ID); return r }() {
		if r.NistID == nist {
			req = r.ReqID
		}
	}
	f.step.err = errors.New("step-up needed")
	if _, err := f.svc.Attest(f.ctx, f.admin, f.acme, a.ID, req, assess.AttestInput{Statement: "We do this."}); err == nil {
		t.Fatal("an attestation was signed without a step-up")
	}
	f.step.err = nil
	if _, err := f.svc.Attest(f.ctx, f.admin, f.acme, a.ID, req, assess.AttestInput{Statement: "  "}); err == nil {
		t.Fatal("an attestation was signed without a statement")
	}
	if _, err := f.svc.Attest(f.ctx, f.viewer, f.acme, a.ID, req, assess.AttestInput{Statement: "x"}); err == nil {
		t.Fatal("a technician attested")
	}
	if _, err := f.svc.Attest(f.ctx, f.admin, f.acme, a.ID, req, assess.AttestInput{Statement: "x", ExpiresAt: ptr(f.now.Add(5 * 365 * 24 * time.Hour))}); err == nil {
		t.Fatal("an attestation was allowed to stand for five years")
	}
	v, err := f.svc.Attest(f.ctx, f.admin, f.acme, a.ID, req, assess.AttestInput{Statement: "Accounts are limited to named people."})
	if err != nil {
		t.Fatal(err)
	}
	if d := v.ExpiresAt.Sub(f.now); d < 364*24*time.Hour || d > 366*24*time.Hour {
		t.Errorf("default expiry %v, want one year", d)
	}
	if r := f.req(a, nist); r.Status != assess.Met || r.Origin != "attested" {
		t.Errorf("after attestation: %s / %s", r.Status, r.Origin)
	}
	if f.n(`SELECT count(*) FROM audit_events WHERE action = 'compliance.attestation.sign' AND details->>'stepUp' = 'true'`) != 1 {
		t.Error("the attestation is not in the audit log with its step-up")
	}
	f.now = f.now.Add(400 * 24 * time.Hour)
	if r := f.req(a, nist); r.Status != assess.NotAssessed {
		t.Errorf("an expired attestation still counts: %s", r.Status)
	}
	// An attestation is never changed.
	if err := f.exec(`UPDATE compliance_attestations SET statement = 'changed'`); err == nil {
		t.Error("an attestation was changed")
	}
}

func ptr[T any](v T) *T { return &v }

func TestAScanNotMetIsNotSetAsideByAStatement(t *testing.T) {
	f := newFixture(t)
	a := f.draft()
	req, _, ctl := f.mapped(5)
	f.scopeDevice(a, "cui")
	f.result(ctl, "failed")
	if _, err := f.svc.Refresh(f.ctx, f.admin, f.acme, a.ID); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.Attest(f.ctx, f.admin, f.acme, a.ID, req, assess.AttestInput{Statement: "We do this."})
	code(t, err, "scan_not_met")
}

func TestFreezeAndCopyOnWrite(t *testing.T) {
	f := newFixture(t)
	a := f.draft()
	f.scopeDevice(a, "cui")
	req, _, _ := f.mapped(5)
	if err := f.svc.UpdateRequirement(f.ctx, f.admin, f.acme, a.ID, req, assess.RequirementUpdate{Statement: ptr("Our statement.")}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Transition(f.ctx, f.viewer, f.acme, a.ID, assess.InReview); err == nil {
		t.Fatal("a technician sent an assessment to review")
	}
	if _, err := f.svc.Transition(f.ctx, f.admin, f.acme, a.ID, assess.Approved); err == nil {
		t.Fatal("a draft was approved without review")
	}
	f.approve(a)
	if f.n(`SELECT count(*) FROM compliance_score_snapshots WHERE assessment_id = $1`, a.ID) != 1 {
		t.Error("approval took no snapshot of the score")
	}
	// Nothing under an approved assessment changes, through the service or around it.
	code(t, f.svc.UpdateRequirement(f.ctx, f.admin, f.acme, a.ID, req, assess.RequirementUpdate{Statement: ptr("changed")}), "assessment_frozen")
	if _, err := f.svc.PutScope(f.ctx, f.admin, f.acme, a.ID, nil); err == nil {
		t.Error("the scope of an approved assessment changed")
	}
	for _, sql := range []string{
		`UPDATE compliance_implementations SET statement = 'x' WHERE assessment_id = $1`,
		`DELETE FROM compliance_implementations WHERE assessment_id = $1`,
		`INSERT INTO compliance_scope_assets (organization_id, assessment_id, device_id, category) VALUES ('` + f.acme.String() + `', $1, '` + f.dev.String() + `', 'cui')`,
		`UPDATE compliance_assessments SET title = 'x' WHERE id = $1`,
		`DELETE FROM compliance_assessments WHERE id = $1`,
		`UPDATE compliance_objective_results SET note = 'x' WHERE assessment_id = $1`,
	} {
		if err := f.exec(sql, a.ID); err == nil {
			t.Errorf("an approved assessment changed under: %s", sql)
		}
	}
	// Copy on write: a new draft carries everything over, and the original stays as it was.
	nd, err := f.svc.NewDraft(f.ctx, f.admin, f.acme, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if nd.State != assess.Draft || nd.Supersedes == nil || *nd.Supersedes != a.ID {
		t.Fatalf("new draft: %+v", nd)
	}
	if err := f.svc.UpdateRequirement(f.ctx, f.admin, f.acme, nd.ID, req, assess.RequirementUpdate{Statement: ptr("Our statement, revised.")}); err != nil {
		t.Fatal(err)
	}
	old, _ := f.svc.Requirements(f.ctx, f.admin, f.acme, a.ID)
	cur, _ := f.svc.Requirements(f.ctx, f.admin, f.acme, nd.ID)
	for i := range old {
		if old[i].ReqID == req && (old[i].Statement != "Our statement." || cur[i].Statement != "Our statement, revised.") {
			t.Errorf("statements: %q and %q", old[i].Statement, cur[i].Statement)
		}
	}
	sc, _ := f.svc.GetScope(f.ctx, f.admin, f.acme, nd.ID)
	if len(sc.Items) != 1 {
		t.Errorf("the scope was not carried over: %d", len(sc.Items))
	}
	_, err = f.svc.NewDraft(f.ctx, f.admin, f.acme, nd.ID)
	code(t, err, "not_approved")
	if _, err := f.svc.Transition(f.ctx, f.admin, f.acme, a.ID, assess.Archived); err != nil {
		t.Fatal(err)
	}
	if f.n(`SELECT count(*) FROM audit_events WHERE action = 'compliance.assessment.transition' AND organization_id = $1`, f.acme) != 3 {
		t.Error("each state change is not in the audit log")
	}
}

func TestEvidenceIsEncryptedHashedAndNeverDeleted(t *testing.T) {
	f := newFixture(t)
	a := f.draft()
	req, _, _ := f.mapped(5)
	plain := []byte("Network diagram, version 3. CUI boundary marked in red.")
	sum := sha256.Sum256(plain)
	ev, err := f.svc.AddEvidence(f.ctx, f.admin, f.acme, assess.EvidenceInput{Title: "Network diagram", MediaType: "text/plain", FileName: "diagram.txt",
		Body: bytes.NewReader(plain), AssessmentID: &a.ID, ReqID: req})
	if err != nil {
		t.Fatal(err)
	}
	if ev.SHA256 != hex.EncodeToString(sum[:]) || ev.Size == nil || *ev.Size != int64(len(plain)) {
		t.Errorf("hash or size wrong: %+v", ev)
	}
	// The body in the database is ciphertext, with a nonce and the key's id.
	var body, nonce []byte
	var keyID string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT body, nonce, key_id FROM compliance_evidence WHERE id = $1`, ev.ID).Scan(&body, &nonce, &keyID)
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("Network diagram")) || len(nonce) != 12 || keyID == "" {
		t.Error("the stored body is not ciphertext with a 96-bit nonce")
	}
	if f.n(`SELECT count(*) FROM compliance_org_keys WHERE organization_id = $1 AND wrapped NOT LIKE 'v1.%'`, f.acme) != 0 {
		t.Error("the data key is not wrapped by the sealer")
	}
	dl, err := f.svc.DownloadEvidence(f.ctx, f.viewer, f.acme, ev.ID)
	if err != nil || !bytes.Equal(dl.Body, plain) {
		t.Fatalf("download: %v", err)
	}
	if f.n(`SELECT count(*) FROM audit_events WHERE action = 'compliance.evidence.download' AND details->>'sha256' = $1 AND actor_label = 'tech@acme.test'`, ev.SHA256) != 1 ||
		f.n(`SELECT count(*) FROM audit_events WHERE action = 'compliance.evidence.upload' AND details->>'sha256' = $1`, ev.SHA256) != 1 {
		t.Error("the upload and the download are not both in the audit log with the hash")
	}
	// Another organization's administrator cannot see it, and the row-level policy agrees.
	if _, err := f.svc.DownloadEvidence(f.ctx, f.other, f.acme, ev.ID); err == nil {
		t.Error("another organization downloaded it")
	}
	if _, err := f.svc.DownloadEvidence(f.ctx, f.other, f.globex, ev.ID); err == nil {
		t.Error("it was reachable through another organization's id")
	}
	var seen int
	if err := f.db.ReadTx(f.ctx, f.other.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT count(*) FROM compliance_evidence`).Scan(&seen)
	}); err != nil || seen != 0 {
		t.Errorf("row-level security showed %d rows to another organization (%v)", seen, err)
	}
	// Never deleted, never changed, only superseded.
	for _, sql := range []string{`DELETE FROM compliance_evidence WHERE id = $1`, `UPDATE compliance_evidence SET title = 'x' WHERE id = $1`,
		`UPDATE compliance_evidence SET body = '\x00' WHERE id = $1`, `UPDATE compliance_evidence SET sha256 = 'x' WHERE id = $1`} {
		if err := f.exec(sql, ev.ID); err == nil {
			t.Errorf("evidence changed under: %s", sql)
		}
	}
	v2 := []byte("Network diagram, version 4.")
	ev2, err := f.svc.AddEvidence(f.ctx, f.admin, f.acme, assess.EvidenceInput{Title: "Network diagram", Body: bytes.NewReader(v2), Supersedes: &ev.ID})
	if err != nil {
		t.Fatal(err)
	}
	old, err := f.svc.DownloadEvidence(f.ctx, f.admin, f.acme, ev.ID)
	if err != nil || old.SupersededBy == nil || *old.SupersededBy != ev2.ID || !bytes.Equal(old.Body, plain) {
		t.Errorf("the replaced evidence: %v %+v", err, old)
	}
	if f.n(`SELECT count(*) FROM compliance_evidence_links WHERE evidence_id = $1 AND assessment_id = $2`, ev2.ID, a.ID) != 1 {
		t.Error("the new evidence did not take the old one's place")
	}
	_, err = f.svc.AddEvidence(f.ctx, f.admin, f.acme, assess.EvidenceInput{Title: "again", Body: bytes.NewReader(v2), Supersedes: &ev.ID})
	code(t, err, "already_superseded")
	// A link is evidence too.
	if _, err := f.svc.AddEvidence(f.ctx, f.admin, f.acme, assess.EvidenceInput{Kind: "link", Title: "Policy", URL: "javascript:alert(1)"}); err == nil {
		t.Error("a javascript link was accepted")
	}
	if _, err := f.svc.AddEvidence(f.ctx, f.admin, f.acme, assess.EvidenceInput{Kind: "link", Title: "Policy", URL: "https://example.test/policy"}); err != nil {
		t.Error(err)
	}
	// A technician may not upload.
	if _, err := f.svc.AddEvidence(f.ctx, f.viewer, f.acme, assess.EvidenceInput{Title: "x", Body: bytes.NewReader(v2)}); err == nil {
		t.Error("a technician uploaded evidence")
	}
}

func TestEvidenceCap(t *testing.T) {
	f := newFixture(t)
	big := io.LimitReader(zeros{}, assess.MaxEvidenceBytes+1)
	_, err := f.svc.AddEvidence(f.ctx, f.admin, f.acme, assess.EvidenceInput{Title: "big", Body: big})
	if !errors.Is(err, assess.ErrTooLarge) {
		t.Fatalf("64 MiB plus one byte: %v", err)
	}
	ok, err := f.svc.AddEvidence(f.ctx, f.admin, f.acme, assess.EvidenceInput{Title: "at the cap", Body: io.LimitReader(zeros{}, assess.MaxEvidenceBytes)})
	if err != nil {
		t.Fatalf("exactly 64 MiB: %v", err)
	}
	dl, err := f.svc.DownloadEvidence(f.ctx, f.admin, f.acme, ok.ID)
	if err != nil || len(dl.Body) != assess.MaxEvidenceBytes {
		t.Fatalf("download at the cap: %v", err)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestEvidenceBlobCannotMoveToAnotherRow(t *testing.T) {
	f := newFixture(t)
	e1, _ := f.svc.AddEvidence(f.ctx, f.admin, f.acme, assess.EvidenceInput{Title: "one", Body: strings.NewReader("first")})
	e2, _ := f.svc.AddEvidence(f.ctx, f.admin, f.acme, assess.EvidenceInput{Title: "two", Body: strings.NewReader("second")})
	// A blob copied onto another row (done as the table's owner, around the trigger) does not open.
	err := f.db.InTx(f.ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(f.ctx, `ALTER TABLE compliance_evidence DISABLE TRIGGER compliance_evidence_no_change`); err != nil {
			return err
		}
		if _, err := tx.Exec(f.ctx, `UPDATE compliance_evidence t SET body = s.body, nonce = s.nonce, sha256 = s.sha256 FROM compliance_evidence s WHERE s.id = $1 AND t.id = $2`, e1.ID, e2.ID); err != nil {
			return err
		}
		_, err := tx.Exec(f.ctx, `ALTER TABLE compliance_evidence ENABLE TRIGGER compliance_evidence_no_change`)
		return err
	})
	if err != nil {
		t.Skipf("the test database role cannot move a blob around the trigger: %v", err)
	}
	_, err = f.svc.DownloadEvidence(f.ctx, f.admin, f.acme, e2.ID)
	code(t, err, "evidence_unreadable")
	if f.n(`SELECT count(*) FROM audit_events WHERE action = 'compliance.evidence.download' AND outcome = 'failure'`) != 1 {
		t.Error("the refused download is not in the audit log")
	}
}

func TestPOAMEligibilityAndBoard(t *testing.T) {
	f := newFixture(t)
	a := f.draft()
	f.scopeDevice(a, "cui")
	_, nist5, ctl5 := f.mapped(5)
	f.result(ctl5, "not_in_place")
	if _, err := f.svc.Refresh(f.ctx, f.admin, f.acme, a.ID); err != nil {
		t.Fatal(err)
	}
	n, err := f.svc.GeneratePOAM(f.ctx, f.admin, f.acme, a.ID)
	if err != nil || n == 0 {
		t.Fatalf("generate: %d %v", n, err)
	}
	if again, _ := f.svc.GeneratePOAM(f.ctx, f.admin, f.acme, a.ID); again != 0 {
		t.Errorf("a second generate made %d items", again)
	}
	b, err := f.svc.POAM(f.ctx, f.admin, f.acme, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	var item *assess.POAMView
	for i := range b.Items {
		if b.Items[i].NistID == nist5 {
			item = &b.Items[i]
		}
	}
	if item == nil || item.Eligible || item.Points != 5 || item.Status != "draft" {
		t.Fatalf("the five-point item: %+v", item)
	}
	if time.Until(parse(t, item.ClosesBy)) < 170*24*time.Hour {
		t.Errorf("closes by %s, want about 180 days out", item.ClosesBy)
	}
	code(t, f.svc.UpdatePOAM(f.ctx, f.admin, f.acme, a.ID, item.ID, assess.POAMUpdate{Status: ptr("open")}), "poam_not_allowed")
	// A one-point requirement may be confirmed, and then has milestones.
	_, nist1, ctl1 := f.mapped(1)
	f.result(ctl1, "failed")
	if _, err := f.svc.Refresh(f.ctx, f.admin, f.acme, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.GeneratePOAM(f.ctx, f.admin, f.acme, a.ID); err != nil {
		t.Fatal(err)
	}
	b, _ = f.svc.POAM(f.ctx, f.admin, f.acme, a.ID)
	var one *assess.POAMView
	for i := range b.Items {
		if b.Items[i].NistID == nist1 {
			one = &b.Items[i]
		}
	}
	if one == nil || !one.Eligible {
		t.Fatalf("the one-point item: %+v", one)
	}
	if err := f.svc.UpdatePOAM(f.ctx, f.admin, f.acme, a.ID, one.ID, assess.POAMUpdate{Status: ptr("open")}); err != nil {
		t.Fatal(err)
	}
	m, err := f.svc.AddMilestone(f.ctx, f.admin, f.acme, a.ID, one.ID, "Roll the setting out", ptr("2027-03-01"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SetMilestone(f.ctx, f.admin, f.acme, a.ID, m.ID, true); err != nil {
		t.Fatal(err)
	}
	// An item that is not closed in 180 days is overdue, and the gate says so.
	f.now = f.now.Add(200 * 24 * time.Hour)
	d, _ := f.svc.Get(f.ctx, f.admin, f.acme, a.ID)
	if len(d.Gate.Overdue) != 1 {
		t.Errorf("overdue: %v", d.Gate.Overdue)
	}
	f.approve(a)
	if err := f.exec(`UPDATE compliance_poam_milestones SET status = 'open'`); err == nil {
		t.Error("a milestone of an approved assessment changed")
	}
}

func parse(t *testing.T, s string) time.Time {
	t.Helper()
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSSPAndExports(t *testing.T) {
	f := newFixture(t)
	a := f.draft()
	f.scopeDevice(a, "cui")
	req, _, ctl := f.mapped(1)
	f.result(ctl, "failed")
	_, _ = f.svc.Refresh(f.ctx, f.admin, f.acme, a.ID)
	_, _ = f.svc.GeneratePOAM(f.ctx, f.admin, f.acme, a.ID)
	if err := f.svc.UpdateRequirement(f.ctx, f.admin, f.acme, a.ID, req, assess.RequirementUpdate{Statement: ptr("We limit this to named people.")}); err != nil {
		t.Fatal(err)
	}
	doc, err := f.svc.GenerateSSP(f.ctx, f.admin, f.acme, a.ID)
	if err != nil || !doc.Exists || len(doc.Sections) < 8 {
		t.Fatalf("ssp: %v %+v", err, doc)
	}
	var reqs, free int
	for _, s := range doc.Sections {
		if s.SectionID == "requirements" {
			reqs = s.Position
			if !strings.Contains(s.Body, "We limit this to named people.") {
				t.Error("the generated section lacks the statement")
			}
		}
		if !s.Generated && free == 0 {
			free = s.Position + 1
		}
	}
	if err := f.svc.UpdateSSPSection(f.ctx, f.admin, f.acme, a.ID, free-1, "Our own words."); err != nil {
		t.Fatal(err)
	}
	doc2, _ := f.svc.GenerateSSP(f.ctx, f.admin, f.acme, a.ID)
	if doc2.Sections[free-1].Body != "Our own words." || doc2.Sections[reqs].Body == "" {
		t.Error("generating again overwrote a section a person wrote, or emptied a generated one")
	}
	for _, format := range []string{assess.FormatOSCALSSP, assess.FormatOSCALPOAM, assess.FormatRequirements, assess.FormatPOAMCSV, assess.FormatBundle, assess.FormatPDF} {
		file, err := f.svc.Export(f.ctx, f.admin, f.acme, a.ID, format)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		h := sha256.Sum256(file.Body)
		if file.SHA256 != hex.EncodeToString(h[:]) || len(file.Body) == 0 {
			t.Errorf("%s: hash", format)
		}
		if f.n(`SELECT count(*) FROM audit_events WHERE action = 'compliance.export' AND details->>'format' = $1 AND details->>'sha256' = $2`, format, file.SHA256) != 1 {
			t.Errorf("%s: the export hash is not in the audit log", format)
		}
		low := strings.ToLower(string(file.Body))
		if format != assess.FormatBundle && format != assess.FormatPDF && (strings.Contains(low, "compliant") || strings.Contains(low, "certified")) {
			t.Errorf("%s says compliant or certified", format)
		}
		if format == assess.FormatPDF && !bytes.HasPrefix(file.Body, []byte("%PDF-1.4")) {
			t.Error("not a PDF")
		}
		if format == assess.FormatBundle {
			zr, err := zip.NewReader(bytes.NewReader(file.Body), int64(len(file.Body)))
			if err != nil {
				t.Fatal(err)
			}
			names := map[string]bool{}
			for _, z := range zr.File {
				names[z.Name] = true
			}
			for _, want := range []string{"ssp.oscal.json", "poam.oscal.json", "requirements.csv", "poam.csv", "report.pdf", "score.json", "MANIFEST.json"} {
				if !names[want] {
					t.Errorf("the bundle lacks %s", want)
				}
			}
		}
	}
	if _, err := f.svc.Export(f.ctx, f.viewer, f.acme, a.ID, assess.FormatPDF); err == nil {
		t.Error("a technician exported")
	}
	if _, err := f.svc.Export(f.ctx, f.admin, f.acme, a.ID, "docx"); err == nil {
		t.Error("an unknown format was accepted")
	}
}

func TestAnotherOrganizationSeesNothing(t *testing.T) {
	f := newFixture(t)
	a := f.draft()
	if _, err := f.svc.Get(f.ctx, f.other, f.acme, a.ID); err == nil {
		t.Error("another organization read an assessment")
	}
	if _, err := f.svc.Get(f.ctx, f.other, f.globex, a.ID); err == nil {
		t.Error("an assessment answered under another organization's id")
	}
	l, err := f.svc.List(f.ctx, f.other, f.globex)
	if err != nil || len(l) != 0 {
		t.Errorf("list: %d %v", len(l), err)
	}
	var seen int
	if err := f.db.ReadTx(f.ctx, f.other.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM compliance_assessments) + (SELECT count(*) FROM compliance_implementations)`).Scan(&seen)
	}); err != nil || seen != 0 {
		t.Errorf("row-level security: %d rows (%v)", seen, err)
	}
	if _, err := f.svc.Create(f.ctx, f.viewer, f.acme, assess.CreateInput{Title: "x"}); err == nil {
		t.Error("a technician made an assessment")
	}
	// A child cannot name another organization's assessment.
	if err := f.exec(`INSERT INTO compliance_scope_assets (organization_id, assessment_id, device_id, category) VALUES ($1, $2, $3, 'cui')`, f.globex, a.ID, f.dev); err == nil {
		t.Error("a child row named another organization's assessment")
	}
}

func TestScopeKeepsOutOfScopeOutOfTheCount(t *testing.T) {
	f := newFixture(t)
	a := f.draft()
	_, _, ctl := f.mapped(5)
	f.scopeDevice(a, "out_of_scope")
	f.result(ctl, "failed")
	res, _ := f.svc.Refresh(f.ctx, f.admin, f.acme, a.ID)
	if res.InScope != 0 {
		t.Errorf("%d in scope", res.InScope)
	}
	sc, _ := f.svc.GetScope(f.ctx, f.admin, f.acme, a.ID)
	if len(sc.Items) != 1 || sc.Items[0].Category != "out_of_scope" || sc.Unlisted != 0 {
		t.Errorf("scope: %+v", sc)
	}
	d, _ := f.svc.Get(f.ctx, f.admin, f.acme, a.ID)
	if d.Counts[assess.NotMet] != 0 {
		t.Error("a failure outside the scope was counted")
	}
	f.device("HQ-OTHER")
	sc, _ = f.svc.GetScope(f.ctx, f.admin, f.acme, a.ID)
	if sc.Unlisted != 1 {
		t.Errorf("an unlisted computer is not shown: %d", sc.Unlisted)
	}
	if _, err := f.svc.PutScope(f.ctx, f.admin, f.acme, a.ID, []assess.ScopeInput{{DeviceID: &f.dev, Category: "nonsense"}}); err == nil {
		t.Error("a made-up category was accepted")
	}
}
