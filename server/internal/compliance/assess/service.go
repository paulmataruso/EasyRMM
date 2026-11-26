package assess

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// StepUpVerifier is httpapi.Sessions' VerifyStepUp (ADR-0055): it fails unless the session has
// recently confirmed the person again.
type StepUpVerifier interface {
	VerifyStepUp(ctx context.Context) error
}

// Service is the assessment workspace.
type Service struct {
	db     *database.DB
	audit  *audit.Logger
	sealer *secrets.Sealer
	stepUp StepUpVerifier
	log    *slog.Logger
	now    func() time.Time
}

// New builds the service. The sealer wraps each organization's evidence data key.
func New(db *database.DB, auditLog *audit.Logger, sealer *secrets.Sealer, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, sealer: sealer, log: log, now: time.Now}
}

// SetStepUp gives the service the step-up check. Without one, an attestation is refused.
func (s *Service) SetStepUp(v StepUpVerifier) { s.stepUp = v }

// SetClock replaces the clock, for tests.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Frameworks an assessment can be made for: both carry the 110 requirements the score is made of.
var frameworks = map[string]bool{"cmmc-l2": true, "nist-800-171r2": true}

// Assessment is an assessment record.
type Assessment struct {
	ID         uuid.UUID  `json:"id"`
	OrgID      uuid.UUID  `json:"organizationId"`
	Framework  string     `json:"framework"`
	Version    string     `json:"frameworkVersion"`
	Title      string     `json:"title"`
	Assessor   string     `json:"assessor"`
	State      string     `json:"state"`
	ApprovedBy *uuid.UUID `json:"approvedBy"`
	ApprovedAt *time.Time `json:"approvedAt"`
	Supersedes *uuid.UUID `json:"supersedes"`
	ScanID     *uuid.UUID `json:"scanId"`
	CreatedAt  time.Time  `json:"createdAt"`
	UpdatedAt  time.Time  `json:"updatedAt"`
	// Frozen says no change is possible; the record was approved.
	Frozen bool `json:"frozen"`
}

const assessmentCols = `id, organization_id, framework_key, framework_version, title, coalesce(assessor, ''), state, approved_by, approved_at,
	supersedes, scan_id, created_at, updated_at`

func scanAssessment(row pgx.Row) (*Assessment, error) {
	var a Assessment
	if err := row.Scan(&a.ID, &a.OrgID, &a.Framework, &a.Version, &a.Title, &a.Assessor, &a.State, &a.ApprovedBy, &a.ApprovedAt,
		&a.Supersedes, &a.ScanID, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperr.NotFound()
		}
		return nil, err
	}
	a.Frozen = Frozen(a.State)
	return &a, nil
}

func load(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (*Assessment, error) {
	return scanAssessment(tx.QueryRow(ctx, `SELECT `+assessmentCols+` FROM compliance_assessments WHERE id = $1 AND organization_id = $2`, id, org))
}

// need checks the permission in the organization; a person without it is told the thing is not there.
func need(c access.Caller, perm rbac.Permission, org uuid.UUID) error {
	if !c.Can(perm, rbac.Org(org)) {
		return apperr.NotFound()
	}
	return nil
}

// editable is the assessment, when it can be changed: only a draft can.
func editable(a *Assessment) error {
	switch a.State {
	case Draft:
		return nil
	case InReview:
		return apperr.Conflict("assessment_in_review", "The assessment is in review. Send it back to draft to change it.")
	}
	return apperr.Conflict("assessment_frozen", "The assessment is approved and cannot change. Start a new draft from it.")
}

func (s *Service) event(c access.Caller, action string, a *Assessment, details map[string]any) audit.Event {
	return audit.Event{Actor: c.Actor, Action: action, OrganizationID: a.OrgID, TargetType: "compliance_assessment", TargetID: a.ID.String(),
		Outcome: audit.Success, Details: details}
}

// ---- assessments -----------------------------------------------------------------------------

// CreateInput makes an assessment.
type CreateInput struct {
	Title     string `json:"title"`
	Framework string `json:"framework"`
	Assessor  string `json:"assessor"`
}

// Create makes a draft with every requirement not assessed.
func (s *Service) Create(ctx context.Context, c access.Caller, org uuid.UUID, in CreateInput) (*Assessment, error) {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return nil, err
	}
	if in.Framework == "" {
		in.Framework = "cmmc-l2"
	}
	f := apperr.Fields{}
	f.Check(len(in.Title) > 0 && len(in.Title) <= 200 && len(trim(in.Title)) > 0, "title", "Give the assessment a title of up to 200 characters.")
	f.Check(frameworks[in.Framework], "framework", "Choose cmmc-l2 or nist-800-171r2.")
	f.Check(len(in.Assessor) <= 200, "assessor", "Up to 200 characters.")
	if err := f.Err(); err != nil {
		return nil, err
	}
	var out *Assessment
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var ver string
		if err := tx.QueryRow(ctx, `SELECT version FROM compliance_frameworks WHERE key = $1`, in.Framework).Scan(&ver); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.Conflict("framework_missing", "That framework is not loaded.")
			}
			return err
		}
		a, err := scanAssessment(tx.QueryRow(ctx, `INSERT INTO compliance_assessments (organization_id, framework_key, framework_version, title, assessor, created_by)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6) RETURNING `+assessmentCols, org, in.Framework, ver, trim(in.Title), trim(in.Assessor), nilUser(c)))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_implementations (organization_id, assessment_id, req_id)
			SELECT $1, $2, req_id FROM compliance_requirements WHERE framework_key = $3 AND framework_version = $4`, org, a.ID, in.Framework, ver); err != nil {
			return err
		}
		out = a
		return s.audit.Write(ctx, tx, s.event(c, "compliance.assessment.create", a, map[string]any{"framework": in.Framework}))
	})
	return out, err
}

// List lists an organization's assessments, newest first.
func (s *Service) List(ctx context.Context, c access.Caller, org uuid.UUID) ([]Assessment, error) {
	if err := need(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	out := []Assessment{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+assessmentCols+` FROM compliance_assessments WHERE organization_id = $1 ORDER BY created_at DESC`, org)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAssessment(rows)
			if err != nil {
				return err
			}
			out = append(out, *a)
		}
		return rows.Err()
	})
	return out, err
}

// Detail is an assessment with its score.
type Detail struct {
	Assessment
	Score Range `json:"score"`
	Gate  Gate  `json:"gate"`
	// Counts are the requirements by status.
	Counts map[string]int `json:"counts"`
	// Disclaimer is carried by every compliance screen and report.
	Disclaimer string `json:"disclaimer"`
	// Note says what the score is and is not.
	Note string `json:"note"`
}

// Get reads an assessment and its score range.
func (s *Service) Get(ctx context.Context, c access.Caller, org, id uuid.UUID) (*Detail, error) {
	if err := need(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	var d *Detail
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		d, err = s.detail(ctx, tx, a)
		return err
	})
	return d, err
}

func (s *Service) detail(ctx context.Context, tx pgx.Tx, a *Assessment) (*Detail, error) {
	reqs, err := scoreReqs(ctx, tx, a, s.now())
	if err != nil {
		return nil, err
	}
	items, err := gateItems(ctx, tx, a.ID)
	if err != nil {
		return nil, err
	}
	d := &Detail{Assessment: *a, Score: ComputeRange(reqs), Gate: ComputeGate(reqs, items, s.now()), Counts: map[string]int{}, Disclaimer: disclaimer, Note: scoreNote}
	for _, r := range reqs {
		d.Counts[r.Status]++
	}
	return d, nil
}

const (
	disclaimer = "Assessment aid. It reports what EasyRMM could check on the computers in scope and what people have stated. It is not an assessment, an audit, a certification or legal advice."
	scoreNote  = "The score follows the DoD assessment methodology's values. EasyRMM never posts a score to SPRS: a person does, after their own review."
)

// Transition moves an assessment through its workflow. Approval records a snapshot of the score and freezes the record.
func (s *Service) Transition(ctx context.Context, c access.Caller, org, id uuid.UUID, to string) (*Assessment, error) {
	var out *Assessment
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		perm, ok := Allowed(a.State, to)
		if !ok {
			return apperr.Conflict("bad_transition", "An assessment cannot move from "+a.State+" to "+to+".")
		}
		if err := need(c, perm, org); err != nil {
			return err
		}
		from := a.State
		if to == Approved {
			if err := s.snapshot(ctx, tx, a); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE compliance_assessments SET state = 'approved', approved_by = $3, approved_at = now(), updated_at = now()
				WHERE id = $1 AND organization_id = $2`, id, org, nilUser(c))
		} else {
			_, err = tx.Exec(ctx, `UPDATE compliance_assessments SET state = $3, updated_at = now() WHERE id = $1 AND organization_id = $2`, id, org, to)
		}
		if err != nil {
			return err
		}
		if out, err = load(ctx, tx, org, id); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, s.event(c, "compliance.assessment.transition", out, map[string]any{"from": from, "to": to}))
	})
	return out, err
}

// snapshot stores the score range and gate as they stand, for the record.
func (s *Service) snapshot(ctx context.Context, tx pgx.Tx, a *Assessment) error {
	d, err := s.detail(ctx, tx, a)
	if err != nil {
		return err
	}
	gate, _ := json.Marshal(d.Gate)
	basis, _ := json.Marshal(map[string]any{"counts": d.Counts, "scanId": a.ScanID, "framework": a.Framework, "version": a.Version})
	_, err = tx.Exec(ctx, `INSERT INTO compliance_score_snapshots (organization_id, assessment_id, sprs_low, sprs_high, l2_gate, l1_count, basis)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, a.OrgID, a.ID, d.Score.Low, d.Score.High, gate, d.Score.L1Met, basis)
	return err
}

// NewDraft starts a new draft from an approved or archived assessment (copy-on-write): the scope,
// statuses, statements, attestations, plan of action, documents and evidence links are copied, and the
// original is left as it was.
func (s *Service) NewDraft(ctx context.Context, c access.Caller, org, id uuid.UUID) (*Assessment, error) {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return nil, err
	}
	var out *Assessment
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		src, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		if !src.Frozen {
			return apperr.Conflict("not_approved", "Only an approved assessment needs a new draft; this one can be changed.")
		}
		a, err := scanAssessment(tx.QueryRow(ctx, `INSERT INTO compliance_assessments (organization_id, framework_key, framework_version, profile_key, title,
			assessor, supersedes, scan_id, created_by) SELECT organization_id, framework_key, framework_version, profile_key, title, assessor, id, scan_id, $3
			FROM compliance_assessments WHERE id = $1 AND organization_id = $2 RETURNING `+assessmentCols, id, org, nilUser(c)))
		if err != nil {
			return err
		}
		for _, q := range []string{
			`INSERT INTO compliance_scope_assets (organization_id, assessment_id, device_id, group_id, category, reason)
				SELECT organization_id, $2, device_id, group_id, category, reason FROM compliance_scope_assets WHERE assessment_id = $1`,
			`INSERT INTO compliance_implementations (organization_id, assessment_id, req_id, status, origin, partial, statement, responsibility, owner_user, reviewed_at, next_review)
				SELECT organization_id, $2, req_id, status, origin, partial, statement, responsibility, owner_user, reviewed_at, next_review
				FROM compliance_implementations WHERE assessment_id = $1`,
			`INSERT INTO compliance_objective_results (organization_id, assessment_id, req_id, obj_id, determination, method, source, attestation_id, note, decided_by, decided_at)
				SELECT organization_id, $2, req_id, obj_id, determination, method, source, attestation_id, note, decided_by, decided_at
				FROM compliance_objective_results WHERE assessment_id = $1`,
			`INSERT INTO compliance_evidence_links (organization_id, evidence_id, assessment_id, req_id, obj_id, linked_by, linked_at)
				SELECT organization_id, evidence_id, $2, req_id, obj_id, linked_by, linked_at FROM compliance_evidence_links WHERE assessment_id = $1`,
		} {
			if _, err := tx.Exec(ctx, q, id, a.ID); err != nil {
				return err
			}
		}
		if err := copyPOAM(ctx, tx, org, id, a.ID); err != nil {
			return err
		}
		if err := copyDocuments(ctx, tx, org, id, a.ID); err != nil {
			return err
		}
		out = a
		return s.audit.Write(ctx, tx, s.event(c, "compliance.assessment.new_draft", a, map[string]any{"from": id}))
	})
	return out, err
}

func copyPOAM(ctx context.Context, tx pgx.Tx, org, from, to uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT id FROM compliance_poam_items WHERE assessment_id = $1`, from)
	if err != nil {
		return err
	}
	var old []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		old = append(old, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, o := range old {
		var n uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO compliance_poam_items (organization_id, assessment_id, req_id, weakness, point_value, basis, owner_user, resources,
			scheduled_completion, status, eligible, eligibility_reason, opened_on, closes_by)
			SELECT organization_id, $2, req_id, weakness, point_value, basis, owner_user, resources, scheduled_completion, status, eligible, eligibility_reason, opened_on, closes_by
			FROM compliance_poam_items WHERE id = $1 RETURNING id`, o, to).Scan(&n); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_poam_milestones (organization_id, poam_id, title, due, status, evidence_id)
			SELECT organization_id, $2, title, due, status, evidence_id FROM compliance_poam_milestones WHERE poam_id = $1`, o, n); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_evidence_links (organization_id, evidence_id, poam_id, linked_by, linked_at)
			SELECT organization_id, evidence_id, $2, linked_by, linked_at FROM compliance_evidence_links WHERE poam_id = $1`, o, n); err != nil {
			return err
		}
	}
	return nil
}

func copyDocuments(ctx context.Context, tx pgx.Tx, org, from, to uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT id FROM compliance_documents WHERE assessment_id = $1`, from)
	if err != nil {
		return err
	}
	var old []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		old = append(old, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, o := range old {
		var n uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO compliance_documents (organization_id, assessment_id, kind, template_id, version)
			SELECT organization_id, $2, kind, template_id, version + 1 FROM compliance_documents WHERE id = $1 RETURNING id`, o, to).Scan(&n); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_document_sections (organization_id, document_id, position, section_id, heading, body, generated)
			SELECT organization_id, $2, position, section_id, heading, body, generated FROM compliance_document_sections WHERE document_id = $1`, o, n); err != nil {
			return err
		}
	}
	return nil
}
