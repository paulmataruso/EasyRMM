package assess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// RequirementRow is a requirement in the list.
type RequirementRow struct {
	ReqID          string     `json:"reqId"`
	NistID         string     `json:"nistId"`
	Title          string     `json:"title"`
	Family         string     `json:"family"`
	Class          string     `json:"class"`
	Weight         int        `json:"weight"`
	Status         string     `json:"status"`
	Origin         string     `json:"origin"`
	Partial        bool       `json:"partial"`
	HasPartial     bool       `json:"hasPartial"`
	Responsibility string     `json:"responsibility"`
	OwnerUser      *uuid.UUID `json:"ownerUser"`
	NextReview     *string    `json:"nextReview"`
	Statement      string     `json:"statement"`
	Objectives     int        `json:"objectives"`
	ObjectivesMet  int        `json:"objectivesMet"`
	Evidence       int        `json:"evidence"`
}

type implRow struct {
	Status, Origin, Statement, Responsibility string
	Partial                                   bool
	Owner                                     *uuid.UUID
	NextReview                                *string
}

func implRows(ctx context.Context, tx pgx.Tx, id uuid.UUID) (map[string]implRow, error) {
	rows, err := tx.Query(ctx, `SELECT req_id, status, origin, partial, statement, responsibility, owner_user, to_char(next_review, 'YYYY-MM-DD')
		FROM compliance_implementations WHERE assessment_id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]implRow{}
	for rows.Next() {
		var id string
		var r implRow
		if err := rows.Scan(&id, &r.Status, &r.Origin, &r.Partial, &r.Statement, &r.Responsibility, &r.Owner, &r.NextReview); err != nil {
			return nil, err
		}
		out[id] = r
	}
	return out, rows.Err()
}

// Requirements lists every requirement of the assessment with its status.
func (s *Service) Requirements(ctx context.Context, c access.Caller, org, id uuid.UUID) ([]RequirementRow, error) {
	if err := need(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	var out []RequirementRow
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		fw, err := loadFramework(ctx, tx, a.Framework, a.Version)
		if err != nil {
			return err
		}
		impl, err := implRows(ctx, tx, id)
		if err != nil {
			return err
		}
		var obj map[ObjectiveKey]storedRow
		if !a.Frozen {
			if obj, err = objectiveRows(ctx, tx, a, s.now()); err != nil {
				return err
			}
		}
		ev := map[string]int{}
		er, err := tx.Query(ctx, `SELECT req_id, count(DISTINCT evidence_id) FROM compliance_evidence_links WHERE assessment_id = $1 AND req_id IS NOT NULL GROUP BY req_id`, id)
		if err != nil {
			return err
		}
		for er.Next() {
			var r string
			var n int
			if err := er.Scan(&r, &n); err != nil {
				er.Close()
				return err
			}
			ev[r] = n
		}
		er.Close()
		if err := er.Err(); err != nil {
			return err
		}
		stored, err := storedObjectives(ctx, tx, id)
		if err != nil {
			return err
		}
		out = make([]RequirementRow, 0, len(fw))
		for _, r := range fw {
			im := impl[r.ID]
			if !a.Frozen {
				d := derive(r, obj, s.now())
				im.Status, im.Origin = d.Status, d.Origin
			}
			row := RequirementRow{ReqID: r.ID, NistID: r.Nist, Title: r.Title, Family: r.Family, Class: r.Class, Weight: r.Weight, Status: im.Status, Origin: im.Origin,
				Partial: im.Partial, HasPartial: r.Partial > 0, Responsibility: im.Responsibility, OwnerUser: im.Owner, NextReview: im.NextReview,
				Statement: im.Statement, Objectives: len(r.Objectives), Evidence: ev[r.ID]}
			for _, o := range r.Objectives {
				if d := stored[ObjectiveKey{r.ID, o.ID}]; d == Met || d == NotApplicable {
					row.ObjectivesMet++
				}
			}
			out = append(out, row)
		}
		return nil
	})
	return out, err
}

func storedObjectives(ctx context.Context, tx pgx.Tx, id uuid.UUID) (map[ObjectiveKey]string, error) {
	rows, err := tx.Query(ctx, `SELECT req_id, obj_id, determination FROM compliance_objective_results WHERE assessment_id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[ObjectiveKey]string{}
	for rows.Next() {
		var k ObjectiveKey
		var d string
		if err := rows.Scan(&k.Req, &k.Obj, &d); err != nil {
			return nil, err
		}
		out[k] = d
	}
	return out, rows.Err()
}

// ObjectiveView is an objective and what is known of it.
type ObjectiveView struct {
	ID            string     `json:"id"`
	Text          string     `json:"text"`
	Methods       []string   `json:"methods"`
	Controls      []string   `json:"controls"`
	Whole         bool       `json:"whole"`
	Determination string     `json:"determination"`
	Source        string     `json:"source"`
	Method        string     `json:"method"`
	Note          string     `json:"note"`
	DecidedAt     *time.Time `json:"decidedAt"`
	// Expired says a stated "met" has run out (an attestation past its date, or evidence past its date).
	Expired bool `json:"expired"`
}

// AttestationView is a signed statement.
type AttestationView struct {
	ID         uuid.UUID `json:"id"`
	Objectives []string  `json:"objectives"`
	Statement  string    `json:"statement"`
	Signer     uuid.UUID `json:"signer"`
	SignedAt   time.Time `json:"signedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Expired    bool      `json:"expired"`
}

// RequirementDetail is one requirement in full.
type RequirementDetail struct {
	RequirementRow
	Text          string            `json:"text"`
	ObjectiveList []ObjectiveView   `json:"objectiveList"`
	Attestations  []AttestationView `json:"attestations"`
	EvidenceList  []EvidenceView    `json:"evidenceList"`
}

// Requirement reads one requirement with its objectives, attestations and evidence.
func (s *Service) Requirement(ctx context.Context, c access.Caller, org, id uuid.UUID, req string) (*RequirementDetail, error) {
	rows, err := s.Requirements(ctx, c, org, id)
	if err != nil {
		return nil, err
	}
	var d *RequirementDetail
	for i := range rows {
		if rows[i].ReqID == req {
			d = &RequirementDetail{RequirementRow: rows[i], ObjectiveList: []ObjectiveView{}, Attestations: []AttestationView{}, EvidenceList: []EvidenceView{}}
		}
	}
	if d == nil {
		return nil, apperr.NotFound()
	}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		fw, err := loadFramework(ctx, tx, a.Framework, a.Version)
		if err != nil {
			return err
		}
		stored, err := objectiveRows(ctx, tx, a, s.now())
		if err != nil {
			return err
		}
		meth := map[ObjectiveKey]string{}
		mr, err := tx.Query(ctx, `SELECT obj_id, coalesce(method, '') FROM compliance_objective_results WHERE assessment_id = $1 AND req_id = $2`, id, req)
		if err != nil {
			return err
		}
		for mr.Next() {
			var o, m string
			if err := mr.Scan(&o, &m); err != nil {
				mr.Close()
				return err
			}
			meth[ObjectiveKey{req, o}] = m
		}
		mr.Close()
		for _, r := range fw {
			if r.ID != req {
				continue
			}
			d.Text = r.Text
			for _, o := range r.Objectives {
				v := ObjectiveView{ID: o.ID, Text: o.Text, Methods: nz(o.Methods), Controls: nz(o.Controls), Whole: r.Whole, Determination: NotAssessed, Method: meth[ObjectiveKey{req, o.ID}]}
				if sr, ok := stored[ObjectiveKey{req, o.ID}]; ok {
					v.Determination, v.Source, v.Note = sr.Determination, sr.Source, sr.Note
					t := sr.DecidedAt
					v.DecidedAt = &t
					if sr.Determination == Met && (Effective(sr.Row, s.now()) != Met || sr.NoEvidence) {
						v.Expired = true
						if !a.Frozen {
							v.Determination = NotAssessed
						}
					}
				}
				d.ObjectiveList = append(d.ObjectiveList, v)
			}
		}
		ar, err := tx.Query(ctx, `SELECT id, objectives, statement, signer, signed_at, expires_at FROM compliance_attestations
			WHERE assessment_id = $1 AND req_id = $2 ORDER BY signed_at DESC`, id, req)
		if err != nil {
			return err
		}
		for ar.Next() {
			var v AttestationView
			if err := ar.Scan(&v.ID, &v.Objectives, &v.Statement, &v.Signer, &v.SignedAt, &v.ExpiresAt); err != nil {
				ar.Close()
				return err
			}
			v.Expired = !s.now().Before(v.ExpiresAt)
			d.Attestations = append(d.Attestations, v)
		}
		ar.Close()
		if err := ar.Err(); err != nil {
			return err
		}
		d.EvidenceList, err = evidenceFor(ctx, tx, org, id, req)
		return err
	})
	return d, err
}

func nz(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// RequirementUpdate is a person's edit of a requirement's record.
type RequirementUpdate struct {
	Statement      *string    `json:"statement"`
	Responsibility *string    `json:"responsibility"`
	OwnerUser      *uuid.UUID `json:"ownerUser"`
	NextReview     *string    `json:"nextReview"`
	Partial        *bool      `json:"partial"`
}

// UpdateRequirement edits the statement, responsibility, owner, review date and partial-credit flag.
func (s *Service) UpdateRequirement(ctx context.Context, c access.Caller, org, id uuid.UUID, req string, in RequirementUpdate) error {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return err
	}
	f := apperr.Fields{}
	if in.Statement != nil {
		f.Check(len(*in.Statement) <= 20000, "statement", "Up to 20000 characters.")
	}
	if in.Responsibility != nil {
		r := *in.Responsibility
		f.Check(r == "customer" || r == "msp" || r == "inherited" || r == "shared", "responsibility", "Choose customer, msp, inherited or shared.")
	}
	if in.NextReview != nil && *in.NextReview != "" {
		_, err := time.Parse("2006-01-02", *in.NextReview)
		f.Check(err == nil, "nextReview", "Use a date like 2027-06-30.")
	}
	if err := f.Err(); err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		if err := editable(a); err != nil {
			return err
		}
		fw, err := loadFramework(ctx, tx, a.Framework, a.Version)
		if err != nil {
			return err
		}
		var r *fwReq
		for _, x := range fw {
			if x.ID == req {
				r = x
			}
		}
		if r == nil {
			return apperr.NotFound()
		}
		if in.Partial != nil && *in.Partial && r.Partial == 0 {
			return apperr.Invalid("partial", "Only 3.5.3 and 3.13.11 have a partial-credit case in the methodology.")
		}
		var owner any
		if in.OwnerUser != nil {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM role_assignments WHERE user_id = $1 AND (organization_id = $2 OR organization_id IS NULL)`, *in.OwnerUser, org).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return apperr.Invalid("ownerUser", "Choose a person who has access to this organization.")
			}
			owner = *in.OwnerUser
		}
		nr := any(nil)
		if in.NextReview != nil && *in.NextReview != "" {
			nr = *in.NextReview
		}
		tag, err := tx.Exec(ctx, `UPDATE compliance_implementations SET
			statement = coalesce($3, statement), responsibility = coalesce($4, responsibility),
			owner_user = CASE WHEN $5::boolean THEN $6 ELSE owner_user END,
			next_review = CASE WHEN $7::boolean THEN $8::date ELSE next_review END,
			partial = coalesce($9, partial), reviewed_at = now()
			WHERE assessment_id = $1 AND req_id = $2`, id, req, in.Statement, in.Responsibility, in.OwnerUser != nil, owner, in.NextReview != nil, nr, in.Partial)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return apperr.NotFound()
		}
		det := map[string]any{"req": req}
		if in.Statement != nil {
			h := sha256.Sum256([]byte(*in.Statement))
			det["statementSha256"] = hex.EncodeToString(h[:])
		}
		return s.audit.Write(ctx, tx, s.event(c, "compliance.requirement.update", a, det))
	})
}

// ObjectiveSet is a person's call on one objective.
type ObjectiveSet struct {
	Determination string `json:"determination"`
	Source        string `json:"source"`
	Method        string `json:"method"`
	Note          string `json:"note"`
}

// SetObjective records a determination made by upload (evidence is attached) or interview (a note says
// who was asked). An attestation has its own route. A scan result that says "not met" cannot be set aside
// by a person's statement: fix it, or wait for the next scan.
func (s *Service) SetObjective(ctx context.Context, c access.Caller, org, id uuid.UUID, req, obj string, in ObjectiveSet) error {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return err
	}
	f := apperr.Fields{}
	f.Check(in.Determination == Met || in.Determination == NotMet || in.Determination == NotApplicable || in.Determination == NotAssessed, "determination", "Choose met, not_met, not_applicable or not_assessed.")
	f.Check(in.Source == SourceUpload || in.Source == SourceInterview, "source", "Choose upload or interview. An attestation is signed on its own.")
	f.Check(in.Method == "" || in.Method == "examine" || in.Method == "interview" || in.Method == "test", "method", "Choose examine, interview or test.")
	f.Check(len(in.Note) <= 4000, "note", "Up to 4000 characters.")
	f.Check(in.Source != SourceInterview || trim(in.Note) != "", "note", "Say who was asked and what they said.")
	if err := f.Err(); err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		a, fw, r, err := s.target(ctx, tx, org, id, req)
		if err != nil {
			return err
		}
		if !hasObjective(r, obj) {
			return apperr.NotFound()
		}
		if err := s.checkScanNotMet(ctx, tx, id, req, obj, in.Determination); err != nil {
			return err
		}
		if in.Source == SourceUpload && in.Determination == Met {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM compliance_evidence_links l JOIN compliance_evidence e ON e.id = l.evidence_id
				WHERE l.assessment_id = $1 AND l.req_id = $2 AND (l.obj_id IS NULL OR l.obj_id = $3) AND (e.expires_at IS NULL OR e.expires_at > now())`, id, req, obj).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return apperr.Conflict("no_evidence", "Attach evidence to this requirement first.")
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_objective_results (organization_id, assessment_id, req_id, obj_id, determination, method, source, note, decided_by, decided_at)
			VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, $8, $9, now())
			ON CONFLICT (assessment_id, req_id, obj_id) DO UPDATE SET determination = EXCLUDED.determination, method = EXCLUDED.method, source = EXCLUDED.source,
			attestation_id = NULL, note = EXCLUDED.note, decided_by = EXCLUDED.decided_by, decided_at = now()`,
			org, id, req, obj, in.Determination, in.Method, in.Source, trim(in.Note), nilUser(c)); err != nil {
			return err
		}
		if err := s.recompute(ctx, tx, a, fw); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, s.event(c, "compliance.objective.set", a, map[string]any{"req": req, "objective": obj, "determination": in.Determination, "source": in.Source}))
	})
}

func hasObjective(r *fwReq, obj string) bool {
	for _, o := range r.Objectives {
		if o.ID == obj {
			return true
		}
	}
	return false
}

// target loads an editable assessment, its framework and one requirement.
func (s *Service) target(ctx context.Context, tx pgx.Tx, org, id uuid.UUID, req string) (*Assessment, []*fwReq, *fwReq, error) {
	a, err := load(ctx, tx, org, id)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := editable(a); err != nil {
		return nil, nil, nil, err
	}
	fw, err := loadFramework(ctx, tx, a.Framework, a.Version)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, r := range fw {
		if r.ID == req {
			return a, fw, r, nil
		}
	}
	return nil, nil, nil, apperr.NotFound()
}

// checkScanNotMet refuses to set aside, by a statement, a scan's finding that the objective is not met.
func (s *Service) checkScanNotMet(ctx context.Context, tx pgx.Tx, id uuid.UUID, req, obj, to string) error {
	if to != Met && to != NotApplicable {
		return nil
	}
	var det, src string
	err := tx.QueryRow(ctx, `SELECT determination, source FROM compliance_objective_results WHERE assessment_id = $1 AND req_id = $2 AND obj_id = $3`, id, req, obj).Scan(&det, &src)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if src == SourceScan && det == NotMet {
		return apperr.Conflict("scan_not_met", "A scan found this does not meet. Fix it and scan again; a statement does not set a scan result aside.")
	}
	return nil
}

// AttestInput is a signed statement that an objective (or the whole requirement) is implemented.
type AttestInput struct {
	Objectives []string   `json:"objectives"`
	Statement  string     `json:"statement"`
	ExpiresAt  *time.Time `json:"expiresAt"`
}

// MaxAttestation is the longest an attestation can stand.
const MaxAttestation = 2 * 365 * 24 * time.Hour

// DefaultAttestation is how long an attestation stands when no date is given: one year.
const DefaultAttestation = 365 * 24 * time.Hour

// Attest signs an attestation. It is evidence, never a scan result: it needs compliance.attest, a
// statement of the person's own, and a fresh step-up. It expires (one year unless a date is given).
func (s *Service) Attest(ctx context.Context, c access.Caller, org, id uuid.UUID, req string, in AttestInput) (*AttestationView, error) {
	if err := need(c, rbac.PermComplianceAttest, org); err != nil {
		return nil, err
	}
	f := apperr.Fields{}
	f.Check(trim(in.Statement) != "" && len(in.Statement) <= 20000, "statement", "Write the statement in your own words (up to 20000 characters).")
	now := s.now()
	exp := now.Add(DefaultAttestation)
	if in.ExpiresAt != nil {
		exp = *in.ExpiresAt
	}
	f.Check(exp.After(now) && !exp.After(now.Add(MaxAttestation)), "expiresAt", "Choose a date within the next two years.")
	if err := f.Err(); err != nil {
		return nil, err
	}
	if s.stepUp == nil {
		return nil, apperr.Unavailable("stepup_unavailable", "Step-up confirmation is not available.")
	}
	if err := s.stepUp.VerifyStepUp(ctx); err != nil {
		return nil, err
	}
	var out *AttestationView
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		a, fw, r, err := s.target(ctx, tx, org, id, req)
		if err != nil {
			return err
		}
		objs := in.Objectives
		if len(objs) == 0 {
			for _, o := range r.Objectives {
				objs = append(objs, o.ID)
			}
		}
		for _, o := range objs {
			if !hasObjective(r, o) {
				return apperr.Invalid("objectives", "An objective named does not belong to this requirement.")
			}
			if err := s.checkScanNotMet(ctx, tx, id, req, o, Met); err != nil {
				return err
			}
		}
		h := sha256.Sum256([]byte(in.Statement))
		v := &AttestationView{Objectives: objs, Statement: in.Statement, Signer: c.Actor.ID, ExpiresAt: exp}
		if err := tx.QueryRow(ctx, `INSERT INTO compliance_attestations (organization_id, assessment_id, req_id, objectives, statement, statement_sha256, signer, stepup_proof, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, signed_at`,
			org, id, req, objs, in.Statement, hex.EncodeToString(h[:]), c.Actor.ID, "step-up verified "+now.UTC().Format(time.RFC3339), exp).Scan(&v.ID, &v.SignedAt); err != nil {
			return err
		}
		for _, o := range objs {
			if _, err := tx.Exec(ctx, `INSERT INTO compliance_objective_results (organization_id, assessment_id, req_id, obj_id, determination, method, source, attestation_id, note, decided_by, decided_at)
				VALUES ($1, $2, $3, $4, 'met', NULL, 'attestation', $5, '', $6, now())
				ON CONFLICT (assessment_id, req_id, obj_id) DO UPDATE SET determination = 'met', method = NULL, source = 'attestation', attestation_id = EXCLUDED.attestation_id,
				note = '', decided_by = EXCLUDED.decided_by, decided_at = now()`, org, id, req, o, v.ID, nilUser(c)); err != nil {
				return err
			}
		}
		if err := s.recompute(ctx, tx, a, fw); err != nil {
			return err
		}
		out = v
		return s.audit.Write(ctx, tx, s.event(c, "compliance.attestation.sign", a, map[string]any{"req": req, "attestation": v.ID, "statementSha256": hex.EncodeToString(h[:]),
			"objectives": objs, "expiresAt": exp.UTC().Format(time.RFC3339), "stepUp": true}))
	})
	return out, err
}
