package assess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess/export"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess/oscal"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess/report"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content/templates"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// SectionView is a section of a document.
type SectionView struct {
	Position  int    `json:"position"`
	SectionID string `json:"sectionId"`
	Heading   string `json:"heading"`
	Body      string `json:"body"`
	Generated bool   `json:"generated"`
	// Hint is the template's prompt for a section a person writes.
	Hint string `json:"hint"`
}

// DocumentView is a document of the assessment.
type DocumentView struct {
	ID         *uuid.UUID    `json:"id"`
	Kind       string        `json:"kind"`
	TemplateID string        `json:"templateId"`
	Title      string        `json:"title"`
	Version    int           `json:"version"`
	Sections   []SectionView `json:"sections"`
	// Exists says the document has been started; before that the sections shown are the template's.
	Exists bool `json:"exists"`
}

// Templates lists the document skeletons EasyRMM carries.
func (s *Service) Templates() ([]templates.Template, error) { return templates.All() }

// SSP reads the system security plan, or the template it would start from.
func (s *Service) SSP(ctx context.Context, c access.Caller, org, id uuid.UUID) (*DocumentView, error) {
	if err := need(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	t, err := templates.Get("ssp-v1")
	if err != nil {
		return nil, err
	}
	d := &DocumentView{Kind: "ssp", TemplateID: t.ID, Title: t.Title, Version: 1, Sections: []SectionView{}}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		var did uuid.UUID
		err = tx.QueryRow(ctx, `SELECT id, version FROM compliance_documents WHERE assessment_id = $1 AND kind = 'ssp' AND template_id = $2`, a.ID, t.ID).Scan(&did, &d.Version)
		if errors.Is(err, pgx.ErrNoRows) {
			for i, sec := range t.Sections {
				d.Sections = append(d.Sections, SectionView{Position: i, SectionID: sec.ID, Heading: sec.Heading, Generated: sec.Generate != "", Hint: sec.Body})
			}
			return nil
		}
		if err != nil {
			return err
		}
		d.ID, d.Exists = &did, true
		hint := map[string]string{}
		for _, sec := range t.Sections {
			hint[sec.ID] = sec.Body
		}
		rows, err := tx.Query(ctx, `SELECT position, section_id, heading, body, generated FROM compliance_document_sections WHERE document_id = $1 ORDER BY position`, did)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v SectionView
			if err := rows.Scan(&v.Position, &v.SectionID, &v.Heading, &v.Body, &v.Generated); err != nil {
				return err
			}
			v.Hint = hint[v.SectionID]
			d.Sections = append(d.Sections, v)
		}
		return rows.Err()
	})
	return d, err
}

// GenerateSSP starts the plan from the template, or writes the generated sections again from the
// assessment as it now stands. A section a person has edited is theirs and is left alone.
func (s *Service) GenerateSSP(ctx context.Context, c access.Caller, org, id uuid.UUID) (*DocumentView, error) {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return nil, err
	}
	t, err := templates.Get("ssp-v1")
	if err != nil {
		return nil, err
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		if err := editable(a); err != nil {
			return err
		}
		rep, err := s.buildReport(ctx, tx, a, false)
		if err != nil {
			return err
		}
		var did uuid.UUID
		err = tx.QueryRow(ctx, `SELECT id FROM compliance_documents WHERE assessment_id = $1 AND kind = 'ssp' AND template_id = $2`, a.ID, t.ID).Scan(&did)
		if errors.Is(err, pgx.ErrNoRows) {
			if err := tx.QueryRow(ctx, `INSERT INTO compliance_documents (organization_id, assessment_id, kind, template_id) VALUES ($1, $2, 'ssp', $3) RETURNING id`, org, a.ID, t.ID).Scan(&did); err != nil {
				return err
			}
			for i, sec := range t.Sections {
				if _, err := tx.Exec(ctx, `INSERT INTO compliance_document_sections (organization_id, document_id, position, section_id, heading, body, generated) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
					org, did, i, sec.ID, sec.Heading, Generated(sec.Generate, rep), sec.Generate != ""); err != nil {
					return err
				}
			}
		} else if err != nil {
			return err
		} else {
			for _, sec := range t.Sections {
				if sec.Generate == "" {
					continue
				}
				if _, err := tx.Exec(ctx, `UPDATE compliance_document_sections SET body = $3 WHERE document_id = $1 AND section_id = $2 AND generated`, did, sec.ID, Generated(sec.Generate, rep)); err != nil {
					return err
				}
			}
		}
		return s.audit.Write(ctx, tx, s.event(c, "compliance.ssp.generate", a, map[string]any{"document": did}))
	})
	if err != nil {
		return nil, err
	}
	return s.SSP(ctx, c, org, id)
}

// UpdateSSPSection saves a person's text in a section. A generated section that is edited becomes the
// person's own: it is no longer rewritten when the plan is generated again.
func (s *Service) UpdateSSPSection(ctx context.Context, c access.Caller, org, id uuid.UUID, position int, body string) error {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return err
	}
	if len(body) > 200000 {
		return apperr.Invalid("body", "Up to 200000 characters.")
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		if err := editable(a); err != nil {
			return err
		}
		h := sha256.Sum256([]byte(body))
		tag, err := tx.Exec(ctx, `UPDATE compliance_document_sections s SET body = $3, generated = false FROM compliance_documents d
			WHERE s.document_id = d.id AND d.assessment_id = $1 AND d.kind = 'ssp' AND s.position = $2`, a.ID, position, body)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return apperr.NotFound()
		}
		return s.audit.Write(ctx, tx, s.event(c, "compliance.ssp.update", a, map[string]any{"position": position, "bodySha256": hex.EncodeToString(h[:])}))
	})
}

// ---- the report and the exports ---------------------------------------------------------------

func (s *Service) buildReport(ctx context.Context, tx pgx.Tx, a *Assessment, withSSP bool) (*report.Report, error) {
	r := &report.Report{AssessmentID: a.ID.String(), OrgID: a.OrgID.String(), Title: a.Title, Assessor: a.Assessor, State: a.State, Framework: a.Framework,
		Version: a.Version, Generated: s.now(), Approved: a.ApprovedAt, Disclaimer: disclaimer}
	if err := tx.QueryRow(ctx, `SELECT name FROM organizations WHERE id = $1`, a.OrgID).Scan(&r.OrgName); err != nil {
		return nil, err
	}
	sc, err := readScope(ctx, tx, a)
	if err != nil {
		return nil, err
	}
	for _, i := range sc.Items {
		r.Scope = append(r.Scope, report.ScopeItem{Name: i.Name, Kind: i.Kind, Category: i.Category, Reason: i.Reason})
	}
	fw, err := loadFramework(ctx, tx, a.Framework, a.Version)
	if err != nil {
		return nil, err
	}
	reqs, err := scoreReqs(ctx, tx, a, s.now())
	if err != nil {
		return nil, err
	}
	impl, err := implRows(ctx, tx, a.ID)
	if err != nil {
		return nil, err
	}
	stored, err := storedObjectives(ctx, tx, a.ID)
	if err != nil {
		return nil, err
	}
	ev := map[string][]report.EvidenceRef{}
	er, err := tx.Query(ctx, `SELECT DISTINCT l.req_id, e.id, e.title, e.sha256, e.kind FROM compliance_evidence_links l JOIN compliance_evidence e ON e.id = l.evidence_id
		WHERE l.assessment_id = $1 AND l.req_id IS NOT NULL ORDER BY 1, 2`, a.ID)
	if err != nil {
		return nil, err
	}
	for er.Next() {
		var req string
		var e report.EvidenceRef
		if err := er.Scan(&req, &e.ID, &e.Title, &e.SHA256, &e.Kind); err != nil {
			er.Close()
			return nil, err
		}
		ev[req] = append(ev[req], e)
	}
	er.Close()
	if err := er.Err(); err != nil {
		return nil, err
	}
	for i, q := range fw {
		im := impl[q.ID]
		row := report.Requirement{ID: q.ID, NistID: q.Nist, Title: q.Title, Family: q.Family, Status: reqs[i].Status, Origin: im.Origin, Partial: im.Partial && reqs[i].Status == NotMet,
			Weight: q.Weight, Statement: im.Statement, Responsibility: im.Responsibility, Evidence: ev[q.ID]}
		if im.NextReview != nil {
			row.NextReview = *im.NextReview
		}
		for _, o := range q.Objectives {
			d := stored[ObjectiveKey{q.ID, o.ID}]
			if d == "" {
				d = NotAssessed
			}
			row.Objectives = append(row.Objectives, report.Objective{ID: o.ID, Determination: d})
		}
		r.Requirements = append(r.Requirements, row)
	}
	items, err := s.poamItems(ctx, tx, a)
	if err != nil {
		return nil, err
	}
	for _, p := range items {
		it := report.POAMItem{ID: p.ID.String(), ReqID: p.ReqID, NistID: p.NistID, Weakness: p.Weakness, Points: p.Points, Eligible: p.Eligible, Reason: p.EligibilityReason,
			Status: p.Status, OpenedOn: p.OpenedOn, ClosesBy: p.ClosesBy, Resources: p.Resources}
		for _, m := range p.Milestones {
			due := ""
			if m.Due != nil {
				due = *m.Due
			}
			it.Milestones = append(it.Milestones, report.Milestone{Title: m.Title, Due: due, Status: m.Status})
		}
		r.POAM = append(r.POAM, it)
	}
	gi, err := gateItems(ctx, tx, a.ID)
	if err != nil {
		return nil, err
	}
	rg := ComputeRange(reqs)
	g := ComputeGate(reqs, gi, s.now())
	r.Score = report.Score{Low: rg.Low, High: rg.High, Number: rg.Number, NotMet: rg.NotMet, Unassessed: rg.Unassessed, Met: rg.Met, SSPMissing: rg.SSPMissing,
		GateOutcome: g.Outcome, GateMin: g.MinScore, L1Met: rg.L1Met, L1Of: rg.L1Of, Blockers: []string{}}
	for _, b := range g.Low.Blockers {
		r.Score.Blockers = append(r.Score.Blockers, b.ReqID+": "+b.Reason)
	}
	if withSSP {
		rows, err := tx.Query(ctx, `SELECT s.section_id, s.heading, s.body, s.generated FROM compliance_document_sections s JOIN compliance_documents d ON d.id = s.document_id
			WHERE d.assessment_id = $1 AND d.kind = 'ssp' ORDER BY s.position`, a.ID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var sec report.Section
			if err := rows.Scan(&sec.ID, &sec.Heading, &sec.Body, &sec.Generated); err != nil {
				return nil, err
			}
			r.SSP = append(r.SSP, sec)
		}
		return r, rows.Err()
	}
	return r, nil
}

// Export formats.
const (
	FormatOSCALSSP     = "oscal-ssp"
	FormatOSCALPOAM    = "oscal-poam"
	FormatRequirements = "requirements-csv"
	FormatPOAMCSV      = "poam-csv"
	FormatBundle       = "bundle"
	FormatPDF          = "pdf"
)

// File is an export ready to send.
type File struct {
	Name        string
	ContentType string
	Body        []byte
	SHA256      string
}

// Export makes a file from the assessment. Its SHA-256 is recorded in the audit log with who asked
// and for which format. An export of a draft is allowed, and says so in the file's own state field.
func (s *Service) Export(ctx context.Context, c access.Caller, org, id uuid.UUID, format string) (*File, error) {
	if err := need(c, rbac.PermComplianceExport, org); err != nil {
		return nil, err
	}
	var f *File
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		rep, err := s.buildReport(ctx, tx, a, true)
		if err != nil {
			return err
		}
		base := fmt.Sprintf("assessment-%s", a.ID.String()[:8])
		var body []byte
		switch format {
		case FormatOSCALSSP:
			f = &File{Name: base + "-ssp.oscal.json", ContentType: "application/json"}
			body, err = oscal.SSP(rep)
		case FormatOSCALPOAM:
			f = &File{Name: base + "-poam.oscal.json", ContentType: "application/json"}
			body, err = oscal.POAM(rep)
			if errors.Is(err, oscal.ErrNoItems) {
				return apperr.Conflict("no_poam_items", "There are no plan of action items to export yet.")
			}
		case FormatRequirements:
			f = &File{Name: base + "-requirements.csv", ContentType: "text/csv; charset=utf-8"}
			body, err = export.Requirements(rep)
		case FormatPOAMCSV:
			f = &File{Name: base + "-poam.csv", ContentType: "text/csv; charset=utf-8"}
			body, err = export.POAM(rep)
		case FormatBundle:
			f = &File{Name: base + ".zip", ContentType: "application/zip"}
			body, err = export.Bundle(rep)
		case FormatPDF:
			f = &File{Name: base + ".pdf", ContentType: "application/pdf"}
			body = export.PDF(rep)
		default:
			return apperr.Invalid("format", "Choose oscal-ssp, oscal-poam, requirements-csv, poam-csv, bundle or pdf.")
		}
		if err != nil {
			return err
		}
		h := sha256.Sum256(body)
		f.Body, f.SHA256 = body, hex.EncodeToString(h[:])
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "compliance.export", OrganizationID: org, TargetType: "compliance_assessment", TargetID: id.String(),
			Outcome: audit.Success, Details: map[string]any{"format": format, "sha256": f.SHA256, "size": len(body), "state": a.State}})
	})
	return f, err
}
