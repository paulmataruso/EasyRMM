package assess

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/rollup"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// MilestoneView is a step of a plan-of-action item.
type MilestoneView struct {
	ID     uuid.UUID  `json:"id"`
	Title  string     `json:"title"`
	Due    *string    `json:"due"`
	Status string     `json:"status"`
	Done   bool       `json:"done"`
	Evid   *uuid.UUID `json:"evidenceId"`
}

// POAMView is a plan-of-action item.
type POAMView struct {
	ID                  uuid.UUID       `json:"id"`
	ReqID               string          `json:"reqId"`
	NistID              string          `json:"nistId"`
	Title               string          `json:"title"`
	Weakness            string          `json:"weakness"`
	Points              int             `json:"points"`
	Eligible            bool            `json:"eligible"`
	EligibilityReason   string          `json:"eligibilityReason"`
	Status              string          `json:"status"`
	OpenedOn            string          `json:"openedOn"`
	ClosesBy            string          `json:"closesBy"`
	Overdue             bool            `json:"overdue"`
	OwnerUser           *uuid.UUID      `json:"ownerUser"`
	Resources           string          `json:"resources"`
	ScheduledCompletion *string         `json:"scheduledCompletion"`
	Basis               json.RawMessage `json:"basis"`
	Milestones          []MilestoneView `json:"milestones"`
	// RequirementStatus is the requirement's status now: an item for a requirement that is met is ready to close.
	RequirementStatus string `json:"requirementStatus"`
}

// POAMBoard is the plan of action with its rules in view.
type POAMBoard struct {
	Items []POAMView `json:"items"`
	// Note says what a plan of action is and is not.
	Note string `json:"note"`
}

const poamNote = "A plan of action does not make a requirement met: a requirement not yet implemented scores as not met until it is. " +
	"Each item must be closed within 180 days, and a closeout assessment confirms it."

// POAM reads the board.
func (s *Service) POAM(ctx context.Context, c access.Caller, org, id uuid.UUID) (*POAMBoard, error) {
	if err := need(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	b := &POAMBoard{Items: []POAMView{}, Note: poamNote}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		b.Items, err = s.poamItems(ctx, tx, a)
		return err
	})
	return b, err
}

func (s *Service) poamItems(ctx context.Context, tx pgx.Tx, a *Assessment) ([]POAMView, error) {
	reqs, err := scoreReqs(ctx, tx, a, s.now())
	if err != nil {
		return nil, err
	}
	fw, err := loadFramework(ctx, tx, a.Framework, a.Version)
	if err != nil {
		return nil, err
	}
	title, byNist := map[string]string{}, map[string]string{}
	for _, r := range fw {
		title[r.ID] = r.Title
		byNist[r.ID] = r.Nist
	}
	status := map[string]string{}
	for i, r := range fw {
		status[r.ID] = reqs[i].Status
	}
	rows, err := tx.Query(ctx, `SELECT id, req_id, weakness, point_value, basis, owner_user, resources, to_char(scheduled_completion, 'YYYY-MM-DD'), status, eligible,
		eligibility_reason, to_char(opened_on, 'YYYY-MM-DD'), closes_by FROM compliance_poam_items WHERE assessment_id = $1 ORDER BY req_id`, a.ID)
	if err != nil {
		return nil, err
	}
	var out []POAMView
	for rows.Next() {
		var v POAMView
		var closes time.Time
		if err := rows.Scan(&v.ID, &v.ReqID, &v.Weakness, &v.Points, &v.Basis, &v.OwnerUser, &v.Resources, &v.ScheduledCompletion, &v.Status, &v.Eligible, &v.EligibilityReason, &v.OpenedOn, &closes); err != nil {
			rows.Close()
			return nil, err
		}
		v.ClosesBy = closes.Format("2006-01-02")
		v.Overdue = (v.Status == "open" || v.Status == "in_progress") && s.now().After(closes.AddDate(0, 0, 1))
		v.NistID, v.Title, v.RequirementStatus = byNist[v.ReqID], title[v.ReqID], status[v.ReqID]
		v.Milestones = []MilestoneView{}
		out = append(out, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		mr, err := tx.Query(ctx, `SELECT id, title, to_char(due, 'YYYY-MM-DD'), status, evidence_id FROM compliance_poam_milestones WHERE poam_id = $1 ORDER BY due NULLS LAST, title`, out[i].ID)
		if err != nil {
			return nil, err
		}
		for mr.Next() {
			var m MilestoneView
			if err := mr.Scan(&m.ID, &m.Title, &m.Due, &m.Status, &m.Evid); err != nil {
				mr.Close()
				return nil, err
			}
			m.Done = m.Status == "done"
			out[i].Milestones = append(out[i].Milestones, m)
		}
		mr.Close()
		if err := mr.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GeneratePOAM makes a draft item for each requirement that is not met and has none, with the failing
// computers and fix-queue items it found, its point value, whether the rule allows it on a plan of
// action, and the 180-day clock. A person then confirms. It is automatic behavior and checks the
// development scope.
func (s *Service) GeneratePOAM(ctx context.Context, c access.Caller, org, id uuid.UUID) (int, error) {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return 0, err
	}
	if !devscope.Allowed(org) {
		return 0, apperr.Conflict("dev_scope", "This build does not run compliance work for this organization.")
	}
	made := 0
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
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
		reqs, err := scoreReqs(ctx, tx, a, s.now())
		if err != nil {
			return err
		}
		in, _, err := s.scanInput(ctx, tx, a, fw)
		if err != nil {
			return err
		}
		fail := failing(fw, in)
		fixes, err := fixItems(ctx, tx, org, fail)
		if err != nil {
			return err
		}
		for _, d := range DraftItems(reqs) {
			var req *fwReq
			for _, r := range fw {
				if r.Nist == d.ReqID {
					req = r
				}
			}
			if req == nil {
				continue
			}
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM compliance_poam_items WHERE assessment_id = $1 AND req_id = $2`, id, req.ID).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				continue
			}
			basis, _ := json.Marshal(map[string]any{"failingComputers": len(fail[req.ID]), "controls": controlsOfFailing(fail[req.ID]), "fixItems": fixes[req.ID]})
			weak := fmt.Sprintf("Requirement %s is not met.", req.Nist)
			if k := len(fail[req.ID]); k > 0 {
				weak = fmt.Sprintf("Requirement %s is not met: %d check(s) on computers in scope do not meet.", req.Nist, k)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO compliance_poam_items (organization_id, assessment_id, req_id, weakness, point_value, basis, status, eligible, eligibility_reason, opened_on, closes_by)
				VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7, $8, current_date, $9)`,
				org, id, req.ID, weak, d.Points, basis, d.Eligible, d.Reason, ClosesBy(s.now())); err != nil {
				return err
			}
			made++
		}
		return s.audit.Write(ctx, tx, s.event(c, "compliance.poam.generate", a, map[string]any{"drafted": made}))
	})
	return made, err
}

type finding struct {
	Device  uuid.UUID
	Control string
}

// failing lists, for each requirement, the checks that do not meet on computers in scope.
func failing(fw []*fwReq, in ScanInput) map[string][]finding {
	var flat []rollup.Requirement
	for _, r := range fw {
		rr := rollup.Requirement{ID: r.ID, Class: compliance.ReqTechnical}
		seen := map[string]bool{}
		for _, o := range r.Objectives {
			for _, ctl := range o.Controls {
				if !seen[ctl] {
					seen[ctl] = true
					rr.Mappings = append(rr.Mappings, rollup.Mapping{ControlID: ctl, Relation: compliance.RelSatisfies})
				}
			}
		}
		flat = append(flat, rr)
	}
	out := map[string][]finding{}
	for _, o := range rollup.Compute(rollup.Input{Requirements: flat, Results: in.Results, InScope: in.InScope, OutOfScope: in.OutOfScope, Now: in.Now, Fresh: in.Fresh}) {
		for _, f := range o.Failing {
			out[o.ReqID] = append(out[o.ReqID], finding{f.DeviceID, f.ControlID})
		}
	}
	return out
}

func controlsOfFailing(l []finding) []string {
	var out []string
	for _, f := range l {
		if !slices.Contains(out, f.Control) {
			out = append(out, f.Control)
		}
	}
	slices.Sort(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// fixItems finds the fix-queue items for the failing checks.
func fixItems(ctx context.Context, tx pgx.Tx, org uuid.UUID, fail map[string][]finding) (map[string][]uuid.UUID, error) {
	var devs []uuid.UUID
	var ctls []string
	for _, l := range fail {
		for _, f := range l {
			devs = append(devs, f.Device)
			ctls = append(ctls, f.Control)
		}
	}
	out := map[string][]uuid.UUID{}
	if len(devs) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT id, device_id, control_id FROM compliance_fix_items WHERE organization_id = $1 AND device_id = ANY ($2) AND control_id = ANY ($3)
		AND state NOT IN ('verified', 'resolved', 'undone')`, org, devs, ctls)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type key struct {
		d uuid.UUID
		c string
	}
	byPair := map[key][]uuid.UUID{}
	for rows.Next() {
		var id, d uuid.UUID
		var ctl string
		if err := rows.Scan(&id, &d, &ctl); err != nil {
			return nil, err
		}
		byPair[key{d, ctl}] = append(byPair[key{d, ctl}], id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for req, l := range fail {
		for _, f := range l {
			out[req] = append(out[req], byPair[key{f.Device, f.Control}]...)
		}
	}
	return out, nil
}

// POAMUpdate is an edit of a plan-of-action item.
type POAMUpdate struct {
	Weakness            *string    `json:"weakness"`
	OwnerUser           *uuid.UUID `json:"ownerUser"`
	Resources           *string    `json:"resources"`
	ScheduledCompletion *string    `json:"scheduledCompletion"`
	Status              *string    `json:"status"`
}

var poamStatuses = []string{"draft", "open", "in_progress", "closed", "accepted"}

// UpdatePOAM edits an item. An item the rule does not allow stays a draft (or is closed): it cannot be
// opened. Confirming a draft (moving it to open) starts its 180 days from that day.
func (s *Service) UpdatePOAM(ctx context.Context, c access.Caller, org, id, item uuid.UUID, in POAMUpdate) error {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return err
	}
	f := apperr.Fields{}
	if in.Status != nil {
		f.Check(slices.Contains(poamStatuses, *in.Status), "status", "Choose draft, open, in_progress, closed or accepted.")
	}
	if in.Weakness != nil {
		f.Check(len(*in.Weakness) <= 20000, "weakness", "Up to 20000 characters.")
	}
	if in.Resources != nil {
		f.Check(len(*in.Resources) <= 4000, "resources", "Up to 4000 characters.")
	}
	if in.ScheduledCompletion != nil && *in.ScheduledCompletion != "" {
		_, err := time.Parse("2006-01-02", *in.ScheduledCompletion)
		f.Check(err == nil, "scheduledCompletion", "Use a date like 2027-06-30.")
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
		var elig bool
		var cur, reason string
		if err := tx.QueryRow(ctx, `SELECT eligible, status, eligibility_reason FROM compliance_poam_items WHERE id = $1 AND assessment_id = $2`, item, id).Scan(&elig, &cur, &reason); err != nil {
			return apperr.NotFound()
		}
		if in.Status != nil && !elig && *in.Status != "draft" && *in.Status != "closed" {
			return apperr.Conflict("poam_not_allowed", "This requirement may not be on a plan of action: "+reason)
		}
		sc := any(nil)
		if in.ScheduledCompletion != nil && *in.ScheduledCompletion != "" {
			sc = *in.ScheduledCompletion
		}
		start := in.Status != nil && cur == "draft" && *in.Status == "open"
		if _, err := tx.Exec(ctx, `UPDATE compliance_poam_items SET weakness = coalesce($3, weakness), resources = coalesce($4, resources),
			owner_user = CASE WHEN $5::boolean THEN $6 ELSE owner_user END, scheduled_completion = CASE WHEN $7::boolean THEN $8::date ELSE scheduled_completion END,
			status = coalesce($9, status), opened_on = CASE WHEN $10::boolean THEN current_date ELSE opened_on END,
			closes_by = CASE WHEN $10::boolean THEN $11::date ELSE closes_by END
			WHERE id = $1 AND assessment_id = $2`, item, id, in.Weakness, in.Resources, in.OwnerUser != nil, in.OwnerUser, in.ScheduledCompletion != nil, sc, in.Status, start, ClosesBy(s.now())); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, s.event(c, "compliance.poam.update", a, map[string]any{"item": item, "status": in.Status}))
	})
}

// AddMilestone adds a step to an item.
func (s *Service) AddMilestone(ctx context.Context, c access.Caller, org, id, item uuid.UUID, title string, due *string) (*MilestoneView, error) {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return nil, err
	}
	f := apperr.Fields{}
	f.Check(trim(title) != "" && len(title) <= 500, "title", "Describe the step in up to 500 characters.")
	d := any(nil)
	if due != nil && *due != "" {
		_, err := time.Parse("2006-01-02", *due)
		f.Check(err == nil, "due", "Use a date like 2027-06-30.")
		d = *due
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	var m MilestoneView
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		if err := editable(a); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM compliance_poam_items WHERE id = $1 AND assessment_id = $2`, item, id).Scan(&n); err != nil || n == 0 {
			return apperr.NotFound()
		}
		if err := tx.QueryRow(ctx, `INSERT INTO compliance_poam_milestones (organization_id, poam_id, title, due) VALUES ($1, $2, $3, $4)
			RETURNING id, title, to_char(due, 'YYYY-MM-DD'), status`, org, item, trim(title), d).Scan(&m.ID, &m.Title, &m.Due, &m.Status); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, s.event(c, "compliance.poam.milestone", a, map[string]any{"item": item, "milestone": m.ID}))
	})
	return &m, err
}

// SetMilestone marks a step open or done.
func (s *Service) SetMilestone(ctx context.Context, c access.Caller, org, id, milestone uuid.UUID, done bool) error {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
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
		st := "open"
		if done {
			st = "done"
		}
		tag, err := tx.Exec(ctx, `UPDATE compliance_poam_milestones m SET status = $3 FROM compliance_poam_items p
			WHERE m.id = $1 AND p.id = m.poam_id AND p.assessment_id = $2`, milestone, id, st)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return apperr.NotFound()
		}
		return s.audit.Write(ctx, tx, s.event(c, "compliance.poam.milestone", a, map[string]any{"milestone": milestone, "status": st}))
	})
}
