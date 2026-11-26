package assess

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type objDef struct {
	ID       string   `json:"id"`
	Text     string   `json:"text"`
	Methods  []string `json:"methods"`
	Controls []string `json:"controls"`
}

type fwReq struct {
	ID      string
	Nist    string
	Title   string
	Text    string
	Class   string
	Family  string
	Weight  int
	Partial int
	Barred  bool
	L1      bool
	NoCheck bool
	// Objectives are the requirement's own objectives, or one whole-requirement objective when none are loaded.
	Objectives []objDef
	// Whole says the objectives are the single whole-requirement one.
	Whole    bool
	ReqLevel []string
}

// loadFramework reads a framework's requirements with their objectives and the controls mapped to them.
func loadFramework(ctx context.Context, tx pgx.Tx, key, ver string) ([]*fwReq, error) {
	rows, err := tx.Query(ctx, `SELECT req_id, coalesce(flags->>'nist', req_id), title_own, coalesce(text_full, ''), class, coalesce(flags->>'family', ''),
		coalesce(weight, 0), coalesce((flags->>'partial_points')::int, 0), coalesce((flags->>'poam_barred')::boolean, false),
		coalesce((flags->>'l1')::boolean, false), coalesce((flags->>'no_check_yet')::boolean, false)
		FROM compliance_requirements WHERE framework_key = $1 AND framework_version = $2 ORDER BY req_id`, key, ver)
	if err != nil {
		return nil, err
	}
	var out []*fwReq
	idx := map[string]*fwReq{}
	for rows.Next() {
		r := &fwReq{}
		if err := rows.Scan(&r.ID, &r.Nist, &r.Title, &r.Text, &r.Class, &r.Family, &r.Weight, &r.Partial, &r.Barred, &r.L1, &r.NoCheck); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
		idx[r.ID] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	or, err := tx.Query(ctx, `SELECT req_id, obj_id, coalesce(text, ''), methods FROM compliance_objectives
		WHERE framework_key = $1 AND framework_version = $2 ORDER BY req_id, obj_id`, key, ver)
	if err != nil {
		return nil, err
	}
	for or.Next() {
		var req string
		var o objDef
		if err := or.Scan(&req, &o.ID, &o.Text, &o.Methods); err != nil {
			or.Close()
			return nil, err
		}
		if r := idx[req]; r != nil {
			r.Objectives = append(r.Objectives, o)
		}
	}
	or.Close()
	if err := or.Err(); err != nil {
		return nil, err
	}
	mr, err := tx.Query(ctx, `SELECT req_id, coalesce(obj_id, ''), control_id FROM compliance_mappings
		WHERE framework_key = $1 AND framework_version = $2 AND relation = 'satisfies_objective' ORDER BY control_id`, key, ver)
	if err != nil {
		return nil, err
	}
	for mr.Next() {
		var req, obj, ctl string
		if err := mr.Scan(&req, &obj, &ctl); err != nil {
			mr.Close()
			return nil, err
		}
		r := idx[req]
		if r == nil {
			continue
		}
		if obj == "" {
			r.ReqLevel = append(r.ReqLevel, ctl)
			continue
		}
		for i := range r.Objectives {
			if r.Objectives[i].ID == obj {
				r.Objectives[i].Controls = append(r.Objectives[i].Controls, ctl)
			}
		}
	}
	mr.Close()
	if err := mr.Err(); err != nil {
		return nil, err
	}
	for _, r := range out {
		if len(r.Objectives) == 0 {
			r.Whole = true
			r.Objectives = []objDef{{ID: WholeRequirement, Text: "The requirement as a whole.", Methods: []string{"examine", "interview", "test"}, Controls: r.ReqLevel}}
		}
	}
	return out, nil
}

func objectivesOf(fw []*fwReq) []ReqObjectives {
	out := make([]ReqObjectives, 0, len(fw))
	for _, r := range fw {
		ro := ReqObjectives{ID: r.ID, Class: r.Class, NoCheckYet: r.NoCheck, ReqLevel: r.ReqLevel}
		if !r.Whole {
			for _, o := range r.Objectives {
				ro.Objectives = append(ro.Objectives, Objective{ID: o.ID, Controls: o.Controls})
			}
		}
		out = append(out, ro)
	}
	return out
}

// storedRow is an objective result as stored, with what decides whether it still stands.
type storedRow struct {
	Row
	Note       string
	DecidedAt  time.Time
	NoEvidence bool
}

// objectiveRows reads the stored objective results of an assessment.
func objectiveRows(ctx context.Context, tx pgx.Tx, a *Assessment, now time.Time) (map[ObjectiveKey]storedRow, error) {
	rows, err := tx.Query(ctx, `SELECT o.req_id, o.obj_id, o.determination, o.source, att.expires_at, o.note, o.decided_at,
		(o.source = 'upload' AND NOT EXISTS (SELECT 1 FROM compliance_evidence_links l JOIN compliance_evidence e ON e.id = l.evidence_id
			WHERE l.assessment_id = o.assessment_id AND l.req_id = o.req_id AND (l.obj_id IS NULL OR l.obj_id = o.obj_id)
			AND (e.expires_at IS NULL OR e.expires_at > $2)))
		FROM compliance_objective_results o LEFT JOIN compliance_attestations att ON att.id = o.attestation_id
		WHERE o.assessment_id = $1`, a.ID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[ObjectiveKey]storedRow{}
	for rows.Next() {
		var k ObjectiveKey
		var r storedRow
		if err := rows.Scan(&k.Req, &k.Obj, &r.Determination, &r.Source, &r.AttestationExpires, &r.Note, &r.DecidedAt, &r.NoEvidence); err != nil {
			return nil, err
		}
		out[k] = r
	}
	return out, rows.Err()
}

type implStatus struct {
	Status string
	Origin string
}

// derive works a requirement's status and origin out from its objectives' stored results, now.
func derive(r *fwReq, rows map[ObjectiveKey]storedRow, now time.Time) implStatus {
	var dets []string
	origin := "scan"
	for _, o := range r.Objectives {
		row, ok := rows[ObjectiveKey{r.ID, o.ID}]
		if !ok {
			dets = append(dets, NotAssessed)
			continue
		}
		d := Effective(row.Row, now)
		if row.NoEvidence && d == Met {
			d = NotAssessed
		}
		dets = append(dets, d)
		if d == Met || d == NotApplicable {
			switch row.Source {
			case SourceAttestation, SourceUpload:
				origin = "attested"
			case SourceInterview:
				if origin == "scan" {
					origin = "manual"
				}
			}
		}
	}
	return implStatus{Status: Requirement(dets), Origin: origin}
}

// scoreReqs reads the requirements as the score sees them. A draft or an assessment in review is read
// through its objectives as of now (so that an expired attestation stops counting); an approved one
// is read as it was stored when it was approved.
func scoreReqs(ctx context.Context, tx pgx.Tx, a *Assessment, now time.Time) ([]Req, error) {
	fw, err := loadFramework(ctx, tx, a.Framework, a.Version)
	if err != nil {
		return nil, err
	}
	stored := map[string]struct {
		status  string
		partial bool
	}{}
	rows, err := tx.Query(ctx, `SELECT req_id, status, partial FROM compliance_implementations WHERE assessment_id = $1`, a.ID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, st string
		var p bool
		if err := rows.Scan(&id, &st, &p); err != nil {
			rows.Close()
			return nil, err
		}
		stored[id] = struct {
			status  string
			partial bool
		}{st, p}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var obj map[ObjectiveKey]storedRow
	if !a.Frozen {
		if obj, err = objectiveRows(ctx, tx, a, now); err != nil {
			return nil, err
		}
	}
	out := make([]Req, 0, len(fw))
	for _, r := range fw {
		st := stored[r.ID]
		status := st.status
		if status == "" {
			status = NotAssessed
		}
		if !a.Frozen {
			status = derive(r, obj, now).Status
		}
		out = append(out, Req{ID: r.Nist, Weight: r.Weight, Partial: r.Partial, Barred: r.Barred, Status: status, PartlyDone: st.partial, L1: r.L1})
	}
	return out, nil
}

func gateItems(ctx context.Context, tx pgx.Tx, id uuid.UUID) ([]POAMItem, error) {
	rows, err := tx.Query(ctx, `SELECT req_id, status, closes_by FROM compliance_poam_items WHERE assessment_id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []POAMItem
	for rows.Next() {
		var it POAMItem
		if err := rows.Scan(&it.ReqID, &it.Status, &it.ClosesBy); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// scopeDevices works out who is in scope from the recorded rows: a group's computers take the group's
// category, and a computer named on its own takes its own. In scope is everything not marked out of scope.
func scopeDevices(ctx context.Context, tx pgx.Tx, a *Assessment) (in, out []uuid.UUID, err error) {
	rows, err := tx.Query(ctx, `SELECT d.id, s.category, s.device_id IS NOT NULL FROM compliance_scope_assets s
		JOIN devices d ON (s.device_id = d.id OR d.device_group_id = s.group_id) AND d.organization_id = s.organization_id
		WHERE s.assessment_id = $1`, a.ID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	cat := map[uuid.UUID]string{}
	direct := map[uuid.UUID]bool{}
	for rows.Next() {
		var d uuid.UUID
		var c string
		var isDirect bool
		if err := rows.Scan(&d, &c, &isDirect); err != nil {
			return nil, nil, err
		}
		if direct[d] && !isDirect {
			continue
		}
		cat[d], direct[d] = c, isDirect || direct[d]
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for d, c := range cat {
		if c == "out_of_scope" {
			out = append(out, d)
		} else {
			in = append(in, d)
		}
	}
	sort.Slice(in, func(i, j int) bool { return in[i].String() < in[j].String() })
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return in, out, nil
}
