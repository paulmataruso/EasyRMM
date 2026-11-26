package assess

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/rollup"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Scoping categories: the labels are EasyRMM's own (the exact wording of CMMC's categories is unverified).
var categories = map[string]bool{"cui": true, "security_protection": true, "contractor_risk_managed": true, "specialized": true, "out_of_scope": true}

// ScopeItem is a computer or group in the scope.
type ScopeItem struct {
	ID       uuid.UUID  `json:"id"`
	DeviceID *uuid.UUID `json:"deviceId"`
	GroupID  *uuid.UUID `json:"groupId"`
	Name     string     `json:"name"`
	Kind     string     `json:"kind"`
	Category string     `json:"category"`
	Reason   string     `json:"reason"`
}

// Scope is the recorded scope and how many of the organization's computers it does not name.
type Scope struct {
	Items []ScopeItem `json:"items"`
	// Unlisted computers are in no category: they are not counted, and are listed here by number so that
	// nothing drops out unseen.
	Unlisted int `json:"unlisted"`
}

// ScopeInput is one computer or group and its category.
type ScopeInput struct {
	DeviceID *uuid.UUID `json:"deviceId"`
	GroupID  *uuid.UUID `json:"groupId"`
	Category string     `json:"category"`
	Reason   string     `json:"reason"`
}

// GetScope reads the recorded scope.
func (s *Service) GetScope(ctx context.Context, c access.Caller, org, id uuid.UUID) (*Scope, error) {
	if err := need(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	var out *Scope
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		out, err = readScope(ctx, tx, a)
		return err
	})
	return out, err
}

func readScope(ctx context.Context, tx pgx.Tx, a *Assessment) (*Scope, error) {
	rows, err := tx.Query(ctx, `SELECT s.id, s.device_id, s.group_id, coalesce(d.name, g.name, ''), CASE WHEN s.device_id IS NOT NULL THEN 'computer' ELSE 'group' END, s.category, s.reason
		FROM compliance_scope_assets s LEFT JOIN devices d ON d.id = s.device_id AND d.organization_id = s.organization_id LEFT JOIN device_groups g ON g.id = s.group_id
		WHERE s.assessment_id = $1 ORDER BY 5, 4`, a.ID)
	if err != nil {
		return nil, err
	}
	out := &Scope{Items: []ScopeItem{}}
	for rows.Next() {
		var i ScopeItem
		if err := rows.Scan(&i.ID, &i.DeviceID, &i.GroupID, &i.Name, &i.Kind, &i.Category, &i.Reason); err != nil {
			rows.Close()
			return nil, err
		}
		out.Items = append(out.Items, i)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	in, off, err := scopeDevices(ctx, tx, a)
	if err != nil {
		return nil, err
	}
	var total int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE organization_id = $1`, a.OrgID).Scan(&total); err != nil {
		return nil, err
	}
	out.Unlisted = max(0, total-len(in)-len(off))
	return out, nil
}

// PutScope replaces the recorded scope. Scope is recorded by a person, never inferred.
func (s *Service) PutScope(ctx context.Context, c access.Caller, org, id uuid.UUID, in []ScopeInput) (*Scope, error) {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return nil, err
	}
	f := apperr.Fields{}
	seen := map[uuid.UUID]bool{}
	for _, i := range in {
		f.Check((i.DeviceID == nil) != (i.GroupID == nil), "items", "Each entry names one computer or one group.")
		f.Check(categories[i.Category], "category", "Choose a category from the list.")
		f.Check(len(i.Reason) <= 2000, "reason", "Up to 2000 characters.")
		k := uuid.Nil
		if i.DeviceID != nil {
			k = *i.DeviceID
		} else if i.GroupID != nil {
			k = *i.GroupID
		}
		f.Check(!seen[k], "items", "Each computer or group can be listed once.")
		seen[k] = true
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	var out *Scope
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, org, id)
		if err != nil {
			return err
		}
		if err := editable(a); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM compliance_scope_assets WHERE assessment_id = $1`, id); err != nil {
			return err
		}
		for _, i := range in {
			var n int
			if i.DeviceID != nil {
				err = tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE id = $1 AND organization_id = $2`, *i.DeviceID, org).Scan(&n)
			} else {
				err = tx.QueryRow(ctx, `SELECT count(*) FROM device_groups WHERE id = $1 AND organization_id = $2`, *i.GroupID, org).Scan(&n)
			}
			if err != nil {
				return err
			}
			if n == 0 {
				return apperr.Invalid("items", "A computer or group in the list does not belong to this organization.")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO compliance_scope_assets (organization_id, assessment_id, device_id, group_id, category, reason) VALUES ($1, $2, $3, $4, $5, $6)`,
				org, id, i.DeviceID, i.GroupID, i.Category, trim(i.Reason)); err != nil {
				return err
			}
		}
		if out, err = readScope(ctx, tx, a); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, s.event(c, "compliance.assessment.scope_update", a, map[string]any{"entries": len(in)}))
	})
	return out, err
}

// ---- applying a scan ------------------------------------------------------------------------

// RefreshResult says what applying the scan did.
type RefreshResult struct {
	ScanID     *uuid.UUID `json:"scanId"`
	Updated    int        `json:"updated"`
	NotChanged int        `json:"keptStated"`
	InScope    int        `json:"inScope"`
	Notes      []string   `json:"notes"`
}

func (s *Service) scanInput(ctx context.Context, tx pgx.Tx, a *Assessment, fw []*fwReq) (ScanInput, *uuid.UUID, error) {
	in, off, err := scopeDevices(ctx, tx, a)
	if err != nil {
		return ScanInput{}, nil, err
	}
	days := 30
	if err := tx.QueryRow(ctx, `SELECT freshness_days FROM compliance_org_settings WHERE organization_id = $1`, a.OrgID).Scan(&days); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ScanInput{}, nil, err
	}
	ids := map[string]bool{}
	for _, r := range fw {
		for _, o := range r.Objectives {
			for _, ctl := range o.Controls {
				ids[ctl] = true
			}
		}
	}
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	devs := append(append([]uuid.UUID{}, in...), off...)
	rr, err := tx.Query(ctx, `SELECT control_id, device_id, state, checked_at, owner FROM compliance_results
		WHERE organization_id = $1 AND control_id = ANY ($2) AND device_id = ANY ($3)`, a.OrgID, list, devs)
	if err != nil {
		return ScanInput{}, nil, err
	}
	defer rr.Close()
	res := map[string]map[uuid.UUID]rollup.Result{}
	for rr.Next() {
		var cid string
		var d uuid.UUID
		var r rollup.Result
		var owner []byte
		if err := rr.Scan(&cid, &d, &r.State, &r.CheckedAt, &owner); err != nil {
			return ScanInput{}, nil, err
		}
		if len(owner) > 0 {
			var o struct {
				Name  string `json:"name"`
				Meets bool   `json:"meets"`
			}
			if json.Unmarshal(owner, &o) == nil {
				r.Owner = &rollup.Owner{Name: o.Name, Meets: &o.Meets}
			}
		}
		if res[cid] == nil {
			res[cid] = map[uuid.UUID]rollup.Result{}
		}
		res[cid][d] = r
	}
	if err := rr.Err(); err != nil {
		return ScanInput{}, nil, err
	}
	var scan *uuid.UUID
	var sid uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM compliance_scans WHERE organization_id = $1 AND state IN ('done', 'partial') AND trigger <> 'verify'
		ORDER BY started_at DESC LIMIT 1`, a.OrgID).Scan(&sid); err == nil {
		scan = &sid
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return ScanInput{}, nil, err
	}
	return ScanInput{Results: res, InScope: in, OutOfScope: off, Now: s.now(), Fresh: time.Duration(days) * 24 * time.Hour}, scan, nil
}

// Refresh applies the latest scan's results to the draft: each objective a scan can decide is set from
// the scan. What a person stated is kept, except that a scan finding "not met" replaces it. It is
// automatic behavior and checks the development scope.
func (s *Service) Refresh(ctx context.Context, c access.Caller, org, id uuid.UUID) (*RefreshResult, error) {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return nil, err
	}
	if !devscope.Allowed(org) {
		return nil, apperr.Conflict("dev_scope", "This build does not run compliance work for this organization.")
	}
	out := &RefreshResult{Notes: []string{}}
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
		in, scan, err := s.scanInput(ctx, tx, a, fw)
		if err != nil {
			return err
		}
		out.ScanID, out.InScope = scan, len(in.InScope)
		if scan == nil {
			out.Notes = append(out.Notes, "No scan has finished yet.")
		}
		if len(in.InScope) == 0 {
			out.Notes = append(out.Notes, "No computers are recorded as in scope.")
		}
		dets := FromScan(objectivesOf(fw), in)
		stored, err := objectiveRows(ctx, tx, a, s.now())
		if err != nil {
			return err
		}
		for _, r := range fw {
			for _, o := range r.Objectives {
				k := ObjectiveKey{r.ID, o.ID}
				d := dets[k]
				if len(o.Controls) == 0 && d.Value == NotAssessed {
					continue // nothing for a scan to say about it
				}
				var old *Row
				if sr, ok := stored[k]; ok {
					old = &sr.Row
				}
				if keep, d2 := Merge(old, d); keep {
					out.NotChanged++
					continue
				} else {
					d = d2
				}
				if _, err := tx.Exec(ctx, `INSERT INTO compliance_objective_results (organization_id, assessment_id, req_id, obj_id, determination, source, note, decided_by, decided_at)
					VALUES ($1, $2, $3, $4, $5, 'scan', $6, NULL, now())
					ON CONFLICT (assessment_id, req_id, obj_id) DO UPDATE SET determination = EXCLUDED.determination, source = 'scan', method = NULL,
					attestation_id = NULL, note = EXCLUDED.note, decided_by = NULL, decided_at = now()`, org, id, r.ID, o.ID, d.Value, d.Reason); err != nil {
					return err
				}
				out.Updated++
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE compliance_assessments SET scan_id = $2, updated_at = now() WHERE id = $1`, id, scan); err != nil {
			return err
		}
		if err := s.recompute(ctx, tx, a, fw); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, s.event(c, "compliance.assessment.refresh", a, map[string]any{"scanId": scan, "updated": out.Updated, "keptStated": out.NotChanged}))
	})
	return out, err
}

// recompute stores each requirement's status and origin from its objectives.
func (s *Service) recompute(ctx context.Context, tx pgx.Tx, a *Assessment, fw []*fwReq) error {
	rows, err := objectiveRows(ctx, tx, a, s.now())
	if err != nil {
		return err
	}
	b := &pgx.Batch{}
	for _, r := range fw {
		st := derive(r, rows, s.now())
		b.Queue(`UPDATE compliance_implementations SET status = $3, origin = $4 WHERE assessment_id = $1 AND req_id = $2`, a.ID, r.ID, st.Status, st.Origin)
	}
	br := tx.SendBatch(ctx, b)
	for range fw {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return err
		}
	}
	return br.Close()
}
