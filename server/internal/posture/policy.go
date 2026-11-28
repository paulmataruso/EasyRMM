package posture

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/rollup"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Posture policies (ADR-0082, slice P4): an organization's own weight for a
// control, over the built-in default. A weight of 0 leaves the control out of
// the score.

// Weight bounds of a policy.
const (
	MinWeight = 0
	MaxWeight = 5
)

// controlIDPattern is what a control id looks like (the migration's CHECK).
var controlIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// DefaultWeight is what a control weighs when its organization has not set a
// weight: the built-in weight, or 1 for a control the table does not name.
func DefaultWeight(control string) int {
	if w, ok := weights[control]; ok && w >= 1 {
		return w
	}
	return 1
}

// applyOverrides sets the weights an organization chose and leaves out the
// controls it set to 0. It returns items itself when there is nothing to do.
func applyOverrides(items []rollup.Item, ov map[string]int) []rollup.Item {
	if len(ov) == 0 {
		return items
	}
	out := make([]rollup.Item, 0, len(items))
	for _, it := range items {
		if w, ok := ov[it.ID]; ok {
			if w == 0 {
				continue
			}
			it.Weight = w
		}
		out = append(out, it)
	}
	return out
}

// loadOverrides reads the weights the organizations chose, in the caller's
// transaction.
func loadOverrides(ctx context.Context, tx pgx.Tx, orgs []uuid.UUID) (map[uuid.UUID]map[string]int, error) {
	out := map[uuid.UUID]map[string]int{}
	rows, err := tx.Query(ctx, `SELECT organization_id, control_id, weight FROM posture_policies WHERE organization_id = ANY ($1)`, orgs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var o uuid.UUID
		var c string
		var w int
		if err := rows.Scan(&o, &c, &w); err != nil {
			return nil, err
		}
		if out[o] == nil {
			out[o] = map[string]int{}
		}
		out[o][c] = w
	}
	return out, rows.Err()
}

// Policy is one control's weight for an organization.
type Policy struct {
	ControlID string `json:"controlId"`
	Label     string `json:"label"`
	// Weight is what the control weighs now; Default what it weighs when the
	// organization has not chosen.
	Weight  int `json:"weight"`
	Default int `json:"default"`
	// Overridden says the organization chose Weight.
	Overridden bool       `json:"overridden"`
	UpdatedAt  *time.Time `json:"updatedAt"`
}

func newPolicy(control string, weight *int, at *time.Time) Policy {
	p := Policy{ControlID: control, Label: Label(control), Default: DefaultWeight(control), UpdatedAt: at}
	p.Weight = p.Default
	if weight != nil {
		p.Weight, p.Overridden = *weight, true
	}
	return p
}

// requirePolicy checks the caller may manage the organization's posture
// policies (org.manage). A caller who may not sees nothing there.
func requirePolicy(c access.Caller, org uuid.UUID) error {
	if !c.Can(rbac.PermOrgManage, rbac.Org(org)) {
		return apperr.NotFound()
	}
	return nil
}

func validControl(control string) error {
	f := apperr.Fields{}
	f.Check(controlIDPattern.MatchString(control), "controlId", "That is not a control.")
	return f.Err()
}

// ListPolicies lists the weights an organization chose, by control.
func (s *Service) ListPolicies(ctx context.Context, c access.Caller, org uuid.UUID) ([]Policy, error) {
	if err := requirePolicy(c, org); err != nil {
		return nil, err
	}
	out := []Policy{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT control_id, weight, updated_at FROM posture_policies WHERE organization_id = $1 ORDER BY control_id`, org)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var w int
			var at time.Time
			if err := rows.Scan(&id, &w, &at); err != nil {
				return err
			}
			out = append(out, newPolicy(id, &w, &at))
		}
		return rows.Err()
	})
	return out, err
}

// GetPolicy reads one control's weight for an organization: the chosen one, or
// the default.
func (s *Service) GetPolicy(ctx context.Context, c access.Caller, org uuid.UUID, control string) (*Policy, error) {
	if err := requirePolicy(c, org); err != nil {
		return nil, err
	}
	if err := validControl(control); err != nil {
		return nil, err
	}
	var w *int
	var at *time.Time
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var ww int
		var aa time.Time
		err := tx.QueryRow(ctx, `SELECT weight, updated_at FROM posture_policies WHERE organization_id = $1 AND control_id = $2`, org, control).Scan(&ww, &aa)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		w, at = &ww, &aa
		return err
	})
	if err != nil {
		return nil, err
	}
	p := newPolicy(control, w, at)
	return &p, nil
}

// SetPolicy sets one control's weight for an organization (0 leaves it out of
// the score). It needs org.manage.
func (s *Service) SetPolicy(ctx context.Context, c access.Caller, org uuid.UUID, control string, weight int) (*Policy, error) {
	if err := requirePolicy(c, org); err != nil {
		return nil, err
	}
	f := apperr.Fields{}
	f.Check(controlIDPattern.MatchString(control), "controlId", "That is not a control.")
	f.Check(weight >= MinWeight && weight <= MaxWeight, "weight", "Choose a weight from 0 to 5.")
	if err := f.Err(); err != nil {
		return nil, err
	}
	var by *uuid.UUID
	if c.Principal != nil {
		id := c.Principal.UserID
		by = &id
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO posture_policies (organization_id, control_id, weight, updated_at, updated_by)
			VALUES ($1, $2, $3, now(), $4)
			ON CONFLICT (organization_id, control_id) DO UPDATE SET weight = EXCLUDED.weight, updated_at = now(), updated_by = EXCLUDED.updated_by`,
			org, control, weight, by); err != nil {
			return err
		}
		return s.auditPolicy(ctx, tx, c, org, "posture.policy_set", control, weight)
	})
	if err != nil {
		return nil, err
	}
	return s.GetPolicy(ctx, c, org, control)
}

// DeletePolicy resets one control to its default weight.
func (s *Service) DeletePolicy(ctx context.Context, c access.Caller, org uuid.UUID, control string) error {
	if err := requirePolicy(c, org); err != nil {
		return err
	}
	if err := validControl(control); err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM posture_policies WHERE organization_id = $1 AND control_id = $2`, org, control)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return s.auditPolicy(ctx, tx, c, org, "posture.policy_reset", control, DefaultWeight(control))
	})
}

func (s *Service) auditPolicy(ctx context.Context, tx pgx.Tx, c access.Caller, org uuid.UUID, action, control string, weight int) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: action, OrganizationID: org, Outcome: audit.Success,
		TargetType: "organization", TargetID: org.String(), Details: map[string]any{"control": control, "weight": weight}})
}
