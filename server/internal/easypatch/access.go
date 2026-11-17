package easypatch

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Access to EasyPatch from EasyRMM (integration plan, section 6.4). One
// function decides what someone may do in EasyPatch, from their EasyRMM
// roles: whether the product switch is shown now, and later the role and
// organizations EasyRMM's sign-in gives EasyPatch.

// The EasyPatch roles EasyRMM grants. EasyPatch gives one role per person.
const (
	RoleSuperAdmin = "SuperAdmin"
	RoleAdmin      = "Admin"
	RoleReadOnly   = "ReadOnly"
)

// Access is someone's access in EasyPatch.
type Access struct {
	Role string `json:"role"`
	// Organizations are EasyPatch's ids of the organizations the role holds
	// in, sorted; empty for a SuperAdmin, who holds it in all of them.
	Organizations []uuid.UUID `json:"organizations"`
}

// easyPatchAccess decides p's access in EasyPatch, given the linked
// organizations (EasyRMM's id to EasyPatch's), or nil for none:
//
//   - a super administrator is a SuperAdmin;
//   - otherwise only organization-wide (or platform-wide) grants on linked
//     organizations count: a grant on one site never opens the whole
//     EasyPatch organization;
//   - Admin over the organizations where p has patch.configure, when there
//     is one; otherwise ReadOnly over those where p has patch.view. With
//     one role per person, organizations p may only view are left out when
//     p may configure others: gaining access somewhere never demotes anyone.
func easyPatchAccess(p *rbac.Principal, linked map[uuid.UUID]uuid.UUID) *Access {
	if p == nil {
		return nil
	}
	if p.IsSuperAdmin() {
		return &Access{Role: RoleSuperAdmin, Organizations: []uuid.UUID{}}
	}
	var configure, view []uuid.UUID
	for org, ep := range linked {
		if p.Can(rbac.PermPatchConfigure, rbac.Org(org)) {
			configure = append(configure, ep)
		}
		if p.Can(rbac.PermPatchView, rbac.Org(org)) {
			view = append(view, ep)
		}
	}
	sortIDs := func(ids []uuid.UUID) []uuid.UUID {
		sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
		return ids
	}
	switch {
	case len(configure) > 0:
		return &Access{Role: RoleAdmin, Organizations: sortIDs(configure)}
	case len(view) > 0:
		return &Access{Role: RoleReadOnly, Organizations: sortIDs(view)}
	}
	return nil
}

// Access is the caller's access in EasyPatch, or nil for none.
func (s *Service) Access(ctx context.Context, c access.Caller) (*Access, error) {
	if c.Principal == nil {
		return nil, nil
	}
	if c.Principal.IsSuperAdmin() {
		return easyPatchAccess(c.Principal, nil), nil
	}
	linked := map[uuid.UUID]uuid.UUID{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT organization_id, easypatch_id FROM easypatch_organizations`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var org, ep uuid.UUID
			if err := rows.Scan(&org, &ep); err != nil {
				return err
			}
			linked[org] = ep
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return easyPatchAccess(c.Principal, linked), nil
}

// Switch is what the console's product switch shows.
type Switch struct {
	// Show is true when EasyPatch is set up and the caller has access to it.
	Show bool `json:"show"`
	// Answering is false when a call to EasyPatch failed since its last
	// successful check (every ten minutes): EasyPatch is down, or refuses
	// EasyRMM's token. The switch still links to it, in case it recovered.
	Answering bool `json:"answering"`
	// FailingSince is when that call failed.
	FailingSince *time.Time `json:"failingSince,omitempty"`
}

// Switch says whether to show the caller the product switch, and whether
// EasyPatch was answering. Anyone signed in may ask; the answer says no
// more than whether the switch is shown.
func (s *Service) Switch(ctx context.Context, c access.Caller) (Switch, error) {
	conn, err := s.Connection(ctx)
	if err != nil || !conn.Configured || consoleURL(conn) == "" {
		return Switch{}, err
	}
	a, err := s.Access(ctx, c)
	if err != nil || a == nil {
		return Switch{}, err
	}
	sw := Switch{Show: true, Answering: true}
	if conn.LastErrorAt != nil && (conn.CheckedAt == nil || conn.LastErrorAt.After(*conn.CheckedAt)) {
		sw.Answering, sw.FailingSince = false, conn.LastErrorAt
	}
	return sw, nil
}
