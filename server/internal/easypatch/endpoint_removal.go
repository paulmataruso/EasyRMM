package easypatch

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Removing an endpoint only the patching engine has (ADR-0050): one no
// EasyRMM device is linked to, such as a computer decommissioned before its
// device was. Its agent is asked to uninstall itself through
// easypatch_removals, as for a deleted device, and its endpoint is revoked
// once it has, or after uninstallGrace. The engine lists active endpoints
// only, so it then leaves the patching overview.

// RemoveEndpoint asks for the removal of an endpoint no device is linked to.
// Asking again while it is under way changes nothing.
func (s *Service) RemoveEndpoint(ctx context.Context, c access.Caller, id uuid.UUID) (UnmatchedEndpoint, error) {
	r, cl, err := s.conn(ctx)
	if err != nil {
		return UnmatchedEndpoint{}, err
	}
	if r == nil {
		return UnmatchedEndpoint{}, errNotConfigured
	}
	linked, err := s.linkedOrgs(ctx, c)
	if err != nil {
		return UnmatchedEndpoint{}, err
	}
	// The engine is asked in the organizations whose patching the caller
	// sees whole, as the patching overview lists them.
	var orgs []uuid.UUID
	for ep, o := range linked {
		if c.Can(rbac.PermPatchView, rbac.Org(o.id)) {
			orgs = append(orgs, ep)
		}
	}
	if len(orgs) == 0 {
		return UnmatchedEndpoint{}, apperr.NotFound()
	}
	e, err := cl.Endpoint(s.as(ctx, c, RoleReadOnly, orgs...), id)
	if err != nil {
		s.noteError(err)
		return UnmatchedEndpoint{}, epError(err)
	}
	o, ok := linked[e.Summary.OrganizationID]
	if !ok || !c.Can(rbac.PermPatchView, rbac.Org(o.id)) {
		return UnmatchedEndpoint{}, apperr.NotFound()
	}
	if !c.Can(rbac.PermDeviceRetire, rbac.Org(o.id)) {
		return UnmatchedEndpoint{}, apperr.Forbidden()
	}
	if e.Summary.Status != "Active" {
		return UnmatchedEndpoint{}, apperr.Conflict("endpoint_inactive", "The patching engine no longer patches this endpoint.")
	}
	out := UnmatchedEndpoint{Endpoint: e.Summary, OrganizationID: o.id, OrganizationName: o.name, CanRemove: true}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var device bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM easypatch_devices WHERE endpoint_id = $1)`, id).Scan(&device); err != nil {
			return err
		}
		if device {
			return apperr.Conflict("endpoint_linked", "A device in EasyRMM is linked to this endpoint. Remove the device, or stop patching it, instead.")
		}
		tag, err := tx.Exec(ctx, `INSERT INTO easypatch_removals (endpoint_id, reason, hostname) VALUES ($1, $2, $3)
			ON CONFLICT (endpoint_id) DO NOTHING`, id, RemovalDeleted, cut(e.Summary.Hostname, 255))
		if err != nil {
			return err
		}
		removals, err := endpointRemovals(ctx, tx, []uuid.UUID{id})
		if err != nil {
			return err
		}
		out.Removal = removals[id]
		if tag.RowsAffected() == 0 {
			return nil
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "patch.endpoint_remove", OrganizationID: o.id,
			TargetType: "easypatch_endpoint", TargetID: id.String(), Outcome: audit.Success,
			Details: map[string]any{"endpoint": e.Summary.Hostname}})
	})
	if err != nil {
		return UnmatchedEndpoint{}, err
	}
	s.Kick()
	return out, nil
}

// endpointRemovals reads the removals of the given endpoints.
func endpointRemovals(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) (map[uuid.UUID]*AgentRemoval, error) {
	rows, err := tx.Query(ctx, `SELECT endpoint_id, reason, state, requested_at, last_error FROM easypatch_removals WHERE endpoint_id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID]*AgentRemoval{}
	for rows.Next() {
		var id uuid.UUID
		var r AgentRemoval
		var at time.Time
		if err := rows.Scan(&id, &r.Reason, &r.State, &at, &r.Error); err != nil {
			return nil, err
		}
		r.RequestedAt = at
		out[id] = &r
	}
	return out, rows.Err()
}
