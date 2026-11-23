package devices

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// TreeGroup is a device group, as the console's device tree shows it.
type TreeGroup struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organizationId"`
	SiteID         uuid.UUID `json:"siteId"`
	Name           string    `json:"name"`
}

// TreeCount is how many devices sit directly in a site (GroupID nil: those
// without a group) or in one of its groups, and how many are online.
type TreeCount struct {
	SiteID  uuid.UUID  `json:"siteId"`
	GroupID *uuid.UUID `json:"groupId"`
	Total   int        `json:"total"`
	Online  int        `json:"online"`
}

// Tree is what the console's tree needs beyond the organizations and sites:
// the device groups, and the device counts it shows before a node's devices
// are loaded (ADR-0069).
type Tree struct {
	Groups []TreeGroup `json:"groups"`
	Counts []TreeCount `json:"counts"`
}

// Tree returns every device group the caller can see and the counts of the
// devices they may view.
func (s *Service) Tree(ctx context.Context, c access.Caller) (*Tree, error) {
	out := &Tree{Groups: []TreeGroup{}, Counts: []TreeCount{}}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT g.id, g.organization_id, g.site_id, g.name FROM device_groups g ORDER BY lower(g.name), g.id`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var g TreeGroup
			if err := rows.Scan(&g.ID, &g.OrganizationID, &g.SiteID, &g.Name); err != nil {
				rows.Close()
				return err
			}
			out.Groups = append(out.Groups, g)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		counts, err := tx.Query(ctx, `SELECT d.organization_id, d.site_id, d.device_group_id, count(*)::int,
				(count(*) FILTER (WHERE d.remote_online OR `+agentOnline+`))::int
			FROM devices d GROUP BY d.organization_id, d.site_id, d.device_group_id`)
		if err != nil {
			return err
		}
		defer counts.Close()
		for counts.Next() {
			var org uuid.UUID
			var n TreeCount
			if err := counts.Scan(&org, &n.SiteID, &n.GroupID, &n.Total, &n.Online); err != nil {
				return err
			}
			if c.Can(rbac.PermDeviceView, rbac.Site(org, n.SiteID)) {
				out.Counts = append(out.Counts, n)
			}
		}
		return counts.Err()
	})
	return out, err
}
