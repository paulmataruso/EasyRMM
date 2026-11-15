package remote

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Device is a managed endpoint as the console shows it.
type Device struct {
	ID               uuid.UUID  `json:"id"`
	OrganizationID   uuid.UUID  `json:"organizationId"`
	OrganizationName string     `json:"organizationName"`
	SiteID           uuid.UUID  `json:"siteId"`
	SiteName         string     `json:"siteName"`
	DeviceGroupID    *uuid.UUID `json:"deviceGroupId"`
	DeviceGroupName  string     `json:"deviceGroupName,omitempty"`
	Name             string     `json:"name"`
	Hostname         string     `json:"hostname"`
	OSDescription    string     `json:"osDescription"`
	Platform         string     `json:"platform"`
	RemoteAgent      bool       `json:"remoteAgent"`
	RemoteOnline     bool       `json:"remoteOnline"`
	LastSeenAt       *time.Time `json:"lastSeenAt"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
	// What the caller may do with it.
	CanDesktop  bool `json:"canDesktop"`
	CanTerminal bool `json:"canTerminal"`
	CanFiles    bool `json:"canFiles"`

	meshNodeID string
}

// DeviceQuery filters a device list.
type DeviceQuery struct {
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	Search         string
	// Status is "", "online" or "offline".
	Status string
}

// MaxDevices bounds one list response.
const MaxDevices = 5000

const deviceColumns = `d.id, d.organization_id, o.name, d.site_id, s.name, d.device_group_id, coalesce(g.name, ''),
	d.name, d.hostname, d.os_description, d.platform, coalesce(d.mesh_node_id, ''), d.remote_online, d.last_seen_at,
	d.created_at, d.updated_at`

const deviceFrom = ` FROM devices d
	JOIN sites s ON s.id = d.site_id
	JOIN organizations o ON o.id = d.organization_id
	LEFT JOIN device_groups g ON g.id = d.device_group_id`

func scanDevice(row pgx.Row) (*Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.OrganizationID, &d.OrganizationName, &d.SiteID, &d.SiteName, &d.DeviceGroupID, &d.DeviceGroupName,
		&d.Name, &d.Hostname, &d.OSDescription, &d.Platform, &d.meshNodeID, &d.RemoteOnline, &d.LastSeenAt,
		&d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	d.RemoteAgent = d.meshNodeID != ""
	return &d, nil
}

func (d *Device) decorate(c access.Caller) {
	r := rbac.Site(d.OrganizationID, d.SiteID)
	d.CanDesktop = d.RemoteAgent && c.Can(rbac.PermRemoteDesktop, r)
	d.CanTerminal = d.RemoteAgent && c.Can(rbac.PermTerminal, r)
	d.CanFiles = d.RemoteAgent && c.Can(rbac.PermFiles, r)
}

// ListDevices returns the devices the caller can see, by name.
func (s *Service) ListDevices(ctx context.Context, c access.Caller, q DeviceQuery) ([]*Device, error) {
	switch q.Status {
	case "", "online", "offline":
	default:
		return nil, apperr.Invalid("status", "Use online or offline.")
	}
	out := []*Device{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+deviceColumns+deviceFrom+`
			WHERE ($1::uuid IS NULL OR d.organization_id = $1)
			  AND ($2::uuid IS NULL OR d.site_id = $2)
			  AND ($3 = '' OR strpos(lower(d.name), lower($3)) > 0 OR strpos(lower(d.hostname), lower($3)) > 0)
			  AND ($4 = '' OR d.remote_online = ($4 = 'online'))
			ORDER BY lower(d.name), d.id LIMIT $5`,
			nullUUID(q.OrganizationID), nullUUID(q.SiteID), strings.TrimSpace(q.Search), q.Status, MaxDevices)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d, err := scanDevice(rows)
			if err != nil {
				return err
			}
			if !c.Can(rbac.PermDeviceView, rbac.Site(d.OrganizationID, d.SiteID)) {
				continue
			}
			d.decorate(c)
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// GetDevice returns one device the caller can see.
func (s *Service) GetDevice(ctx context.Context, c access.Caller, id uuid.UUID) (*Device, error) {
	var d *Device
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		d, err = scanDevice(tx.QueryRow(ctx, `SELECT `+deviceColumns+deviceFrom+` WHERE d.id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermDeviceView, rbac.Site(d.OrganizationID, d.SiteID)) {
		return nil, apperr.NotFound()
	}
	d.decorate(c)
	return d, nil
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
