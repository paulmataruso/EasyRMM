// Package devices is the inventory of managed endpoints: devices enrolled by
// the EasyRMM agent (ADR-0015) and devices discovered through MeshCentral
// (ADR-0014). It is available whether or not remote access is enabled.
package devices

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// AgentOnlineWindow is how recently the EasyRMM agent must have reported for
// its device to count as online: three missed heartbeats.
const AgentOnlineWindow = 3 * time.Minute

// Agent is the EasyRMM agent of an enrolled device.
type Agent struct {
	Version    string     `json:"version"`
	Arch       string     `json:"arch"`
	Online     bool       `json:"online"`
	LastSeenAt *time.Time `json:"lastSeenAt"`
	EnrolledAt time.Time  `json:"enrolledAt"`
}

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
	// Online is true while either the EasyRMM agent or MeshAgent is
	// connected.
	Online bool `json:"online"`
	// Agent is nil for a device known only through MeshCentral.
	Agent *Agent `json:"agent"`
	// RemoteAgent and RemoteOnline describe MeshAgent.
	RemoteAgent  bool       `json:"remoteAgent"`
	RemoteOnline bool       `json:"remoteOnline"`
	LastSeenAt   *time.Time `json:"lastSeenAt"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
	// What the caller may do with it.
	CanDesktop  bool `json:"canDesktop"`
	CanTerminal bool `json:"canTerminal"`
	CanFiles    bool `json:"canFiles"`

	// MeshNodeID is MeshCentral's node identifier, empty without MeshAgent.
	MeshNodeID string `json:"-"`
}

// Query filters a device list.
type Query struct {
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	Search         string
	// Status is "", "online" or "offline".
	Status string
}

// MaxList bounds one list response.
const MaxList = 5000

// agentOnline is the SQL form of Agent.Online.
var agentOnline = fmt.Sprintf("coalesce(d.agent_last_seen_at > now() - interval '%d seconds', false)", int(AgentOnlineWindow.Seconds()))

var columns = `d.id, d.organization_id, o.name, d.site_id, s.name, d.device_group_id, coalesce(g.name, ''),
	d.name, d.hostname, d.os_description, d.platform, coalesce(d.mesh_node_id, ''), d.remote_online,
	greatest(d.last_seen_at, d.agent_last_seen_at), d.created_at, d.updated_at,
	d.enrolled_at, coalesce(d.agent_version, ''), coalesce(d.agent_arch, ''), d.agent_last_seen_at, ` + agentOnline

const from = ` FROM devices d
	JOIN sites s ON s.id = d.site_id
	JOIN organizations o ON o.id = d.organization_id
	LEFT JOIN device_groups g ON g.id = d.device_group_id`

func scan(row pgx.Row) (*Device, error) {
	var (
		d          Device
		enrolledAt *time.Time
		a          Agent
	)
	err := row.Scan(&d.ID, &d.OrganizationID, &d.OrganizationName, &d.SiteID, &d.SiteName, &d.DeviceGroupID, &d.DeviceGroupName,
		&d.Name, &d.Hostname, &d.OSDescription, &d.Platform, &d.MeshNodeID, &d.RemoteOnline,
		&d.LastSeenAt, &d.CreatedAt, &d.UpdatedAt,
		&enrolledAt, &a.Version, &a.Arch, &a.LastSeenAt, &a.Online)
	if err != nil {
		return nil, err
	}
	d.RemoteAgent = d.MeshNodeID != ""
	if enrolledAt != nil {
		a.EnrolledAt = *enrolledAt
		d.Agent = &a
	}
	d.Online = d.RemoteOnline || a.Online
	return &d, nil
}

// Service reads the device inventory.
type Service struct {
	db     *database.DB
	remote bool
}

// New returns a Service. remote says whether remote access is enabled on
// this server; without it no device offers remote sessions.
func New(db *database.DB, remote bool) *Service {
	return &Service{db: db, remote: remote}
}

func (s *Service) decorate(c access.Caller, d *Device) {
	r := rbac.Site(d.OrganizationID, d.SiteID)
	ok := s.remote && d.RemoteAgent
	d.CanDesktop = ok && c.Can(rbac.PermRemoteDesktop, r)
	d.CanTerminal = ok && c.Can(rbac.PermTerminal, r)
	d.CanFiles = ok && c.Can(rbac.PermFiles, r)
}

// List returns the devices the caller can see, by name.
func (s *Service) List(ctx context.Context, c access.Caller, q Query) ([]*Device, error) {
	switch q.Status {
	case "", "online", "offline":
	default:
		return nil, apperr.Invalid("status", "Use online or offline.")
	}
	out := []*Device{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+columns+from+`
			WHERE ($1::uuid IS NULL OR d.organization_id = $1)
			  AND ($2::uuid IS NULL OR d.site_id = $2)
			  AND ($3 = '' OR strpos(lower(d.name), lower($3)) > 0 OR strpos(lower(d.hostname), lower($3)) > 0)
			  AND ($4 = '' OR (d.remote_online OR `+agentOnline+`) = ($4 = 'online'))
			ORDER BY lower(d.name), d.id LIMIT $5`,
			nullUUID(q.OrganizationID), nullUUID(q.SiteID), strings.TrimSpace(q.Search), q.Status, MaxList)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d, err := scan(rows)
			if err != nil {
				return err
			}
			if !c.Can(rbac.PermDeviceView, rbac.Site(d.OrganizationID, d.SiteID)) {
				continue
			}
			s.decorate(c, d)
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one device the caller can see.
func (s *Service) Get(ctx context.Context, c access.Caller, id uuid.UUID) (*Device, error) {
	d, err := Lookup(ctx, s.db, c, id)
	if err != nil {
		return nil, err
	}
	s.decorate(c, d)
	return d, nil
}

// Lookup reads one device the caller may view, without the per-caller
// actions. Other services use it to resolve a device before acting on it.
func Lookup(ctx context.Context, db *database.DB, c access.Caller, id uuid.UUID) (*Device, error) {
	var d *Device
	err := db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		d, err = scan(tx.QueryRow(ctx, `SELECT `+columns+from+` WHERE d.id = $1`, id))
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
	return d, nil
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
