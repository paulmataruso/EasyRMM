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
	Version string `json:"version"`
	Arch    string `json:"arch"`
	// SHA256 is the SHA-256 of the agent's executable as it reported it;
	// empty for agents too old to update themselves (ADR-0027).
	SHA256     string     `json:"sha256"`
	Online     bool       `json:"online"`
	LastSeenAt *time.Time `json:"lastSeenAt"`
	EnrolledAt time.Time  `json:"enrolledAt"`
	// Update is where the agent stands against the build the server serves
	// for its platform; nil when the server serves none.
	Update *AgentUpdate `json:"update"`

	// The update the server holds for the agent, if any.
	updateState, updateTarget string
}

// AgentUpdate is where a device's agent stands against the server's build
// (ADR-0027).
type AgentUpdate struct {
	// Status is one of the Update* constants.
	Status string `json:"status"`
	// Version is the version of the server's build, "" when unknown.
	Version string `json:"version"`
	// Attempts and Error describe failed attempts at this build.
	Attempts int    `json:"attempts"`
	Error    string `json:"error"`
	// Requested: someone asked for the update in the console.
	Requested bool `json:"requested"`
}

// Update statuses.
const (
	UpdateCurrent     = "current"     // runs the server's build
	UpdateAvailable   = "available"   // runs another build; no update planned
	UpdateQueued      = "queued"      // waits for its turn or its next attempt
	UpdateUpdating    = "updating"    // was told to update
	UpdateFailed      = "failed"      // failed every attempt; waits for someone to ask again
	UpdateUnsupported = "unsupported" // too old to update itself
)

// UpdateStatus classifies an agent from the SHA-256 of its executable, the
// SHA-256 of the server's build for its platform, and the state and target
// of the update the server holds for it ("" for none).
func UpdateStatus(agentSHA, buildSHA, state, target string) string {
	switch {
	case agentSHA == "":
		return UpdateUnsupported
	case agentSHA == buildSHA:
		return UpdateCurrent
	case target != buildSHA:
		return UpdateAvailable
	case state == "sent":
		return UpdateUpdating
	case state == "queued":
		return UpdateQueued
	case state == "failed":
		return UpdateFailed
	}
	return UpdateAvailable
}

// BuildLookup returns the SHA-256 and version of the agent build the
// server serves for a platform and architecture.
type BuildLookup func(platform, arch string) (sha256, version string, ok bool)

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
	// CanRunScripts: the caller holds script.run here and the device has
	// the EasyRMM agent (ADR-0017). Whether a script's shell suits the
	// device is checked per script.
	CanRunScripts bool `json:"canRunScripts"`
	// CanUpdateAgent: the caller holds device.edit here and the device has
	// the EasyRMM agent (ADR-0027).
	CanUpdateAgent bool `json:"canUpdateAgent"`

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
	d.enrolled_at, coalesce(d.agent_version, ''), coalesce(d.agent_arch, ''), d.agent_last_seen_at, ` + agentOnline + `,
	coalesce(d.agent_sha256, ''), coalesce(u.state, ''), coalesce(u.target_sha256, ''), coalesce(u.attempts, 0),
	coalesce(u.error, ''), coalesce(u.requested, false)`

const from = ` FROM devices d
	JOIN sites s ON s.id = d.site_id
	JOIN organizations o ON o.id = d.organization_id
	LEFT JOIN device_groups g ON g.id = d.device_group_id
	LEFT JOIN agent_updates u ON u.device_id = d.id`

func scan(row pgx.Row) (*Device, error) {
	var (
		d          Device
		enrolledAt *time.Time
		a          Agent
		u          AgentUpdate
	)
	err := row.Scan(&d.ID, &d.OrganizationID, &d.OrganizationName, &d.SiteID, &d.SiteName, &d.DeviceGroupID, &d.DeviceGroupName,
		&d.Name, &d.Hostname, &d.OSDescription, &d.Platform, &d.MeshNodeID, &d.RemoteOnline,
		&d.LastSeenAt, &d.CreatedAt, &d.UpdatedAt,
		&enrolledAt, &a.Version, &a.Arch, &a.LastSeenAt, &a.Online,
		&a.SHA256, &a.updateState, &a.updateTarget, &u.Attempts, &u.Error, &u.Requested)
	if err != nil {
		return nil, err
	}
	d.RemoteAgent = d.MeshNodeID != ""
	if enrolledAt != nil {
		a.EnrolledAt = *enrolledAt
		if a.updateState != "" {
			a.Update = &u // completed by Service.decorate
		}
		d.Agent = &a
	}
	d.Online = d.RemoteOnline || a.Online
	return &d, nil
}

// Service reads the device inventory.
type Service struct {
	db     *database.DB
	remote bool
	builds BuildLookup
}

// New returns a Service. remote says whether remote access is enabled on
// this server; without it no device offers remote sessions.
func New(db *database.DB, remote bool) *Service {
	return &Service{db: db, remote: remote}
}

// SetBuilds tells the service which agent builds the server serves, so
// devices show whether their agent is up to date (ADR-0027).
func (s *Service) SetBuilds(b BuildLookup) { s.builds = b }

func (s *Service) decorate(c access.Caller, d *Device) {
	r := rbac.Site(d.OrganizationID, d.SiteID)
	ok := s.remote && d.RemoteAgent
	d.CanDesktop = ok && c.Can(rbac.PermRemoteDesktop, r)
	d.CanTerminal = ok && c.Can(rbac.PermTerminal, r)
	d.CanFiles = ok && c.Can(rbac.PermFiles, r)
	d.CanRunScripts = d.Agent != nil && c.Can(rbac.PermScriptRun, r)
	d.CanUpdateAgent = d.Agent != nil && c.Can(rbac.PermDeviceEdit, r)
	s.updateStatus(d)
}

// updateStatus fills in the agent's update status against the server's
// build, or leaves it nil when the server serves none for the device.
func (s *Service) updateStatus(d *Device) {
	a := d.Agent
	if a == nil {
		return
	}
	var sha, version string
	ok := false
	if s.builds != nil {
		sha, version, ok = s.builds(d.Platform, a.Arch)
	}
	if !ok {
		a.Update = nil
		return
	}
	u := a.Update
	if u == nil || a.updateTarget != sha {
		u = &AgentUpdate{} // an update to an earlier build is moot
	}
	u.Status, u.Version = UpdateStatus(a.SHA256, sha, a.updateState, a.updateTarget), version
	if u.Status == UpdateCurrent || u.Status == UpdateUnsupported {
		u.Attempts, u.Error, u.Requested = 0, "", false
	}
	a.Update = u
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

// RecentConnection is a device the caller opened a remote session on.
type RecentConnection struct {
	Device *Device `json:"device"`
	// Kind is the kind of the latest session: desktop, terminal or files.
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
}

// MaxRecent bounds the recent connections listed.
const MaxRecent = 10

// RecentConnections lists the devices the calling user opened remote
// sessions on in the last 90 days, latest first, from the audit log: at most
// MaxRecent, and only devices the caller can still see, with what the caller
// may do on them now. Empty when remote access is off or the caller is not a
// user.
func (s *Service) RecentConnections(ctx context.Context, c access.Caller) ([]RecentConnection, error) {
	out := []RecentConnection{}
	if !s.remote || c.Principal == nil || c.Principal.UserID == uuid.Nil {
		return out, nil
	}
	type launch struct {
		at   time.Time
		kind string
	}
	var ids []uuid.UUID
	launches := map[uuid.UUID]launch{}
	// The caller's own audit entries: read without the caller's scope, which
	// may not include the audit log, and limited to the caller by actor.
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		ids, launches = nil, map[uuid.UUID]launch{}
		rows, err := tx.Query(ctx, `SELECT device_id, max(occurred_at), (array_agg(details->>'kind' ORDER BY occurred_at DESC, id DESC))[1]
			FROM audit_log
			WHERE actor_type = 'user' AND actor_id = $1 AND action = 'device.remote_session' AND outcome = 'success'
			  AND device_id IS NOT NULL AND occurred_at > now() - interval '90 days'
			GROUP BY device_id
			ORDER BY 2 DESC, 1
			LIMIT $2`, c.Principal.UserID, 3*MaxRecent)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				id   uuid.UUID
				l    launch
				kind *string
			)
			if err := rows.Scan(&id, &l.at, &kind); err != nil {
				return err
			}
			if kind != nil {
				l.kind = *kind
			}
			ids = append(ids, id)
			launches[id] = l
		}
		return rows.Err()
	})
	if err != nil || len(ids) == 0 {
		return out, err
	}
	found := map[uuid.UUID]*Device{}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		found = map[uuid.UUID]*Device{}
		rows, err := tx.Query(ctx, `SELECT `+columns+from+` WHERE d.id = ANY($1)`, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d, err := scan(rows)
			if err != nil {
				return err
			}
			found[d.ID] = d
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		d := found[id]
		if d == nil || !c.Can(rbac.PermDeviceView, rbac.Site(d.OrganizationID, d.SiteID)) {
			continue
		}
		s.decorate(c, d)
		l := launches[id]
		out = append(out, RecentConnection{Device: d, Kind: l.kind, At: l.at})
		if len(out) == MaxRecent {
			break
		}
	}
	return out, nil
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
