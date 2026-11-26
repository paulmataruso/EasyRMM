// Package devices is the inventory of managed endpoints: devices enrolled by
// the EasyRMM agent (ADR-0015) and devices discovered through MeshCentral
// (ADR-0014). It is available whether or not remote access is enabled.
package devices

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/audit"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/posture"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

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
	// Accepts is what the agent's build last said its polls accept, such as
	// job.pwsh (ADR-0064); nil when the build it runs has not said.
	Accepts []string `json:"accepts"`
	// PowerShell7 says whether its last inventory listed a usable
	// PowerShell 7; nil when the inventory listed no PowerShell installs
	// (an agent too old to look, or not Windows).
	PowerShell7 *bool `json:"powerShell7"`
	// PowerShell7Blocked says why a pwsh run fails there, without falling
	// back to Windows PowerShell, when the inventory listed no usable
	// PowerShell 7 but a blocked one (agentproto.PowerShellInstall.Blocked,
	// ADR-0064); empty otherwise.
	PowerShell7Blocked string `json:"powerShell7Blocked,omitempty"`

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
	// WaitingFor is the release's version while only signed builds are
	// handed out and none was signed from it yet (ADR-0049).
	WaitingFor string `json:"waitingFor,omitempty"`
}

// Update statuses.
const (
	UpdateCurrent     = "current"     // runs the server's build
	UpdateAvailable   = "available"   // runs another build; no update planned
	UpdateQueued      = "queued"      // waits for its turn or its next attempt
	UpdateUpdating    = "updating"    // was told to update
	UpdateFailed      = "failed"      // failed every attempt; waits for someone to ask again
	UpdateUnsupported = "unsupported" // too old to update itself
	UpdateWaiting     = "waiting"     // no build is handed out for it until one is signed (ADR-0049)
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

// ServedBuild is the agent build the server serves for a platform and
// architecture.
type ServedBuild struct {
	SHA256, Version string
	// WaitingFor is the release's version while only signed Windows builds
	// are handed out and none was signed from it (ADR-0049). SHA256 and
	// Version are then an older signed build's, or empty when there is none.
	WaitingFor string
}

// BuildLookup returns the agent build the server serves for a platform and
// architecture.
type BuildLookup func(org uuid.UUID, platform, arch string) (ServedBuild, bool)

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
	RemoteAgent  bool `json:"remoteAgent"`
	RemoteOnline bool `json:"remoteOnline"`
	// Remote says why remote access is not connected (ADR-0069); nil
	// without the EasyRMM agent.
	Remote     *RemoteStatus `json:"remote"`
	LastSeenAt *time.Time    `json:"lastSeenAt"`
	CreatedAt  time.Time     `json:"createdAt"`
	UpdatedAt  time.Time     `json:"updatedAt"`
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
	// CanReconnectRemote: the caller holds device.edit here, the device has
	// the EasyRMM agent, and this server runs remote access (ADR-0069).
	CanReconnectRemote bool `json:"canReconnectRemote"`
	// CanRepairPatching: the caller holds device.edit here, the device has
	// the EasyRMM agent, and its EasyPatch agent is linked to it (ADR-0069).
	CanRepairPatching bool `json:"canRepairPatching"`
	// CanRepairEasyRMM: the caller holds patch.manage here, the device has
	// the EasyRMM agent, and its EasyPatch agent is linked to it: the EasyPatch
	// agent can repair the EasyRMM agent (ADR-0069).
	CanRepairEasyRMM bool `json:"canRepairEasyRmm"`
	// patched: the device's organization is patched and its EasyPatch agent
	// is linked.
	patched bool
	// CanManageSoftware: the caller holds software.manage here and the
	// device has the EasyRMM agent on Windows or Linux (ADR-0028).
	CanManageSoftware bool `json:"canManageSoftware"`
	// CanCheckHardening: the caller holds script.run here and the device
	// has the EasyRMM agent on Linux or Windows (ADR-0051, ADR-0054).
	CanCheckHardening bool `json:"canCheckHardening"`
	// CanHarden: the caller holds device.harden here and the device has the
	// EasyRMM agent on Linux or Windows: it may apply and undo hardening (ADR-0051, ADR-0054).
	CanHarden bool `json:"canHarden"`
	// CanRemove: the caller may remove the device (ADR-0050).
	CanRemove bool `json:"canRemove"`
	// Removal is the device's removal while it waits for its agent, nil
	// when nobody asked for one.
	Removal *Removal `json:"removal"`
	// Hardening sums up what hardening jobs found on the device, nil until
	// one reported (ADR-0051).
	Hardening *HardeningSummary `json:"hardening"`
	// DiskHealth sums up its disks' health, nil while its agent has
	// reported none (ADR-0065).
	DiskHealth *DiskHealthSummary `json:"diskHealth"`
	// Posture is its security posture (ADR-0082): a word, a score and how
	// many controls fail or cannot be told. Nil for a device posture does
	// not cover (no EasyRMM agent, or neither Linux nor Windows).
	Posture *posture.Summary `json:"posture"`

	// MeshNodeID is MeshCentral's node identifier, empty without MeshAgent.
	MeshNodeID string `json:"-"`
}

// HardeningSummary is what the last hardening jobs found on a device: when
// the latest reported, and how many modules are in each state (ADR-0051).
// The device's Hardening tab has the detail.
type HardeningSummary struct {
	CheckedAt time.Time      `json:"checkedAt"`
	States    map[string]int `json:"states"`
}

// DiskHealthSummary is a device's disk health (ADR-0065, "A device's disk
// health"): its label, and how many of its disks show each state.
type DiskHealthSummary struct {
	// Label is the highest of the disks' states in the order failing,
	// warning, unknown, healthy; else unavailable if any disk is, else
	// unsupported.
	Label  string         `json:"label"`
	States map[string]int `json:"states"`
}

// Disk health filters of a device list (Query.DiskHealth): a label, or
// DiskNotReported. DiskUnavailable and DiskUnsupported find a device with
// any disk in that state, whatever its label.
const (
	DiskFailing     = "failing"
	DiskWarning     = "warning"
	DiskUnknown     = "unknown"
	DiskHealthy     = "healthy"
	DiskUnavailable = "unavailable"
	DiskUnsupported = "unsupported"
	// DiskNotReported: the device's agent has reported no disk health.
	DiskNotReported = "not_reported"
)

// Hardening filters of a device list (Query.Hardening).
const (
	// HardeningAttention: a module is not, or only partly, in place, was
	// left half applied, or failed.
	HardeningAttention = "attention"
	// HardeningInPlace: checked, and no module needs attention.
	HardeningInPlace = "in_place"
	// HardeningUnchecked: a Linux or Windows device with the EasyRMM agent that no
	// hardening job has reported on.
	HardeningUnchecked = "unchecked"
)

// ComplianceFailing is Query.Compliance's one value (ADR-0078, section 7): a
// computer with a stored compliance result that does not meet.
const ComplianceFailing = "failing"

// complianceFailingStates are the result states that do not meet.
var complianceFailingStates = []string{"not_in_place", "partly", "half_applied", "failed"}

// attentionStates are the module states HardeningAttention looks for, as
// the jobs package names them.
var attentionStates = []string{"partly", "not_in_place", "half_applied", "failed"}

// Removal is a device's removal waiting for its agent to uninstall itself
// (ADR-0050).
type Removal struct {
	RequestedAt time.Time `json:"requestedAt"`
	// SentAt is when a heartbeat answer first carried the instruction, nil
	// while the agent has not checked in since.
	SentAt *time.Time `json:"sentAt"`
	// ReportedAt and Error: the agent could not remove itself, and why.
	ReportedAt *time.Time `json:"reportedAt"`
	Error      string     `json:"error"`
}

// Query filters a device list.
type Query struct {
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	// GroupID lists one device group's devices.
	GroupID uuid.UUID
	// Ungrouped lists only the devices in no group.
	Ungrouped bool
	Search    string
	// Status is "", "online" or "offline".
	Status string
	// Hardening is "" or one of the Hardening* filters.
	Hardening string
	// DiskHealth is "" or one of the Disk* filters.
	DiskHealth string
	// Compliance is "" or ComplianceFailing.
	Compliance string
	// Posture is "" or one of posture.Filter*: the devices whose security
	// posture meets its policy, does not, or cannot be told (ADR-0082).
	Posture string
}

// maxPostureScan bounds how many devices a posture filter looks through before
// it keeps MaxList of them.
const maxPostureScan = 100000

// MaxList bounds one list response.
const MaxList = 5000

// agentOnline is the SQL form of Agent.Online: the device's agent has not
// missed three of its own heartbeats (agent_online_until, set from the
// interval the agent uses; ADR-0058).
const agentOnline = "coalesce(d.agent_online_until > now(), false)"

var columns = `d.id, d.organization_id, o.name, d.site_id, s.name, d.device_group_id, coalesce(g.name, ''),
	d.name, d.hostname, d.os_description, d.platform, coalesce(d.mesh_node_id, ''), d.remote_online,
	greatest(d.last_seen_at, d.agent_last_seen_at), d.created_at, d.updated_at,
	d.enrolled_at, coalesce(d.agent_version, ''), coalesce(d.agent_arch, ''), d.agent_last_seen_at, ` + agentOnline + `,
	coalesce(d.agent_sha256, ''), coalesce(u.state, ''), coalesce(u.target_sha256, ''), coalesce(u.attempts, 0),
	coalesce(u.error, ''), coalesce(u.requested, false),
	rm.requested_at, rm.sent_at, rm.reported_at, coalesce(rm.error, ''),
	hc.checked_at, coalesce(hs.states, '{}'),
	CASE WHEN d.agent_accepts_build IS NOT DISTINCT FROM coalesce(d.agent_sha256, d.agent_version) THEN d.agent_accepts END,
	d.powershell7, coalesce(d.powershell7_blocked, ''), ds.label, coalesce(ds.states, '{}'),
	d.meshagent_state, d.meshagent_state_at, d.remote_changed_at, d.mesh_wrong_group,
	(EXISTS (SELECT 1 FROM easypatch_devices ep WHERE ep.device_id = d.id AND ep.state = 'linked')
		AND EXISTS (SELECT 1 FROM easypatch_organizations eo WHERE eo.organization_id = d.organization_id))`

// from joins what the columns read. hs counts the device's hardening
// modules by state, as {"in_place": 9, "partly": 1}; ds its disks by the
// state the console shows, with the device's label (NULL without disks).
const from = ` FROM devices d
	JOIN sites s ON s.id = d.site_id
	JOIN organizations o ON o.id = d.organization_id
	LEFT JOIN device_groups g ON g.id = d.device_group_id
	LEFT JOIN agent_updates u ON u.device_id = d.id
	LEFT JOIN device_removals rm ON rm.device_id = d.id
	LEFT JOIN device_hardening_checks hc ON hc.device_id = d.id
	LEFT JOIN LATERAL (
		SELECT jsonb_object_agg(x.state, x.n) AS states
		FROM (SELECT h.state, count(*) AS n FROM device_hardening h WHERE h.device_id = d.id GROUP BY h.state) x
	) hs ON true
	LEFT JOIN LATERAL (
		SELECT jsonb_object_agg(x.state, x.n) AS states, CASE
				WHEN bool_or(x.state = 'failing') THEN 'failing'
				WHEN bool_or(x.state = 'warning') THEN 'warning'
				WHEN bool_or(x.state = 'unknown') THEN 'unknown'
				WHEN bool_or(x.state = 'healthy') THEN 'healthy'
				WHEN bool_or(x.state = 'unavailable') THEN 'unavailable'
				WHEN bool_or(x.state = 'unsupported') THEN 'unsupported'
			END AS label
		FROM (SELECT easyrmm_disk_state(h.missing_since, h.state, h.judged_level, h.judged_at) AS state, count(*) AS n
			FROM device_disk_health h WHERE h.device_id = d.id GROUP BY 1) x
	) ds ON true`

func scan(row pgx.Row) (*Device, error) {
	var (
		d          Device
		enrolledAt *time.Time
		a          Agent
		u          AgentUpdate
		rm         Removal
		asked      *time.Time
		checkedAt  *time.Time
		states     map[string]int
		diskLabel  *string
		diskStates map[string]int
		ri         remoteInput
	)
	err := row.Scan(&d.ID, &d.OrganizationID, &d.OrganizationName, &d.SiteID, &d.SiteName, &d.DeviceGroupID, &d.DeviceGroupName,
		&d.Name, &d.Hostname, &d.OSDescription, &d.Platform, &d.MeshNodeID, &d.RemoteOnline,
		&d.LastSeenAt, &d.CreatedAt, &d.UpdatedAt,
		&enrolledAt, &a.Version, &a.Arch, &a.LastSeenAt, &a.Online,
		&a.SHA256, &a.updateState, &a.updateTarget, &u.Attempts, &u.Error, &u.Requested,
		&asked, &rm.SentAt, &rm.ReportedAt, &rm.Error,
		&checkedAt, &states, &a.Accepts, &a.PowerShell7, &a.PowerShell7Blocked, &diskLabel, &diskStates,
		&ri.state, &ri.stateAt, &ri.changedAt, &ri.wrongGroup, &d.patched)
	if err != nil {
		return nil, err
	}
	d.RemoteAgent = d.MeshNodeID != ""
	if asked != nil {
		rm.RequestedAt = *asked
		d.Removal = &rm
	}
	if checkedAt != nil {
		d.Hardening = &HardeningSummary{CheckedAt: *checkedAt, States: states}
	}
	if diskLabel != nil {
		d.DiskHealth = &DiskHealthSummary{Label: *diskLabel, States: diskStates}
	}
	if enrolledAt != nil {
		a.EnrolledAt = *enrolledAt
		if a.updateState != "" {
			a.Update = &u // completed by Service.decorate
		}
		d.Agent = &a
	}
	d.Online = d.RemoteOnline || a.Online
	if enrolledAt != nil {
		ri.remoteOnline, ri.agentOnline, ri.enrolledAt = d.RemoteOnline, a.Online, enrolledAt
		d.Remote = remoteStatus(ri)
	}
	return &d, nil
}

// Service reads the device inventory.
type Service struct {
	db           *database.DB
	remote       bool
	builds       BuildLookup
	audit        *audit.Logger
	moved        func()
	movedDevices func([]uuid.UUID)
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
	d.CanReconnectRemote = s.remote && d.Agent != nil && c.Can(rbac.PermDeviceEdit, r)
	d.CanRepairPatching = d.patched && d.Agent != nil && c.Can(rbac.PermDeviceEdit, r)
	d.CanRepairEasyRMM = d.patched && d.Agent != nil && c.Can(rbac.PermPatchManage, r)
	d.CanManageSoftware = d.Agent != nil && (d.Platform == "windows" || d.Platform == "linux") && c.Can(rbac.PermSoftwareManage, r)
	d.CanCheckHardening = d.Agent != nil && (d.Platform == "linux" || d.Platform == "windows") && c.Can(rbac.PermScriptRun, r)
	d.CanHarden = d.Agent != nil && (d.Platform == "linux" || d.Platform == "windows") && c.Can(rbac.PermDeviceHarden, r)
	d.CanRemove = c.Can(rbac.PermDeviceRetire, r)
	s.updateStatus(d)
}

// updateStatus fills in the agent's update status against the server's
// build, or leaves it nil when the server serves none for the device.
func (s *Service) updateStatus(d *Device) {
	a := d.Agent
	if a == nil {
		return
	}
	var b ServedBuild
	ok := false
	if s.builds != nil {
		b, ok = s.builds(d.OrganizationID, d.Platform, a.Arch)
	}
	if !ok {
		a.Update = nil
		return
	}
	if b.SHA256 == "" {
		a.Update = &AgentUpdate{Status: UpdateWaiting, WaitingFor: b.WaitingFor}
		return
	}
	u := a.Update
	if u == nil || a.updateTarget != b.SHA256 {
		u = &AgentUpdate{} // an update to an earlier build is moot
	}
	u.Status, u.Version, u.WaitingFor = UpdateStatus(a.SHA256, b.SHA256, a.updateState, a.updateTarget), b.Version, b.WaitingFor
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
	switch q.Hardening {
	case "", HardeningAttention, HardeningInPlace, HardeningUnchecked:
	default:
		return nil, apperr.Invalid("hardening", "Use attention, in_place or unchecked.")
	}
	if q.Compliance != "" && q.Compliance != ComplianceFailing {
		return nil, apperr.Invalid("compliance", "Use failing.")
	}
	if !posture.ValidFilter(q.Posture) {
		return nil, apperr.Invalid("posture", "Use meets, does_not_meet or cannot_tell.")
	}
	limit := MaxList
	if q.Posture != "" {
		limit = maxPostureScan
	}
	switch q.DiskHealth {
	case "", DiskFailing, DiskWarning, DiskUnknown, DiskHealthy, DiskUnavailable, DiskUnsupported, DiskNotReported:
	default:
		return nil, apperr.Invalid("diskHealth", "Use failing, warning, unknown, healthy, unavailable, unsupported or not_reported.")
	}
	out := []*Device{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+columns+from+`
			WHERE NOT d.quick_assist -- Quick Assist devices live in their own section (ADR-0080)
			  AND ($1::uuid IS NULL OR d.organization_id = $1)
			  AND ($2::uuid IS NULL OR d.site_id = $2)
			  AND ($9::uuid IS NULL OR d.device_group_id = $9)
			  AND (NOT $10 OR d.device_group_id IS NULL)
			  AND ($3 = '' OR strpos(lower(d.name), lower($3)) > 0 OR strpos(lower(d.hostname), lower($3)) > 0)
			  AND ($4 = '' OR (d.remote_online OR `+agentOnline+`) = ($4 = 'online'))
			  AND CASE $6
				WHEN 'attention' THEN coalesce(hs.states ?| $7::text[], false)
				WHEN 'in_place' THEN hc.device_id IS NOT NULL AND NOT coalesce(hs.states ?| $7::text[], false)
				WHEN 'unchecked' THEN d.platform IN ('linux', 'windows') AND d.enrolled_at IS NOT NULL AND hc.device_id IS NULL
				ELSE true END
			  AND ($11 = '' OR EXISTS (SELECT 1 FROM compliance_results cr WHERE cr.device_id = d.id AND cr.state = ANY ($12::text[])))
			  AND CASE $8
				WHEN '' THEN true
				WHEN 'not_reported' THEN ds.label IS NULL
				WHEN 'unavailable' THEN coalesce(ds.states ? $8, false)
				WHEN 'unsupported' THEN coalesce(ds.states ? $8, false)
				ELSE ds.label IS NOT DISTINCT FROM $8 END
			ORDER BY lower(d.name), d.id LIMIT $5`,
			nullUUID(q.OrganizationID), nullUUID(q.SiteID), strings.TrimSpace(q.Search), q.Status, limit, q.Hardening, attentionStates,
			q.DiskHealth, nullUUID(q.GroupID), q.Ungrouped, q.Compliance, complianceFailingStates)
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
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		return s.attachPosture(ctx, tx, &out, q.Posture)
	})
	return out, err
}

// attachPosture sets each device's posture and, with a filter, keeps the
// devices that match it, at most MaxList of them (ADR-0082).
func (s *Service) attachPosture(ctx context.Context, tx pgx.Tx, list *[]*Device, filter string) error {
	refs := make([]posture.Ref, 0, len(*list))
	for _, d := range *list {
		refs = append(refs, posture.Ref{ID: d.ID, Org: d.OrganizationID, Platform: d.Platform, Enrolled: d.Agent != nil})
	}
	m, err := posture.Load(ctx, tx, refs, time.Now())
	if err != nil {
		return err
	}
	kept := (*list)[:0]
	for _, d := range *list {
		p := m[d.ID]
		if p != nil {
			d.Posture = p.Summary()
		}
		if posture.Matches(p, filter) && len(kept) < MaxList {
			kept = append(kept, d)
		}
	}
	*list = kept
	return nil
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
