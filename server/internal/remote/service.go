package remote

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
)

// Mesh is the part of the MeshCentral client the service uses.
type Mesh interface {
	Connected() bool
	Meshes(ctx context.Context) ([]meshcentral.Mesh, error)
	CreateMesh(ctx context.Context, name, desc string) (string, error)
	EditMesh(ctx context.Context, meshID, name, desc string) error
	DeleteMesh(ctx context.Context, meshID string) error
	Users(ctx context.Context) ([]meshcentral.User, error)
	AddUser(ctx context.Context, name, realName string, siteRights uint32) error
	EditUser(ctx context.Context, userID, realName string, siteRights uint32) error
	DeleteUser(ctx context.Context, userID string) error
	SetMeshRights(ctx context.Context, meshID, userID string, rights uint32) error
	RemoveMeshUser(ctx context.Context, meshID, userID string) error
	Nodes(ctx context.Context) ([]meshcentral.Node, error)
	RemoveDevice(ctx context.Context, nodeID string) error
	MoveDevice(ctx context.Context, nodeID, meshID string) error
	UninstallAgent(ctx context.Context, nodeID string) error
}

// Config configures the service.
type Config struct {
	// MeshURL is the public MeshCentral origin (https://mesh.rmm.example.com).
	MeshURL *url.URL
	// LoginKey is the shared login-cookie key.
	LoginKey []byte
	// Interval between full reconciliations (default 5 minutes).
	Interval time.Duration
	// DiscoveryGrace is how long a MeshCentral node in an EasyRMM group that
	// no device claims waits before it is recorded as a discovered device.
	// An EasyRMM agent that installs MeshAgent reports the node with its next
	// heartbeat; recording the node before that would list the machine twice
	// until the two are merged. Zero records a node at once. The server uses
	// DefaultDiscoveryGrace.
	DiscoveryGrace time.Duration
}

// DefaultDiscoveryGrace is two agent heartbeats: the time an EasyRMM agent
// has to report the MeshAgent node it installed before MeshCentral's report of
// the node is taken for a machine without one.
const DefaultDiscoveryGrace = 2 * time.Minute

// Service keeps MeshCentral in step with EasyRMM and launches sessions.
type Service struct {
	db    *database.DB
	audit *audit.Logger
	mesh  Mesh
	cfg   Config
	log   *slog.Logger
	now   func() time.Time

	full    chan struct{}
	devices chan struct{}

	syncMu sync.Mutex // one reconciliation at a time
	// Held by syncMu: nodes no device claims yet, with when a sync first saw
	// them, and the refresh due when the first of them may be recorded.
	unclaimed map[string]time.Time
	recheck   *time.Timer

	statusMu sync.Mutex
	status   Status
}

// Status describes the integration's health.
type Status struct {
	// Address is the public MeshCentral origin agents and sessions use.
	Address       string     `json:"address"`
	Connected     bool       `json:"connected"`
	LastSyncAt    *time.Time `json:"lastSyncAt,omitempty"`
	LastError     string     `json:"lastError,omitempty"`
	LastErrorAt   *time.Time `json:"lastErrorAt,omitempty"`
	Devices       int        `json:"devices"`
	DevicesOnline int        `json:"devicesOnline"`
}

// New builds the service.
func New(db *database.DB, auditLog *audit.Logger, mesh Mesh, cfg Config, log *slog.Logger) *Service {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{
		db: db, audit: auditLog, mesh: mesh, cfg: cfg, log: log, now: time.Now,
		full: make(chan struct{}, 1), devices: make(chan struct{}, 1),
		unclaimed: map[string]time.Time{},
	}
}

// Changed requests a full reconciliation soon, after sites, organizations,
// users or role assignments change. It never blocks.
func (s *Service) Changed() {
	select {
	case s.full <- struct{}{}:
	default:
	}
}

// DevicesChanged requests a device refresh soon.
func (s *Service) DevicesChanged() {
	select {
	case s.devices <- struct{}{}:
	default:
	}
}

// HandleEvent reacts to MeshCentral events: any device event (added,
// removed, renamed, connected, disconnected) schedules a device refresh.
// MeshCentral 1.3.1 sends connection changes as "nodeconnect" without an
// etype, so those are matched by action.
func (s *Service) HandleEvent(ev meshcentral.Event) {
	if ev.Type != "node" && ev.Action != "nodeconnect" {
		return
	}
	s.DevicesChanged()
}

// Status reports the integration's health.
func (s *Service) Status(ctx context.Context) Status {
	s.statusMu.Lock()
	st := s.status
	s.statusMu.Unlock()
	st.Connected = s.mesh.Connected()
	if s.cfg.MeshURL != nil {
		st.Address = s.cfg.MeshURL.String()
	}
	_ = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE remote_online) FROM devices WHERE mesh_node_id IS NOT NULL`).
			Scan(&st.Devices, &st.DevicesOnline)
	})
	return st
}

func (s *Service) recordResult(err error) {
	now := s.now()
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if err != nil {
		s.status.LastError, s.status.LastErrorAt = err.Error(), &now
		return
	}
	s.status.LastSyncAt = &now
	s.status.LastError, s.status.LastErrorAt = "", nil
}

// Run reconciles on start, whenever something changes, and periodically,
// until ctx ends. Changes are debounced so bursts cause one pass.
func (s *Service) Run(ctx context.Context) {
	tick := time.NewTicker(s.cfg.Interval)
	defer tick.Stop()
	s.Changed()
	for {
		full := false
		select {
		case <-ctx.Done():
			return
		case <-s.full:
			full = true
		case <-s.devices:
		case <-tick.C:
			full = true
		}
		// Debounce: absorb further requests for a moment.
		select {
		case <-ctx.Done():
			return
		case <-time.After(750 * time.Millisecond):
		}
		select {
		case <-s.full:
			full = true
		default:
		}
		select {
		case <-s.devices:
		default:
		}
		if !s.mesh.Connected() {
			continue // the client's OnReady hook calls Changed when it connects
		}
		var err error
		if full {
			err = s.Reconcile(ctx)
		} else {
			err = s.SyncDevices(ctx)
		}
		if err != nil && ctx.Err() == nil {
			s.log.Error("remote access: synchronizing with MeshCentral failed", "error", err)
		}
	}
}

// Reconcile makes MeshCentral's groups, accounts and rights match EasyRMM
// and refreshes devices.
func (s *Service) Reconcile(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	err := s.reconcile(ctx)
	s.recordResult(err)
	return err
}

func (s *Service) reconcile(ctx context.Context) error {
	want, err := loadDesired(ctx, s.db)
	if err != nil {
		return err
	}
	mapping, err := s.loadMapping(ctx)
	if err != nil {
		return err
	}
	meshes, err := s.mesh.Meshes(ctx)
	if err != nil {
		return fmt.Errorf("listing device groups: %w", err)
	}
	mp := planMeshes(want.sites, meshes, mapping)
	var errs []error
	for _, site := range mp.stale {
		if err := s.forgetMesh(ctx, site); err != nil {
			errs = append(errs, err)
		}
	}
	for site, meshID := range mp.adopt {
		if err := s.recordMesh(ctx, site, meshID); err != nil {
			errs = append(errs, err)
		}
	}
	for _, site := range mp.create {
		id, err := s.mesh.CreateMesh(ctx, site.meshName(), site.meshDesc())
		if err != nil {
			errs = append(errs, fmt.Errorf("creating group for site %s: %w", site.ID, err))
			continue
		}
		if err := s.recordMesh(ctx, site.ID, id); err != nil {
			errs = append(errs, err)
			continue
		}
		mp.mesh[site.ID], mp.known[id] = id, site.ID
		s.log.Info("remote access: created MeshCentral device group", "site_id", site.ID)
	}
	for _, r := range mp.rename {
		if err := s.mesh.EditMesh(ctx, r.MeshID, r.Name, r.Desc); err != nil {
			errs = append(errs, fmt.Errorf("renaming group %s: %w", r.MeshID, err))
		}
	}
	for _, id := range mp.remove {
		if err := s.mesh.DeleteMesh(ctx, id); err != nil {
			errs = append(errs, fmt.Errorf("deleting group %s: %w", id, err))
		} else {
			s.log.Info("remote access: deleted MeshCentral device group of a removed site", "mesh_id", id)
		}
	}

	accounts, err := s.mesh.Users(ctx)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("listing accounts: %w", err))...)
	}
	up := planUsers(want.users, accounts)
	for _, u := range up.add {
		if err := s.mesh.AddUser(ctx, accountName(u.ID), realName(u), meshcentral.TechnicianSiteRights); err != nil && !meshcentral.IsAlreadyExists(err) {
			errs = append(errs, fmt.Errorf("creating account for user %s: %w", u.ID, err))
		}
	}
	for _, u := range up.edit {
		if err := s.mesh.EditUser(ctx, accountID(u.ID), realName(u), meshcentral.TechnicianSiteRights); err != nil {
			errs = append(errs, fmt.Errorf("updating account for user %s: %w", u.ID, err))
		}
	}
	for _, id := range up.remove {
		// Deleting the account closes its MeshCentral sessions too.
		if err := s.mesh.DeleteUser(ctx, id); err != nil && !meshcentral.IsUnknown(err) {
			errs = append(errs, fmt.Errorf("deleting account %s: %w", id, err))
		}
	}

	// Re-read groups: links changed with the accounts above.
	meshes, err = s.mesh.Meshes(ctx)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("listing device groups: %w", err))...)
	}
	for _, c := range planRights(want.users, meshes, mp.known) {
		var err error
		if c.Rights == 0 {
			err = s.mesh.RemoveMeshUser(ctx, c.MeshID, c.UserID)
		} else {
			err = s.mesh.SetMeshRights(ctx, c.MeshID, c.UserID, c.Rights)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("setting rights of %s on %s: %w", c.UserID, c.MeshID, err))
		}
	}
	if err := s.syncDevices(ctx, mp.known); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (s *Service) loadMapping(ctx context.Context) (map[uuid.UUID]string, error) {
	out := map[uuid.UUID]string{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT site_id, mesh_id FROM mesh_sites`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var site uuid.UUID
			var mesh string
			if err := rows.Scan(&site, &mesh); err != nil {
				return err
			}
			out[site] = mesh
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("loading device group mapping: %w", err)
	}
	return out, nil
}

func (s *Service) recordMesh(ctx context.Context, siteID uuid.UUID, meshID string) error {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO mesh_sites (site_id, organization_id, mesh_id, synced_name)
			SELECT id, organization_id, $2, name FROM sites WHERE id = $1
			ON CONFLICT (site_id) DO UPDATE SET mesh_id = EXCLUDED.mesh_id`, siteID, meshID)
		return err
	})
	if err != nil {
		return fmt.Errorf("recording group of site %s: %w", siteID, err)
	}
	return nil
}

func (s *Service) forgetMesh(ctx context.Context, siteID uuid.UUID) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM mesh_sites WHERE site_id = $1`, siteID)
		return err
	})
}

// SyncDevices refreshes devices from MeshCentral.
func (s *Service) SyncDevices(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	mapping, err := s.loadMapping(ctx)
	if err != nil {
		return err
	}
	known := map[string]uuid.UUID{}
	for site, mesh := range mapping {
		known[mesh] = site
	}
	return s.syncDevices(ctx, known)
}

// syncDevices upserts a device for every MeshCentral node in an EasyRMM
// group and removes devices whose node is gone.
func (s *Service) syncDevices(ctx context.Context, known map[string]uuid.UUID) error {
	nodes, err := s.mesh.Nodes(ctx)
	if err != nil {
		return fmt.Errorf("listing devices: %w", err)
	}
	// Empty, not nil: a NULL array would match nothing in the deletes below.
	present, sites, types, online := []string{}, []uuid.UUID{}, []int32{}, []bool{}
	for _, n := range nodes {
		if site, ok := known[n.MeshID]; ok {
			present = append(present, n.ID)
			sites = append(sites, site)
			types = append(types, int32(n.Agent.Type)) //nolint:gosec // MeshCentral agent types are small numbers
			online = append(online, n.AgentConnected())
		}
	}
	now := s.now()
	var (
		waiting map[string]time.Time
		soonest time.Duration
		retired map[string]retiredNode
		doomed  []retiredNode
		moves   []nodeMove
	)
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		waiting, soonest = map[string]time.Time{}, 0
		recorded, err := s.recordedNodes(ctx, tx, present)
		if err != nil {
			return err
		}
		if retired, err = retiredNodes(ctx, tx, present); err != nil {
			return err
		}
		doomed = doomed[:0]
		// Enrolled devices (ADR-0015) keep the facts their EasyRMM agent
		// reports; MeshCentral only says whether MeshAgent is connected. A
		// link to a node in another site's group is refused: the node id an
		// agent reports is not proof that the node is that device.
		// The exception is a device moved to its site whose node is still in
		// the group of the site it came from: the node follows below
		// (ADR-0069).
		if _, err := tx.Exec(ctx, `
			UPDATE devices d SET mesh_from_site_id = NULL
			FROM unnest($1::text[], $2::uuid[]) AS n(node, site)
			WHERE d.mesh_node_id = n.node AND d.mesh_from_site_id IS NOT NULL AND d.site_id = n.site`,
			present, sites); err != nil {
			return fmt.Errorf("settling moved devices: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE devices d SET mesh_node_id = NULL, mesh_agent_type = NULL, remote_online = false, mesh_wrong_group = true
			FROM unnest($1::text[], $2::uuid[]) AS n(node, site)
			WHERE d.mesh_node_id = n.node AND d.agent_public_key IS NOT NULL AND d.site_id <> n.site
			  AND d.mesh_from_site_id IS DISTINCT FROM n.site`,
			present, sites); err != nil {
			return fmt.Errorf("unlinking devices: %w", err)
		}
		pending, err := tx.Query(ctx, `
			SELECT d.id, d.mesh_node_id, d.site_id
			FROM devices d JOIN unnest($1::text[], $2::uuid[]) AS n(node, site) ON d.mesh_node_id = n.node
			WHERE d.agent_public_key IS NOT NULL AND d.mesh_from_site_id = n.site AND d.site_id <> n.site`,
			present, sites)
		if err != nil {
			return fmt.Errorf("finding moved devices: %w", err)
		}
		moves = moves[:0]
		for pending.Next() {
			var m nodeMove
			if err := pending.Scan(&m.device, &m.node, &m.site); err != nil {
				pending.Close()
				return err
			}
			moves = append(moves, m)
		}
		pending.Close()
		if err := pending.Err(); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE devices d SET mesh_agent_type = n.type, remote_online = n.online, mesh_wrong_group = false,
			    last_seen_at = CASE WHEN n.online OR d.remote_online THEN now() ELSE d.last_seen_at END
			FROM unnest($1::text[], $2::int[], $3::bool[]) AS n(node, type, online)
			WHERE d.mesh_node_id = n.node AND d.agent_public_key IS NOT NULL
			  AND ((d.mesh_agent_type, d.remote_online) IS DISTINCT FROM (n.type, n.online) OR d.mesh_wrong_group)`,
			present, types, online); err != nil {
			return fmt.Errorf("updating enrolled devices: %w", err)
		}
		for _, n := range nodes {
			site, ok := known[n.MeshID]
			if !ok {
				continue
			}
			if !recorded[n.ID] && s.cfg.DiscoveryGrace > 0 {
				first, seen := s.unclaimed[n.ID]
				if !seen {
					first = now
				}
				if wait := first.Add(s.cfg.DiscoveryGrace).Sub(now); wait > 0 {
					// Not yet: the agent that installed MeshAgent may claim it.
					waiting[n.ID] = first
					if soonest == 0 || wait < soonest {
						soonest = wait
					}
					continue
				}
			}
			if r, ok := retired[n.ID]; ok {
				// A removed device's MeshAgent came back, or its node is not
				// removed yet: no discovered device (ADR-0050).
				r.connected = n.AgentConnected()
				doomed = append(doomed, r)
				continue
			}
			hostname := n.OSName
			if hostname == "" {
				hostname = n.Name
			}
			name := n.Name
			if name == "" {
				name = hostname
			}
			if name == "" {
				name = "Unnamed device"
			}
			// Discovered devices follow MeshCentral; the conflict update skips
			// enrolled ones, handled above.
			_, err := tx.Exec(ctx, `
				INSERT INTO devices (organization_id, site_id, name, hostname, os_description, platform,
				                     mesh_node_id, mesh_agent_type, remote_online, last_seen_at)
				SELECT s.organization_id, s.id, $2, $3, $4, $5, $6, $7, $8, CASE WHEN $8 THEN now() END
				FROM sites s WHERE s.id = $1
				ON CONFLICT (mesh_node_id) DO UPDATE SET
				    organization_id = EXCLUDED.organization_id,
				    site_id = EXCLUDED.site_id,
				    device_group_id = CASE WHEN devices.site_id = EXCLUDED.site_id THEN devices.device_group_id END,
				    name = EXCLUDED.name,
				    hostname = EXCLUDED.hostname,
				    os_description = EXCLUDED.os_description,
				    platform = EXCLUDED.platform,
				    mesh_agent_type = EXCLUDED.mesh_agent_type,
				    remote_online = EXCLUDED.remote_online,
				    last_seen_at = CASE WHEN EXCLUDED.remote_online OR devices.remote_online THEN now() ELSE devices.last_seen_at END
				WHERE devices.agent_public_key IS NULL
				  AND (devices.organization_id, devices.site_id, devices.name, devices.hostname, devices.os_description,
				       devices.platform, devices.mesh_agent_type, devices.remote_online)
				   IS DISTINCT FROM (EXCLUDED.organization_id, EXCLUDED.site_id, EXCLUDED.name, EXCLUDED.hostname,
				       EXCLUDED.os_description, EXCLUDED.platform, EXCLUDED.mesh_agent_type, EXCLUDED.remote_online)`,
				site, truncateRunes(name, 255), truncateRunes(hostname, 255), truncateRunes(n.OSDesc, 500),
				platformOf(n.Agent.Type), n.ID, n.Agent.Type, n.AgentConnected())
			if err != nil {
				return fmt.Errorf("recording device %s: %w", n.ID, err)
			}
		}
		// A node MeshCentral no longer has: a discovered device goes with it,
		// an enrolled one only loses its remote-access link.
		if _, err := tx.Exec(ctx, `
			UPDATE devices SET mesh_node_id = NULL, mesh_agent_type = NULL, remote_online = false
			WHERE agent_public_key IS NOT NULL AND mesh_node_id IS NOT NULL AND NOT (mesh_node_id = ANY ($1))`, present); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM devices WHERE agent_public_key IS NULL AND mesh_node_id IS NOT NULL AND NOT (mesh_node_id = ANY ($1))`, present)
		return err
	})
	if err != nil {
		return err
	}
	s.moveNodes(ctx, moves, known)
	if wait := s.removeRetired(ctx, doomed); wait > 0 && (soonest == 0 || wait < soonest) {
		soonest = wait
	}
	// Claimed, recorded and vanished nodes are forgotten: a node that comes
	// back waits again.
	s.unclaimed = waiting
	if s.recheck != nil {
		s.recheck.Stop()
		s.recheck = nil
	}
	if soonest > 0 {
		s.recheck = time.AfterFunc(soonest, s.DevicesChanged)
	}
	return nil
}

// nodeMove is a device whose node is to move to its site's device group.
type nodeMove struct {
	device uuid.UUID
	node   string
	site   uuid.UUID
}

// moveNodes moves the nodes of devices moved to another site into their new
// site's device group (ADR-0069). A node that cannot be moved now stays
// pending, and the next sync tries again.
func (s *Service) moveNodes(ctx context.Context, moves []nodeMove, known map[string]uuid.UUID) {
	meshOf := make(map[uuid.UUID]string, len(known))
	for mesh, site := range known {
		meshOf[site] = mesh
	}
	moved := false
	for _, m := range moves {
		mesh, ok := meshOf[m.site]
		if !ok {
			s.log.Warn("remote access: the new site of a moved device has no device group yet", "device_id", m.device, "site_id", m.site)
			continue
		}
		if err := s.mesh.MoveDevice(ctx, m.node, mesh); err != nil {
			s.log.Warn("remote access: moving a device's node failed; it stays pending", "error", err, "device_id", m.device)
			continue
		}
		moved = true
		s.log.Info("remote access: moved a device to its new site's device group", "device_id", m.device, "site_id", m.site)
	}
	if moved {
		// The next sync sees the nodes in their groups and settles the devices.
		s.DevicesChanged()
	}
}

// Removed devices' nodes (ADR-0050).
const (
	// RetiredAttemptGap is the least time between two attempts on one node.
	RetiredAttemptGap = time.Minute
	// RetiredUninstalls is how many times a connected MeshAgent is asked to
	// uninstall itself before its node is removed regardless.
	RetiredUninstalls = 3
	// RetiredReturnGap is the least time between two removals of a node that
	// came back: its MeshAgent did not uninstall itself, typically because
	// it does not run as the service MeshCentral installs (EasyRMM's own
	// runs as easyrmm-meshagent; the EasyRMM agent removes that one). It
	// is not asked again; MeshCentral forgets it once an hour.
	RetiredReturnGap = time.Hour
)

// retiredNode is a node of a removed device that MeshCentral still lists.
type retiredNode struct {
	node       string
	device     uuid.UUID
	attemptAt  *time.Time
	uninstalls int
	connected  bool
	// returned says MeshCentral removed the node once already.
	returned bool
	// windows: never sent uninstallagent (ADR-0071).
	windows bool
}

// retiredNodes returns the nodes among nodes that belong to devices removed
// in the last RetiredFor, and that no device holds since.
func retiredNodes(ctx context.Context, tx pgx.Tx, nodes []string) (map[string]retiredNode, error) {
	rows, err := tx.Query(ctx, `SELECT r.mesh_node_id, r.device_id, r.mesh_attempt_at, r.mesh_uninstalls, r.mesh_removed_at IS NOT NULL, r.platform = 'windows' FROM retired_devices r
		WHERE r.mesh_node_id = ANY ($1) AND r.expires_at > now()
		  AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.mesh_node_id = r.mesh_node_id)`, nodes)
	if err != nil {
		return nil, fmt.Errorf("listing removed devices' nodes: %w", err)
	}
	defer rows.Close()
	out := map[string]retiredNode{}
	for rows.Next() {
		var r retiredNode
		if err := rows.Scan(&r.node, &r.device, &r.attemptAt, &r.uninstalls, &r.returned, &r.windows); err != nil {
			return nil, err
		}
		out[r.node] = r
	}
	return out, rows.Err()
}

// removeRetired has the MeshAgents of removed devices uninstall themselves
// while connected, then removes their nodes, at most once per node every
// RetiredAttemptGap, or RetiredReturnGap for a node that came back. It
// returns when the next attempt is due, zero for none. Failures are
// recorded on the removed device and tried again.
func (s *Service) removeRetired(ctx context.Context, nodes []retiredNode) time.Duration {
	var next time.Duration
	for _, r := range nodes {
		gap := RetiredAttemptGap
		if r.returned {
			gap = RetiredReturnGap
		}
		if r.attemptAt != nil {
			if wait := r.attemptAt.Add(gap).Sub(s.now()); wait > 0 {
				if next == 0 || wait < next {
					next = wait
				}
				continue
			}
		}
		var (
			err    error
			update string
		)
		// Never to Windows: MeshCentral's uninstallagent also deletes the
		// Diagnostic Agent, whose name every MeshAgent on the computer shares
		// (ADR-0071). Our MeshAgent is removed by our own agent.
		uninstall := r.connected && !r.returned && !r.windows && r.uninstalls < RetiredUninstalls
		if uninstall {
			err = s.mesh.UninstallAgent(ctx, r.node)
			update = `UPDATE retired_devices SET mesh_attempt_at = $3, mesh_uninstalls = mesh_uninstalls + 1, mesh_error = $2 WHERE device_id = $1`
			s.log.Info("remote access: asked the MeshAgent of a removed device to uninstall itself", "device_id", r.device, "error", err)
		} else {
			err = s.mesh.RemoveDevice(ctx, r.node)
			update = `UPDATE retired_devices SET mesh_attempt_at = $3, mesh_error = $2,
				mesh_removed_at = CASE WHEN $2 = '' THEN now() ELSE mesh_removed_at END,
				mesh_uninstalls = CASE WHEN $2 = '' THEN 0 ELSE mesh_uninstalls END
				WHERE device_id = $1`
			if err == nil {
				s.log.Info("remote access: removed a removed device's node from MeshCentral", "device_id", r.device)
			}
		}
		msg := ""
		if err != nil {
			msg = truncateRunes(err.Error(), 1000)
			s.log.Warn("remote access: cleaning up a removed device in MeshCentral failed", "device_id", r.device, "error", err)
		}
		if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			// The service's clock, which the gap is measured on.
			_, err := tx.Exec(ctx, update, r.device, msg, s.now())
			return err
		}); err != nil {
			s.log.Error("remote access: recording a removed device's cleanup failed", "device_id", r.device, "error", err)
		}
		// Again after the gap: to remove the node of a MeshAgent asked to
		// uninstall, or to retry a failure. A removed node is gone.
		if (err != nil || uninstall) && (next == 0 || gap < next) {
			next = gap
		}
	}
	return next
}

// recordedNodes reports which of the nodes a device already holds.
func (s *Service) recordedNodes(ctx context.Context, tx pgx.Tx, nodes []string) (map[string]bool, error) {
	out := map[string]bool{}
	if s.cfg.DiscoveryGrace <= 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT mesh_node_id FROM devices WHERE mesh_node_id = ANY ($1)`, nodes)
	if err != nil {
		return nil, fmt.Errorf("listing recorded devices: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var node string
		if err := rows.Scan(&node); err != nil {
			return nil, err
		}
		out[node] = true
	}
	return out, rows.Err()
}
