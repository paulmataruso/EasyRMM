package agents

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/rdpcreds"
)

// Removing a device (ADR-0050).

// UninstallValid is how long an uninstall instruction is valid. Each
// heartbeat answer while the removal waits carries a fresh one.
const UninstallValid = 10 * time.Minute

// RetiredFor is how long EasyRMM remembers a removed device's agents, so
// that they still uninstall themselves if the computer comes back.
const RetiredFor = 90 * 24 * time.Hour

// RetiredRetry is how long the agent of a device removed by force waits
// before it is told again to uninstall itself, after it reported that it
// could not.
const RetiredRetry = time.Hour

// Removal outcomes for the console.
const (
	// RemovalAsked: the agent is asked to uninstall itself; the device is
	// deleted when it confirms.
	RemovalAsked = "asked"
	// RemovalDone: the device is deleted. A device without an EasyRMM agent
	// has nothing to wait for.
	RemovalDone = "removed"
)

// RequestRemoval asks for a device to be removed. A device with an EasyRMM
// agent is told to uninstall it and is deleted when it confirms; asking
// again after a failure sends a new instruction. A device without one
// (discovered through MeshCentral) is removed at once, and its MeshAgent
// uninstalled through MeshCentral.
func (s *Service) RequestRemoval(ctx context.Context, c access.Caller, deviceID uuid.UUID) (string, error) {
	d, err := s.retirable(ctx, c, deviceID)
	if err != nil {
		return "", err
	}
	if d.Agent == nil {
		return RemovalDone, s.retire(ctx, c, d.ID, false)
	}
	if s.keys == nil {
		return "", apperr.Conflict("no_job_key", "The server cannot sign instructions to agents.")
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO device_removals (device_id, id, requested_by) VALUES ($1, $2, $3)
			ON CONFLICT (device_id) DO UPDATE SET id = $2, requested_at = now(), requested_by = $3,
				sent_at = NULL, reported_at = NULL, error = ''`, d.ID, uuid.New(), userID(c)); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.removal_request", Outcome: audit.Success,
			OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"device": d.Name},
		})
	})
	if err != nil {
		return "", err
	}
	if s.wake != nil {
		s.wake(d.ID, "removal") // the agent's next heartbeat carries the uninstall
	}
	return RemovalAsked, nil
}

// CancelRemoval withdraws a removal that has not been confirmed. An agent
// that already started uninstalling itself still finishes, and its report
// deletes the device.
func (s *Service) CancelRemoval(ctx context.Context, c access.Caller, deviceID uuid.UUID) error {
	d, err := s.retirable(ctx, c, deviceID)
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM device_removals WHERE device_id = $1`, d.ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return apperr.Conflict("not_removing", "Nobody asked for this device to be removed.")
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.removal_cancel", Outcome: audit.Success,
			OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"device": d.Name},
		})
	})
}

// ForceRemove deletes a device without waiting for its agent: one that is
// off, gone, or failed to uninstall itself. Its agents are remembered for
// RetiredFor and uninstall themselves if the computer comes back.
func (s *Service) ForceRemove(ctx context.Context, c access.Caller, deviceID uuid.UUID) error {
	d, err := s.retirable(ctx, c, deviceID)
	if err != nil {
		return err
	}
	return s.retire(ctx, c, d.ID, true)
}

// retirable looks up a device the caller may remove.
func (s *Service) retirable(ctx context.Context, c access.Caller, id uuid.UUID) (*devices.Device, error) {
	d, err := devices.Lookup(ctx, s.db, c, id)
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermDeviceRetire, rbac.Site(d.OrganizationID, d.SiteID)); err != nil {
		return nil, err
	}
	return d, nil
}

// retire deletes a device on someone's behalf and remembers what may still
// run on the computer: its EasyRMM agent when forced, and its MeshAgent.
func (s *Service) retire(ctx context.Context, c access.Caller, id uuid.UUID, forced bool) error {
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		r, err := lockDevice(ctx, tx, id)
		if err != nil {
			return err
		}
		key := r.key
		if !forced {
			key = nil
		}
		if err := r.remember(ctx, tx, key, forced, s.now()); err != nil {
			return err
		}
		if err := rdpcreds.PurgeDevice(ctx, tx, s.audit, c.Actor, id, r.org, r.site, r.name, "device removed"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM devices WHERE id = $1`, id); err != nil {
			return err
		}
		details := map[string]any{"device": r.name, "forced": forced, "agent": r.key != nil}
		if r.removal != nil {
			details["removalRequested"] = r.removal.Format(time.RFC3339)
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.remove", Outcome: audit.Success,
			OrganizationID: r.org, SiteID: r.site, DeviceID: id, TargetType: "device", TargetID: id.String(),
			Details: details,
		})
	})
	if err != nil {
		return err
	}
	s.deleted(id)
	return nil
}

// doomed is a device being deleted, as locked for it.
type doomed struct {
	id, org, site uuid.UUID
	name          string
	key           []byte
	node          string
	platform      string
	removal       *time.Time
}

func lockDevice(ctx context.Context, tx pgx.Tx, id uuid.UUID) (*doomed, error) {
	r := doomed{id: id}
	err := tx.QueryRow(ctx, `SELECT d.organization_id, d.site_id, d.name, d.agent_public_key, coalesce(d.mesh_node_id, ''), d.platform, m.requested_at
		FROM devices d LEFT JOIN device_removals m ON m.device_id = d.id
		WHERE d.id = $1 FOR UPDATE OF d`, id).Scan(&r.org, &r.site, &r.name, &r.key, &r.node, &r.platform, &r.removal)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	return &r, err
}

// remember keeps what may still run on the computer of a device being
// deleted: the agent holding key (nil when there is none to wait for) and
// the MeshAgent node. Nothing is kept when there is neither.
func (r *doomed) remember(ctx context.Context, tx pgx.Tx, key []byte, mayRemain bool, now time.Time) error {
	if key == nil && r.node == "" {
		return nil
	}
	var node *string
	if r.node != "" {
		node = &r.node
	}
	// A removed device keeps its last report of the keys it trusts, so that
	// its uninstall instruction is signed by the same rule (ADR-0057). It is
	// written by this insert: the table's rows are changed only with the system
	// scope, and a person removes the device.
	_, err := tx.Exec(ctx, `INSERT INTO retired_devices (device_id, organization_id, site_id, name, agent_public_key, mesh_node_id, expires_at, platform, mesh_may_remain,
			job_keys_report, job_keys_report_at, job_keys_report_sha, job_keys_first_reported_at, job_key_cutover_generation, job_key_cutover_at, job_key_given_generation)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9,
			d.job_keys_report, d.job_keys_report_at, coalesce(d.job_keys_report_sha, d.agent_sha256), d.job_keys_first_reported_at,
			d.job_key_cutover_generation, d.job_key_cutover_at, d.job_key_given_generation
		FROM (SELECT 1) one LEFT JOIN devices d ON d.id = $1`,
		r.id, r.org, r.site, r.name, key, node, now.Add(RetiredFor), r.platform, mayRemain && r.platform == "windows" && node != nil)
	return err
}

// deleted has MeshCentral's devices refreshed soon, which removes the
// nodes of removed devices, and tells whoever asked.
func (s *Service) deleted(id uuid.UUID) {
	if s.gone != nil {
		s.gone(id)
	}
	if s.mesh != nil {
		s.mesh.Linked()
	}
	if s.removed != nil {
		s.removed()
	}
}

// uninstallFor returns the signed uninstall instruction for a device whose
// removal waits for its agent, or nil. It records when the instruction was
// first sent. Called within the heartbeat's transaction.
func (s *Service) uninstallFor(ctx context.Context, tx pgx.Tx, d *Device) (*agentproto.SignedUninstall, error) {
	if s.keys == nil {
		return nil, nil
	}
	var id uuid.UUID
	err := tx.QueryRow(ctx, `UPDATE device_removals SET sent_at = coalesce(sent_at, now())
		WHERE device_id = $1 AND reported_at IS NULL RETURNING id`, d.ID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.signUninstall(ctx, tx, id, d.ID)
}

func (s *Service) signUninstall(ctx context.Context, tx pgx.Tx, id, deviceID uuid.UUID) (*agentproto.SignedUninstall, error) {
	now := s.now().UTC()
	key, _, err := s.keys.Issue(ctx, tx, deviceID, agentproto.InstructionUninstall, id.String())
	if err != nil {
		return nil, fmt.Errorf("agents: signing the uninstall instruction: %w", err)
	}
	u, err := agentproto.SignUninstall(key, agentproto.UninstallPayload{
		V: agentproto.UninstallPayloadVersion, ID: id.String(), DeviceID: deviceID.String(),
		IssuedAt: now, ExpiresAt: now.Add(UninstallValid),
	})
	if err != nil {
		return nil, fmt.Errorf("agents: signing the uninstall instruction: %w", err)
	}
	return &u, nil
}

// RetiredHeartbeat answers the heartbeat of a device removed by force: the
// uninstall instruction, unless its agent reported a failure within the
// last RetiredRetry. Nothing about the device is recorded.
func (s *Service) RetiredHeartbeat(ctx context.Context, d *Device) (*agentproto.HeartbeatResponse, error) {
	out := &agentproto.HeartbeatResponse{
		Protocol:         agentproto.Protocol,
		HeartbeatSeconds: int(HeartbeatInterval.Seconds()),
	}
	// A removed device is signed for by the report it left (ADR-0057), and is
	// offered no statement: it gets nothing but its uninstall instruction.
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var reported *time.Time
		err := tx.QueryRow(ctx, `SELECT agent_reported_at FROM retired_devices WHERE device_id = $1`, d.ID).Scan(&reported)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnknownDevice
		}
		if err != nil {
			return err
		}
		if s.keys == nil {
			return nil
		}
		c, err := s.keys.For(ctx, tx, d.ID)
		if err != nil {
			return err
		}
		out.JobKey, out.JobKeyGeneration = c.Key.Encoded(), c.Key.Generation
		if reported != nil && s.now().Before(reported.Add(RetiredRetry)) {
			return nil
		}
		out.Uninstall, err = s.signUninstall(ctx, tx, d.ID, d.ID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ErrBadReport is a removal report that is not valid.
var ErrBadReport = errors.New("agents: the removal report is not valid")

// Removed records an agent's report on uninstalling itself. A device whose
// agent removed its service is deleted, whether or not someone still waits
// for it: the agent never runs again. A device removed by force stops
// being waited for. A failure is recorded for the console.
func (s *Service) Removed(ctx context.Context, d *Device, ip netip.Addr, rep agentproto.RemovedReport) error {
	if len(rep.ID) > 64 {
		return ErrBadReport
	}
	rep.Error = clean(rep.Error, agentproto.MaxRemovalError)
	actor := audit.Actor{Type: audit.ActorAgent, ID: d.ID, Label: d.Hostname, SourceIP: ip}
	if d.Retired {
		return s.retiredRemoved(ctx, d, actor, rep)
	}
	deleted := false
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		r, err := lockDevice(ctx, tx, d.ID)
		if errors.Is(err, apperr.ErrNotFound) {
			return ErrUnknownDevice
		}
		if err != nil {
			return err
		}
		ev := audit.Event{
			Actor: actor, OrganizationID: r.org, SiteID: r.site, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"device": r.name},
		}
		if rep.Error != "" {
			ev.Details["error"] = rep.Error
		}
		if !rep.Removed {
			// Recorded against the removal it answers; any other is stale.
			tag, err := tx.Exec(ctx, `UPDATE device_removals SET reported_at = now(), sent_at = coalesce(sent_at, now()), error = $3
				WHERE device_id = $1 AND id::text = $2 AND reported_at IS NULL`, d.ID, rep.ID, nonEmpty(rep.Error, "The agent did not say why."))
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			ev.Action, ev.Outcome = "device.removal_failed", audit.Failure
			return s.audit.Write(ctx, tx, ev)
		}
		if r.removal == nil {
			// Nobody asked for this removal: a device key alone must not be
			// able to silence a device, so it is marked, not deleted
			// (ADR-0053 amending ADR-0050).
			return s.markUninstalled(ctx, tx, r, d, actor, "", rep.Error)
		}
		if err := r.remember(ctx, tx, nil, rep.Error != "", s.now()); err != nil {
			return err
		}
		if err := rdpcreds.PurgeDevice(ctx, tx, s.audit, actor, d.ID, r.org, r.site, r.name, "device removed"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM devices WHERE id = $1`, d.ID); err != nil {
			return err
		}
		deleted = true
		ev.Action, ev.Outcome = "device.remove", audit.Success
		ev.Details["confirmed"] = true
		return s.audit.Write(ctx, tx, ev)
	})
	if err != nil {
		return err
	}
	if deleted {
		s.deleted(d.ID)
	}
	return nil
}

// NoticeAgentUninstalled is the kind of the notice "agent removed without a
// request" (ADR-0053); its subject is the device's ID.
const NoticeAgentUninstalled = "agent_uninstalled"

// Uninstalled records an agent's report that it is being uninstalled without
// the server's instruction (ADR-0053, ADR-0056): by hand, or by removing its
// package. The device is marked Uninstalled, not deleted, and a notice is
// opened, because a device key alone must not be able to silence a device.
func (s *Service) Uninstalled(ctx context.Context, d *Device, ip netip.Addr, rep agentproto.UninstalledReport) error {
	if !agentproto.ValidInstaller(rep.Installer) {
		return ErrBadReport
	}
	if d.Retired {
		// Removed from the console already; nothing to mark.
		return nil
	}
	actor := audit.Actor{Type: audit.ActorAgent, ID: d.ID, Label: d.Hostname, SourceIP: ip}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		r, err := lockDevice(ctx, tx, d.ID)
		if errors.Is(err, apperr.ErrNotFound) {
			return ErrUnknownDevice
		}
		if err != nil {
			return err
		}
		return s.markUninstalled(ctx, tx, r, d, actor, rep.Installer, "")
	})
}

// markUninstalled marks a device Uninstalled: audited, its policy alerts
// resolved, and the notice opened (critical, and held by no maintenance
// window). It stays until someone removes the device or its agent checks in
// again. The device row is locked by the caller.
func (s *Service) markUninstalled(ctx context.Context, tx pgx.Tx, r *doomed, d *Device, actor audit.Actor, installer, errText string) error {
	// The installer the heartbeats named stands in when the report names none.
	var how string
	if err := tx.QueryRow(ctx, `UPDATE devices SET agent_uninstalled_at = coalesce(agent_uninstalled_at, now()),
			agent_uninstalled_installer = coalesce(NULLIF($2, ''), agent_uninstalled_installer, installer)
		WHERE id = $1 RETURNING coalesce(agent_uninstalled_installer, '')`, d.ID, installer).Scan(&how); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE alerts SET status = 'resolved', resolved_at = now(), resolution = 'uninstalled'
		WHERE device_id = $1 AND status <> 'resolved'`, d.ID); err != nil {
		return err
	}
	title := "Agent removed without a request: " + r.name
	detail := "The EasyRMM agent on " + r.name + " was uninstalled " + installerPhrase(how) + ", and nobody asked for it in the console. " +
		"Remove the device in the console if this was meant; it stays listed until you do or its agent checks in again."
	if errText != "" {
		detail += " The agent said: " + errText
	}
	if _, err := tx.Exec(ctx, `INSERT INTO notices (organization_id, kind, subject, site_id, device_id, title, detail) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (coalesce(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), kind, subject) WHERE resolved_at IS NULL
		DO UPDATE SET detail = EXCLUDED.detail`,
		r.org, NoticeAgentUninstalled, d.ID.String(), r.site, d.ID, clean(title, 200), clean(detail, 1000)); err != nil {
		return err
	}
	return s.audit.Write(ctx, tx, audit.Event{
		Actor: actor, Action: "device.agent_uninstalled", Outcome: audit.Success,
		OrganizationID: r.org, SiteID: r.site, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
		Details: map[string]any{"device": r.name, "installer": how},
	})
}

// installerPhrase says how an agent was removed, for the notice.
func installerPhrase(installer string) string {
	switch installer {
	case agentproto.InstallerDEB:
		return "by removing its DEB package"
	case agentproto.InstallerRPM:
		return "by removing its RPM package"
	case agentproto.InstallerMSI:
		return "by removing its MSI package"
	}
	return "by hand"
}

// retiredRemoved records the report of an agent whose device was removed
// by force.
func (s *Service) retiredRemoved(ctx context.Context, d *Device, actor audit.Actor, rep agentproto.RemovedReport) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var (
			tag pgconn.CommandTag
			err error
		)
		// The service's clock, which RetiredRetry is measured on.
		if rep.Removed {
			tag, err = tx.Exec(ctx, `UPDATE retired_devices SET agent_public_key = NULL, cleaned_at = now(),
					agent_reported_at = $3, agent_error = $2
				WHERE device_id = $1`, d.ID, rep.Error, s.now())
		} else {
			tag, err = tx.Exec(ctx, `UPDATE retired_devices SET agent_reported_at = $3, agent_error = $2 WHERE device_id = $1`,
				d.ID, nonEmpty(rep.Error, "The agent did not say why."), s.now())
		}
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrUnknownDevice
		}
		ev := audit.Event{
			Actor: actor, Action: "device.retired_cleanup", Outcome: audit.Success,
			OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"device": d.Hostname, "removed": rep.Removed},
		}
		if rep.Error != "" {
			ev.Details["error"] = rep.Error
		}
		if !rep.Removed {
			ev.Outcome = audit.Failure
		}
		return s.audit.Write(ctx, tx, ev)
	})
}

func nonEmpty(s, otherwise string) string {
	if s == "" {
		return otherwise
	}
	return s
}

// LeftBehindMaxList bounds the list of devices that may have left MeshAgent behind.
const LeftBehindMaxList = 200

// LeftBehind is a removed Windows device whose EasyRMM agent was not there to
// remove EasyRMM's MeshAgent (ADR-0071). EasyRMM does not ask MeshCentral to
// uninstall it, so it may still be on the computer.
type LeftBehind struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	OrganizationID uuid.UUID `json:"organizationId"`
	SiteID         uuid.UUID `json:"siteId"`
	RemovedAt      time.Time `json:"removedAt"`
}

// ListLeftBehind returns the removed devices, within the retention period and
// the caller's reach, whose MeshAgent may remain: those the caller may remove
// devices from, whose agent has not since confirmed that it uninstalled itself.
func (s *Service) ListLeftBehind(ctx context.Context, c access.Caller) ([]LeftBehind, error) {
	out := []LeftBehind{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT device_id, name, organization_id, site_id, removed_at FROM retired_devices
			WHERE mesh_may_remain AND cleaned_at IS NULL AND expires_at > now() ORDER BY removed_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var l LeftBehind
			if err := rows.Scan(&l.ID, &l.Name, &l.OrganizationID, &l.SiteID, &l.RemovedAt); err != nil {
				return err
			}
			if c.Can(rbac.PermDeviceRetire, rbac.Site(l.OrganizationID, l.SiteID)) && len(out) < LeftBehindMaxList {
				out = append(out, l)
			}
		}
		return rows.Err()
	})
	return out, err
}
