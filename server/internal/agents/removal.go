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
	if s.updateKey == nil {
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
		if err := r.remember(ctx, tx, key, s.now()); err != nil {
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
	s.deleted()
	return nil
}

// doomed is a device being deleted, as locked for it.
type doomed struct {
	id, org, site uuid.UUID
	name          string
	key           []byte
	node          string
	removal       *time.Time
}

func lockDevice(ctx context.Context, tx pgx.Tx, id uuid.UUID) (*doomed, error) {
	r := doomed{id: id}
	err := tx.QueryRow(ctx, `SELECT d.organization_id, d.site_id, d.name, d.agent_public_key, coalesce(d.mesh_node_id, ''), m.requested_at
		FROM devices d LEFT JOIN device_removals m ON m.device_id = d.id
		WHERE d.id = $1 FOR UPDATE OF d`, id).Scan(&r.org, &r.site, &r.name, &r.key, &r.node, &r.removal)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	return &r, err
}

// remember keeps what may still run on the computer of a device being
// deleted: the agent holding key (nil when there is none to wait for) and
// the MeshAgent node. Nothing is kept when there is neither.
func (r *doomed) remember(ctx context.Context, tx pgx.Tx, key []byte, now time.Time) error {
	if key == nil && r.node == "" {
		return nil
	}
	var node *string
	if r.node != "" {
		node = &r.node
	}
	_, err := tx.Exec(ctx, `INSERT INTO retired_devices (device_id, organization_id, site_id, name, agent_public_key, mesh_node_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		r.id, r.org, r.site, r.name, key, node, now.Add(RetiredFor))
	return err
}

// deleted has MeshCentral's devices refreshed soon, which removes the
// nodes of removed devices, and tells whoever asked.
func (s *Service) deleted() {
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
	if s.updateKey == nil {
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
	return s.signUninstall(id, d.ID)
}

func (s *Service) signUninstall(id, deviceID uuid.UUID) (*agentproto.SignedUninstall, error) {
	now := s.now().UTC()
	u, err := agentproto.SignUninstall(s.updateKey, agentproto.UninstallPayload{
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
		JobKey:           s.jobKey,
	}
	var reported *time.Time
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT agent_reported_at FROM retired_devices WHERE device_id = $1`, d.ID).Scan(&reported)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnknownDevice
	}
	if err != nil {
		return nil, err
	}
	if s.updateKey == nil || (reported != nil && s.now().Before(reported.Add(RetiredRetry))) {
		return out, nil
	}
	if out.Uninstall, err = s.signUninstall(d.ID, d.ID); err != nil {
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
		if err := r.remember(ctx, tx, nil, s.now()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM devices WHERE id = $1`, d.ID); err != nil {
			return err
		}
		deleted = true
		ev.Action, ev.Outcome = "device.remove", audit.Success
		ev.Details["confirmed"] = true
		if r.removal == nil {
			ev.Details["removalCanceled"] = true
		}
		return s.audit.Write(ctx, tx, ev)
	})
	if err != nil {
		return err
	}
	if deleted {
		s.deleted()
	}
	return nil
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
