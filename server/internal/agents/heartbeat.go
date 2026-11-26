package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Heartbeat records that a device's agent is alive, refreshes its facts and
// links its MeshAgent when the agent reports one.
func (s *Service) Heartbeat(ctx context.Context, d *Device, ip netip.Addr, req agentproto.HeartbeatRequest) (*agentproto.HeartbeatResponse, error) {
	f, err := cleanFacts(req.Facts)
	if err != nil {
		return nil, apperr.Invalid("facts", err.Error())
	}
	var meshState []byte
	if req.MeshAgent != nil {
		meshState = s.meshState(ctx, d.SiteID, *req.MeshAgent)
	}
	linked := false
	var (
		update    *agentproto.SignedUpdate
		uninstall *agentproto.SignedUninstall
	)
	// What the agent may do about Defender, and what it reported of it
	// (ADR-0070); a bad report is refused before anything is stored.
	allowed := s.defenderAllowed(d.OrganizationID)
	report, err := checkDefenderReport(req)
	if err != nil {
		return nil, err
	}
	var before string
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_ = tx.QueryRow(ctx, `SELECT coalesce(agent_version, '') FROM devices WHERE id = $1`, d.ID).Scan(&before)
		// The name follows the hostname until someone renames the device.
		tag, err := tx.Exec(ctx, `UPDATE devices SET
				name = CASE WHEN name = hostname THEN $2 ELSE name END,
				hostname = $2, os_description = $3, platform = $4, agent_version = $5, agent_arch = $6,
				agent_sha256 = NULLIF($7, ''), agent_last_seen_at = now(),
				meshagent_state = coalesce($8::jsonb, meshagent_state),
				meshagent_state_at = CASE WHEN $8::jsonb IS NULL THEN meshagent_state_at ELSE now() END
			WHERE id = $1 AND agent_public_key IS NOT NULL`,
			d.ID, f.hostname, f.os, f.platform, f.version, f.arch, f.sha256, meshState)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrUnknownDevice
		}
		if allowed {
			if err := s.storeDefender(ctx, tx, d, f.hostname, ip, report); err != nil {
				return err
			}
		}
		if f.meshNode != "" && f.meshNode != d.MeshNodeID {
			if linked, err = s.link(ctx, tx, d, f, ip); err != nil {
				return err
			}
		}
		// A device being removed gets nothing but its uninstall
		// instruction (ADR-0050).
		if uninstall, err = s.uninstallFor(ctx, tx, d); err != nil || uninstall != nil {
			return err
		}
		// The update is an extra: when settling it fails, the heartbeat
		// still counts.
		sp, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		if update, err = s.planUpdate(ctx, sp, d, f, req.Update, ip); err != nil {
			s.log.Error("agents: settling the agent update failed", "error", err, "device_id", d.ID)
			update = nil
			return sp.Rollback(ctx)
		}
		return sp.Commit(ctx)
	})
	if errors.Is(err, ErrUnknownDevice) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("agents: heartbeat: %w", err)
	}
	if linked && s.mesh != nil {
		s.mesh.Linked()
	}
	if s.version != nil && f.version != "" && f.version != before {
		// A build the list may not hold yet (ADR-0070).
		s.version(f.version)
	}
	available, err := s.meshAvailable(ctx, d.SiteID)
	if err != nil {
		s.log.Warn("agents: checking remote access failed", "error", err, "device_id", d.ID)
	}
	return &agentproto.HeartbeatResponse{
		Protocol:         agentproto.Protocol,
		HeartbeatSeconds: int(HeartbeatInterval.Seconds()),
		MeshAgent:        agentproto.MeshAgentInfo{Available: available, SettingsSHA256: s.pendingSettings(ctx, d, f, available)},
		JobKey:           s.jobKey,
		Update:           update,
		Uninstall:        uninstall,
		Defender:         &agentproto.DefenderPolicy{Enabled: allowed},
	}, nil
}

// movingFrom reports whether d was moved to its site from the site whose
// device group a node is in: the node is d's, on its way to the new group
// (ADR-0069).
func (s *Service) movingFrom(ctx context.Context, tx pgx.Tx, d *Device, site uuid.UUID) bool {
	var from *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT mesh_from_site_id FROM devices WHERE id = $1`, d.ID).Scan(&from); err != nil {
		return false
	}
	return from != nil && *from == site
}

// pendingSettings is the hash of the MeshAgent settings an agent must apply
// after its device moved to another site, or "" when none are pending. The
// agent reports the hash it applied; the instruction ends when they agree.
func (s *Service) pendingSettings(ctx context.Context, d *Device, f facts, available bool) string {
	if !available {
		return ""
	}
	var pending bool
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT mesh_settings_pending FROM devices WHERE id = $1`, d.ID).Scan(&pending)
	}); err != nil || !pending {
		return ""
	}
	b, err := s.MeshAgentSettings(ctx, d)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	want := hex.EncodeToString(sum[:])
	if f.meshSettings != want {
		return want
	}
	if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET mesh_settings_pending = false WHERE id = $1`, d.ID)
		return err
	}); err != nil {
		s.log.Warn("agents: settling the MeshAgent settings failed", "error", err, "device_id", d.ID)
	}
	return ""
}

// link attaches the MeshCentral node the agent reported to its device.
//
// The node id is not a secret, so a report is only believed within the
// device's own site: a device discovered there under that node is merged
// into the enrolled one, and an enrolled device holding the node (the same
// machine enrolled again) gives it up. A node already known in another site
// is left alone; MeshCentral's device sync also unlinks an enrolled device
// whose node turns out to belong to another site's group.
func (s *Service) link(ctx context.Context, tx pgx.Tx, d *Device, f facts, ip netip.Addr) (bool, error) {
	var (
		otherID   uuid.UUID
		otherSite uuid.UUID
		otherName string
		enrolled  bool
		agentType *int
		online    bool
		lastSeen  *time.Time
	)
	err := tx.QueryRow(ctx, `SELECT id, site_id, name, agent_public_key IS NOT NULL, mesh_agent_type, remote_online, last_seen_at
		FROM devices WHERE mesh_node_id = $1 FOR UPDATE`, f.meshNode).
		Scan(&otherID, &otherSite, &otherName, &enrolled, &agentType, &online, &lastSeen)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// MeshCentral has not reported the node yet; its next device sync
		// confirms or undoes the link.
		_, err = tx.Exec(ctx, `UPDATE devices SET mesh_node_id = $2, mesh_agent_type = NULL, remote_online = false WHERE id = $1`, d.ID, f.meshNode)
		if err == nil {
			err = keepNode(ctx, tx, d, f.meshNode)
		}
		return err == nil, err
	case err != nil:
		return false, err
	case otherSite != d.SiteID && !s.movingFrom(ctx, tx, d, otherSite):
		s.log.Warn("agents: a device reported a MeshAgent node of another site; not linked",
			"device_id", d.ID, "node_device_id", otherID)
		return false, nil
	}
	details := map[string]any{"device": f.hostname}
	if enrolled {
		_, err = tx.Exec(ctx, `UPDATE devices SET mesh_node_id = NULL, mesh_agent_type = NULL, remote_online = false WHERE id = $1`, otherID)
		details["previousDevice"], details["previousDeviceId"] = otherName, otherID.String()
	} else {
		// Sessions started on the discovered device now belong to this one.
		if _, err = tx.Exec(ctx, `UPDATE remote_grants SET device_id = $2 WHERE device_id = $1`, otherID, d.ID); err == nil {
			_, err = tx.Exec(ctx, `DELETE FROM devices WHERE id = $1`, otherID)
		}
		details["mergedDevice"], details["mergedDeviceId"] = otherName, otherID.String()
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET mesh_node_id = $2, mesh_agent_type = $3, remote_online = $4,
			last_seen_at = greatest(last_seen_at, $5) WHERE id = $1`,
		d.ID, f.meshNode, agentType, online, lastSeen); err != nil {
		return false, err
	}
	if err := keepNode(ctx, tx, d, f.meshNode); err != nil {
		return false, err
	}
	err = s.audit.Write(ctx, tx, audit.Event{
		Actor:  audit.Actor{Type: audit.ActorAgent, ID: d.ID, Label: f.hostname, SourceIP: ip},
		Action: "device.remote_link", Outcome: audit.Success,
		OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
		Details: details,
	})
	return err == nil, err
}

// keepNode lets a device linked to a MeshAgent node keep it when the node
// belonged to a device removed from the same site (ADR-0050): the computer
// was enrolled again, so its MeshAgent is not to be uninstalled.
func keepNode(ctx context.Context, tx pgx.Tx, d *Device, node string) error {
	_, err := tx.Exec(ctx, `UPDATE retired_devices SET mesh_node_id = NULL WHERE mesh_node_id = $1 AND site_id = $2`, node, d.SiteID)
	return err
}
