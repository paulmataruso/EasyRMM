package agents

import (
	"context"
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
	linked := false
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		// The name follows the hostname until someone renames the device.
		tag, err := tx.Exec(ctx, `UPDATE devices SET
				name = CASE WHEN name = hostname THEN $2 ELSE name END,
				hostname = $2, os_description = $3, platform = $4, agent_version = $5, agent_arch = $6,
				agent_last_seen_at = now()
			WHERE id = $1 AND agent_public_key IS NOT NULL`,
			d.ID, f.hostname, f.os, f.platform, f.version, f.arch)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrUnknownDevice
		}
		if f.meshNode != "" && f.meshNode != d.MeshNodeID {
			linked, err = s.link(ctx, tx, d, f, ip)
		}
		return err
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
	available, err := s.meshAvailable(ctx, d.SiteID)
	if err != nil {
		s.log.Warn("agents: checking remote access failed", "error", err, "device_id", d.ID)
	}
	return &agentproto.HeartbeatResponse{
		HeartbeatSeconds: int(HeartbeatInterval.Seconds()),
		MeshAgent:        agentproto.MeshAgentInfo{Available: available},
		JobKey:           s.jobKey,
	}, nil
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
		return err == nil, err
	case err != nil:
		return false, err
	case otherSite != d.SiteID:
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
	err = s.audit.Write(ctx, tx, audit.Event{
		Actor:  audit.Actor{Type: audit.ActorAgent, ID: d.ID, Label: f.hostname, SourceIP: ip},
		Action: "device.remote_link", Outcome: audit.Success,
		OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
		Details: details,
	})
	return err == nil, err
}
