package assets

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

const unreadReason = "The agent could not read it."

// agentFields is what the agent reports, per field: the device's name and
// the inventory's SMBIOS identifiers. An empty value is unknown until the
// collector says otherwise (ADR-0066).
func agentFields(deviceName string, sys agentproto.SystemInfo) map[string]string {
	return map[string]string{
		"name":          cleanValue(deviceName),
		"manufacturer":  cleanValue(sys.Manufacturer),
		"model":         cleanValue(sys.Model),
		"serial_number": cleanValue(sys.Serial),
	}
}

// suggestKind is the kind the agent's report suggests, which people change.
func suggestKind(sys agentproto.SystemInfo, osDescription string) string {
	switch {
	case sys.Virtualization != "" && sys.Virtualization != "container":
		return "virtual_machine"
	case strings.Contains(strings.ToLower(osDescription), "server"):
		return "server"
	}
	return "workstation"
}

// writeAgentValues stores the agent's values of an asset, rewriting only
// the ones that changed, and refreshes the effective columns when any did.
// The agent's values are the only ones it touches.
func writeAgentValues(ctx context.Context, tx pgx.Tx, assetID, org uuid.UUID, vals map[string]string, force bool) error {
	changed := force
	for _, f := range Catalog {
		v, ok := vals[f.Name]
		if !ok {
			continue
		}
		state, reason := "reported", ""
		if v == "" {
			state, reason = "unknown", unreadReason
		}
		tag, err := tx.Exec(ctx, `INSERT INTO asset_field_values (asset_id, organization_id, field, source, value, state, reason, observed_at)
			VALUES ($1, $2, $3, 'agent', $4, $5, $6, now())
			ON CONFLICT (asset_id, field, source) DO UPDATE SET value = $4, state = $5, reason = $6, observed_at = now(), recorded_at = now()
			WHERE (asset_field_values.value, asset_field_values.state) IS DISTINCT FROM ($4, $5)`,
			assetID, org, f.Name, v, state, reason)
		if err != nil {
			return err
		}
		changed = changed || tag.RowsAffected() > 0
	}
	if !changed {
		return nil
	}
	return refresh(ctx, tx, assetID)
}

func readInventory(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID) (agentproto.SystemInfo, bool, error) {
	var data []byte
	err := tx.QueryRow(ctx, `SELECT data FROM device_inventory WHERE device_id = $1`, deviceID).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return agentproto.SystemInfo{}, false, nil
	}
	if err != nil {
		return agentproto.SystemInfo{}, false, err
	}
	var inv agentproto.Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return agentproto.SystemInfo{}, false, err
	}
	return inv.System, true, nil
}

// copyAgentValues copies a device's stored inventory into a new asset's
// agent values.
func copyAgentValues(ctx context.Context, tx pgx.Tx, assetID, deviceID uuid.UUID) error {
	var org uuid.UUID
	var name string
	if err := tx.QueryRow(ctx, `SELECT organization_id, name FROM devices WHERE id = $1`, deviceID).Scan(&org, &name); err != nil {
		return err
	}
	sys, ok, err := readInventory(ctx, tx, deviceID)
	if err != nil {
		return err
	}
	if !ok {
		return writeAgentValues(ctx, tx, assetID, org, map[string]string{"name": cleanValue(name)}, false)
	}
	return writeAgentValues(ctx, tx, assetID, org, agentFields(name, sys), false)
}

// SyncAgent copies a device's reported system identifiers into its asset
// record, making the record when the device has none: called in the
// transaction that stores the inventory, which runs at the system scope,
// so every statement names the device's organization. It writes only what
// changed. Organizations outside the development scope are left alone.
func SyncAgent(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, sys agentproto.SystemInfo) error {
	var org, site uuid.UUID
	var name, osDesc string
	err := tx.QueryRow(ctx, `SELECT organization_id, site_id, name, os_description FROM devices WHERE id = $1`, deviceID).Scan(&org, &site, &name, &osDesc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !devscope.Allowed(org) {
		return nil
	}
	var assetID uuid.UUID
	created := false
	err = tx.QueryRow(ctx, `SELECT id FROM assets WHERE device_id = $1`, deviceID).Scan(&assetID)
	if errors.Is(err, pgx.ErrNoRows) {
		created = true
		err = tx.QueryRow(ctx, `INSERT INTO assets (organization_id, site_id, device_id, kind, status) VALUES ($1, $2, $3, $4, 'in_use') RETURNING id`,
			org, site, deviceID, suggestKind(sys, osDesc)).Scan(&assetID)
	}
	if err != nil {
		return err
	}
	return writeAgentValues(ctx, tx, assetID, org, agentFields(name, sys), created)
}

// Backfill makes asset records for devices that have an inventory and no
// record, in batches of 100 in short transactions at the system scope.
// It is called at start; once every device has a record it costs one query.
func (s *Service) Backfill(ctx context.Context) error {
	for {
		var n int
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT i.device_id FROM device_inventory i
				WHERE NOT EXISTS (SELECT 1 FROM assets a WHERE a.device_id = i.device_id)
				AND EXISTS (SELECT 1 FROM devices d WHERE d.id = i.device_id) ORDER BY i.device_id LIMIT 100`)
			if err != nil {
				return err
			}
			ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			if err != nil {
				return err
			}
			for _, id := range ids {
				sys, _, err := readInventory(ctx, tx, id)
				if err != nil {
					return err
				}
				if err := SyncAgent(ctx, tx, id, sys); err != nil {
					return err
				}
			}
			// A batch of devices the development scope holds back makes no
			// progress: stop rather than read it again.
			var made int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM assets WHERE device_id = ANY ($1)`, ids).Scan(&made); err != nil {
				return err
			}
			if made == len(ids) {
				n = len(ids)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if n < 100 {
			return nil
		}
	}
}
