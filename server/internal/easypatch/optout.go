package easypatch

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Stopping patching for a device (ADR-0040). With automatic installs on by
// default, a device that must not be patched, such as a fragile server, is
// opted out: EasyRMM removes its EasyPatch agent and installs none,
// automatically or when asked, until patching is allowed again. An agent
// someone installs on the computer by hand is left alone.

// manageDevices checks a request naming devices and reads them, each one
// the caller may manage patching of; one the caller may not manage fails
// the whole request.
func (s *Service) manageDevices(ctx context.Context, c access.Caller, in ActionInput) ([]deviceRow, error) {
	if len(in.UpdateIDs) > 0 || in.ScheduledAt != nil {
		return nil, apperr.Invalid("deviceIds", "This takes devices only.")
	}
	if len(in.DeviceIDs) == 0 || len(in.DeviceIDs) > MaxBulk {
		return nil, apperr.Invalid("deviceIds", fmt.Sprintf("Choose from 1 to %d devices.", MaxBulk))
	}
	seen := map[uuid.UUID]bool{}
	var devices []deviceRow
	for _, id := range in.DeviceIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		d, err := s.device(ctx, c, id, rbac.PermPatchManage)
		if err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, nil
}

func actorID(c access.Caller) *uuid.UUID {
	if c.Actor.Type == audit.ActorUser && c.Actor.ID != uuid.Nil {
		return &c.Actor.ID
	}
	return nil
}

// StopPatching opts devices out of patching. Their EasyPatch agent, when
// EasyRMM manages it, is removed by the next reconcile pass.
func (s *Service) StopPatching(ctx context.Context, c access.Caller, in ActionInput) (ActionResult, error) {
	devices, err := s.manageDevices(ctx, c, in)
	if err != nil {
		return ActionResult{}, err
	}
	res := ActionResult{Results: []ActionItem{}}
	for _, d := range devices {
		item := ActionItem{DeviceID: d.id, DeviceName: d.name}
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			var state string
			err := tx.QueryRow(ctx, `SELECT state FROM easypatch_installs WHERE device_id = $1 FOR UPDATE`, d.id).Scan(&state)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
			case err != nil:
				return err
			case state == InstallSent:
				item.Message = "The device is installing the EasyPatch agent now. Stop patching once the install has finished."
				return nil
			}
			tag, err := tx.Exec(ctx, `INSERT INTO easypatch_opt_outs (device_id, opted_out_by) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
				d.id, actorID(c))
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				item.OK, item.Message = true, "Patching was already stopped."
				return nil
			}
			if _, err := tx.Exec(ctx, `DELETE FROM easypatch_installs WHERE device_id = $1 AND state = 'waiting'`, d.id); err != nil {
				return err
			}
			// Only an agent EasyRMM has checked is EasyRMM's to remove.
			if _, err := tx.Exec(ctx, `INSERT INTO easypatch_removals (endpoint_id, device_id, reason, hostname)
				SELECT e.endpoint_id, $1, 'opted_out', $2 FROM easypatch_devices e WHERE e.device_id = $1 AND e.state = 'linked'
				ON CONFLICT (endpoint_id) DO NOTHING`, d.id, cut(d.name, 255)); err != nil {
				return err
			}
			var removing bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM easypatch_removals WHERE device_id = $1)`, d.id).Scan(&removing); err != nil {
				return err
			}
			item.OK = true
			switch {
			case removing:
				item.Message = "Patching stopped. EasyRMM is removing the EasyPatch agent."
			case d.state == LinkUnlinked || d.state == LinkPending:
				item.Message = "Patching stopped. EasyRMM could not confirm that the device's EasyPatch agent is one it manages, so the agent stays installed."
			default:
				item.Message = "Patching stopped."
			}
			return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "patch.stop", OrganizationID: d.organizationID,
				SiteID: d.siteID, DeviceID: d.id, TargetType: "device", TargetID: d.id.String(), Outcome: audit.Success,
				Details: map[string]any{"device": d.name, "removingAgent": removing}})
		})
		if err != nil {
			return ActionResult{}, err
		}
		res.add(item)
	}
	s.fleet.clear()
	s.Kick()
	return res, nil
}

// AllowPatching undoes StopPatching. A removal not sent yet is dropped;
// automatic installs, where they are on, put the agent back.
func (s *Service) AllowPatching(ctx context.Context, c access.Caller, in ActionInput) (ActionResult, error) {
	devices, err := s.manageDevices(ctx, c, in)
	if err != nil {
		return ActionResult{}, err
	}
	res := ActionResult{Results: []ActionItem{}}
	for _, d := range devices {
		item := ActionItem{DeviceID: d.id, DeviceName: d.name}
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `DELETE FROM easypatch_opt_outs WHERE device_id = $1`, d.id)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				item.OK, item.Message = true, "Patching was not stopped."
				return nil
			}
			if _, err := tx.Exec(ctx, `DELETE FROM easypatch_removals WHERE device_id = $1 AND reason = 'opted_out' AND state = 'pending'`,
				d.id); err != nil {
				return err
			}
			// The install record of the removed agent would hold automatic
			// installs back.
			if _, err := tx.Exec(ctx, `DELETE FROM easypatch_installs WHERE device_id = $1 AND state IN ('succeeded', 'failed')`, d.id); err != nil {
				return err
			}
			var auto bool
			if err := tx.QueryRow(ctx, `SELECT coalesce((SELECT auto_install FROM easypatch_organizations WHERE organization_id = $1), false)`,
				d.organizationID).Scan(&auto); err != nil {
				return err
			}
			item.OK, item.Message = true, "Patching allowed again. Install the EasyPatch agent to patch the device."
			if auto {
				item.Message = "Patching allowed again. EasyRMM installs the EasyPatch agent shortly."
			}
			return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "patch.allow", OrganizationID: d.organizationID,
				SiteID: d.siteID, DeviceID: d.id, TargetType: "device", TargetID: d.id.String(), Outcome: audit.Success,
				Details: map[string]any{"device": d.name}})
		})
		if err != nil {
			return ActionResult{}, err
		}
		res.add(item)
	}
	s.fleet.clear()
	return res, nil
}
