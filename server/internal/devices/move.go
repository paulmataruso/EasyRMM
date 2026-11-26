package devices

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/rdpcreds"
)

// MaxMove bounds the devices one move names.
const MaxMove = 500

// MoveInput names the devices to move and where (ADR-0069).
type MoveInput struct {
	DeviceIDs []uuid.UUID `json:"deviceIds"`
	SiteID    uuid.UUID   `json:"siteId"`
	// GroupID is a device group of the site; nil puts the devices in none.
	GroupID *uuid.UUID `json:"groupId"`
}

// MoveResult says how many devices moved and how many were already there.
type MoveResult struct {
	Moved     int `json:"moved"`
	Unchanged int `json:"unchanged"`
	// OtherOrganization is how many of the moved devices changed organization.
	OtherOrganization int `json:"otherOrganization"`
	// CanceledRuns is how many queued job runs of the old organizations were
	// canceled with them.
	CanceledRuns int `json:"canceledRuns"`
}

// SetAudit gives the service the audit log device moves are recorded in.
func (s *Service) SetAudit(a *audit.Logger) { s.audit = a }

// OnMoved registers a function called after devices moved to another site,
// so that remote access follows them (ADR-0069).
func (s *Service) OnMoved(f func()) { s.moved = f }

// OnMovedDevices registers a function called with the devices that moved,
// after they did, so that their agents are told at once (ADR-0059).
func (s *Service) OnMovedDevices(f func([]uuid.UUID)) { s.movedDevices = f }

type moving struct {
	id                  uuid.UUID
	name                string
	org, site           uuid.UUID
	group               *uuid.UUID
	orgName, siteName   string
	groupName           string
	otherSite, otherOrg bool
}

// Move puts devices in another device group, site or organization, all or
// none: every device is checked before the first changes. A move within a
// site needs device.edit; to another site of the organization also
// site.manage on both sites; to another organization also org.manage on both
// organizations. A device moved to another organization leaves its old
// organization's data behind: queued runs are canceled, a run in progress
// refuses the move, remote sessions end, and its alerts go (they have no
// organization of their own); job runs and audit records keep theirs.
func (s *Service) Move(ctx context.Context, c access.Caller, in MoveInput) (*MoveResult, error) {
	if !c.CanAnywhere(rbac.PermDeviceEdit) {
		return nil, apperr.Forbidden()
	}
	ids := slices.Clone(in.DeviceIDs)
	slices.SortFunc(ids, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	ids = slices.Compact(ids)
	f := apperr.Fields{}
	f.Check(len(ids) > 0, "deviceIds", "Choose at least one device.")
	f.Check(len(ids) <= MaxMove, "deviceIds", fmt.Sprintf("Move at most %d devices at once.", MaxMove))
	f.Check(in.SiteID != uuid.Nil, "siteId", "Choose a site.")
	if err := f.Err(); err != nil {
		return nil, err
	}
	res := &MoveResult{}
	var moved []uuid.UUID
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		*res = MoveResult{}
		moved = nil
		var tgtOrg uuid.UUID
		var tgtSite string
		err := tx.QueryRow(ctx, `SELECT organization_id, name FROM sites WHERE id = $1`, in.SiteID).Scan(&tgtOrg, &tgtSite)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !c.Can(rbac.PermSiteView, rbac.Site(tgtOrg, in.SiteID))) {
			return apperr.Invalid("siteId", "That site does not exist.")
		}
		if err != nil {
			return err
		}
		var tgtGroup string
		if in.GroupID != nil {
			err := tx.QueryRow(ctx, `SELECT name FROM device_groups WHERE id = $1 AND site_id = $2`, *in.GroupID, in.SiteID).Scan(&tgtGroup)
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.Invalid("groupId", "That device group is not in the site.")
			}
			if err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, `SELECT d.id, d.name, d.organization_id, d.site_id, d.device_group_id, o.name, s.name, coalesce(g.name, '')
			FROM devices d JOIN organizations o ON o.id = d.organization_id JOIN sites s ON s.id = d.site_id
				LEFT JOIN device_groups g ON g.id = d.device_group_id
			WHERE d.id = ANY ($1) ORDER BY d.id FOR UPDATE OF d`, ids)
		if err != nil {
			return err
		}
		var devs []*moving
		for rows.Next() {
			var m moving
			if err := rows.Scan(&m.id, &m.name, &m.org, &m.site, &m.group, &m.orgName, &m.siteName, &m.groupName); err != nil {
				rows.Close()
				return err
			}
			// A device the caller cannot see does not exist for them.
			if c.Can(rbac.PermDeviceView, rbac.Site(m.org, m.site)) {
				devs = append(devs, &m)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(devs) != len(ids) {
			return apperr.NotFound()
		}
		var forbidden, busy []string
		var todo []*moving
		for _, m := range devs {
			m.otherSite, m.otherOrg = m.site != in.SiteID, m.org != tgtOrg
			here := rbac.Site(m.org, m.site)
			switch {
			case !c.Can(rbac.PermDeviceEdit, here):
				forbidden = append(forbidden, m.name)
				continue
			case m.otherSite && (!c.Can(rbac.PermSiteManage, here) || !c.Can(rbac.PermSiteManage, rbac.Site(tgtOrg, in.SiteID))):
				forbidden = append(forbidden, m.name)
				continue
			case m.otherOrg && (!c.Can(rbac.PermOrgManage, rbac.Org(m.org)) || !c.Can(rbac.PermOrgManage, rbac.Org(tgtOrg))):
				forbidden = append(forbidden, m.name)
				continue
			}
			if !m.otherSite && sameGroup(m.group, in.GroupID) {
				res.Unchanged++
				continue
			}
			if m.otherOrg {
				var running int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM job_runs WHERE device_id = $1 AND status IN ('sent', 'running')`, m.id).Scan(&running); err != nil {
					return err
				}
				if running > 0 {
					busy = append(busy, m.name)
					continue
				}
			}
			todo = append(todo, m)
		}
		if len(forbidden) > 0 {
			return apperr.Forbidden()
		}
		if len(busy) > 0 {
			return apperr.Conflict("device_busy", fmt.Sprintf("%s %s running a job for its organization. Try again when it finishes.",
				strings.Join(busy, ", "), map[bool]string{true: "is", false: "are"}[len(busy) == 1]))
		}
		for _, m := range todo {
			if err := s.moveOne(ctx, tx, c, m, in, tgtOrg, tgtSite, tgtGroup, res); err != nil {
				return err
			}
		}
		res.Moved = len(todo)
		for _, m := range todo {
			moved = append(moved, m.id)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if res.Moved > 0 && s.moved != nil {
		s.moved()
	}
	if len(moved) > 0 && s.movedDevices != nil {
		s.movedDevices(moved)
	}
	return res, nil
}

func sameGroup(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (s *Service) moveOne(ctx context.Context, tx pgx.Tx, c access.Caller, m *moving, in MoveInput, tgtOrg uuid.UUID, tgtSite, tgtGroup string, res *MoveResult) error {
	// The MeshCentral node follows the site: it stays in the group of the
	// site it was in until the device sync moves it, and the agent rewrites
	// MeshAgent's settings (ADR-0069).
	if _, err := tx.Exec(ctx, `UPDATE devices SET organization_id = $2, site_id = $3, device_group_id = $4,
			mesh_from_site_id = CASE
				WHEN mesh_node_id IS NULL OR site_id = $3 THEN mesh_from_site_id
				WHEN coalesce(mesh_from_site_id, site_id) = $3 THEN NULL
				ELSE coalesce(mesh_from_site_id, site_id) END,
			mesh_settings_pending = mesh_settings_pending OR (mesh_node_id IS NOT NULL AND site_id <> $3)
		WHERE id = $1`, m.id, tgtOrg, in.SiteID, in.GroupID); err != nil {
		return err
	}
	// Verbose logging was turned on by someone with rights on the old site,
	// and its row names that site, so it ends with a move to another one.
	if m.otherSite {
		if _, err := tx.Exec(ctx, `DELETE FROM agent_log_verbose WHERE device_id = $1`, m.id); err != nil {
			return err
		}
		// The escrow rows follow the device, and row-level security reads
		// their site (ADR-0081); a move to another organization deletes them
		// below.
		for _, table := range []string{"device_encrypted_volumes", "recovery_key_escrows"} {
			if _, err := tx.Exec(ctx, `UPDATE `+table+` SET site_id = $2 WHERE device_id = $1`, m.id, in.SiteID); err != nil {
				return err
			}
		}
	}
	details := map[string]any{
		"device": m.name, "fromOrganization": m.orgName, "fromSite": m.siteName, "fromGroup": m.groupName,
		"toSite": tgtSite, "toGroup": tgtGroup, "toOrganizationId": tgtOrg.String(), "toSiteId": in.SiteID.String(),
		"fromOrganizationId": m.org.String(), "fromSiteId": m.site.String(),
	}
	if m.otherOrg {
		res.OtherOrganization++
		canceled, err := s.leaveOrganization(ctx, tx, c, m)
		if err != nil {
			return err
		}
		res.CanceledRuns += canceled
		details["canceledRuns"] = canceled
		// The old organization's people see the move as well.
		if err := s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.move_out", Outcome: audit.Success,
			OrganizationID: m.org, SiteID: m.site, DeviceID: m.id, TargetType: "device", TargetID: m.id.String(), Details: details,
		}); err != nil {
			return err
		}
	}
	return s.audit.Write(ctx, tx, audit.Event{
		Actor: c.Actor, Action: "device.move", Outcome: audit.Success,
		OrganizationID: tgtOrg, SiteID: in.SiteID, DeviceID: m.id, TargetType: "device", TargetID: m.id.String(), Details: details,
	})
}

// leaveOrganization settles what stays behind when a device changes
// organization, and returns how many queued runs it canceled. Job runs,
// audit records and patch history keep their organization and site; the
// patching link follows the existing moved rule in the engine reconcile.
func (s *Service) leaveOrganization(ctx context.Context, tx pgx.Tx, c access.Caller, m *moving) (int, error) {
	rows, err := tx.Query(ctx, `UPDATE job_runs SET status = 'canceled', finished_at = now(), cancel_requested_at = now(), canceled_by = $2,
			error = 'The device moved to another organization before the run started.'
		WHERE device_id = $1 AND status = 'queued' RETURNING id, job_id, site_id`, m.id, nullUUID(c.Actor.ID))
	if err != nil {
		return 0, err
	}
	type canceled struct{ id, job, site uuid.UUID }
	var done []canceled
	for rows.Next() {
		var x canceled
		if err := rows.Scan(&x.id, &x.job, &x.site); err != nil {
			rows.Close()
			return 0, err
		}
		done = append(done, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, x := range done {
		if err := s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "job.cancel", Outcome: audit.Success,
			OrganizationID: m.org, SiteID: x.site, DeviceID: m.id, TargetType: "job_run", TargetID: x.id.String(),
			Details: map[string]any{"device": m.name, "jobId": x.job.String(), "reason": "device moved to another organization"},
		}); err != nil {
			return 0, err
		}
	}
	// Open remote sessions end: their grants go, and a cookie without its
	// grant opens nothing.
	if _, err := tx.Exec(ctx, `DELETE FROM remote_grants WHERE device_id = $1`, m.id); err != nil {
		return 0, err
	}
	// Alerts follow their device and have no organization of their own, so
	// the old organization's alerts, open and resolved, must not turn up in
	// the new one.
	if _, err := tx.Exec(ctx, `DELETE FROM alerts WHERE device_id = $1`, m.id); err != nil {
		return 0, err
	}
	// Agent logs record what the old organization's people ran and set on
	// the device, so they go too (ADR-0069).
	// Repairs name who asked for them and keep their steps' output, so the
	// history goes as well; a report for a repair that is gone is ignored.
	for _, table := range []string{"agent_log_records", "agent_log_days", "agent_log_follow", "agent_repairs"} {
		if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE device_id = $1`, m.id); err != nil {
			return 0, err
		}
	}
	// Saved RDP credentials belong to the old organization's people and are
	// never carried over: all of them go, each audited (ADR-0079).
	if err := rdpcreds.PurgeDevice(ctx, tx, s.audit, c.Actor, m.id, m.org, m.site, m.name, "device moved to another organization"); err != nil {
		return 0, err
	}
	// Recovery keys are sealed to the old organization's key and its people
	// lose the device, so the records and volume rows end; the agent escrows
	// again to the new organization's key. One audit event gives the count,
	// never key data (ADR-0081).
	var records, volumes int64
	tag, err := tx.Exec(ctx, `DELETE FROM recovery_key_escrows WHERE device_id = $1`, m.id)
	if err != nil {
		return 0, err
	}
	records = tag.RowsAffected()
	if tag, err = tx.Exec(ctx, `DELETE FROM device_encrypted_volumes WHERE device_id = $1`, m.id); err != nil {
		return 0, err
	}
	volumes = tag.RowsAffected()
	if records+volumes > 0 {
		if err := s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "recovery_key.destroyed", Outcome: audit.Success,
			OrganizationID: m.org, SiteID: m.site, DeviceID: m.id, TargetType: "device", TargetID: m.id.String(),
			Details: map[string]any{"device": m.name, "records": records, "volumes": volumes, "reason": "device moved to another organization"},
		}); err != nil {
			return 0, err
		}
	}
	return len(done), nil
}
