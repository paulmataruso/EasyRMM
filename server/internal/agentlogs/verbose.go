package agentlogs

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Verbose mode lasts 1 to 24 hours, 2 by default.
const (
	MinVerboseHours     = 1
	MaxVerboseHours     = 24
	DefaultVerboseHours = 2
)

// setBy is the user who set a mode, nil for anyone else.
func setBy(c access.Caller) *uuid.UUID {
	if c.Actor.Type != audit.ActorUser || c.Actor.ID == uuid.Nil {
		return nil
	}
	id := c.Actor.ID
	return &id
}

func sortStrings(s []string) { sort.Strings(s) }

// verboseOf returns the verbose mode in force for a device: the later end
// of its own and its group's.
func verboseOf(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID) (*Verbose, error) {
	var until time.Time
	var group *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT v.until, v.group_id FROM agent_log_verbose v
		WHERE v.until > now() AND (v.device_id = $1 OR v.group_id = (SELECT device_group_id FROM devices WHERE id = $1))
		ORDER BY v.until DESC LIMIT 1`, deviceID).Scan(&until, &group)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v := &Verbose{Until: until, Scope: "device"}
	if group != nil {
		g := group.String()
		v.Scope, v.GroupID = "group", &g
	}
	return v, nil
}

func checkHours(hours int) (time.Duration, error) {
	if hours == 0 {
		hours = DefaultVerboseHours
	}
	if hours < MinVerboseHours || hours > MaxVerboseHours {
		return 0, apperr.Invalid("hours", fmt.Sprintf("must be a whole number from %d to %d", MinVerboseHours, MaxVerboseHours))
	}
	return time.Duration(hours) * time.Hour, nil
}

// SetDeviceVerbose has the device's agents log at Debug for hours hours
// (1 to 24, 2 when zero), replacing an earlier setting of the device's. It
// needs device.edit and is audited. It returns when it ends.
func (s *Service) SetDeviceVerbose(ctx context.Context, c access.Caller, deviceID uuid.UUID, hours int) (time.Time, error) {
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return time.Time{}, err
	}
	if err := c.Require(rbac.PermDeviceEdit, rbac.Site(d.OrganizationID, d.SiteID)); err != nil {
		return time.Time{}, err
	}
	dur, err := checkHours(hours)
	if err != nil {
		return time.Time{}, err
	}
	var until time.Time
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO agent_log_verbose (organization_id, site_id, device_id, until, set_by)
			VALUES ($1, $2, $3, now() + $4::interval, $5)
			ON CONFLICT (device_id) WHERE device_id IS NOT NULL
			DO UPDATE SET until = excluded.until, set_by = excluded.set_by, set_at = now()
			RETURNING until`, d.OrganizationID, d.SiteID, d.ID, dur, setBy(c)).Scan(&until); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.logs_verbose", Outcome: audit.Success,
			OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"device": d.Hostname, "hours": int(dur / time.Hour), "until": until},
		})
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("agentlogs: turning on verbose mode: %w", err)
	}
	return until, nil
}

// ClearDeviceVerbose ends the device's own verbose mode. One set on its
// group stays, and the answer says so.
func (s *Service) ClearDeviceVerbose(ctx context.Context, c access.Caller, deviceID uuid.UUID) error {
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return err
	}
	if err := c.Require(rbac.PermDeviceEdit, rbac.Site(d.OrganizationID, d.SiteID)); err != nil {
		return err
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM agent_log_verbose WHERE device_id = $1`, d.ID)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.logs_verbose_off", Outcome: audit.Success,
			OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"device": d.Hostname},
		})
	})
	if err != nil {
		return fmt.Errorf("agentlogs: turning off verbose mode: %w", err)
	}
	return nil
}

// groupSite finds a device group the caller may see.
func (s *Service) groupSite(ctx context.Context, c access.Caller, id uuid.UUID) (org, site uuid.UUID, name string, err error) {
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id, site_id, name FROM device_groups WHERE id = $1`, id).Scan(&org, &site, &name)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, "", apperr.NotFound()
	}
	if err == nil && !c.Can(rbac.PermDeviceView, rbac.Site(org, site)) {
		return uuid.Nil, uuid.Nil, "", apperr.NotFound()
	}
	return org, site, name, err
}

// SetGroupVerbose is SetDeviceVerbose for every device of a group. It needs
// device.edit at the group's site.
func (s *Service) SetGroupVerbose(ctx context.Context, c access.Caller, groupID uuid.UUID, hours int) (time.Time, error) {
	org, site, name, err := s.groupSite(ctx, c, groupID)
	if err != nil {
		return time.Time{}, err
	}
	if err := c.Require(rbac.PermDeviceEdit, rbac.Site(org, site)); err != nil {
		return time.Time{}, err
	}
	dur, err := checkHours(hours)
	if err != nil {
		return time.Time{}, err
	}
	var until time.Time
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO agent_log_verbose (organization_id, site_id, group_id, until, set_by)
			VALUES ($1, $2, $3, now() + $4::interval, $5)
			ON CONFLICT (group_id) WHERE group_id IS NOT NULL
			DO UPDATE SET until = excluded.until, set_by = excluded.set_by, set_at = now()
			RETURNING until`, org, site, groupID, dur, setBy(c)).Scan(&until); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.logs_verbose", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "device_group", TargetID: groupID.String(),
			Details: map[string]any{"group": name, "hours": int(dur / time.Hour), "until": until},
		})
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("agentlogs: turning on verbose mode: %w", err)
	}
	return until, nil
}

// ClearGroupVerbose ends a group's verbose mode.
func (s *Service) ClearGroupVerbose(ctx context.Context, c access.Caller, groupID uuid.UUID) error {
	org, site, name, err := s.groupSite(ctx, c, groupID)
	if err != nil {
		return err
	}
	if err := c.Require(rbac.PermDeviceEdit, rbac.Site(org, site)); err != nil {
		return err
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM agent_log_verbose WHERE group_id = $1`, groupID)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.logs_verbose_off", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "device_group", TargetID: groupID.String(),
			Details: map[string]any{"group": name},
		})
	})
	if err != nil {
		return fmt.Errorf("agentlogs: turning off verbose mode: %w", err)
	}
	return nil
}
