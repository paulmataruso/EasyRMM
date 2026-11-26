package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// CleanRoles keeps the roles of a report that the server knows: a known
// name with a known state, once each, in the order of agentproto.RoleNames.
// The agent's version text is cut to 64 characters. Nothing here fails: an
// odd report never stops a heartbeat.
func CleanRoles(in []agentproto.Role) []agentproto.Role {
	out := []agentproto.Role{}
	for _, name := range agentproto.RoleNames {
		for _, r := range in {
			if r.Name != name || !agentproto.ValidRoleState(r.State) {
				continue
			}
			r.Version = cleanText(r.Version, 64)
			out = append(out, r)
			break
		}
	}
	return out
}

func cleanText(s string, maxRunes int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxRunes {
		s = string([]rune(s)[:maxRunes])
	}
	return s
}

// StoreRoles records what a heartbeat reported, inside its transaction, and
// says whether the agent is to rescan at once. A nil report (an agent that
// does not detect roles, or could not) leaves the stored list alone: it
// reads as unknown once RolesKnownFor has passed. A role that was reported
// before and is missing now is removed, and the registered hooks run for it
// (ADR-0073). An organization outside the dev scope stores nothing.
func (s *Service) StoreRoles(ctx context.Context, tx pgx.Tx, deviceID, orgID uuid.UUID, reported []agentproto.Role) (rescan bool, err error) {
	if !devscope.Allowed(orgID) {
		return false, nil
	}
	var old []byte
	if err := tx.QueryRow(ctx, `SELECT roles, roles_rescan FROM devices WHERE id = $1 FOR UPDATE`, deviceID).Scan(&old, &rescan); err != nil {
		return false, fmt.Errorf("modules: reading roles: %w", err)
	}
	if reported == nil {
		if rescan {
			_, err = tx.Exec(ctx, `UPDATE devices SET roles_rescan = false WHERE id = $1`, deviceID)
		}
		return rescan, err
	}
	clean := CleanRoles(reported)
	b, err := json.Marshal(clean)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET roles = $2, roles_at = now(), roles_rescan = false WHERE id = $1`, deviceID, b); err != nil {
		return false, fmt.Errorf("modules: storing roles: %w", err)
	}
	var before []agentproto.Role
	if len(old) > 0 {
		_ = json.Unmarshal(old, &before)
	}
	for _, r := range before {
		if slices.ContainsFunc(clean, func(n agentproto.Role) bool { return n.Name == r.Name }) {
			continue
		}
		def, ok := ForRole(r.Name)
		if !ok {
			continue
		}
		for _, h := range s.removed {
			if err := h(ctx, tx, deviceID, orgID, def.Module); err != nil {
				return false, fmt.Errorf("modules: clearing %s after its role was removed: %w", def.Module, err)
			}
		}
	}
	return rescan, nil
}

// DeviceRole is one role of a device as the console shows it.
type DeviceRole struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
	// Module is the module the role offers; Enabled says whether it is on
	// for the device's site.
	Module  Module `json:"module"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
}

// DeviceRoles is a device's roles. Known is false when the agent has not
// reported any, or last did more than RolesKnownFor ago: the console then
// says "not detected yet", never "not installed".
type DeviceRoles struct {
	Known      bool         `json:"known"`
	ReportedAt *time.Time   `json:"reportedAt"`
	Roles      []DeviceRole `json:"roles"`
}

type stored struct {
	roles []agentproto.Role
	at    *time.Time
}

func (s *Service) storedRoles(ctx context.Context, deviceID uuid.UUID) (stored, error) {
	var (
		raw []byte
		out stored
	)
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT roles, roles_at FROM devices WHERE id = $1`, deviceID).Scan(&raw, &out.at)
	})
	if err != nil {
		return stored{}, err
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out.roles)
	}
	return out, nil
}

func (st stored) known(now time.Time) bool {
	return st.at != nil && now.Sub(*st.at) <= RolesKnownFor
}

// Roles returns a device's roles. It needs device.view at the device.
func (s *Service) Roles(ctx context.Context, c access.Caller, deviceID uuid.UUID) (*DeviceRoles, error) {
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return nil, err
	}
	st, err := s.storedRoles(ctx, d.ID)
	if err != nil {
		return nil, fmt.Errorf("modules: reading roles: %w", err)
	}
	out := &DeviceRoles{Known: st.known(s.now()), ReportedAt: st.at, Roles: []DeviceRole{}}
	if !out.Known {
		return out, nil
	}
	for _, r := range st.roles {
		def, ok := ForRole(r.Name)
		if !ok {
			continue
		}
		on, err := s.Enabled(ctx, d.OrganizationID, d.SiteID, def.Module)
		if err != nil {
			return nil, fmt.Errorf("modules: reading the toggle: %w", err)
		}
		out.Roles = append(out.Roles, DeviceRole{Name: r.Name, State: r.State, Version: r.Version, Module: def.Module, Label: def.Label, Enabled: on})
	}
	return out, nil
}

// Offered finds a device for a module's endpoint. The module is offered when
// the device reported its role, the module is on for the device's site and
// the caller may view it; otherwise the answer is not found, never forbidden,
// so that the endpoint confirms nothing about the device's roles.
func (s *Service) Offered(ctx context.Context, c access.Caller, deviceID uuid.UUID, m Module) (*devices.Device, error) {
	def, ok := Lookup(m)
	if !ok {
		return nil, apperr.NotFound()
	}
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return nil, err
	}
	if !c.Can(def.View, rbac.Site(d.OrganizationID, d.SiteID)) {
		return nil, apperr.NotFound()
	}
	st, err := s.storedRoles(ctx, d.ID)
	if err != nil {
		return nil, fmt.Errorf("modules: reading roles: %w", err)
	}
	if !st.known(s.now()) || !slices.ContainsFunc(st.roles, func(r agentproto.Role) bool { return r.Name == def.Role }) {
		return nil, apperr.NotFound()
	}
	on, err := s.Enabled(ctx, d.OrganizationID, d.SiteID, m)
	if err != nil {
		return nil, fmt.Errorf("modules: reading the toggle: %w", err)
	}
	if !on {
		return nil, apperr.NotFound()
	}
	return d, nil
}

// RequestRescan asks a device's agent to detect its roles at once, at its
// next heartbeat. It needs device.edit and is audited.
func (s *Service) RequestRescan(ctx context.Context, c access.Caller, deviceID uuid.UUID) error {
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return err
	}
	if err := c.Require(rbac.PermDeviceEdit, rbac.Site(d.OrganizationID, d.SiteID)); err != nil {
		return err
	}
	if !devscope.Allowed(d.OrganizationID) {
		return apperr.Conflict("dev_scope", "this organization is outside the development scope")
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE devices SET roles_rescan = true WHERE id = $1`, d.ID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.roles_rescan", Outcome: audit.Success,
			OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"device": d.Hostname},
		})
	})
	if err != nil {
		return fmt.Errorf("modules: asking for a rescan: %w", err)
	}
	return nil
}
