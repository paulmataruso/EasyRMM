// Package tenancy manages organizations, sites and device groups: the
// hierarchy every managed device, permission and report hangs from.
//
// Every query runs inside the caller's row-level-security scope, so objects
// outside it are invisible (reported as not found). Permission checks on top
// of that distinguish reading from changing.
package tenancy

import (
	"context"
	"errors"
	"strings"
	"time"
	_ "time/tzdata" // site time zones must validate in minimal containers
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Field limits, matching the database constraints.
const (
	MaxNameLength        = 200
	MaxNotesLength       = 10000
	MaxAddressLength     = 1000
	MaxDescriptionLength = 2000
)

// Organization is a customer of the MSP (or the MSP itself).
type Organization struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Notes     string    `json:"notes"`
	SiteCount int       `json:"siteCount"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	// CanManage tells the client whether the caller may edit it.
	CanManage bool `json:"canManage"`
	// CanRename tells the client whether the caller may change its name:
	// names are unique on the server, so only platform-wide administrators
	// rename, and an organization's own administrators cannot probe for
	// other customers' names.
	CanRename bool `json:"canRename"`
}

// Site is a location or logical subdivision of an organization.
type Site struct {
	ID               uuid.UUID `json:"id"`
	OrganizationID   uuid.UUID `json:"organizationId"`
	OrganizationName string    `json:"organizationName"`
	Name             string    `json:"name"`
	Timezone         string    `json:"timezone"`
	Address          string    `json:"address"`
	Notes            string    `json:"notes"`
	DeviceGroupCount int       `json:"deviceGroupCount"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
	CanManage        bool      `json:"canManage"`
}

// DeviceGroup organizes devices within a site.
type DeviceGroup struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organizationId"`
	SiteID         uuid.UUID `json:"siteId"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// OrganizationInput is the editable part of an organization.
type OrganizationInput struct {
	Name  string `json:"name"`
	Notes string `json:"notes"`
}

// SiteInput is the editable part of a site.
type SiteInput struct {
	Name     string `json:"name"`
	Timezone string `json:"timezone"`
	Address  string `json:"address"`
	Notes    string `json:"notes"`
}

// DeviceGroupInput is the editable part of a device group.
type DeviceGroupInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Service implements tenancy operations.
type Service struct {
	db       *database.DB
	audit    *audit.Logger
	onChange func()
}

// New builds the service.
func New(db *database.DB, auditLog *audit.Logger) *Service {
	return &Service{db: db, audit: auditLog}
}

// OnChange registers a function called after changes that affect remote
// access: names, sites, roles and account status. It must not block.
func (s *Service) OnChange(f func()) { s.onChange = f }

func (s *Service) changed() {
	if s.onChange != nil {
		s.onChange()
	}
}

func checkName(f apperr.Fields, name string) {
	n := utf8.RuneCountInString(name)
	f.Check(n >= 1, "name", "Enter a name.")
	f.Check(n <= MaxNameLength, "name", "Use at most 200 characters.")
	f.Check(!strings.ContainsAny(name, "\x00\r\n\t"), "name", "Names cannot contain line breaks or control characters.")
}

func (in *OrganizationInput) normalize() error {
	in.Name = strings.TrimSpace(in.Name)
	f := apperr.Fields{}
	checkName(f, in.Name)
	f.Check(utf8.RuneCountInString(in.Notes) <= MaxNotesLength, "notes", "Notes are limited to 10,000 characters.")
	return f.Err()
}

func (in *SiteInput) normalize() error {
	in.Name = strings.TrimSpace(in.Name)
	in.Timezone = strings.TrimSpace(in.Timezone)
	if in.Timezone == "" {
		in.Timezone = "UTC"
	}
	f := apperr.Fields{}
	checkName(f, in.Name)
	f.Check(ValidTimezone(in.Timezone), "timezone", "Choose a time zone from the list, such as Europe/London.")
	f.Check(utf8.RuneCountInString(in.Address) <= MaxAddressLength, "address", "The address is limited to 1,000 characters.")
	f.Check(utf8.RuneCountInString(in.Notes) <= MaxNotesLength, "notes", "Notes are limited to 10,000 characters.")
	return f.Err()
}

func (in *DeviceGroupInput) normalize() error {
	in.Name = strings.TrimSpace(in.Name)
	f := apperr.Fields{}
	checkName(f, in.Name)
	f.Check(utf8.RuneCountInString(in.Description) <= MaxDescriptionLength, "description", "The description is limited to 2,000 characters.")
	return f.Err()
}

// ValidTimezone reports whether tz is an IANA time zone name.
func ValidTimezone(tz string) bool {
	if tz == "" || tz == "Local" || len(tz) > 64 {
		return false
	}
	_, err := time.LoadLocation(tz)
	return err == nil
}

// ---------------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------------

const orgColumns = `o.id, o.name, o.notes, o.created_at, o.updated_at,
	(SELECT count(*) FROM sites s WHERE s.organization_id = o.id)`

func scanOrg(row pgx.Row) (Organization, error) {
	var o Organization
	err := row.Scan(&o.ID, &o.Name, &o.Notes, &o.CreatedAt, &o.UpdatedAt, &o.SiteCount)
	return o, err
}

// ListOrganizations returns the organizations visible to the caller, sorted
// by name. query filters by a case-insensitive name substring.
func (s *Service) ListOrganizations(ctx context.Context, c access.Caller, query string) ([]Organization, error) {
	out := []Organization{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+orgColumns+` FROM organizations o
			WHERE $1 = '' OR strpos(lower(o.name), lower($1)) > 0
			ORDER BY lower(o.name), o.id LIMIT 5000`, strings.TrimSpace(query))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			o, err := scanOrg(rows)
			if err != nil {
				return err
			}
			o.CanManage = c.Can(rbac.PermOrgManage, rbac.Org(o.ID))
			o.CanRename = c.CanGlobal(rbac.PermOrgManage)
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// GetOrganization returns one organization.
func (s *Service) GetOrganization(ctx context.Context, c access.Caller, id uuid.UUID) (*Organization, error) {
	var o Organization
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		o, err = scanOrg(tx.QueryRow(ctx, `SELECT `+orgColumns+` FROM organizations o WHERE o.id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	o.CanManage = c.Can(rbac.PermOrgManage, rbac.Org(o.ID))
	o.CanRename = c.CanGlobal(rbac.PermOrgManage)
	return &o, nil
}

func mapOrgWriteError(err error) error {
	if database.IsUniqueViolation(err) && database.ConstraintName(err) == "organizations_name_key" {
		return apperr.Invalid("name", "An organization with this name already exists.")
	}
	return err
}

// CreateOrganization adds an organization. Only platform-wide administrators
// may do this.
func (s *Service) CreateOrganization(ctx context.Context, c access.Caller, in OrganizationInput) (*Organization, error) {
	if err := c.RequireGlobal(rbac.PermOrgCreate); err != nil {
		return nil, err
	}
	if err := in.normalize(); err != nil {
		return nil, err
	}
	var o Organization
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO organizations (name, notes) VALUES ($1, $2)
			RETURNING id, name, notes, created_at, updated_at`, in.Name, in.Notes).
			Scan(&o.ID, &o.Name, &o.Notes, &o.CreatedAt, &o.UpdatedAt)
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "organization.create", Outcome: audit.Success,
			OrganizationID: o.ID, TargetType: "organization", TargetID: o.ID.String(), Details: map[string]any{"name": o.Name}})
	})
	if err != nil {
		return nil, mapOrgWriteError(err)
	}
	o.CanManage = true
	o.CanRename = c.CanGlobal(rbac.PermOrgManage)
	return &o, nil
}

// UpdateOrganization edits an organization. Changing its name needs
// org.manage platform-wide: names are unique across all organizations, so
// a rename would tell an organization's administrator which other names
// exist.
func (s *Service) UpdateOrganization(ctx context.Context, c access.Caller, id uuid.UUID, in OrganizationInput) (*Organization, error) {
	if _, err := s.GetOrganization(ctx, c, id); err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermOrgManage, rbac.Org(id)); err != nil {
		return nil, err
	}
	if err := in.normalize(); err != nil {
		return nil, err
	}
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var oldName string
		if err := tx.QueryRow(ctx, `SELECT name FROM organizations WHERE id = $1 FOR UPDATE`, id).Scan(&oldName); err != nil {
			return err
		}
		if oldName != in.Name && !c.CanGlobal(rbac.PermOrgManage) {
			return apperr.Invalid("name", "Only a Super Administrator can rename an organization.")
		}
		if _, err := tx.Exec(ctx, `UPDATE organizations SET name = $2, notes = $3 WHERE id = $1`, id, in.Name, in.Notes); err != nil {
			return err
		}
		details := map[string]any{"name": in.Name}
		if oldName != in.Name {
			details["previousName"] = oldName
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "organization.update", Outcome: audit.Success,
			OrganizationID: id, TargetType: "organization", TargetID: id.String(), Details: details})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, mapOrgWriteError(err)
	}
	s.changed()
	return s.GetOrganization(ctx, c, id)
}

// DeleteOrganization removes an empty organization. Sites must be deleted
// first so that nothing is removed by accident.
func (s *Service) DeleteOrganization(ctx context.Context, c access.Caller, id uuid.UUID) error {
	org, err := s.GetOrganization(ctx, c, id)
	if err != nil {
		return err
	}
	if err := c.RequireGlobal(rbac.PermOrgCreate); err != nil {
		return err
	}
	if org.SiteCount > 0 {
		return apperr.Conflict("organization_not_empty", "Delete this organization's sites before deleting it.")
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "organization.delete", Outcome: audit.Success,
			OrganizationID: id, TargetType: "organization", TargetID: id.String(), Details: map[string]any{"name": org.Name}})
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return apperr.NotFound()
	case database.IsForeignKeyViolation(err):
		return apperr.Conflict("organization_not_empty", "Delete this organization's sites before deleting it.")
	}
	return err
}

// ---------------------------------------------------------------------------
// Sites
// ---------------------------------------------------------------------------

const siteColumns = `s.id, s.organization_id, o.name, s.name, s.timezone, s.address, s.notes, s.created_at, s.updated_at,
	(SELECT count(*) FROM device_groups g WHERE g.site_id = s.id)`

func scanSite(row pgx.Row) (Site, error) {
	var x Site
	err := row.Scan(&x.ID, &x.OrganizationID, &x.OrganizationName, &x.Name, &x.Timezone, &x.Address, &x.Notes,
		&x.CreatedAt, &x.UpdatedAt, &x.DeviceGroupCount)
	return x, err
}

// ListSites returns visible sites, optionally limited to one organization.
func (s *Service) ListSites(ctx context.Context, c access.Caller, orgID uuid.UUID, query string) ([]Site, error) {
	out := []Site{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+siteColumns+` FROM sites s JOIN organizations o ON o.id = s.organization_id
			WHERE ($1::uuid IS NULL OR s.organization_id = $1)
			  AND ($2 = '' OR strpos(lower(s.name), lower($2)) > 0)
			ORDER BY lower(o.name), lower(s.name), s.id LIMIT 10000`, nullUUID(orgID), strings.TrimSpace(query))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			x, err := scanSite(rows)
			if err != nil {
				return err
			}
			x.CanManage = c.Can(rbac.PermSiteManage, rbac.Site(x.OrganizationID, x.ID))
			out = append(out, x)
		}
		return rows.Err()
	})
	return out, err
}

// GetSite returns one site.
func (s *Service) GetSite(ctx context.Context, c access.Caller, id uuid.UUID) (*Site, error) {
	var x Site
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		x, err = scanSite(tx.QueryRow(ctx, `SELECT `+siteColumns+` FROM sites s JOIN organizations o ON o.id = s.organization_id WHERE s.id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	x.CanManage = c.Can(rbac.PermSiteManage, rbac.Site(x.OrganizationID, x.ID))
	return &x, nil
}

func mapSiteWriteError(err error) error {
	if database.IsUniqueViolation(err) && database.ConstraintName(err) == "sites_org_name_key" {
		return apperr.Invalid("name", "This organization already has a site with this name.")
	}
	return err
}

// CreateSite adds a site to an organization.
func (s *Service) CreateSite(ctx context.Context, c access.Caller, orgID uuid.UUID, in SiteInput) (*Site, error) {
	if _, err := s.GetOrganization(ctx, c, orgID); err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermOrgManage, rbac.Org(orgID)); err != nil {
		return nil, err
	}
	if err := in.normalize(); err != nil {
		return nil, err
	}
	var id uuid.UUID
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name, timezone, address, notes) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			orgID, in.Name, in.Timezone, in.Address, in.Notes).Scan(&id)
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "site.create", Outcome: audit.Success,
			OrganizationID: orgID, SiteID: id, TargetType: "site", TargetID: id.String(), Details: map[string]any{"name": in.Name}})
	})
	if err != nil {
		return nil, mapSiteWriteError(err)
	}
	s.changed()
	return s.GetSite(ctx, c, id)
}

// UpdateSite edits a site.
func (s *Service) UpdateSite(ctx context.Context, c access.Caller, id uuid.UUID, in SiteInput) (*Site, error) {
	cur, err := s.GetSite(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermSiteManage, rbac.Site(cur.OrganizationID, id)); err != nil {
		return nil, err
	}
	if err := in.normalize(); err != nil {
		return nil, err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE sites SET name = $2, timezone = $3, address = $4, notes = $5 WHERE id = $1`,
			id, in.Name, in.Timezone, in.Address, in.Notes)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		details := map[string]any{"name": in.Name, "timezone": in.Timezone}
		if cur.Name != in.Name {
			details["previousName"] = cur.Name
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "site.update", Outcome: audit.Success,
			OrganizationID: cur.OrganizationID, SiteID: id, TargetType: "site", TargetID: id.String(), Details: details})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, mapSiteWriteError(err)
	}
	s.changed()
	return s.GetSite(ctx, c, id)
}

// DeleteSite removes a site and its device groups. Sites that still have
// devices cannot be deleted (enforced by the devices foreign key).
func (s *Service) DeleteSite(ctx context.Context, c access.Caller, id uuid.UUID) error {
	cur, err := s.GetSite(ctx, c, id)
	if err != nil {
		return err
	}
	if err := c.Require(rbac.PermOrgManage, rbac.Org(cur.OrganizationID)); err != nil {
		return err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM sites WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "site.delete", Outcome: audit.Success,
			OrganizationID: cur.OrganizationID, SiteID: id, TargetType: "site", TargetID: id.String(), Details: map[string]any{"name": cur.Name}})
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return apperr.NotFound()
	case database.IsForeignKeyViolation(err):
		// Moving and retiring devices are not available yet, so the message only states the rule.
		return apperr.Conflict("site_not_empty", "This site still has devices, so it cannot be deleted.")
	case err == nil:
		s.changed()
	}
	return err
}

// ---------------------------------------------------------------------------
// Device groups
// ---------------------------------------------------------------------------

const groupColumns = `id, organization_id, site_id, name, description, created_at, updated_at`

func scanGroup(row pgx.Row) (DeviceGroup, error) {
	var g DeviceGroup
	err := row.Scan(&g.ID, &g.OrganizationID, &g.SiteID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt)
	return g, err
}

// ListDeviceGroups returns a site's device groups.
func (s *Service) ListDeviceGroups(ctx context.Context, c access.Caller, siteID uuid.UUID) ([]DeviceGroup, error) {
	if _, err := s.GetSite(ctx, c, siteID); err != nil {
		return nil, err
	}
	out := []DeviceGroup{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+groupColumns+` FROM device_groups WHERE site_id = $1 ORDER BY lower(name), id`, siteID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, err := scanGroup(rows)
			if err != nil {
				return err
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Service) getGroup(ctx context.Context, c access.Caller, id uuid.UUID) (*DeviceGroup, error) {
	var g DeviceGroup
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		g, err = scanGroup(tx.QueryRow(ctx, `SELECT `+groupColumns+` FROM device_groups WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	return &g, err
}

func mapGroupWriteError(err error) error {
	if database.IsUniqueViolation(err) && database.ConstraintName(err) == "device_groups_site_name_key" {
		return apperr.Invalid("name", "This site already has a group with this name.")
	}
	return err
}

// CreateDeviceGroup adds a device group to a site.
func (s *Service) CreateDeviceGroup(ctx context.Context, c access.Caller, siteID uuid.UUID, in DeviceGroupInput) (*DeviceGroup, error) {
	site, err := s.GetSite(ctx, c, siteID)
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermSiteManage, rbac.Site(site.OrganizationID, siteID)); err != nil {
		return nil, err
	}
	if err := in.normalize(); err != nil {
		return nil, err
	}
	var id uuid.UUID
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO device_groups (organization_id, site_id, name, description) VALUES ($1, $2, $3, $4) RETURNING id`,
			site.OrganizationID, siteID, in.Name, in.Description).Scan(&id)
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "device_group.create", Outcome: audit.Success,
			OrganizationID: site.OrganizationID, SiteID: siteID, TargetType: "device_group", TargetID: id.String(), Details: map[string]any{"name": in.Name}})
	})
	if err != nil {
		return nil, mapGroupWriteError(err)
	}
	return s.getGroup(ctx, c, id)
}

// UpdateDeviceGroup edits a device group.
func (s *Service) UpdateDeviceGroup(ctx context.Context, c access.Caller, id uuid.UUID, in DeviceGroupInput) (*DeviceGroup, error) {
	g, err := s.getGroup(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermSiteManage, rbac.Site(g.OrganizationID, g.SiteID)); err != nil {
		return nil, err
	}
	if err := in.normalize(); err != nil {
		return nil, err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE device_groups SET name = $2, description = $3 WHERE id = $1`, id, in.Name, in.Description)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "device_group.update", Outcome: audit.Success,
			OrganizationID: g.OrganizationID, SiteID: g.SiteID, TargetType: "device_group", TargetID: id.String(), Details: map[string]any{"name": in.Name}})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, mapGroupWriteError(err)
	}
	return s.getGroup(ctx, c, id)
}

// DeleteDeviceGroup removes a device group. Devices in it stay in the site,
// ungrouped.
func (s *Service) DeleteDeviceGroup(ctx context.Context, c access.Caller, id uuid.UUID) error {
	g, err := s.getGroup(ctx, c, id)
	if err != nil {
		return err
	}
	if err := c.Require(rbac.PermSiteManage, rbac.Site(g.OrganizationID, g.SiteID)); err != nil {
		return err
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM device_groups WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "device_group.delete", Outcome: audit.Success,
			OrganizationID: g.OrganizationID, SiteID: g.SiteID, TargetType: "device_group", TargetID: id.String(), Details: map[string]any{"name": g.Name}})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return apperr.NotFound()
	}
	return err
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
