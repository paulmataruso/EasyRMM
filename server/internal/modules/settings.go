package modules

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

// Setting is one module's toggle at an organization or a site.
type Setting struct {
	Module Module `json:"module"`
	Label  string `json:"label"`
	// Enabled is what applies here: the site's override, else the
	// organization's, else on.
	Enabled bool `json:"enabled"`
	// Override is the row at this level, nil when there is none and the
	// level inherits (at an organization, when it has the default).
	Override *bool `json:"override"`
}

// scope is where a toggle is read or set.
type scope struct {
	org, site uuid.UUID // site is Nil for an organization
	name      string    // "organization" or "site"
}

func (s *Service) organizationScope(ctx context.Context, c access.Caller, id uuid.UUID) (scope, error) {
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var got uuid.UUID
		return tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id = $1`, id).Scan(&got)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return scope{}, apperr.NotFound()
	}
	return scope{org: id, name: "organization"}, err
}

func (s *Service) siteScope(ctx context.Context, c access.Caller, id uuid.UUID) (scope, error) {
	var org uuid.UUID
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id FROM sites WHERE id = $1`, id).Scan(&org)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return scope{}, apperr.NotFound()
	}
	return scope{org: org, site: id, name: "site"}, err
}

func (sc scope) resource() rbac.Resource {
	if sc.site == uuid.Nil {
		return rbac.Org(sc.org)
	}
	return rbac.Site(sc.org, sc.site)
}

// view and manage are the permissions for the level.
func (sc scope) view() rbac.Permission {
	if sc.site == uuid.Nil {
		return rbac.PermOrgView
	}
	return rbac.PermSiteView
}

func (sc scope) manage() rbac.Permission {
	if sc.site == uuid.Nil {
		return rbac.PermOrgManage
	}
	return rbac.PermSiteManage
}

// Level says whether an id names an organization or a site.
type Level string

// The levels a toggle is set at.
const (
	AtOrganization Level = "organization"
	AtSite         Level = "site"
)

func (s *Service) resolveScope(ctx context.Context, c access.Caller, l Level, id uuid.UUID) (scope, error) {
	var (
		sc  scope
		err error
	)
	if l == AtSite {
		sc, err = s.siteScope(ctx, c, id)
	} else {
		sc, err = s.organizationScope(ctx, c, id)
	}
	if err != nil {
		return scope{}, err
	}
	// Someone who may not see the level gets not found, as elsewhere.
	if !c.Can(sc.view(), sc.resource()) {
		return scope{}, apperr.NotFound()
	}
	return sc, nil
}

// Settings lists every module's toggle at an organization or a site. It
// needs org.view or site.view there.
func (s *Service) Settings(ctx context.Context, c access.Caller, l Level, id uuid.UUID) ([]Setting, error) {
	sc, err := s.resolveScope(ctx, c, l, id)
	if err != nil {
		return nil, err
	}
	out := make([]Setting, 0, len(Catalog))
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, def := range Catalog {
			st := Setting{Module: def.Module, Label: def.Label}
			if err := enabledIn(ctx, tx, sc.org, sc.site, def.Module, &st.Enabled); err != nil {
				return err
			}
			var o bool
			err := tx.QueryRow(ctx, `SELECT enabled FROM windows_module_settings
				WHERE module = $1 AND organization_id = $2 AND site_id IS NOT DISTINCT FROM $3`,
				string(def.Module), sc.org, nullID(sc.site)).Scan(&o)
			switch {
			case err == nil:
				st.Override = &o
			case !errors.Is(err, pgx.ErrNoRows):
				return err
			}
			out = append(out, st)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("modules: reading the toggles: %w", err)
	}
	return out, nil
}

func nullID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// SetEnabled turns a module on or off at an organization (org.manage) or
// overrides it at a site (site.manage), and audits the change. Turning a
// module off deletes nothing: its stored data ages out under retention.
func (s *Service) SetEnabled(ctx context.Context, c access.Caller, l Level, id uuid.UUID, m Module, enabled bool) error {
	if _, ok := Lookup(m); !ok {
		return apperr.Invalid("module", "is not a Windows module")
	}
	sc, err := s.resolveScope(ctx, c, l, id)
	if err != nil {
		return err
	}
	if err := c.Require(sc.manage(), sc.resource()); err != nil {
		return err
	}
	return s.change(ctx, c, sc, m, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE windows_module_settings SET enabled = $4, set_by = $5, set_at = now()
			WHERE module = $1 AND organization_id = $2 AND site_id IS NOT DISTINCT FROM $3`,
			string(m), sc.org, nullID(sc.site), enabled, c.Actor.Label)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO windows_module_settings (organization_id, site_id, module, enabled, set_by)
			SELECT $2, $3, $1, $4, $5
			WHERE NOT EXISTS (SELECT 1 FROM windows_module_settings
				WHERE module = $1 AND organization_id = $2 AND site_id IS NOT DISTINCT FROM $3)`,
			string(m), sc.org, nullID(sc.site), enabled, c.Actor.Label)
		return err
	})
}

// ClearOverride removes a site's own row for a module, so that the site
// follows its organization again. It needs site.manage.
func (s *Service) ClearOverride(ctx context.Context, c access.Caller, siteID uuid.UUID, m Module) error {
	if _, ok := Lookup(m); !ok {
		return apperr.Invalid("module", "is not a Windows module")
	}
	sc, err := s.resolveScope(ctx, c, AtSite, siteID)
	if err != nil {
		return err
	}
	if err := c.Require(sc.manage(), sc.resource()); err != nil {
		return err
	}
	return s.change(ctx, c, sc, m, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM windows_module_settings WHERE module = $1 AND site_id = $2`, string(m), sc.site)
		return err
	})
}

// change runs write and audits windows_module.set with the module, the
// scope and the old and new value that applies there.
func (s *Service) change(ctx context.Context, c access.Caller, sc scope, m Module, write func(pgx.Tx) error) error {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var before, after bool
		if err := enabledIn(ctx, tx, sc.org, sc.site, m, &before); err != nil {
			return err
		}
		if err := write(tx); err != nil {
			return err
		}
		if err := enabledIn(ctx, tx, sc.org, sc.site, m, &after); err != nil {
			return err
		}
		target, targetType := sc.org, "organization"
		if sc.site != uuid.Nil {
			target, targetType = sc.site, "site"
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "windows_module.set", Outcome: audit.Success,
			OrganizationID: sc.org, SiteID: sc.site, TargetType: targetType, TargetID: target.String(),
			Details: map[string]any{"module": string(m), "scope": sc.name, "old": before, "new": after},
		})
	})
	if err != nil {
		return fmt.Errorf("modules: changing the toggle: %w", err)
	}
	return nil
}
