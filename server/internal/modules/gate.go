package modules

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// Allowed is the gate of every scheduled read, rescan, alert evaluation and
// default-policy creation a module starts (ADR-0073): the organization must
// be inside the dev scope and the module must be on for the site. It is the
// only way the framework dispatches such work. A site of uuid.Nil asks at
// the organization. When the toggle cannot be read the answer is no.
func (s *Service) Allowed(ctx context.Context, org, site uuid.UUID, m Module) bool {
	if !devscope.Allowed(org) {
		return false
	}
	on, err := s.Enabled(ctx, org, site, m)
	return err == nil && on
}

// Enabled resolves a module's toggle: the site's own row wins over the
// organization's, and with neither the module is on.
func (s *Service) Enabled(ctx context.Context, org, site uuid.UUID, m Module) (bool, error) {
	var on bool
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return enabledIn(ctx, tx, org, site, m, &on)
	})
	return on, err
}

func enabledIn(ctx context.Context, tx pgx.Tx, org, site uuid.UUID, m Module, on *bool) error {
	// A site's row sorts first; the organization's row has a NULL site.
	err := tx.QueryRow(ctx, `SELECT enabled FROM windows_module_settings
		WHERE module = $3 AND ((site_id = $2) OR (site_id IS NULL AND organization_id = $1))
		ORDER BY site_id IS NULL LIMIT 1`, org, site, string(m)).Scan(on)
	if errors.Is(err, pgx.ErrNoRows) {
		*on = true
		return nil
	}
	return err
}
