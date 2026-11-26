package engine

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/rollup"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Summary is a count of the latest stored results for an organization or a
// site (ADR-0078, section 7: the site's result card). It is read from stored
// results and never starts a job.
type Summary struct {
	Enabled bool `json:"enabled"`
	// Devices is how many computers have a result; Controls how many results.
	Devices int `json:"devices"`
	// Meets, DoesNotMeet and CannotTell count results by the words the
	// console uses (section 9); Stale counts those older than the
	// organization's window, which are not counted among the others.
	Meets       int `json:"meets"`
	DoesNotMeet int `json:"doesNotMeet"`
	CannotTell  int `json:"cannotTell"`
	Stale       int `json:"stale"`
	// FailingDevices is how many computers have a control that does not meet.
	FailingDevices int        `json:"failingDevices"`
	LastScan       *time.Time `json:"lastScan"`
	Disclaimer     string     `json:"disclaimer"`
}

// Summarize counts the latest results of an organization, or of one of its
// sites when site is not the zero id. It needs compliance.view in the
// organization.
func (s *Service) Summarize(ctx context.Context, c access.Caller, org, site uuid.UUID) (*Summary, error) {
	if !c.Can(rbac.PermComplianceView, rbac.Org(org)) {
		return nil, apperr.NotFound()
	}
	out := &Summary{Disclaimer: compliance.Disclaimer}
	now := s.now()
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT coalesce((SELECT enabled FROM compliance_org_settings WHERE organization_id = $1), false)`, org).Scan(&out.Enabled); err != nil {
			return err
		}
		fresh, err := freshness(ctx, tx, org)
		if err != nil {
			return err
		}
		if site != uuid.Nil {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM sites WHERE id = $1 AND organization_id = $2`, site, org).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return apperr.NotFound()
			}
		}
		rows, err := tx.Query(ctx, `SELECT r.device_id, r.state, r.checked_at FROM compliance_results r JOIN devices d ON d.id = r.device_id
			WHERE r.organization_id = $1 AND ($2 = '00000000-0000-0000-0000-000000000000'::uuid OR d.site_id = $2)`, org, site)
		if err != nil {
			return err
		}
		defer rows.Close()
		devs, failing := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
		for rows.Next() {
			var d uuid.UUID
			var r rollup.Result
			if err := rows.Scan(&d, &r.State, &r.CheckedAt); err != nil {
				return err
			}
			devs[d] = true
			st := rollup.EffectiveState(r, now, fresh)
			if st == compliance.StateStale {
				out.Stale++
				continue
			}
			switch compliance.ResultWord(st) {
			case compliance.WordMeets:
				out.Meets++
			case compliance.WordDoesNotMeet:
				out.DoesNotMeet++
				failing[d] = true
			default:
				out.CannotTell++
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		out.Devices, out.FailingDevices = len(devs), len(failing)
		rows.Close()
		var last time.Time
		err = tx.QueryRow(ctx, `SELECT finished_at FROM compliance_scans WHERE organization_id = $1 AND state IN ('done', 'partial')
			AND trigger <> 'verify' ORDER BY started_at DESC LIMIT 1`, org).Scan(&last)
		switch {
		case err == nil:
			out.LastScan = &last
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return err
		}
		return nil
	})
	return out, err
}

// DeviceOrg is the organization of a computer the caller can see.
func (s *Service) DeviceOrg(ctx context.Context, c access.Caller, device uuid.UUID) (uuid.UUID, error) {
	var org uuid.UUID
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id FROM devices WHERE id = $1`, device).Scan(&org)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, apperr.NotFound()
	}
	return org, err
}

// SiteOrg is the organization of a site the caller can see.
func (s *Service) SiteOrg(ctx context.Context, c access.Caller, site uuid.UUID) (uuid.UUID, error) {
	var org uuid.UUID
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id FROM sites WHERE id = $1`, site).Scan(&org)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, apperr.NotFound()
	}
	return org, err
}
