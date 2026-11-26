package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Fleet states of one computer, from its last backup.status snapshot.
const (
	StateOK            = "ok"             // a successful backup in the last 24 hours
	StateFailed        = "failed"         // the last run failed and no success followed
	StateOverdue       = "overdue"        // no success for 2 days, or never
	StateNotConfigured = "not_configured" // the feature is installed with no policy
	StateNotInstalled  = "not_installed"  // a server without the feature
	StateNoData        = "no_data"        // not read yet, or a desktop (not managed)
	StateStale         = "stale"          // a success 1 to 2 days ago
)

// FleetDevice is one computer in the Backup card's table.
type FleetDevice struct {
	DeviceID    uuid.UUID  `json:"deviceId"`
	SiteID      uuid.UUID  `json:"siteId"`
	Name        string     `json:"name"`
	State       string     `json:"state"`
	LastSuccess *time.Time `json:"lastSuccess"`
	LastFailure *time.Time `json:"lastFailure"`
	OpenAlerts  int        `json:"openAlerts"`
}

// FleetCounts are the numbers of the card.
type FleetCounts struct {
	BackedUp      int `json:"backedUp"`
	Stale         int `json:"stale"`
	Failed        int `json:"failed"`
	Overdue       int `json:"overdue"`
	NotConfigured int `json:"notConfigured"`
	NotInstalled  int `json:"notInstalled"`
	NoData        int `json:"noData"`
}

// Fleet is what the organization and site Backup cards show. A card sends no
// job: it reads the stored snapshots.
type Fleet struct {
	Enabled bool          `json:"enabled"`
	Counts  FleetCounts   `json:"counts"`
	Devices []FleetDevice `json:"devices"`
}

// Level is where a card sits.
type Level string

// Levels.
const (
	AtOrganization Level = "organization"
	AtSite         Level = "site"
)

// Cards reads the Backup cards' numbers.
type Cards struct {
	db   *database.DB
	mods *modules.Service
	now  func() time.Time
}

// NewCards builds the reader.
func NewCards(db *database.DB, mods *modules.Service) *Cards {
	return &Cards{db: db, mods: mods, now: time.Now}
}

// classify turns a snapshot into a state. A desktop (role kind "client") is
// not managed and shows no state.
func classify(role string, snap *Status, at time.Time) string {
	switch {
	case role == "not_installed" || (snap != nil && !snap.Installed):
		return StateNotInstalled
	case snap == nil:
		return StateNoData
	case !snap.Configured:
		return StateNotConfigured
	case snap.LastFailure != nil && (snap.LastSuccess == nil || snap.LastFailure.After(*snap.LastSuccess)):
		return StateFailed
	case snap.LastSuccess == nil || at.Sub(*snap.LastSuccess) >= 48*time.Hour:
		return StateOverdue
	case at.Sub(*snap.LastSuccess) >= 24*time.Hour:
		return StateStale
	}
	return StateOK
}

// Read returns the card for an organization or a site. It needs
// backup.view there; someone who lacks it gets not found, as elsewhere.
func (c *Cards) Read(ctx context.Context, caller access.Caller, l Level, id uuid.UUID) (*Fleet, error) {
	var org, site uuid.UUID
	err := c.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		if l == AtSite {
			site = id
			return tx.QueryRow(ctx, `SELECT organization_id FROM sites WHERE id = $1`, id).Scan(&org)
		}
		org = id
		return tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id = $1`, id).Scan(&org)
	})
	if err != nil || !caller.Can(rbac.PermBackupView, scope(org, site)) {
		return nil, apperr.NotFound()
	}
	f := &Fleet{Devices: []FleetDevice{}}
	if f.Enabled, err = c.mods.Enabled(ctx, org, site, modules.WindowsBackup); err != nil {
		return nil, fmt.Errorf("backup: reading the toggle: %w", err)
	}
	if !f.Enabled {
		return f, nil
	}
	at := c.now()
	err = c.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT d.id, d.site_id, d.name, r->>'state', s.data,
			       (SELECT count(*) FROM alerts a WHERE a.device_id = d.id AND a.status <> 'resolved' AND a.kind LIKE 'backup\_%')
			FROM devices d
			CROSS JOIN LATERAL jsonb_array_elements(d.roles) r
			LEFT JOIN windows_module_snapshots s
			       ON s.device_id = d.id AND s.action = 'windows_backup.status' AND s.params_hash = ''
			WHERE d.organization_id = $1 AND ($2::uuid IS NULL OR d.site_id = $2) AND d.platform = 'windows'
			  AND r->>'name' = 'windows_backup'
			ORDER BY d.name, d.id`, org, nullID(site))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				fd    FleetDevice
				state string
				data  []byte
			)
			if err := rows.Scan(&fd.DeviceID, &fd.SiteID, &fd.Name, &state, &data, &fd.OpenAlerts); err != nil {
				return err
			}
			var snap *Status
			if len(data) > 0 {
				var st Status
				if json.Unmarshal(data, &st) == nil {
					snap = &st
					fd.LastSuccess, fd.LastFailure = st.LastSuccess, st.LastFailure
				}
			}
			fd.State = classify(state, snap, at)
			f.Devices = append(f.Devices, fd)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("backup: reading the fleet: %w", err)
	}
	for _, d := range f.Devices {
		switch d.State {
		case StateOK:
			f.Counts.BackedUp++
		case StateStale:
			f.Counts.Stale++
		case StateFailed:
			f.Counts.Failed++
		case StateOverdue:
			f.Counts.Overdue++
		case StateNotConfigured:
			f.Counts.NotConfigured++
		case StateNotInstalled:
			f.Counts.NotInstalled++
		default:
			f.Counts.NoData++
		}
	}
	return f, nil
}

func scope(org, site uuid.UUID) rbac.Resource {
	if site == uuid.Nil {
		return rbac.Org(org)
	}
	return rbac.Site(org, site)
}

func nullID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
