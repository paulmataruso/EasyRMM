package defenderlog

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/defender"
)

// FleetRow is one computer's protection state, from what is already stored:
// the last defender.status snapshot (refreshed hourly while the module is on),
// the open Defender alerts and the detections of the last 30 days. Nothing here
// sends a job to a device (ADR-0073: cards and fleet tables never do).
type FleetRow struct {
	DeviceID           uuid.UUID  `json:"deviceId"`
	Name               string     `json:"name"`
	SiteID             uuid.UUID  `json:"siteId"`
	SiteName           string     `json:"siteName"`
	RunningMode        string     `json:"runningMode"`
	RealTimeProtection *bool      `json:"realTimeProtection"`
	TamperProtected    *bool      `json:"tamperProtected"`
	SignatureAgeDays   *int       `json:"signatureAgeDays"`
	QuickScanAgeDays   *int       `json:"quickScanAgeDays"`
	ReadAt             *time.Time `json:"readAt"`
	OpenAlerts         int        `json:"openAlerts"`
	Threats30Days      int        `json:"threats30Days"`
}

// Fleet is the table and the counts of a site's or an organization's card.
type Fleet struct {
	Items []FleetRow `json:"items"`
	// Protected: real-time protection is on and Defender is the active
	// antivirus. NotProtected: it is off. Unknown: not read yet, or passive.
	Protected     int `json:"protected"`
	NotProtected  int `json:"notProtected"`
	SignaturesOld int `json:"signaturesOld"`
	Threats30Days int `json:"threats30Days"`
	Unknown       int `json:"unknown"`
}

// SignaturesOldDays is the age at which a card counts signatures as old
// (amber at 3 days, ADR-0074 section 2).
const SignaturesOldDays = 3

// Fleet reads the Defender state of the computers of an organization or a
// site that have the role, where the module is on. It needs defender.view at
// the level.
func (s *Store) Fleet(ctx context.Context, c access.Caller, org uuid.UUID, site *uuid.UUID) (*Fleet, error) {
	scope := rbac.Org(org)
	if site != nil {
		scope = rbac.Site(org, *site)
	}
	if !c.Can(rbac.PermDefenderView, scope) {
		return nil, apperr.NotFound()
	}
	def, ok := modules.Lookup(modules.Defender)
	if !ok {
		return nil, apperr.NotFound()
	}
	out := &Fleet{Items: []FleetRow{}}
	allowed := map[uuid.UUID]bool{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id, d.name, d.site_id, st.name, s.taken_at, s.data,
				(SELECT count(*) FROM alerts a WHERE a.device_id = d.id AND a.kind LIKE 'defender\_%' AND a.status <> 'resolved'),
				(SELECT count(*) FROM defender_events e WHERE e.device_id = d.id AND e.event_id IN (1006, 1116, 1015) AND e.occurred_at > now() - interval '30 days')
			FROM devices d
			JOIN sites st ON st.id = d.site_id
			LEFT JOIN windows_module_snapshots s ON s.device_id = d.id AND s.action = 'defender.status' AND s.params_hash = ''
			WHERE d.organization_id = $1 AND ($2::uuid IS NULL OR d.site_id = $2) AND d.platform = 'windows' AND d.agent_public_key IS NOT NULL
			  AND jsonb_path_exists(coalesce(d.roles, '[]'::jsonb), '$[*] ? (@.name == $role && @.state == "present")', jsonb_build_object('role', $3::text))
			ORDER BY d.name`, org, site, def.Role)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				r    FleetRow
				data []byte
			)
			if err := rows.Scan(&r.DeviceID, &r.Name, &r.SiteID, &r.SiteName, &r.ReadAt, &data, &r.OpenAlerts, &r.Threats30Days); err != nil {
				return err
			}
			on, seen := allowed[r.SiteID]
			if !seen {
				on = s.gate != nil && s.gate.Allowed(ctx, org, r.SiteID, modules.Defender)
				allowed[r.SiteID] = on
			}
			if !on {
				continue
			}
			var st defender.Status
			if len(data) > 0 && json.Unmarshal(data, &st) == nil {
				r.RunningMode, r.RealTimeProtection, r.TamperProtected = st.RunningMode, st.RealTimeProtectionEnabled, st.TamperProtected
				r.SignatureAgeDays, r.QuickScanAgeDays = st.SignatureAgeDays, st.QuickScanAgeDays
			}
			out.Items = append(out.Items, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("defenderlog: reading the fleet: %w", err)
	}
	for _, r := range out.Items {
		passive := r.RunningMode != "" && r.RunningMode != "Normal" && r.RunningMode != "EDR Block Mode"
		switch {
		case r.RealTimeProtection == nil || passive:
			out.Unknown++
		case *r.RealTimeProtection:
			out.Protected++
		default:
			out.NotProtected++
		}
		if r.SignatureAgeDays != nil && *r.SignatureAgeDays >= SignaturesOldDays {
			out.SignaturesOld++
		}
		out.Threats30Days += r.Threats30Days
	}
	return out, nil
}

// SiteOrganization finds the organization of a site the caller can see, or
// not found.
func (s *Store) SiteOrganization(ctx context.Context, c access.Caller, site uuid.UUID) (uuid.UUID, error) {
	var org uuid.UUID
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id FROM sites WHERE id = $1`, site).Scan(&org)
	})
	if err != nil {
		return uuid.Nil, apperr.NotFound()
	}
	return org, nil
}
