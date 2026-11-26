package monitoring

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
)

// MaxSlowDevices bounds the list a policy shows.
const MaxSlowDevices = 500

// SlowDevice is a device a policy covers whose heartbeat interval makes the
// policy wait longer than its minutes (ADR-0058): an Offline policy waits
// three of the device's intervals, a processor, memory or disk policy
// judges a window of at least 1.2 intervals.
type SlowDevice struct {
	DeviceID         uuid.UUID `json:"deviceId"`
	Name             string    `json:"name"`
	SiteID           uuid.UUID `json:"siteId"`
	SiteName         string    `json:"siteName"`
	HeartbeatSeconds int       `json:"heartbeatSeconds"`
	// WaitMinutes is how long the policy really waits on this device, rounded
	// up.
	WaitMinutes int `json:"waitMinutes"`
}

// SlowDevices lists the enrolled devices the caller can see that the policy
// covers and that wait longer than the policy's minutes, longest first, and
// how many there are.
func (s *Service) SlowDevices(ctx context.Context, c access.Caller, id uuid.UUID) ([]SlowDevice, int, error) {
	out := []SlowDevice{}
	total := 0
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if _, err := s.getPolicy(ctx, tx, c, id, false); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT d.id, d.name, d.site_id, st.name, d.agent_heartbeat_seconds,
				ceil(greatest(p.minutes * 60, CASE p.kind WHEN 'offline' THEN 3.0 ELSE `+windowIntervals+` END * d.agent_heartbeat_seconds) / 60)::int AS wait,
				count(*) OVER ()
			FROM alert_policies p
			JOIN devices d ON d.agent_public_key IS NOT NULL AND NOT d.quick_assist AND (p.organization_id IS NULL
				OR (p.organization_id = d.organization_id AND (p.site_id IS NULL OR p.site_id = d.site_id)))
			JOIN sites st ON st.id = d.site_id
			WHERE p.id = $1 AND p.kind IN ('offline', 'cpu', 'memory', 'disk')
			  AND CASE p.kind WHEN 'offline' THEN 3.0 ELSE `+windowIntervals+` END * d.agent_heartbeat_seconds > p.minutes * 60
			ORDER BY wait DESC, d.name, d.id LIMIT $2`, id, MaxSlowDevices)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d SlowDevice
			if err := rows.Scan(&d.DeviceID, &d.Name, &d.SiteID, &d.SiteName, &d.HeartbeatSeconds, &d.WaitMinutes, &total); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, total, err
}
