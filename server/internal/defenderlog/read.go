package defenderlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/defender"
)

// Offerer is modules.Service.Offered: a device's module endpoint, or not found.
type Offerer interface {
	Offered(ctx context.Context, c access.Caller, deviceID uuid.UUID, m modules.Module) (*devices.Device, error)
}

// Event is one stored event as the console shows it. Sensitive is set only
// for a caller who holds defender.view_sensitive.
type Event struct {
	ID         int64           `json:"id"`
	EventID    int             `json:"eventId"`
	At         time.Time       `json:"at"`
	Severity   int             `json:"severity"`
	ThreatName string          `json:"threatName,omitempty"`
	Category   string          `json:"category,omitempty"`
	Action     string          `json:"action,omitempty"`
	Summary    json.RawMessage `json:"summary"`
	Sensitive  json.RawMessage `json:"sensitive,omitempty"`
	Ours       bool            `json:"ours"`
	Backfill   bool            `json:"backfill"`
}

// Events is a device's recent events, newest first.
type Events struct {
	Items []Event `json:"items"`
	// Gap is when events may have been missed (a cleared or wrapped log).
	Gap *time.Time `json:"gap"`
}

// MaxEvents is the most one read returns.
const MaxEvents = 200

// List returns a device's events for the Events panel. It needs the module
// offered on the device (defender.view, 404 otherwise); a caller without
// defender.view_sensitive gets the summaries only, which hold no path, user
// or changed value.
func (s *Store) List(ctx context.Context, o Offerer, c access.Caller, deviceID uuid.UUID, limit int) (*Events, error) {
	d, err := o.Offered(ctx, c, deviceID, modules.Defender)
	if err != nil {
		return nil, err
	}
	limit = max(1, min(limit, MaxEvents))
	sensitive := c.Can(rbac.PermDefenderViewSensitive, rbac.Site(d.OrganizationID, d.SiteID))
	out := &Events{Items: []Event{}}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, event_id, occurred_at, severity, threat_name, category, action, summary, sensitive, ours, backfill
			FROM defender_events WHERE device_id = $1 ORDER BY occurred_at DESC, id DESC LIMIT $2`, d.ID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e Event
			var sens []byte
			if err := rows.Scan(&e.ID, &e.EventID, &e.At, &e.Severity, &e.ThreatName, &e.Category, &e.Action, &e.Summary, &sens, &e.Ours, &e.Backfill); err != nil {
				return err
			}
			if sensitive && len(sens) > 0 {
				e.Sensitive = sens
			}
			out.Items = append(out.Items, e)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		var gap *string
		if err := tx.QueryRow(ctx, `SELECT data->>'gap' FROM windows_module_snapshots WHERE device_id = $1 AND action = $2 AND params_hash = ''`,
			d.ID, defender.EventsAction).Scan(&gap); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if gap != nil {
			if t, err := time.Parse(time.RFC3339, *gap); err == nil {
				out.Gap = &t
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("defenderlog: reading events: %w", err)
	}
	return out, nil
}
