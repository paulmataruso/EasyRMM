package agentsettings

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// limitsSetting is the platform's limits in the settings table.
const limitsSetting = "agent_settings.limits"

// Limits are what the platform sets about agent settings and that never
// reach an agent (ADR-0058). The most live connections one organization may
// hold arrives with ADR-0059's first slice, which uses it.
type Limits struct {
	// MinHeartbeatSeconds is the shortest interval organizations, sites and
	// devices may set: 30 seconds by default, at most 300.
	MinHeartbeatSeconds int `json:"minHeartbeatSeconds"`
}

// DefaultLimits are the limits where the platform has set none.
func DefaultLimits() Limits { return Limits{MinHeartbeatSeconds: MinHeartbeatSeconds} }

func (l Limits) check() error {
	if l.MinHeartbeatSeconds < MinHeartbeatSeconds || l.MinHeartbeatSeconds > MaxHeartbeatSeconds {
		return &apperr.Error{Kind: apperr.KindInvalid, Code: "setting_invalid", Message: "Some fields need attention.",
			Fields: map[string]string{"minHeartbeatSeconds": "Use a whole number from 30 to 300."}}
	}
	return nil
}

// readLimits reads the limits inside a transaction. A missing or damaged
// setting means the defaults.
func readLimits(ctx context.Context, tx pgx.Tx) (Limits, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, limitsSetting).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultLimits(), nil
	}
	if err != nil {
		return Limits{}, err
	}
	l := DefaultLimits()
	if json.Unmarshal(raw, &l) != nil || l.check() != nil {
		return DefaultLimits(), nil //nolint:nilerr // a damaged setting means the defaults, never a refused heartbeat
	}
	return l, nil
}

// Limits returns the platform's limits.
func (s *Service) Limits(ctx context.Context) (Limits, error) {
	var l Limits
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) (err error) {
		l, err = readLimits(ctx, tx)
		return err
	})
	return l, err
}

// SetLimits changes the platform's limits. It needs settings.manage, and is
// audited and rate limited like every write.
func (s *Service) SetLimits(ctx context.Context, c access.Caller, in Limits) (Limits, error) {
	if err := c.RequireGlobal(rbac.PermSettingsManage); err != nil {
		return Limits{}, err
	}
	if err := s.allowWrite(c, "platform"); err != nil {
		return Limits{}, err
	}
	if err := in.check(); err != nil {
		return Limits{}, err
	}
	var old Limits
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var err error
		if old, err = readLimits(ctx, tx); err != nil {
			return err
		}
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		var by any
		if c.Principal != nil {
			by = c.Principal.UserID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value, updated_at, updated_by) VALUES ($1, $2, now(), $3)
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by`,
			limitsSetting, raw, by); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: ActionLimitsSet, Outcome: audit.Success, TargetType: "agent_settings", TargetID: "limits",
			Details: map[string]any{"minHeartbeatSeconds": in.MinHeartbeatSeconds, "oldMinHeartbeatSeconds": old.MinHeartbeatSeconds},
		})
	})
	return in, err
}
