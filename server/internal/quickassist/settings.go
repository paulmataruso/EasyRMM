package quickassist

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Setting keys (ADR-0080). A missing or out-of-range value is the default.
const (
	SettingIdleMinutes     = "quickassist.idle_minutes"
	SettingMaxSessionHours = "quickassist.max_session_hours"
	SettingRetentionDays   = "quickassist.retention_days"
	SettingBucketBurst     = "quickassist.bucket_burst"
	SettingBucketRefill    = "quickassist.bucket_refill_minutes"
	SettingWaitingCap      = "quickassist.waiting_cap"
	SettingPermanentCap    = "quickassist.permanent_link_cap"
)

// Settings are the configurable limits of Quick Assist.
type Settings struct {
	IdleMinutes         int `json:"idleMinutes"`
	MaxSessionHours     int `json:"maxSessionHours"`
	RetentionDays       int `json:"retentionDays"`
	BucketBurst         int `json:"bucketBurst"`
	BucketRefillMinutes int `json:"bucketRefillMinutes"`
	WaitingCap          int `json:"waitingCap"`
	PermanentLinkCap    int `json:"permanentLinkCap"`
}

// SettingsPatch is a change to the limits: only the fields that are set.
type SettingsPatch struct {
	IdleMinutes         *int `json:"idleMinutes"`
	MaxSessionHours     *int `json:"maxSessionHours"`
	RetentionDays       *int `json:"retentionDays"`
	BucketBurst         *int `json:"bucketBurst"`
	BucketRefillMinutes *int `json:"bucketRefillMinutes"`
	WaitingCap          *int `json:"waitingCap"`
	PermanentLinkCap    *int `json:"permanentLinkCap"`
}

// DefaultSettings are the limits when nothing is set.
func DefaultSettings() Settings {
	return Settings{
		IdleMinutes: 30, MaxSessionHours: int(MaxSessionLife / time.Hour), RetentionDays: int(Retention / (24 * time.Hour)),
		BucketBurst: int(bucketBurst), BucketRefillMinutes: int(bucketRefill / time.Minute),
		WaitingCap: WaitingCap, PermanentLinkCap: MaxPermanentLinks,
	}
}

// settingSpec ties a key to its bounds, its field in Settings and in a patch.
type settingSpec struct {
	key      string
	min, max int
	field    func(*Settings) *int
	patch    func(*SettingsPatch) *int
	message  string
}

var settingSpecs = []settingSpec{
	{SettingIdleMinutes, 5, 240, func(s *Settings) *int { return &s.IdleMinutes }, func(p *SettingsPatch) *int { return p.IdleMinutes }, "The idle limit is 5 to 240 minutes."},
	{SettingMaxSessionHours, 1, 24, func(s *Settings) *int { return &s.MaxSessionHours }, func(p *SettingsPatch) *int { return p.MaxSessionHours }, "A session lasts 1 to 24 hours."},
	{SettingRetentionDays, 1, 365, func(s *Settings) *int { return &s.RetentionDays }, func(p *SettingsPatch) *int { return p.RetentionDays }, "Records are kept 1 to 365 days."},
	{SettingBucketBurst, 1, 20, func(s *Settings) *int { return &s.BucketBurst }, func(p *SettingsPatch) *int { return p.BucketBurst }, "The burst is 1 to 20 downloads."},
	{SettingBucketRefill, 1, 60, func(s *Settings) *int { return &s.BucketRefillMinutes }, func(p *SettingsPatch) *int { return p.BucketRefillMinutes }, "A download is refilled every 1 to 60 minutes."},
	{SettingWaitingCap, 5, 100, func(s *Settings) *int { return &s.WaitingCap }, func(p *SettingsPatch) *int { return p.WaitingCap }, "The waiting list holds 5 to 100 requests."},
	{SettingPermanentCap, 1, 20, func(s *Settings) *int { return &s.PermanentLinkCap }, func(p *SettingsPatch) *int { return p.PermanentLinkCap }, "An organization may have 1 to 20 permanent links."},
}

// MaxSessionLength is the configured length of a session.
func (s Settings) MaxSessionLength() time.Duration {
	return time.Duration(s.MaxSessionHours) * time.Hour
}

// Idle is the configured idle limit.
func (s Settings) Idle() time.Duration { return time.Duration(s.IdleMinutes) * time.Minute }

// LoadSettings reads the limits; a missing or unusable value is its default.
func (s *Service) LoadSettings(ctx context.Context) (Settings, error) {
	var out Settings
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) (err error) {
		out, err = loadSettingsTx(ctx, tx)
		return err
	})
	return out, err
}

func loadSettingsTx(ctx context.Context, tx pgx.Tx) (Settings, error) {
	out := DefaultSettings()
	rows, err := tx.Query(ctx, `SELECT key, value FROM settings WHERE key LIKE 'quickassist.%'`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	raw := map[string][]byte{}
	for rows.Next() {
		var k string
		var v []byte
		if err := rows.Scan(&k, &v); err != nil {
			return out, err
		}
		raw[k] = v
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	for _, sp := range settingSpecs {
		var n int
		if v, ok := raw[sp.key]; ok && json.Unmarshal(v, &n) == nil && n >= sp.min && n <= sp.max {
			*sp.field(&out) = n
		}
	}
	return out, nil
}

// UpdateSettings changes the limits. It needs the platform-wide settings
// permission, checks every bound before writing anything, and is audited.
func (s *Service) UpdateSettings(ctx context.Context, c access.Caller, p SettingsPatch) (Settings, error) {
	if err := c.RequireGlobal(rbac.PermSettingsManage); err != nil {
		return Settings{}, err
	}
	changes := map[string]int{}
	for _, sp := range settingSpecs {
		if v := sp.patch(&p); v != nil {
			if *v < sp.min || *v > sp.max {
				return Settings{}, apperr.Invalid(strings.TrimPrefix(sp.key, "quickassist."), sp.message)
			}
			changes[sp.key] = *v
		}
	}
	var by *uuid.UUID
	if c.Principal != nil {
		by = &c.Principal.UserID
	}
	var out Settings
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for k, v := range changes {
			raw, _ := json.Marshal(v)
			if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3)
				ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by`, k, raw, by); err != nil {
				return err
			}
		}
		var err error
		if out, err = loadSettingsTx(ctx, tx); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "quickassist.settings.update", Outcome: audit.Success,
			TargetType: "setting", TargetID: "quickassist.limits", Details: map[string]any{"changes": changes}})
	})
	return out, err
}
