package posture

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// PatchStatus is what the patching engine says about one device.
type PatchStatus struct {
	DeviceID, OrganizationID uuid.UUID
	// Status is the engine's compliance word.
	Status string
	// At is when the engine read the device's updates.
	At time.Time
}

// PatchFeed is the patching engine as posture reads it: the status of every
// device it patches. A device the feed leaves out keeps its last copy, which
// goes stale.
type PatchFeed interface {
	PosturePatching(ctx context.Context) ([]PatchStatus, error)
}

// RefreshEvery is how often the engine is read.
const RefreshEvery = 15 * time.Minute

// Service reads postures for one computer and keeps patching's copy current.
type Service struct {
	db   *database.DB
	log  *slog.Logger
	now  func() time.Time
	feed PatchFeed
}

// New builds the service; feed may be nil (no patching engine).
func New(db *database.DB, feed PatchFeed, log *slog.Logger) *Service {
	return &Service{db: db, feed: feed, log: log, now: time.Now}
}

// SetClock replaces the clock, for tests.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// RefreshPatching copies the engine's statuses for the organizations the
// dev-scope guard allows, and returns how many it wrote.
func (s *Service) RefreshPatching(ctx context.Context) (int, error) {
	if s.feed == nil {
		return 0, nil
	}
	list, err := s.feed.PosturePatching(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, p := range list {
			if !devscope.Allowed(p.OrganizationID) || p.Status == "" || p.At.IsZero() {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO posture_patching (device_id, status, checked_at) VALUES ($1, $2, $3)
				ON CONFLICT (device_id) DO UPDATE SET status = excluded.status, checked_at = excluded.checked_at`,
				p.DeviceID, p.Status, p.At); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// Run refreshes patching's copy every RefreshEvery until ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(RefreshEvery)
	defer t.Stop()
	for {
		if _, err := s.RefreshPatching(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("posture: reading the patching engine failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Device is one computer's posture and the reasons behind it. It needs
// device.view on the computer. A computer posture does not cover answers with
// Covered false.
type Device struct {
	Covered bool `json:"covered"`
	// Phrase is the word in a sentence.
	Phrase  string   `json:"phrase"`
	Posture *Posture `json:"posture"`
}

// Device reads one computer's posture.
func (s *Service) Device(ctx context.Context, c access.Caller, id uuid.UUID) (*Device, error) {
	var out *Device
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var r Ref
		var site uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id, organization_id, site_id, platform, enrolled_at IS NOT NULL FROM devices WHERE id = $1 AND NOT quick_assist`, id).
			Scan(&r.ID, &r.Org, &site, &r.Platform, &r.Enrolled)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !c.Can(rbac.PermDeviceView, rbac.Site(r.Org, site))) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		m, err := Load(ctx, tx, []Ref{r}, s.now())
		if err != nil {
			return err
		}
		out = &Device{Posture: m[id]}
		if out.Covered = out.Posture != nil; out.Covered {
			out.Phrase = Phrase(out.Posture.Word)
		}
		return nil
	})
	return out, err
}

// RecordLogs notes that log blocks of the computer were accepted just now. The
// log store is a database of its own, so posture keeps this one fact in the main
// database (migration 90621).
func (s *Service) RecordLogs(ctx context.Context, device uuid.UUID) error {
	now := s.now()
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO posture_log_collection (device_id, first_received_at, last_received_at)
			VALUES ($1, $2, $2) ON CONFLICT (device_id) DO UPDATE SET last_received_at = excluded.last_received_at`, device, now)
		return err
	})
}
