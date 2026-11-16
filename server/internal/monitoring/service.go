// Package monitoring watches devices for trouble (ADR-0019): alert
// policies, the evaluator that raises and resolves alerts from devices'
// check-ins and measurements, and the alerts themselves.
package monitoring

import (
	"context"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// EvaluateInterval is how often the server evaluates the policies.
const EvaluateInterval = time.Minute

// MinRetention is the shortest time resolved alerts are kept.
const MinRetention = 24 * time.Hour

// Service manages policies and alerts.
type Service struct {
	db        *database.DB
	audit     *audit.Logger
	retention time.Duration
	log       *slog.Logger
	now       func() time.Time
}

// New builds the service. retention is how long resolved alerts are kept.
func New(db *database.DB, auditLog *audit.Logger, retention time.Duration, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, retention: max(retention, MinRetention), log: log, now: time.Now}
}

// Run evaluates the policies every minute and removes resolved alerts past
// retention every hour, until ctx ends.
func (s *Service) Run(ctx context.Context) {
	tick := time.NewTicker(EvaluateInterval)
	defer tick.Stop()
	var lastPurge time.Time
	for {
		if r, err := s.Evaluate(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("monitoring: evaluating alert policies failed", "error", err)
		} else if err == nil && (r.Opened > 0 || r.Resolved > 0) {
			s.log.Info("monitoring: evaluated alert policies", "opened", r.Opened, "resolved", r.Resolved)
		}
		if time.Since(lastPurge) >= time.Hour {
			if n, err := s.Purge(ctx); err != nil && ctx.Err() == nil {
				s.log.Error("monitoring: alert retention failed", "error", err)
			} else if err == nil {
				lastPurge = time.Now()
				if n > 0 {
					s.log.Info("monitoring: removed resolved alerts past retention", "count", n, "retention", s.retention.String())
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Purge removes alerts resolved longer ago than the retention.
func (s *Service) Purge(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM alerts WHERE status = 'resolved' AND resolved_at < $1`, s.now().Add(-s.retention))
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

// cleanText removes control characters (keeping newlines when asked) and
// surrounding space.
func cleanText(s string, keepNewlines bool) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r == '\t' || (keepNewlines && r == '\n') {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
