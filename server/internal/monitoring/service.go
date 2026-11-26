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
	"github.com/paulmataruso/easyrmm/server/internal/inventory"
)

// EvaluateInterval is how often the server evaluates the policies.
const EvaluateInterval = time.Minute

// MinRetention is the shortest time resolved alerts are kept.
const MinRetention = 24 * time.Hour

// AgentGrace is how long after the server begins serving agents a device
// still counts as seen by offline policies: the longest an EasyRMM agent
// waits between attempts to reach the server (agent/runner's MaxRetry).
// With jitter an agent may wait a tenth longer, which the shortest offline
// policy, MinOfflineMinutes, covers. A restart or an upgrade then raises no
// offline alert (ADR-0052).
const AgentGrace = 5 * time.Minute

// Serving tells when the server last began serving agents (when its
// listeners opened, or when a hold by the updater ended), and false while
// it serves none.
type Serving func() (since time.Time, serving bool)

// Service manages policies and alerts.
type Service struct {
	db        *database.DB
	audit     *audit.Logger
	retention time.Duration
	// metricsKept is how long devices' measurements are kept, as inventory
	// prunes them: an alert's chart starts no earlier.
	metricsKept time.Duration
	log         *slog.Logger
	now         func() time.Time
	serving     Serving
	// mesh says whether EasyRMM's control session to MeshCentral is open and
	// since when; nil without remote access (ADR-0069).
	mesh MeshLink
	// modGate guards the Windows module kinds (UseModules).
	modGate ModuleGate
}

// MeshLink tells whether EasyRMM's connection to MeshCentral is up, and
// when the current one opened.
type MeshLink func() (connected bool, since time.Time)

// RemoteSettle is how long after EasyRMM's connection to MeshCentral
// returns that the remote access policies still judge nothing: devices'
// MeshAgents reconnect meanwhile, and an outage opens no alerts
// (ADR-0069).
const RemoteSettle = 15 * time.Minute

// FollowMesh makes the remote access policies (remote_down and
// agent_silent) judge nothing while the connection to MeshCentral is down
// or within RemoteSettle after it returns. Without it, there is no remote
// access, and their alerts are resolved. Call it before Run.
func (s *Service) FollowMesh(l MeshLink) { s.mesh = l }

// New builds the service. retention is how long resolved alerts are kept,
// metricsKept how long devices' measurements are. Until FollowServing says
// otherwise, the server began serving agents now.
func New(db *database.DB, auditLog *audit.Logger, retention, metricsKept time.Duration, log *slog.Logger) *Service {
	started := time.Now()
	return &Service{db: db, audit: auditLog, retention: max(retention, MinRetention), metricsKept: max(metricsKept, inventory.MinRetention), log: log, now: time.Now,
		serving: func() (time.Time, bool) { return started, true }}
}

// FollowServing makes offline policies count a device as seen no earlier
// than AgentGrace after the moment f gives, and open no alert while the
// server serves no agents. Call it before Run.
func (s *Service) FollowServing(f Serving) { s.serving = f }

// seenFloor is the earliest moment a device counts as seen when an offline
// policy decides whether to open an alert: AgentGrace after the server
// began serving agents, or after now while it serves none.
func (s *Service) seenFloor(now time.Time) time.Time {
	since, serving := s.serving()
	if !serving {
		since = now
	}
	return since.Add(AgentGrace)
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
