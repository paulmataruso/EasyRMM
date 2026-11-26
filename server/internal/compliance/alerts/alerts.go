// Package alerts raises the two compliance alerts ADR-0078 (section 7) names
// and ADR-0082 builds: a fix that did not stand, and a computer whose
// compliance results are out of date. Like Repair failed they belong to no
// policy; the server opens and resolves them, through the same alerts table
// every other alert is in. Both are automatic behavior, so each pass asks
// devscope.Allowed of every organization it touches.
package alerts

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// Alert kinds. The alerts table's kind is a lower-case word with underscores,
// so ADR-0078's compliance.fix_failed is compliance_fix_failed (ADR-0082,
// amended).
const (
	KindFixFailed = "compliance_fix_failed"
	KindScanStale = "compliance_scan_stale"
)

// Every is how often the alerts are judged.
const Every = 10 * time.Minute

const lockKey = 90402

// Service judges the alerts.
type Service struct {
	db  *database.DB
	log *slog.Logger
	now func() time.Time
}

// New builds the service.
func New(db *database.DB, log *slog.Logger) *Service {
	return &Service{db: db, log: log, now: time.Now}
}

// SetClock replaces the clock, for tests.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Result counts what a pass did.
type Result struct{ Opened, Resolved int }

// staleSQL lists the computers whose newest compliance result is older than
// their organization's freshness window: $1 the organizations, $2 now.
const staleSQL = `SELECT l.device_id, l.organization_id, l.at,
		extract(epoch FROM $2::timestamptz - l.at) / 86400 AS days
	FROM (SELECT r.device_id, r.organization_id, max(r.checked_at) AS at FROM compliance_results r
		WHERE r.organization_id = ANY ($1) GROUP BY r.device_id, r.organization_id) l
	JOIN compliance_org_settings s ON s.organization_id = l.organization_id AND s.enabled
	JOIN devices d ON d.id = l.device_id AND NOT d.quick_assist AND NOT ` + devices.LeavingSQL + `
	WHERE l.at < $2::timestamptz - make_interval(days => s.freshness_days)`

const kinds = `('compliance_fix_failed', 'compliance_scan_stale')`

// Evaluate opens, updates and resolves both alerts at the clock's now.
func (s *Service) Evaluate(ctx context.Context) (Result, error) {
	var res Result
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, int64(lockKey)).Scan(&locked); err != nil || !locked {
			return err
		}
		now := s.now().UTC()
		var orgs []uuid.UUID
		rows, err := tx.Query(ctx, `SELECT organization_id FROM compliance_org_settings WHERE enabled`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var o uuid.UUID
			if err := rows.Scan(&o); err != nil {
				rows.Close()
				return err
			}
			if devscope.Allowed(o) {
				orgs = append(orgs, o)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if orgs == nil {
			orgs = []uuid.UUID{}
		}

		// An alert nothing covers any more (the module is off, the organization
		// is outside the scope, the computer is leaving) goes with a reason.
		t, err := tx.Exec(ctx, `UPDATE alerts a SET status = 'resolved', resolved_at = $2, resolution = 'not_covered'
			WHERE a.kind IN `+kinds+` AND a.status <> 'resolved' AND NOT EXISTS (
				SELECT 1 FROM devices d WHERE d.id = a.device_id AND d.organization_id = ANY ($1) AND NOT `+devices.LeavingSQL+`)`, orgs, now)
		if err != nil {
			return err
		}
		res.Resolved += int(t.RowsAffected())

		t, err = tx.Exec(ctx, `INSERT INTO alerts (policy_id, device_id, name, kind, threshold, minutes, severity, subject, subject_label, detail, value, last_value, opened_at)
			SELECT NULL, i.device_id, 'Compliance fix failed', 'compliance_fix_failed', NULL, 0, 'warning', left(i.control_id, 64), left(i.control_id, 300),
				left('A fix for this control did not stand. ' || i.fail_reason, 500), 0, 0, $2
			FROM compliance_fix_items i JOIN devices d ON d.id = i.device_id
			WHERE i.state = 'failed' AND i.organization_id = ANY ($1) AND NOT d.quick_assist AND NOT `+devices.LeavingSQL+`
			ON CONFLICT (device_id, kind, subject) WHERE kind IN `+kinds+` AND status <> 'resolved'
			DO UPDATE SET detail = excluded.detail`, orgs, now)
		if err != nil {
			return err
		}
		res.Opened += int(t.RowsAffected())
		t, err = tx.Exec(ctx, `UPDATE alerts a SET status = 'resolved', resolved_at = $1, resolution = 'cleared'
			WHERE a.kind = 'compliance_fix_failed' AND a.status <> 'resolved' AND NOT EXISTS (
				SELECT 1 FROM compliance_fix_items i WHERE i.device_id = a.device_id AND left(i.control_id, 64) = a.subject AND i.state = 'failed')`, now)
		if err != nil {
			return err
		}
		res.Resolved += int(t.RowsAffected())

		t, err = tx.Exec(ctx, `INSERT INTO alerts (policy_id, device_id, name, kind, threshold, minutes, severity, subject, subject_label, detail, value, last_value, opened_at)
			SELECT NULL, x.device_id, 'Compliance results out of date', 'compliance_scan_stale', NULL, 0, 'warning', 'scan', 'Compliance results',
				'The newest compliance result for this computer is ' || floor(x.days)::int || ' days old, past the organization''s window.', x.days, x.days, $2
			FROM (`+staleSQL+`) x
			ON CONFLICT (device_id, kind, subject) WHERE kind IN `+kinds+` AND status <> 'resolved'
			DO UPDATE SET last_value = excluded.last_value, detail = excluded.detail`, orgs, now)
		if err != nil {
			return err
		}
		res.Opened += int(t.RowsAffected())
		t, err = tx.Exec(ctx, `UPDATE alerts a SET status = 'resolved', resolved_at = $2, resolution = 'cleared'
			WHERE a.kind = 'compliance_scan_stale' AND a.status <> 'resolved'
			  AND NOT EXISTS (SELECT 1 FROM (`+staleSQL+`) x WHERE x.device_id = a.device_id)`, orgs, now)
		if err != nil {
			return err
		}
		res.Resolved += int(t.RowsAffected())
		return nil
	})
	return res, err
}

// Run judges the alerts every Every until ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(Every)
	defer t.Stop()
	for {
		if _, err := s.Evaluate(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("compliance: judging the compliance alerts failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
