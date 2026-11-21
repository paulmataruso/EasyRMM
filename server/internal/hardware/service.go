// Package hardware keeps what devices' agents read from their hardware
// (ADR-0065): each disk's health as the server's rules judge it, its
// history, and what the console shows for it. The agent reports what it
// read; the server judges, so that a rule changes without an agent update.
package hardware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// ErrBadReport is a hardware report the server cannot read.
var ErrBadReport = errors.New("hardware: not a valid hardware report")

// Service stores and reads disk health.
type Service struct {
	db *database.DB
	// full is how long every reading is kept (EASYRMM_METRICS_RETENTION);
	// retention how long one a day is (EASYRMM_HARDWARE_RETENTION).
	full, retention time.Duration
	log             *slog.Logger
}

// New builds the service. Every reading is kept for full, then one a day
// per disk for retention, which is at least full.
func New(db *database.DB, full, retention time.Duration, log *slog.Logger) *Service {
	return &Service{db: db, full: full, retention: max(retention, full), log: log}
}

// Record stores a device's hardware report: each disk's reading as its
// latest and as a sample, judged by the server's rules. A disk with a row
// that the report no longer lists is marked missing; its row, history and
// alerts stay (ADR-0065, "Disks that disappear").
func (s *Service) Record(ctx context.Context, deviceID uuid.UUID, body []byte) error {
	var report agentproto.HardwareReport
	if err := json.Unmarshal(body, &report); err != nil {
		return ErrBadReport
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
			return err
		}
		disks := clean(report.Disks, now)
		keys, unstable, err := diskKeys(ctx, tx, disks)
		if err != nil {
			return err
		}
		var b pgx.Batch
		seen := map[string]bool{}
		listed := []string{}
		for i := range disks {
			d, key := &disks[i], keys[i]
			if seen[key] {
				continue
			}
			seen[key] = true
			listed = append(listed, key)
			r := judge(d)
			facts, err := json.Marshal(nonNil(r.facts))
			if err != nil {
				return err
			}
			attrs, err := json.Marshal(nonNil(r.attributes))
			if err != nil {
				return err
			}
			b.Queue(upsertDisk, deviceID, key, unstable[i], d.Name, d.Model, d.Serial, r.state, r.reason, d.Detail, d.ReadAt, now,
				d.Protocol, d.Route, facts, attrs, r.read, r.judged, r.detail)
			x := r.sample
			b.Queue(`INSERT INTO device_disk_health_samples (device_id, disk_key, at, state, judged, temperature, temperature_limit, wear,
					reallocated, media_errors, pending, uncorrectable, drive_errors, power_on_hours)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) ON CONFLICT DO NOTHING`,
				deviceID, key, now, r.state, r.judged, x.temperature, x.temperatureLimit, x.wear,
				x.reallocated, x.mediaErrors, x.pending, x.uncorrectable, x.driveErrors, x.powerOnHours)
		}
		b.Queue(`UPDATE device_disk_health SET missing_since = $2
			WHERE device_id = $1 AND missing_since IS NULL AND NOT (disk_key = ANY ($3))`, deviceID, now, listed)
		return tx.SendBatch(ctx, &b).Close()
	})
	if err != nil {
		return fmt.Errorf("hardware: storing a report: %w", err)
	}
	return nil
}

// upsertDisk stores a disk's latest reading. Facts and attributes change
// only with a reading that read the disk ($16), the judged columns only
// with one that read its verdict ($17); a disk listed again is no longer
// missing.
const upsertDisk = `INSERT INTO device_disk_health AS h (device_id, disk_key, unstable, name, model, serial, state, reason, detail,
		read_at, received_at, protocol, route, facts, attributes, facts_at, judged_level, judged_reason, judged_detail, judged_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, CASE WHEN $16 THEN $11::timestamptz END,
		CASE WHEN $17 THEN $7 END, CASE WHEN $17 THEN $8 ELSE '' END, CASE WHEN $17 THEN $18 ELSE '' END, CASE WHEN $17 THEN $11::timestamptz END)
	ON CONFLICT (device_id, disk_key) DO UPDATE SET
		unstable = EXCLUDED.unstable, name = EXCLUDED.name, model = EXCLUDED.model, serial = EXCLUDED.serial,
		state = EXCLUDED.state, reason = EXCLUDED.reason, detail = EXCLUDED.detail,
		read_at = EXCLUDED.read_at, received_at = EXCLUDED.received_at,
		protocol = CASE WHEN $16 THEN EXCLUDED.protocol ELSE h.protocol END,
		route = CASE WHEN $16 THEN EXCLUDED.route ELSE h.route END,
		facts = CASE WHEN $16 THEN EXCLUDED.facts ELSE h.facts END,
		attributes = CASE WHEN $16 THEN EXCLUDED.attributes ELSE h.attributes END,
		facts_at = CASE WHEN $16 THEN EXCLUDED.facts_at ELSE h.facts_at END,
		judged_level = CASE WHEN $17 THEN EXCLUDED.judged_level ELSE h.judged_level END,
		judged_reason = CASE WHEN $17 THEN EXCLUDED.judged_reason ELSE h.judged_reason END,
		judged_detail = CASE WHEN $17 THEN EXCLUDED.judged_detail ELSE h.judged_detail END,
		judged_at = CASE WHEN $17 THEN EXCLUDED.judged_at ELSE h.judged_at END,
		missing_since = NULL`

// diskKeys returns each disk's identity from easyrmm_disk_key, the one
// definition the server and the database share, and whether it comes from
// the disk's name for want of a serial.
func diskKeys(ctx context.Context, tx pgx.Tx, disks []agentproto.DiskHealth) ([]string, []bool, error) {
	names, models, serials := make([]string, len(disks)), make([]string, len(disks)), make([]string, len(disks))
	unstable := make([]bool, len(disks))
	for i, d := range disks {
		names[i], models[i], serials[i], unstable[i] = d.Name, d.Model, d.Serial, d.Serial == ""
	}
	rows, err := tx.Query(ctx, `SELECT easyrmm_disk_key(n, m, s)
		FROM unnest($1::text[], $2::text[], $3::text[]) WITH ORDINALITY AS x (n, m, s, i) ORDER BY i`, names, models, serials)
	if err != nil {
		return nil, nil, err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, nil, err
	}
	return keys, unstable, nil
}

// Purge thins readings older than EASYRMM_METRICS_RETENTION to one row per
// disk per UTC day, the day's worst state, its highest temperature and its
// last counts and wear, and removes those days past
// EASYRMM_HARDWARE_RETENTION. Only whole days are thinned, each once.
func (s *Service) Purge(ctx context.Context) error {
	var thinned, removed int64
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `WITH gone AS (
				DELETE FROM device_disk_health_samples
				WHERE NOT daily AND at < date_trunc('day', now() - $1::interval, 'UTC')
				RETURNING *
			)
			INSERT INTO device_disk_health_samples (device_id, disk_key, at, daily, state, judged, temperature, temperature_limit, wear,
				reallocated, media_errors, pending, uncorrectable, drive_errors, power_on_hours)
			SELECT device_id, disk_key, date_trunc('day', at, 'UTC'), true,
				(array_agg(state ORDER BY array_position($2::text[], state)))[1], bool_or(judged), max(temperature),
				(array_agg(temperature_limit ORDER BY at DESC) FILTER (WHERE temperature_limit IS NOT NULL))[1],
				(array_agg(wear ORDER BY at DESC) FILTER (WHERE wear IS NOT NULL))[1],
				(array_agg(reallocated ORDER BY at DESC) FILTER (WHERE reallocated IS NOT NULL))[1],
				(array_agg(media_errors ORDER BY at DESC) FILTER (WHERE media_errors IS NOT NULL))[1],
				(array_agg(pending ORDER BY at DESC) FILTER (WHERE pending IS NOT NULL))[1],
				(array_agg(uncorrectable ORDER BY at DESC) FILTER (WHERE uncorrectable IS NOT NULL))[1],
				(array_agg(drive_errors ORDER BY at DESC) FILTER (WHERE drive_errors IS NOT NULL))[1],
				(array_agg(power_on_hours ORDER BY at DESC) FILTER (WHERE power_on_hours IS NOT NULL))[1]
			FROM gone
			GROUP BY device_id, disk_key, date_trunc('day', at, 'UTC')
			ON CONFLICT DO NOTHING`, interval(s.full), worstFirst)
		if err != nil {
			return err
		}
		thinned = tag.RowsAffected()
		tag, err = tx.Exec(ctx, `DELETE FROM device_disk_health_samples WHERE daily AND at < now() - $1::interval`, interval(s.retention))
		removed = tag.RowsAffected()
		return err
	})
	if err == nil && (thinned > 0 || removed > 0) {
		s.log.Info("hardware: thinned and removed disk health samples", "days_kept", thinned, "days_removed", removed,
			"retention", s.retention.String())
	}
	return err
}

// worstFirst orders states from the worst, for a day's worst state and a
// device's: failing, warning, unknown, unavailable, healthy, unsupported.
var worstFirst = []string{StateFailing, StateWarning, StateUnknown, StateUnavailable, StateHealthy, StateUnsupported}

func interval(d time.Duration) string { return fmt.Sprintf("%d seconds", int64(d.Seconds())) }

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
