package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Disk health alerts (ADR-0065, "Alerts"). Each check opens on complete
// readings only: readings that read the drive's verdict and the facts the
// check watches. One alert per policy, device and disk; it resolves after
// two complete readings in a row since it opened that clear it. A reading
// that could not tell, or a missing disk, changes nothing.

// TemperatureMargin is how far below its threshold, in °C, a disk's
// temperature must be for a temperature alert to resolve.
const TemperatureMargin = 5

// GoneAfter is how long a disk must have been missing from its device's
// hardware reports before its alerts resolve on their own (subject_gone).
const GoneAfter = 14 * 24 * time.Hour

// diskFacts is what one enabled disk health policy sees on one disk of a
// device it covers.
type diskFacts struct {
	policyID, deviceID uuid.UUID
	// subject is the disk's identity; name and model name it.
	subject, name, model string
	check                string
	threshold            *int
	// judgedDetail says in words why the last judged reading was failing
	// or warning.
	judgedDetail string
	// alertID is the policy's unresolved alert on the disk.
	alertID  *uuid.UUID
	openedAt *time.Time
	// readings are the disk's last two complete readings for the check,
	// newest first.
	readings []diskReading
	// For temperature: the complete readings of the policy's minutes, and
	// whether every one is at or above its threshold.
	n    int
	over bool
}

// diskReading is one complete reading as a check sees it: V is the value
// the check watches and Lim its threshold (1 and 1 for failing; for
// temperature the policy's threshold, or the drive's own limit without
// one), with the facts that make the alert's detail.
type diskReading struct {
	At            time.Time `json:"at"`
	V             float64   `json:"v"`
	Lim           float64   `json:"lim"`
	Reallocated   *int64    `json:"reallocated"`
	MediaErrors   *int64    `json:"media_errors"`
	Pending       *int64    `json:"pending"`
	Uncorrectable *int64    `json:"uncorrectable"`
	Wear          *int64    `json:"wear"`
	Temperature   *int64    `json:"temperature"`
}

// openWindow is how old the latest complete reading may be for an alert
// to open on it: a day, which a disk asleep since its last reading is
// still read within.
const openWindow = 24 * time.Hour

// loadDiskFacts reads, for every enabled disk health policy and every disk
// of a device it covers, what decideDisk needs. Disks with no alert whose
// condition does not hold are left out, and so are disks decideDisk would
// do nothing with: missing ones, and ones never judged. Each disk's
// readings are read back only as far as its check needs: since its alert
// opened (two readings after that resolve it), or, without one, openWindow.
// The time bound keeps a disk whose readings never hold the check's facts,
// such as pending sectors on NVMe, from being read back through its whole
// history every minute.
func loadDiskFacts(ctx context.Context, tx pgx.Tx, now time.Time) ([]diskFacts, error) {
	rows, err := tx.Query(ctx, diskFactsSQL, now, openWindow.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []diskFacts
	for rows.Next() {
		var (
			f        diskFacts
			readings []byte
		)
		if err := rows.Scan(&f.policyID, &f.deviceID, &f.subject, &f.name, &f.model, &f.check, &f.threshold,
			&f.judgedDetail, &f.alertID, &f.openedAt, &readings, &f.n, &f.over); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(readings, &f.readings); err != nil {
			return nil, fmt.Errorf("monitoring: reading a disk's readings: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// diskFactsSQL is loadDiskFacts' query: $1 is now, $2 openWindow in
// seconds. The readings' lower bound is a CASE, not coalesce: under the
// samples' row-level security only an expression PostgreSQL knows to be
// leakproof reaches the index, and it does not take coalesce for one. With
// coalesce the bound was a filter, and each disk's history was read back
// whole all the same (measured: TestDiskFactsAtScale).
const diskFactsSQL = `SELECT * FROM (
			SELECT p.id AS policy_id, d.id AS device_id, h.disk_key, h.name, h.model, p.check_name, p.threshold,
				h.judged_detail, a.id AS alert_id, a.opened_at,
				coalesce(r.readings, '[]') AS readings, w.n, coalesce(w.over, false) AS over
			FROM alert_policies p
			JOIN devices d ON p.organization_id IS NULL
				OR (p.organization_id = d.organization_id AND (p.site_id IS NULL OR p.site_id = d.site_id))
			JOIN device_disk_health h ON h.device_id = d.id
			LEFT JOIN alerts a ON a.policy_id = p.id AND a.device_id = d.id AND a.subject = h.disk_key AND a.status <> 'resolved'
			LEFT JOIN alert_suppressions sup ON sup.device_id = d.id AND sup.kind = p.kind AND (sup.subject = '' OR sup.subject = h.disk_key)
			LEFT JOIN LATERAL (
				SELECT jsonb_agg(x ORDER BY x.at DESC) AS readings FROM (
					SELECT s.at,
						(CASE p.check_name
							WHEN 'failing' THEN (s.state = 'failing')::int
							WHEN 'errors' THEN coalesce(s.reallocated, 0)::numeric + coalesce(s.media_errors, 0)
							WHEN 'pending' THEN coalesce(s.pending, 0)::numeric + coalesce(s.uncorrectable, 0)
							WHEN 'wear' THEN s.wear
							ELSE s.temperature END)::float8 AS v,
						(CASE p.check_name WHEN 'failing' THEN 1 WHEN 'temperature' THEN coalesce(p.threshold, s.temperature_limit)
							ELSE p.threshold END)::float8 AS lim,
						s.reallocated, s.media_errors, s.pending, s.uncorrectable, s.wear, s.temperature
					FROM device_disk_health_samples s
					WHERE s.device_id = d.id AND s.disk_key = h.disk_key AND NOT s.daily AND s.judged AND s.at <= $1
					  AND s.at > CASE WHEN a.opened_at IS NULL THEN $1::timestamptz - make_interval(secs => $2) ELSE a.opened_at END
					  AND CASE p.check_name
						WHEN 'failing' THEN true
						WHEN 'errors' THEN s.reallocated IS NOT NULL OR s.media_errors IS NOT NULL
						WHEN 'pending' THEN s.pending IS NOT NULL OR s.uncorrectable IS NOT NULL
						WHEN 'wear' THEN s.wear IS NOT NULL
						ELSE s.temperature IS NOT NULL AND coalesce(p.threshold, s.temperature_limit) IS NOT NULL END
					ORDER BY s.at DESC LIMIT 2
				) x
			) r ON true
			LEFT JOIN LATERAL (
				SELECT count(*) AS n, bool_and(s.temperature >= coalesce(p.threshold, s.temperature_limit)) AS over
				FROM device_disk_health_samples s
				WHERE p.check_name = 'temperature' AND s.device_id = d.id AND s.disk_key = h.disk_key AND NOT s.daily AND s.judged
				  AND s.temperature IS NOT NULL AND coalesce(p.threshold, s.temperature_limit) IS NOT NULL
				  AND s.at > $1::timestamptz - make_interval(mins => p.minutes) AND s.at <= $1
			) w ON true
			WHERE p.enabled AND p.kind = 'disk_health' AND h.missing_since IS NULL AND h.judged_at IS NOT NULL
			  AND sup.id IS NULL
		) f
		WHERE alert_id IS NOT NULL OR CASE check_name
			WHEN 'temperature' THEN n >= 2 AND over
			ELSE (readings->0->>'v')::float8 >= (readings->0->>'lim')::float8 END`

// decideDisk turns a disk's facts into what to do with its alert, and the
// reading that gives the value and detail. A disk without a complete
// reading in its bound changes nothing (missing disks are not loaded).
func decideDisk(f *diskFacts) (action, *diskReading) {
	if len(f.readings) == 0 {
		return actNone, nil
	}
	latest := &f.readings[0]
	if f.alertID == nil {
		met := latest.V >= latest.Lim
		if f.check == CheckTemperature {
			// Every complete reading of the policy's minutes, at least two.
			met = f.n >= 2 && f.over
		}
		if met {
			return actOpen, latest
		}
		return actNone, nil
	}
	if len(f.readings) == 2 && f.openedAt != nil && f.readings[1].At.After(*f.openedAt) &&
		clears(f.check, &f.readings[0]) && clears(f.check, &f.readings[1]) {
		return actResolve, latest
	}
	return actUpdate, latest
}

// clears reports whether a complete reading clears a check: below its
// threshold, and for temperature at least TemperatureMargin below it.
func clears(check string, r *diskReading) bool {
	if check == CheckTemperature {
		return r.V <= r.Lim-TemperatureMargin
	}
	return r.V < r.Lim
}

// maxDetail and maxLabel bound an alert's detail and subject label.
const (
	maxDetail = 500
	maxLabel  = 300
)

// subjectLabel names a disk for people, never by its serial.
func subjectLabel(name, model string) string {
	if model == "" {
		return clip(name, maxLabel)
	}
	return clip(name+" · "+model, maxLabel)
}

// diskDetail says in words what a check found in a reading.
func diskDetail(f *diskFacts, r *diskReading) string {
	var parts []string
	add := func(label string, v *int64) {
		if v != nil {
			parts = append(parts, fmt.Sprintf("%s %d", label, *v))
		}
	}
	switch f.check {
	case CheckFailing:
		if r.V == 0 {
			return "Not failing"
		}
		if f.judgedDetail == "" {
			return "Failing"
		}
		return clip(f.judgedDetail, maxDetail)
	case CheckErrors:
		add("reallocated sectors", r.Reallocated)
		add("media errors", r.MediaErrors)
	case CheckPending:
		add("pending sectors", r.Pending)
		add("uncorrectable sectors", r.Uncorrectable)
	case CheckWear:
		return fmt.Sprintf("%.0f%% of rated endurance used", r.V)
	case CheckTemperature:
		if f.threshold != nil {
			return fmt.Sprintf("%.0f °C; threshold %.0f °C", r.V, r.Lim)
		}
		return fmt.Sprintf("%.0f °C; the drive's own limit %.0f °C", r.V, r.Lim)
	}
	s := strings.Join(parts, ", ")
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// evaluateDisks opens, updates and resolves disk health alerts at now,
// returning how many it opened and resolved.
func evaluateDisks(ctx context.Context, tx pgx.Tx, now time.Time) (opened, resolved int, err error) {
	list, err := loadDiskFacts(ctx, tx, now)
	if err != nil {
		return 0, 0, err
	}
	type row struct {
		ids, devices           []uuid.UUID
		subjects, labels, text []string
		values                 []float64
	}
	var opens, updates, resolves row
	for i := range list {
		f := &list[i]
		act, r := decideDisk(f)
		switch act {
		case actOpen:
			opens.ids = append(opens.ids, f.policyID)
			opens.devices = append(opens.devices, f.deviceID)
			opens.subjects = append(opens.subjects, f.subject)
			opens.labels = append(opens.labels, subjectLabel(f.name, f.model))
			opens.text = append(opens.text, diskDetail(f, r))
			opens.values = append(opens.values, r.V)
		case actUpdate, actResolve:
			c := &updates
			if act == actResolve {
				c = &resolves
			}
			c.ids = append(c.ids, *f.alertID)
			c.text = append(c.text, diskDetail(f, r))
			c.values = append(c.values, r.V)
		}
	}
	if len(opens.ids) > 0 {
		tag, err := tx.Exec(ctx, `INSERT INTO alerts (policy_id, device_id, name, kind, check_name, threshold, minutes, severity,
				subject, subject_label, detail, value, last_value, opened_at)
			SELECT p.id, x.device_id, p.name, p.kind, p.check_name, p.threshold, p.minutes, p.severity,
				x.subject, x.label, x.detail, x.value, x.value, $7
			FROM unnest($1::uuid[], $2::uuid[], $3::text[], $4::text[], $5::text[], $6::float8[])
				AS x(policy_id, device_id, subject, label, detail, value)
			JOIN alert_policies p ON p.id = x.policy_id
			ON CONFLICT (policy_id, device_id, subject) WHERE status <> 'resolved' DO NOTHING`,
			opens.ids, opens.devices, opens.subjects, opens.labels, opens.text, opens.values, now)
		if err != nil {
			return 0, 0, err
		}
		opened = int(tag.RowsAffected())
	}
	if len(updates.ids) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE alerts a SET last_value = x.value, detail = x.detail
			FROM unnest($1::uuid[], $2::float8[], $3::text[]) AS x(id, value, detail)
			WHERE a.id = x.id AND a.status <> 'resolved' AND (a.last_value <> x.value OR a.detail <> x.detail)`,
			updates.ids, updates.values, updates.text); err != nil {
			return 0, 0, err
		}
	}
	if len(resolves.ids) > 0 {
		tag, err := tx.Exec(ctx, `UPDATE alerts a SET status = 'resolved', resolved_at = $4, resolution = 'cleared',
				last_value = x.value, detail = x.detail
			FROM unnest($1::uuid[], $2::float8[], $3::text[]) AS x(id, value, detail)
			WHERE a.id = x.id AND a.status <> 'resolved'`,
			resolves.ids, resolves.values, resolves.text, now)
		if err != nil {
			return 0, 0, err
		}
		resolved = int(tag.RowsAffected())
	}
	return opened, resolved, nil
}

// goneDisks resolves the alerts of disks gone for good (subject_gone) and
// removes their rows; their samples stay until their retention. A disk is
// gone once it has been missing for GoneAfter and no hardware report since
// it went missing lists it (ADR-0065, "Disks that disappear", as amended):
// a report that lists the disk clears missing_since, so a disk still
// missing has not been listed since.
func goneDisks(ctx context.Context, tx pgx.Tx, now time.Time) (int, error) {
	tag, err := tx.Exec(ctx, `WITH gone AS (
			DELETE FROM device_disk_health h
			WHERE h.missing_since <= $1::timestamptz - make_interval(secs => $2)
			RETURNING h.device_id, h.disk_key
		)
		UPDATE alerts a SET status = 'resolved', resolved_at = $1, resolution = 'subject_gone'
		FROM gone WHERE a.device_id = gone.device_id AND a.subject = gone.disk_key AND a.kind = 'disk_health' AND a.status <> 'resolved'`,
		now, GoneAfter.Seconds())
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
