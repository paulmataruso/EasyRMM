package monitoring

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// lockEvaluate is the advisory lock that keeps two servers on one database
// from evaluating at the same time.
const lockEvaluate = 7302265818151

// ResolveWindow is how long a processor, memory or disk measurement must
// stay below the threshold for its alert to resolve (or the policy's
// minutes, when shorter).
const ResolveWindow = 5

// Result counts what an evaluation changed.
type Result struct {
	Opened   int
	Resolved int
	// Skipped is true when another server was evaluating.
	Skipped bool
}

// Evaluate checks every enabled policy against the devices it covers (and
// their disks, for disk health), opens alerts for conditions that hold,
// updates open alerts' latest values and resolves the alerts whose
// condition cleared or no longer applies, or whose disk is gone.
func (s *Service) Evaluate(ctx context.Context) (Result, error) {
	var r Result
	now := s.now()
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		r = Result{}
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, int64(lockEvaluate)).Scan(&locked); err != nil {
			return err
		}
		if !locked {
			r.Skipped = true
			return nil
		}
		n, err := reconcile(ctx, tx, now, uuid.Nil)
		if err != nil {
			return err
		}
		r.Resolved += n
		if n, err = goneDisks(ctx, tx, now); err != nil {
			return err
		}
		r.Resolved += n
		floor := s.seenFloor(now)
		list, err := loadFacts(ctx, tx, now, floor)
		if err != nil {
			return err
		}
		var opens, updates, resolves changes
		for _, f := range list {
			act, v := decide(f, now, floor)
			switch act {
			case actOpen:
				opens.add(f.policyID, f.deviceID, v)
			case actUpdate:
				updates.add(*f.alertID, uuid.Nil, v)
			case actResolve:
				resolves.add(*f.alertID, uuid.Nil, v)
			}
		}
		if len(opens.a) > 0 {
			tag, err := tx.Exec(ctx, `INSERT INTO alerts (policy_id, device_id, name, kind, threshold, minutes, severity, value, last_value, opened_at)
				SELECT p.id, x.device_id, p.name, p.kind, p.threshold, p.minutes, p.severity, x.value, x.value, $4
				FROM unnest($1::uuid[], $2::uuid[], $3::float8[]) AS x(policy_id, device_id, value)
				JOIN alert_policies p ON p.id = x.policy_id
				ON CONFLICT (policy_id, device_id, subject) WHERE status <> 'resolved' DO NOTHING`,
				opens.a, opens.b, opens.v, now)
			if err != nil {
				return err
			}
			r.Opened = int(tag.RowsAffected())
		}
		if len(updates.a) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE alerts a SET last_value = x.value
				FROM unnest($1::uuid[], $2::float8[]) AS x(id, value)
				WHERE a.id = x.id AND a.status <> 'resolved' AND a.last_value IS DISTINCT FROM x.value`,
				updates.a, updates.v); err != nil {
				return err
			}
		}
		if len(resolves.a) > 0 {
			tag, err := tx.Exec(ctx, `UPDATE alerts a SET status = 'resolved', resolved_at = $3, resolution = 'cleared',
					last_value = coalesce(x.value, a.last_value)
				FROM unnest($1::uuid[], $2::float8[]) AS x(id, value)
				WHERE a.id = x.id AND a.status <> 'resolved'`,
				resolves.a, resolves.v, now)
			if err != nil {
				return err
			}
			r.Resolved += int(tag.RowsAffected())
		}
		opened, resolved, err := evaluateDisks(ctx, tx, now)
		r.Opened += opened
		r.Resolved += resolved
		if err != nil {
			return err
		}
		opened, resolved, err = s.evaluateRemote(ctx, tx, now, floor)
		r.Opened += opened
		r.Resolved += resolved
		if err != nil {
			return err
		}
		opened, resolved, err = s.evaluateModules(ctx, tx, now)
		r.Opened += opened
		r.Resolved += resolved
		return err
	})
	return r, err
}

// changes collects one statement's rows as parallel arrays for unnest.
type changes struct {
	a, b []uuid.UUID
	v    []*float64
}

func (c *changes) add(a, b uuid.UUID, v *float64) {
	c.a = append(c.a, a)
	c.b = append(c.b, b)
	c.v = append(c.v, v)
}

// reconcile resolves the unresolved alerts whose policy was deleted, turned
// off or given a different condition (kind, check, threshold or minutes),
// or no longer covers the device, and
// brings the rest up to their policy's name and severity. policyID limits
// it to one policy; uuid.Nil reconciles them all.
func reconcile(ctx context.Context, tx pgx.Tx, now time.Time, policyID uuid.UUID) (int, error) {
	tag, err := tx.Exec(ctx, `WITH stale AS (
			SELECT a.id, CASE
				WHEN p.id IS NULL THEN 'policy_deleted'
				WHEN NOT p.enabled THEN 'policy_off'
				WHEN p.kind <> a.kind OR p.check_name IS DISTINCT FROM a.check_name OR p.threshold IS DISTINCT FROM a.threshold
					OR p.minutes <> a.minutes THEN 'policy_changed'
				WHEN NOT (p.organization_id IS NULL OR (p.organization_id = d.organization_id
					AND (p.site_id IS NULL OR p.site_id = d.site_id))) THEN 'not_covered'
			END AS reason
			FROM alerts a
			JOIN devices d ON d.id = a.device_id
			LEFT JOIN alert_policies p ON p.id = a.policy_id
			WHERE a.status <> 'resolved' AND a.kind <> 'repair_failed' AND ($2::uuid IS NULL OR a.policy_id = $2)
		)
		UPDATE alerts a SET status = 'resolved', resolved_at = $1, resolution = stale.reason
		FROM stale WHERE a.id = stale.id AND stale.reason IS NOT NULL`, now, nullUUID(policyID))
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE alerts a SET name = p.name, severity = p.severity
		FROM alert_policies p
		WHERE p.id = a.policy_id AND a.status <> 'resolved' AND ($1::uuid IS NULL OR a.policy_id = $1)
		  AND (a.name <> p.name OR a.severity <> p.severity)`, nullUUID(policyID)); err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// facts is what one enabled policy sees on one device it covers.
type facts struct {
	policyID, deviceID uuid.UUID
	kind               string
	threshold          *int
	minutes            int
	// alertID is the policy's unresolved alert on the device.
	alertID *uuid.UUID
	// For offline: whether the device is checked in now, and when it last
	// was.
	online bool
	seen   *time.Time
	// interval is the seconds between the device's heartbeats, which its
	// measurements follow (ADR-0058).
	interval int
	// For processor, memory and disk: the measurements of the policy's
	// minutes (n, the lowest, the latest) and of the resolve window (n and
	// the highest).
	n, nRecent int
	lo, last   *float64
	hiRecent   *float64
}

// A window is never shorter than 1.2 of the device's intervals, so the
// jitter of a tenth either way never leaves it empty (ADR-0058). The SQL and
// needed agree on it.
const windowIntervals = "1.2"

// needed is how many measurements a policy's window must hold before it
// opens an alert: at least half of those expected at the device's interval,
// rounded up, and at least one. At 60 seconds it is today's (minutes+1)/2.
func needed(minutes, interval int) int {
	if interval <= 0 {
		interval = 60
	}
	tenths := max(600*minutes, 12*interval) // the window, in tenths of seconds
	return max(1, (tenths+20*interval-1)/(20*interval))
}

// loadFacts reads, for every enabled policy and covered device, what the
// decision needs; disk health has its own (evaluateDisks). Pairs with no alert whose condition plainly does not hold
// are left out, offline ones also until the policy's minutes have passed
// since floor (see decide).
func loadFacts(ctx context.Context, tx pgx.Tx, now, floor time.Time) ([]facts, error) {
	rows, err := tx.Query(ctx, `SELECT * FROM (
			SELECT p.id AS policy_id, d.id AS device_id, p.kind, p.threshold, p.minutes, a.id AS alert_id,
				d.remote_online OR coalesce(d.agent_online_until > $1::timestamptz, false) AS online,
				d.agent_heartbeat_seconds AS hb_seconds,
				greatest(d.last_seen_at, d.agent_last_seen_at) AS seen,
				coalesce(s.n, 0) AS n, coalesce(s.n_recent, 0) AS n_recent, s.lo, s.last, s.hi_recent
			FROM alert_policies p
			JOIN devices d ON NOT d.quick_assist AND (p.organization_id IS NULL
				OR (p.organization_id = d.organization_id AND (p.site_id IS NULL OR p.site_id = d.site_id)))
			LEFT JOIN alerts a ON a.policy_id = p.id AND a.device_id = d.id AND a.status <> 'resolved'
			LEFT JOIN LATERAL (
				SELECT count(*) AS n, min(v) AS lo, (array_agg(v ORDER BY at DESC))[1] AS last,
					count(*) FILTER (WHERE at > $1::timestamptz - make_interval(secs => greatest(least(p.minutes, $2) * 60, `+windowIntervals+` * d.agent_heartbeat_seconds))) AS n_recent,
					max(v) FILTER (WHERE at > $1::timestamptz - make_interval(secs => greatest(least(p.minutes, $2) * 60, `+windowIntervals+` * d.agent_heartbeat_seconds))) AS hi_recent
				FROM (
					SELECT ms.at, (CASE p.kind WHEN 'cpu' THEN ms.cpu_percent WHEN 'memory' THEN ms.memory_percent
						ELSE ms.disk_percent END)::float8 AS v
					FROM device_metric_samples ms
					WHERE p.kind <> 'offline' AND ms.device_id = d.id
					  AND ms.at > $1::timestamptz - make_interval(secs => greatest(p.minutes * 60, `+windowIntervals+` * d.agent_heartbeat_seconds)) AND ms.at <= $1
				) x
			) s ON true
			WHERE p.enabled AND p.kind IN ('offline', 'cpu', 'memory', 'disk')
		) f
		WHERE alert_id IS NOT NULL
		   OR (kind = 'offline' AND NOT online AND seen <= $1::timestamptz - make_interval(mins => minutes)
			AND $3::timestamptz <= $1::timestamptz - make_interval(mins => minutes))
		   OR (kind <> 'offline' AND lo >= threshold)`,
		now, ResolveWindow, floor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []facts
	for rows.Next() {
		var f facts
		if err := rows.Scan(&f.policyID, &f.deviceID, &f.kind, &f.threshold, &f.minutes, &f.alertID,
			&f.online, &f.interval, &f.seen, &f.n, &f.nRecent, &f.lo, &f.last, &f.hiRecent); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

type action int

const (
	actNone action = iota
	actOpen
	actUpdate
	actResolve
)

// decide turns facts into what to do with the pair, and the value to record
// (nil keeps the alert's latest value). An offline policy opens an alert
// only when the device also counts as unseen from floor, the earliest it
// could have checked in since the server began serving agents (ADR-0052);
// an alert already open stays open while the device has not checked in,
// and records how long ago it last did.
func decide(f facts, now, floor time.Time) (action, *float64) {
	if f.kind == KindOffline {
		limit := time.Duration(f.minutes) * time.Minute
		met := !f.online && f.seen != nil && now.Sub(*f.seen) >= limit
		switch {
		case !met && f.alertID != nil:
			return actResolve, nil
		case !met:
			return actNone, nil
		case f.alertID == nil && now.Sub(floor) < limit:
			return actNone, nil
		}
		v := math.Floor(now.Sub(*f.seen).Minutes())
		if f.alertID == nil {
			return actOpen, &v
		}
		return actUpdate, &v
	}
	if f.threshold == nil {
		return actNone, nil
	}
	limit := float64(*f.threshold)
	if f.alertID == nil {
		// Every measurement of the window at or above the threshold, and at
		// least half those expected at the device's interval: a device that
		// has just come back does not trip on one or two readings.
		if f.n >= needed(f.minutes, f.interval) && f.lo != nil && *f.lo >= limit && f.last != nil {
			return actOpen, f.last
		}
		return actNone, nil
	}
	if f.nRecent > 0 && f.hiRecent != nil && *f.hiRecent < limit {
		return actResolve, f.last
	}
	if f.n > 0 && f.last != nil {
		return actUpdate, f.last
	}
	// No measurements: the device is offline, which is the offline
	// policy's business. The alert stays as it is.
	return actNone, nil
}
