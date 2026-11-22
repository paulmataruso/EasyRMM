package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// maxSubject bounds an alert's subject (a disk's identity), as the
// database does.
const maxSubject = 64

// AlertMetrics is the measurement a processor, memory or disk use alert
// watches, over the alert's window with some time either side: from the
// policy's minutes before it opened until it resolved (or now), and never
// before the oldest measurement kept.
type AlertMetrics struct {
	// Metric is cpu, memory or disk (the fullest filesystem).
	Metric    string    `json:"metric"`
	Threshold *int      `json:"threshold"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	// BucketSeconds is the width of each averaged point; there are at most
	// maxPoints of them.
	BucketSeconds int `json:"bucketSeconds"`
	// Trimmed says the window starts later than the alert's, because
	// earlier measurements are no longer kept.
	Trimmed bool          `json:"trimmed"`
	Samples []MetricPoint `json:"samples"`
}

// MetricPoint is the average of the alert's measurement over one bucket.
type MetricPoint struct {
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
}

// metricBuckets are the widths a window is averaged into, the narrowest
// first; maxPoints bounds how many points any window gives.
var metricBuckets = []time.Duration{
	time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute,
	time.Hour, 2 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour,
}

const maxPoints = 240

// alertWindow is the period an alert's chart covers: the policy's minutes
// before it opened until it resolved (or now), with a quarter of that
// either side, at least 15 minutes and at most 6 hours. It never starts
// before kept ago, the oldest measurement still kept, and never ends past
// now; trimmed says the start was moved for that. A window wholly older
// than that is empty, at its start.
func alertWindow(openedAt time.Time, minutes int, resolvedAt *time.Time, now time.Time, kept time.Duration) (from, to time.Time, bucket time.Duration, trimmed bool) {
	start := openedAt.Add(-time.Duration(minutes) * time.Minute)
	end := now
	if resolvedAt != nil {
		end = *resolvedAt
	}
	pad := min(max(end.Sub(start)/4, 15*time.Minute), 6*time.Hour)
	from, to = start.Add(-pad), end.Add(pad)
	if oldest := now.Add(-kept); from.Before(oldest) {
		from, trimmed = oldest, true
	}
	if to.After(now) {
		to = now
	}
	if to.Before(from) {
		to = from
	}
	return from, to, metricBucket(to.Sub(from)), trimmed
}

// metricBucket is the narrowest width that keeps a window of span within
// maxPoints points. date_bin cuts time at fixed multiples of the width, so
// span touches at most span/width + 2 of them. Past the widest of
// metricBuckets (a measurement retention near a year), it is whole days.
func metricBucket(span time.Duration) time.Duration {
	for _, b := range metricBuckets {
		if span/b <= maxPoints-2 {
			return b
		}
	}
	const day = 24 * time.Hour
	return (span/(maxPoints-2)/day + 1) * day
}

// AlertMetrics returns the measurement behind a processor, memory or disk
// use alert. The caller must be able to see the alert and the device's
// measurements.
func (s *Service) AlertMetrics(ctx context.Context, c access.Caller, id uuid.UUID) (*AlertMetrics, error) {
	var out *AlertMetrics
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		a, err := getAlert(ctx, tx, c, id, false)
		if err != nil {
			return err
		}
		if !c.Can(rbac.PermDeviceView, a.site()) {
			return apperr.NotFound()
		}
		column, ok := map[string]string{KindCPU: "cpu_percent", KindMemory: "memory_percent", KindDisk: "disk_percent"}[a.Kind]
		if !ok {
			return apperr.Conflict("alert_has_no_metrics", "Only processor, memory and disk use alerts are measured.")
		}
		from, to, bucket, trimmed := alertWindow(a.OpenedAt, a.Minutes, a.ResolvedAt, s.now(), s.metricsKept)
		out = &AlertMetrics{Metric: a.Kind, Threshold: a.Threshold, From: from, To: to, BucketSeconds: int(bucket.Seconds()), Trimmed: trimmed, Samples: []MetricPoint{}}
		// column comes from the map above, never from the request.
		rows, err := tx.Query(ctx, `SELECT date_bin($2::interval, at, 'epoch'::timestamptz) AS b, avg(`+column+`)::float8
			FROM device_metric_samples WHERE device_id = $1 AND at >= $3 AND at <= $4
			GROUP BY b ORDER BY b`, a.DeviceID, fmt.Sprintf("%d seconds", int64(bucket.Seconds())), from, to)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p MetricPoint
			if err := rows.Scan(&p.At, &p.Value); err != nil {
				return err
			}
			out.Samples = append(out.Samples, p)
		}
		return rows.Err()
	})
	return out, err
}
