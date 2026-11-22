package monitoring

import (
	"testing"
	"time"
)

func TestAlertWindow(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	at := func(m int) time.Time { return now.Add(time.Duration(m) * time.Minute) }
	const day = 24 * 60
	week := 7 * 24 * time.Hour
	cases := map[string]struct {
		opened   time.Time
		minutes  int
		resolved *time.Time
		kept     time.Duration
		from, to time.Time
		bucket   time.Duration
		trimmed  bool
	}{
		// 15 minutes before it opened and 10 open: padded by the 15-minute
		// least before, and never past now.
		"open":     {at(-10), 15, nil, week, at(-40), now, time.Minute, false},
		"resolved": {at(-120), 15, ptr(at(-100)), week, at(-150), at(-85), time.Minute, false},
		// Three days, resolved a day ago: padded by the 6-hour most, about 4
		// days in 30-minute points.
		"long": {at(-4 * day), 60, ptr(at(-day)), week, at(-4*day - 60 - 360), at(-day + 360), 30 * time.Minute, false},
		// Opened 10 days ago and still open: only the last 7 days are kept,
		// in hourly points.
		"open long ago": {at(-10 * day), 5, nil, week, at(-7 * day), now, time.Hour, true},
		// Opened and resolved before the oldest measurement kept: an empty
		// window at the oldest one.
		"ancient": {at(-400 * day), 5, ptr(at(-100 * day)), week, at(-7 * day), at(-7 * day), time.Minute, true},
		// Ends just inside what is kept: 7 hours, in 2-minute points.
		"partly kept": {at(-9 * day), 5, ptr(at(-7*day + 60)), week, at(-7 * day), at(-7*day + 60 + 360), 2 * time.Minute, true},
		// Kept for two years and open all of it: whole days, at most 240
		// points.
		"two years": {at(-800 * day), 5, nil, 730 * 24 * time.Hour, at(-730 * day), now, 4 * 24 * time.Hour, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			from, to, bucket, trimmed := alertWindow(c.opened, c.minutes, c.resolved, now, c.kept)
			if !from.Equal(c.from) || !to.Equal(c.to) || bucket != c.bucket || trimmed != c.trimmed {
				t.Fatalf("window %s to %s by %s (trimmed %t), want %s to %s by %s (trimmed %t)", from, to, bucket, trimmed, c.from, c.to, c.bucket, c.trimmed)
			}
		})
	}
}

// binsTouched counts the date_bin buckets (multiples of bucket since the
// epoch) a closed window from to to touches.
func binsTouched(from, to time.Time, bucket time.Duration) int64 {
	b := int64(bucket)
	floor := func(t time.Time) int64 {
		n := t.UnixNano()
		q := n / b
		if n%b < 0 {
			q--
		}
		return q
	}
	return floor(to) - floor(from) + 1
}

// TestAlertWindowPoints checks that no window, whatever its length,
// retention or alignment, gives more than maxPoints points.
func TestAlertWindowPoints(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 17, 300, time.UTC)
	for _, kept := range []time.Duration{24 * time.Hour, 7 * 24 * time.Hour, 90 * 24 * time.Hour, 730 * 24 * time.Hour, 3650 * 24 * time.Hour} {
		for open := time.Minute; open <= 4000*24*time.Hour; open = open*3/2 + 7*time.Second {
			for _, minutes := range []int{1, 5, 60, 1440} {
				opened := now.Add(-open)
				for _, resolved := range []*time.Time{nil, ptr(opened.Add(open / 3))} {
					from, to, bucket, _ := alertWindow(opened, minutes, resolved, now, kept)
					if from.Before(now.Add(-kept)) || to.After(now) || to.Before(from) {
						t.Fatalf("kept %s, open %s: window %s to %s outside what is kept", kept, open, from, to)
					}
					if n := binsTouched(from, to, bucket); n > maxPoints {
						t.Fatalf("kept %s, open %s, %d minutes: %d points by %s", kept, open, minutes, n, bucket)
					}
				}
			}
		}
	}
}

func TestMetricBucket(t *testing.T) {
	for span, want := range map[time.Duration]time.Duration{
		0:                    time.Minute,
		238 * time.Minute:    time.Minute,
		239 * time.Minute:    2 * time.Minute,
		238 * 24 * time.Hour: 24 * time.Hour,
		239 * 24 * time.Hour: 2 * 24 * time.Hour,
	} {
		if got := metricBucket(span); got != want {
			t.Errorf("metricBucket(%s) = %s, want %s", span, got, want)
		}
	}
}
