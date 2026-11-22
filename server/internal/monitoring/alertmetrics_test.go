package monitoring

import (
	"testing"
	"time"
)

func TestAlertWindow(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	at := func(m int) time.Time { return now.Add(time.Duration(m) * time.Minute) }
	cases := map[string]struct {
		opened   time.Time
		minutes  int
		resolved *time.Time
		from, to time.Time
		bucket   time.Duration
	}{
		// 15 minutes before it opened and 10 open: padded by the 15-minute
		// least before, and never past now.
		"open":     {at(-10), 15, nil, at(-40), now, time.Minute},
		"resolved": {at(-120), 15, ptr(at(-100)), at(-150), at(-85), time.Minute},
		// Three days, resolved a day ago: padded by the 6-hour most, about 4
		// days in 30-minute points.
		"long":    {at(-4 * 24 * 60), 60, ptr(at(-24 * 60)), at(-4*24*60 - 60 - 360), at(-24*60 + 360), 30 * time.Minute},
		"ancient": {at(-400 * 24 * 60), 5, ptr(at(-100 * 24 * 60)), at(-400*24*60 - 5 - 360), at(-100*24*60 + 360), 24 * time.Hour},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			from, to, bucket := alertWindow(c.opened, c.minutes, c.resolved, now)
			if !from.Equal(c.from) || !to.Equal(c.to) || bucket != c.bucket {
				t.Fatalf("window %s to %s by %s, want %s to %s by %s", from, to, bucket, c.from, c.to, c.bucket)
			}
		})
	}
}
