package schedule

import (
	"testing"
	"time"
)

func mustLoc(t *testing.T, n string) *time.Location {
	t.Helper()
	l, err := time.LoadLocation(n)
	if err != nil {
		t.Skip("no tzdata:", err)
	}
	return l
}

func TestNextDailyDaylightSaving(t *testing.T) {
	ny := mustLoc(t, "America/New_York")
	s := Schedule{Kind: KindDaily, At: "02:30"}
	// 2026-03-08 02:30 does not exist in New York: the gap ends at 03:00 EDT.
	got, ok := s.Next(ny, time.Date(2026, 3, 8, 0, 0, 0, 0, ny))
	if !ok || !got.Equal(time.Date(2026, 3, 8, 7, 0, 0, 0, time.UTC)) {
		t.Fatalf("gap: %v %v", got, ok)
	}
	// 2026-11-01 01:30 happens twice: the first one (EDT, 05:30 UTC).
	s.At = "01:30"
	got, _ = s.Next(ny, time.Date(2026, 11, 1, 0, 0, 0, 0, ny))
	if !got.Equal(time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC)) {
		t.Fatalf("repeat: %v", got)
	}
	// The next one is the following day, once.
	got, _ = s.Next(ny, got)
	if !got.Equal(time.Date(2026, 11, 2, 6, 30, 0, 0, time.UTC)) {
		t.Fatalf("after repeat: %v", got)
	}
}

func TestNextWeeklyMonthlyOnceInterval(t *testing.T) {
	utc := time.UTC
	from := time.Date(2026, 1, 28, 12, 0, 0, 0, utc) // a Wednesday
	w := Schedule{Kind: KindWeekly, At: "03:00", Days: []int{1, 5}}
	if got, _ := w.Next(utc, from); !got.Equal(time.Date(2026, 1, 30, 3, 0, 0, 0, utc)) {
		t.Fatalf("weekly: %v", got)
	}
	m := Schedule{Kind: KindMonthly, At: "03:00", DayOfMonth: 31}
	if got, _ := m.Next(utc, from); !got.Equal(time.Date(2026, 1, 31, 3, 0, 0, 0, utc)) {
		t.Fatalf("monthly: %v", got)
	}
	// February has no 31st: the last day.
	if got, _ := m.Next(utc, time.Date(2026, 2, 1, 0, 0, 0, 0, utc)); !got.Equal(time.Date(2026, 2, 28, 3, 0, 0, 0, utc)) {
		t.Fatalf("monthly clamp: %v", got)
	}
	o := Schedule{Kind: KindOnce, Date: "2026-02-01", At: "10:00"}
	if got, ok := o.Next(utc, from); !ok || !got.Equal(time.Date(2026, 2, 1, 10, 0, 0, 0, utc)) {
		t.Fatalf("once: %v %v", got, ok)
	}
	if _, ok := o.Next(utc, time.Date(2026, 2, 2, 0, 0, 0, 0, utc)); ok {
		t.Fatal("a passed once schedule has no next")
	}
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, utc)
	i := Schedule{Kind: KindInterval, EveryMinutes: 90, Anchor: &anchor}
	if got, _ := i.Next(utc, time.Date(2026, 1, 1, 1, 0, 0, 0, utc)); !got.Equal(time.Date(2026, 1, 1, 1, 30, 0, 0, utc)) {
		t.Fatalf("interval: %v", got)
	}
}

func TestLastDue(t *testing.T) {
	utc := time.UTC
	d := Schedule{Kind: KindDaily, At: "03:00"}
	prev := time.Date(2026, 1, 1, 3, 0, 0, 0, utc)
	last, n := d.LastDue(utc, prev, time.Date(2026, 1, 4, 5, 0, 0, 0, utc))
	if n != 4 || !last.Equal(time.Date(2026, 1, 4, 3, 0, 0, 0, utc)) {
		t.Fatalf("daily: %v %d", last, n)
	}
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, utc)
	i := Schedule{Kind: KindInterval, EveryMinutes: 60, Anchor: &anchor}
	last, n = i.LastDue(utc, anchor.Add(time.Hour), anchor.Add(5*time.Hour+10*time.Minute))
	if n != 5 || !last.Equal(anchor.Add(5*time.Hour)) {
		t.Fatalf("interval: %v %d", last, n)
	}
}

func TestClean(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, bad := range []Schedule{
		{Kind: "hourly"}, {Kind: KindDaily, At: "25:00"}, {Kind: KindWeekly, At: "01:00"}, {Kind: KindWeekly, At: "01:00", Days: []int{7}},
		{Kind: KindMonthly, At: "01:00", DayOfMonth: 0}, {Kind: KindInterval, EveryMinutes: 1}, {Kind: KindOnce, At: "01:00", Date: "soon"},
	} {
		if _, err := bad.Clean(now); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	s, err := Schedule{Kind: KindInterval, EveryMinutes: 15}.Clean(now)
	if err != nil || s.Anchor == nil {
		t.Fatalf("interval: %+v %v", s, err)
	}
}
