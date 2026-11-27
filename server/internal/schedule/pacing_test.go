package schedule

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSpread(t *testing.T) {
	got := Spread(4, time.Hour)
	want := []time.Duration{0, 15 * time.Minute, 30 * time.Minute, 45 * time.Minute}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Spread(4, 1h) = %v", got)
		}
	}
	for _, c := range []struct {
		n    int
		span time.Duration
	}{{1, time.Hour}, {5, 0}, {5, 30 * time.Second}} {
		for _, o := range Spread(c.n, c.span) {
			if o != 0 {
				t.Fatalf("Spread(%d, %v) is not all zero", c.n, c.span)
			}
		}
	}
	// More devices than minutes: some share a minute, none is outside the span.
	for _, o := range Spread(100, 10*time.Minute) {
		if o < 0 || o >= 10*time.Minute {
			t.Fatalf("offset %v outside the span", o)
		}
	}
}

func TestPlanStaggersEachSite(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	var devs []device
	for range 3 {
		devs = append(devs, device{id: uuid.New(), site: a})
	}
	for range 2 {
		devs = append(devs, device{id: uuid.New(), site: b})
	}
	plan := Plan(devs, 30*time.Minute)
	// Every site has exactly one device at offset zero, so no site starts at once.
	zero := map[uuid.UUID]int{}
	total := 0
	for _, s := range plan {
		if s.offset == 0 {
			zero[s.site] += len(s.devices)
		}
		total += len(s.devices)
	}
	if zero[a] != 1 || zero[b] != 1 || total != 5 {
		t.Fatalf("plan: %+v", plan)
	}
}
