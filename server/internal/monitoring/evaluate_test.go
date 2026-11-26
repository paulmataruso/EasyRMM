package monitoring

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func ptr[T any](v T) *T { return &v }

func TestDecideOffline(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	alert := ptr(uuid.New())
	ago := func(m float64) *time.Time { return ptr(now.Add(-time.Duration(m * float64(time.Minute)))) }
	cases := map[string]struct {
		f    facts
		want action
		v    *float64
	}{
		"online":                   {facts{online: true, seen: ago(60)}, actNone, nil},
		"offline, not long enough": {facts{seen: ago(14.5)}, actNone, nil},
		"offline long enough":      {facts{seen: ago(31.7)}, actOpen, ptr(31.0)},
		"never seen":               {facts{}, actNone, nil},
		"still offline":            {facts{alertID: alert, seen: ago(45)}, actUpdate, ptr(45.0)},
		"back online":              {facts{alertID: alert, online: true, seen: ago(0)}, actResolve, nil},
		"checked in briefly":       {facts{alertID: alert, seen: ago(2)}, actResolve, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			c.f.kind, c.f.minutes = KindOffline, 15
			got, v := decide(c.f, now, time.Time{})
			if got != c.want || !sameFloat(v, c.v) {
				t.Fatalf("decide = %v %v, want %v %v", got, deref(v), c.want, deref(c.v))
			}
		})
	}
}

// TestDecideOfflineAfterStart: a device counts as seen no earlier than the
// floor, AgentGrace after the server began serving agents (ADR-0052).
func TestDecideOfflineAfterStart(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	alert := ptr(uuid.New())
	ago := func(m float64) time.Time { return now.Add(-time.Duration(m * float64(time.Minute))) }
	cases := map[string]struct {
		f     facts
		floor time.Time
		want  action
		v     *float64
	}{
		"just started":                    {facts{seen: ptr(ago(120))}, ago(-AgentGrace.Minutes()), actNone, nil},
		"a moment short of the minutes":   {facts{seen: ptr(ago(120))}, ago(14.9), actNone, nil},
		"the policy's minutes from floor": {facts{seen: ptr(ago(120))}, ago(15), actOpen, ptr(120.0)},
		"an open alert stays open":        {facts{alertID: alert, seen: ptr(ago(120))}, ago(-AgentGrace.Minutes()), actUpdate, ptr(120.0)},
		"back online after the start":     {facts{alertID: alert, online: true, seen: ptr(ago(0))}, ago(-AgentGrace.Minutes()), actResolve, nil},
		"the floor long past":             {facts{seen: ptr(ago(16))}, ago(600), actOpen, ptr(16.0)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			c.f.kind, c.f.minutes = KindOffline, 15
			got, v := decide(c.f, now, c.floor)
			if got != c.want || !sameFloat(v, c.v) {
				t.Fatalf("decide = %v %v, want %v %v", got, deref(v), c.want, deref(c.v))
			}
		})
	}
}

func TestDecideMeasurements(t *testing.T) {
	now := time.Now()
	alert := ptr(uuid.New())
	cases := map[string]struct {
		f    facts
		want action
		v    *float64
	}{
		"held long enough":         {facts{n: 15, lo: ptr(91.0), last: ptr(97.0)}, actOpen, ptr(97.0)},
		"exactly the threshold":    {facts{n: 15, lo: ptr(90.0), last: ptr(90.0)}, actOpen, ptr(90.0)},
		"half the window measured": {facts{n: 8, lo: ptr(95.0), last: ptr(95.0)}, actOpen, ptr(95.0)},
		"too few measurements":     {facts{n: 7, lo: ptr(95.0), last: ptr(95.0)}, actNone, nil},
		"one dip below":            {facts{n: 15, lo: ptr(89.9), last: ptr(99.0)}, actNone, nil},
		"no measurements":          {facts{}, actNone, nil},
		"still high":               {facts{alertID: alert, n: 15, nRecent: 5, lo: ptr(40.0), hiRecent: ptr(95.0), last: ptr(41.0)}, actUpdate, ptr(41.0)},
		"recently all below":       {facts{alertID: alert, n: 15, nRecent: 5, lo: ptr(10.0), hiRecent: ptr(89.0), last: ptr(12.0)}, actResolve, ptr(12.0)},
		"silent device keeps it":   {facts{alertID: alert}, actNone, nil},
		"no threshold":             {facts{threshold: nil, n: 15, lo: ptr(99.0), last: ptr(99.0)}, actNone, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			c.f.kind, c.f.minutes = KindCPU, 15
			if name != "no threshold" {
				c.f.threshold = ptr(90)
			}
			got, v := decide(c.f, now, now)
			if got != c.want || !sameFloat(v, c.v) {
				t.Fatalf("decide = %v %v, want %v %v", got, deref(v), c.want, deref(c.v))
			}
		})
	}
	// A one-minute policy needs one measurement.
	if got, _ := decide(facts{kind: KindDisk, threshold: ptr(90), minutes: 1, n: 1, lo: ptr(92.0), last: ptr(92.0)}, now, now); got != actOpen {
		t.Fatalf("one-minute policy = %v", got)
	}
}

func TestValidate(t *testing.T) {
	ok := condition{name: "CPU", kind: KindCPU, severity: SeverityWarning, threshold: ptr(90), minutes: 10}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	off := condition{name: "Down", kind: KindOffline, severity: SeverityCritical, threshold: ptr(50), minutes: 3}
	if err := off.validate(); err != nil || off.threshold != nil {
		t.Fatalf("offline: %v, threshold %v", err, off.threshold)
	}
	for name, cd := range map[string]condition{
		"name":        {kind: KindCPU, severity: SeverityWarning, threshold: ptr(90), minutes: 10},
		"kind":        {name: "x", kind: "temperature", severity: SeverityWarning, minutes: 10},
		"severity":    {name: "x", kind: KindCPU, severity: "info", threshold: ptr(90), minutes: 10},
		"threshold":   {name: "x", kind: KindMemory, severity: SeverityWarning, minutes: 10},
		"minutes":     {name: "x", kind: KindOffline, severity: SeverityWarning, minutes: 2},
		"description": {name: "x", kind: KindDisk, severity: SeverityWarning, threshold: ptr(90), minutes: 1, description: string(make([]rune, 2001))},
	} {
		if err := cd.validate(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	for _, m := range []int{0, 1441} {
		cd := ok
		cd.minutes = m
		if cd.validate() == nil {
			t.Errorf("minutes %d accepted", m)
		}
	}
	for _, th := range []int{0, 101} {
		cd := ok
		cd.threshold = ptr(th)
		if cd.validate() == nil {
			t.Errorf("threshold %d accepted", th)
		}
	}
}

func TestCleanText(t *testing.T) {
	if got := cleanText("  a\x00b\tc\nd ", false); got != "ab\tcd" {
		t.Fatalf("got %q", got)
	}
	if got := cleanText("a\nb\x07", true); got != "a\nb" {
		t.Fatalf("got %q", got)
	}
}

func sameFloat(a, b *float64) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func deref(v *float64) any {
	if v == nil {
		return nil
	}
	return *v
}

// A policy opens with at least half the measurements its window expects at the
// device's interval, rounded up, and at least one (ADR-0058); at 60 seconds that is
// today's (minutes+1)/2.
func TestNeeded(t *testing.T) {
	for _, c := range []struct{ minutes, interval, want int }{
		{15, 60, 8}, {5, 60, 3}, {1, 60, 1}, {2, 60, 1}, {10, 60, 5}, {1440, 60, 720},
		{15, 300, 2}, {5, 300, 1}, {1, 300, 1}, {60, 300, 6}, {15, 30, 15}, {1, 30, 1},
		{15, 0, 8}, {15, -3, 8},
	} {
		if got := needed(c.minutes, c.interval); got != c.want {
			t.Errorf("%d minutes at %d seconds: %d, want %d", c.minutes, c.interval, got, c.want)
		}
	}
	// At 60 seconds it is the old rule for every window the policies allow.
	for m := 1; m <= 1440; m++ {
		if got, old := needed(m, 60), max(1, (m+1)/2); m != 1 && got != old {
			t.Fatalf("%d minutes at 60 seconds: %d, the old rule says %d", m, got, old)
		}
	}
}
