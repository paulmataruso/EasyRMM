package docs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func iv(start, end string) Interval { return Interval{Start: start, End: end} }

// TestZone checks that a time zone is read from the system's database once
// and kept (L8): a list of organizations asks for each one's.
func TestZone(t *testing.T) {
	first := Zone("Europe/London")
	if first.String() != "Europe/London" {
		t.Fatalf("Zone = %v", first)
	}
	if again := Zone("Europe/London"); again != first {
		t.Error("the zone was loaded again")
	}
	if Zone("Mars/Olympus_Mons") != time.UTC {
		t.Error("an unknown zone is not UTC")
	}
	if _, kept := zones.Load("Mars/Olympus_Mons"); kept {
		t.Error("an unknown zone was kept")
	}
}

func TestHoursNormalize(t *testing.T) {
	h := Hours{Monday: []Interval{iv("13:00", "17:00"), iv("08:30", "12:00")}, Friday: []Interval{iv("22:00", "02:00")}}
	open, problem := h.Normalize()
	if !open || problem != "" {
		t.Fatalf("a valid schedule: %v %q", open, problem)
	}
	if h.Monday[0].Start != "08:30" || h.Monday[1].Start != "13:00" {
		t.Errorf("intervals not sorted by start: %+v", h.Monday)
	}
	if h.Tuesday == nil || len(h.Tuesday) != 0 || h.Sunday == nil {
		t.Errorf("a day without intervals is not an empty list: %+v", h)
	}
	b, _ := json.Marshal(h)
	if !strings.Contains(string(b), `"tuesday":[]`) {
		t.Errorf("closed days are not written as empty lists: %s", b)
	}

	var none Hours
	if open, problem := none.Normalize(); open || problem != "" {
		t.Errorf("a schedule without intervals: %v %q", open, problem)
	}

	for name, c := range map[string]struct {
		h    Hours
		want string
	}{
		"five a day":          {Hours{Monday: []Interval{iv("01:00", "02:00"), iv("03:00", "04:00"), iv("05:00", "06:00"), iv("07:00", "08:00"), iv("09:00", "10:00")}}, "at most 4"},
		"no colon":            {Hours{Tuesday: []Interval{iv("0830", "12:00")}}, "hours and minutes"},
		"one digit":           {Hours{Tuesday: []Interval{iv("8:30", "12:00")}}, "hours and minutes"},
		"hour 24":             {Hours{Tuesday: []Interval{iv("09:00", "24:00")}}, "hours and minutes"},
		"minute 60":           {Hours{Tuesday: []Interval{iv("09:60", "10:00")}}, "hours and minutes"},
		"letters":             {Hours{Tuesday: []Interval{iv("ab:cd", "10:00")}}, "hours and minutes"},
		"overlap in a day":    {Hours{Wednesday: []Interval{iv("08:00", "12:00"), iv("11:59", "13:00")}}, "overlap"},
		"overlap at midnight": {Hours{Monday: []Interval{iv("22:00", "02:00")}, Tuesday: []Interval{iv("01:00", "03:00")}}, "overlap"},
		"a whole day overlaps": {Hours{Monday: []Interval{iv("09:00", "09:00")}, Tuesday: []Interval{iv("08:00", "10:00")}},
			"overlap"},
		"Sunday into Monday": {Hours{Sunday: []Interval{iv("23:00", "01:00")}, Monday: []Interval{iv("00:30", "02:00")}}, "Sunday"},
	} {
		if _, problem := c.h.Normalize(); !strings.Contains(problem, c.want) {
			t.Errorf("%s: %q, want %q", name, problem, c.want)
		}
	}

	// Touching is not overlapping, across midnight and the week's end too.
	for name, h := range map[string]Hours{
		"in a day":    {Thursday: []Interval{iv("08:00", "12:00"), iv("12:00", "13:00")}},
		"at midnight": {Monday: []Interval{iv("22:00", "00:00")}, Tuesday: []Interval{iv("00:00", "06:00")}},
		"week's end":  {Sunday: []Interval{iv("20:00", "01:00")}, Monday: []Interval{iv("01:00", "09:00")}},
		"every whole day": {Monday: []Interval{iv("00:00", "00:00")}, Tuesday: []Interval{iv("00:00", "00:00")}, Wednesday: []Interval{iv("00:00", "00:00")},
			Thursday: []Interval{iv("00:00", "00:00")}, Friday: []Interval{iv("00:00", "00:00")}, Saturday: []Interval{iv("00:00", "00:00")}, Sunday: []Interval{iv("00:00", "00:00")}},
	} {
		if open, problem := h.Normalize(); !open || problem != "" {
			t.Errorf("%s: %v %q", name, open, problem)
		}
	}
}

func TestParseHours(t *testing.T) {
	if h, err := ParseHours(nil); h != nil || err != nil {
		t.Errorf("none: %v %v", h, err)
	}
	h, err := ParseHours([]byte(`{"monday":[{"start":"12:00","end":"13:00"},{"start":"08:00","end":"09:00"}]}`))
	if err != nil || h.Monday[0].Start != "08:00" || h.Sunday == nil {
		t.Errorf("stored hours: %+v %v", h, err)
	}
	if _, err := ParseHours([]byte(`[]`)); err == nil {
		t.Error("a list read as hours")
	}
}

// at is a wall clock time in loc, which must exist.
func at(t *testing.T, loc *time.Location, s string) time.Time {
	t.Helper()
	x, err := time.ParseInLocation("2006-01-02 15:04", s, loc)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func utc(t *testing.T, s string) time.Time { return at(t, time.UTC, s) }

func TestOpenAt(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	london, err := time.LoadLocation("Europe/London")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct {
		date string
		day  time.Weekday
	}{{"2026-03-08", time.Sunday}, {"2026-11-01", time.Sunday}, {"2026-03-29", time.Sunday}, {"2026-11-23", time.Monday}} {
		if got := utc(t, d.date+" 12:00").Weekday(); got != d.day {
			t.Fatalf("%s is a %s", d.date, got)
		}
	}

	h := Hours{
		Monday:   []Interval{iv("09:00", "17:00")},
		Friday:   []Interval{iv("22:00", "02:00")},
		Saturday: []Interval{iv("10:00", "10:00")},
	}
	h.Normalize()
	for when, want := range map[string]bool{
		"2026-11-23 08:59": false, // Monday
		"2026-11-23 09:00": true,
		"2026-11-23 16:59": true,
		"2026-11-23 17:00": false,
		"2026-11-27 23:30": true, // Friday, running past midnight
		"2026-11-28 01:59": true, // Saturday morning, still Friday's
		"2026-11-28 02:00": false,
		"2026-11-28 10:00": true, // Saturday's 24 hours
		"2026-11-29 09:59": true, // Sunday, still Saturday's
		"2026-11-29 10:00": false,
		"2026-11-24 12:00": false, // Tuesday
	} {
		if got := h.OpenAt(at(t, ny, when), ny); got != want {
			t.Errorf("%s New York: open %v, want %v", when, got, want)
		}
	}

	// A time in the skipped hour begins when the gap ends: 02:30 on the day
	// clocks go forward in New York is 03:00 EDT, 07:00 UTC.
	spring := Hours{Sunday: []Interval{iv("02:30", "04:00")}}
	spring.Normalize()
	for when, want := range map[string]bool{
		"2026-03-08 06:59": false, // 01:59 EST
		"2026-03-08 07:00": true,  // 03:00 EDT
		"2026-03-08 07:59": true,
		"2026-03-08 08:00": false, // 04:00 EDT
	} {
		if got := spring.OpenAt(utc(t, when), ny); got != want {
			t.Errorf("%s UTC, spring forward: open %v, want %v", when, got, want)
		}
	}

	// A time in the repeated hour is its first occurrence: 01:30 on the day
	// clocks go back is 01:30 EDT, 05:30 UTC.
	fall := Hours{Sunday: []Interval{iv("01:30", "03:00")}}
	fall.Normalize()
	for when, want := range map[string]bool{
		"2026-11-01 05:29": false, // 01:29 EDT
		"2026-11-01 05:30": true,  // 01:30 EDT
		"2026-11-01 06:15": true,  // 01:15 EST, the second time round
		"2026-11-01 07:59": true,  // 02:59 EST
		"2026-11-01 08:00": false, // 03:00 EST
	} {
		if got := fall.OpenAt(utc(t, when), ny); got != want {
			t.Errorf("%s UTC, fall back: open %v, want %v", when, got, want)
		}
	}
	early := Hours{Sunday: []Interval{iv("00:00", "01:30")}}
	early.Normalize()
	if early.OpenAt(utc(t, "2026-11-01 06:15"), ny) {
		t.Error("an end in the repeated hour waits for its second occurrence")
	}

	// London goes forward at 01:00 GMT: 01:30 is 02:00 BST, 01:00 UTC.
	uk := Hours{Sunday: []Interval{iv("01:30", "05:00")}}
	uk.Normalize()
	if uk.OpenAt(utc(t, "2026-03-29 00:59"), london) || !uk.OpenAt(utc(t, "2026-03-29 01:00"), london) {
		t.Error("London's skipped hour")
	}
}
