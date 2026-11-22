package docs

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"
)

// zones holds each time zone Zone has loaded, by name. The names are the
// IANA ones organizations and sites are checked against, so it stays as
// small as that list.
var zones sync.Map

// Zone is the time zone of an IANA name, read from the system's database
// once and kept: every organization and site in a list asks for its own.
// A name the system does not know is UTC, and is not kept.
func Zone(name string) *time.Location {
	if loc, ok := zones.Load(name); ok {
		return loc.(*time.Location)
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC
	}
	kept, _ := zones.LoadOrStore(name, loc)
	return kept.(*time.Location)
}

// Business hours (ADR-0066, "The customer record").
const (
	// MaxIntervalsPerDay bounds a day's intervals.
	MaxIntervalsPerDay = 4
	minutesPerDay      = 24 * 60
	minutesPerWeek     = 7 * minutesPerDay
)

// Interval is one stretch of opening on a day: a start and an end in local
// time, "HH:MM" on the 24-hour clock. An end at or before the start runs
// past midnight and belongs to the day it starts; an end equal to the start
// is 24 hours.
type Interval struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// Hours is a weekly schedule of up to four intervals a day. A day with
// none is closed.
type Hours struct {
	Monday    []Interval `json:"monday"`
	Tuesday   []Interval `json:"tuesday"`
	Wednesday []Interval `json:"wednesday"`
	Thursday  []Interval `json:"thursday"`
	Friday    []Interval `json:"friday"`
	Saturday  []Interval `json:"saturday"`
	Sunday    []Interval `json:"sunday"`
}

// day returns the intervals of a weekday.
func (h *Hours) day(d time.Weekday) *[]Interval {
	return [...]*[]Interval{&h.Sunday, &h.Monday, &h.Tuesday, &h.Wednesday, &h.Thursday, &h.Friday, &h.Saturday}[d]
}

// span is an interval as minutes of the week from Monday 00:00. end is
// after start and at most a day later.
type span struct{ start, end int }

// parseClock reads "HH:MM" as minutes after midnight.
func parseClock(s string) (int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	digit := func(b byte) (int, bool) { return int(b - '0'), b >= '0' && b <= '9' }
	h1, ok1 := digit(s[0])
	h2, ok2 := digit(s[1])
	m1, ok3 := digit(s[3])
	m2, ok4 := digit(s[4])
	h, m := h1*10+h2, m1*10+m2
	return h*60 + m, ok1 && ok2 && ok3 && ok4 && h < 24 && m < 60
}

// Normalize sorts each day's intervals by their start and checks the
// schedule: valid times, at most four intervals a day, and no interval
// overlapping another, across midnight and from Sunday into Monday
// included. It reports whether any day has an interval: a schedule without
// one is no schedule, kept as none. The problem is a sentence for people.
func (h *Hours) Normalize() (open bool, problem string) {
	var spans []span
	for i, d := range []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday, time.Saturday, time.Sunday} {
		ivs := h.day(d)
		if *ivs == nil {
			*ivs = []Interval{}
		}
		if len(*ivs) > MaxIntervalsPerDay {
			return false, fmt.Sprintf("Give %s at most %d periods of opening.", d, MaxIntervalsPerDay)
		}
		for _, iv := range *ivs {
			start, ok1 := parseClock(iv.Start)
			end, ok2 := parseClock(iv.End)
			if !ok1 || !ok2 {
				return false, fmt.Sprintf("Give %s's times as hours and minutes, such as 08:30.", d)
			}
			if end <= start {
				end += minutesPerDay
			}
			spans = append(spans, span{i*minutesPerDay + start, i*minutesPerDay + end})
		}
		slices.SortFunc(*ivs, func(a, b Interval) int { return cmp.Compare(a.Start, b.Start) })
	}
	if len(spans) == 0 {
		return false, ""
	}
	slices.SortFunc(spans, func(a, b span) int { return cmp.Compare(a.start, b.start) })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return false, "Periods of opening overlap. Make each end before the next begins."
		}
	}
	// Sunday's last interval may run into Monday.
	if last := spans[len(spans)-1]; last.end-minutesPerWeek > spans[0].start {
		return false, "Sunday's last period runs into Monday's first. Make it end before Monday's begins."
	}
	return true, ""
}

// ParseHours reads a schedule as the database keeps it.
func ParseHours(raw []byte) (*Hours, error) {
	if raw == nil {
		return nil, nil
	}
	var h Hours
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("docs: business hours: %w", err)
	}
	h.Normalize()
	return &h, nil
}

// OpenAt reports whether t falls in an interval, read in loc. Only today's
// intervals and yesterday's that run past midnight can hold t.
func (h *Hours) OpenAt(t time.Time, loc *time.Location) bool {
	local := t.In(loc)
	y, m, d := local.Date()
	for back := 0; back <= 1; back++ {
		day := time.Date(y, m, d-back, 0, 0, 0, 0, time.UTC)
		for _, iv := range *h.day(day.Weekday()) {
			start, _ := parseClock(iv.Start)
			end, _ := parseClock(iv.End)
			endDay := day
			if end <= start {
				endDay = day.AddDate(0, 0, 1)
			}
			if !t.Before(wallClock(day, start, loc)) && t.Before(wallClock(endDay, end, loc)) {
				return true
			}
		}
	}
	return false
}

// wallClock is the instant a local time on a date names, as ADR-0053 reads
// maintenance windows across daylight saving: a time in a skipped hour is
// when the gap ends, and a time in a repeated hour is its first occurrence.
// date is midnight UTC of the date.
func wallClock(date time.Time, minute int, loc *time.Location) time.Time {
	naive := date.Add(time.Duration(minute) * time.Minute)
	// The offsets in effect within a day either side cover every instant
	// that can show this wall clock time.
	var candidates []time.Time
	for _, probe := range []time.Duration{-26 * time.Hour, -13 * time.Hour, 0, 13 * time.Hour, 26 * time.Hour} {
		_, offset := naive.Add(probe).In(loc).Zone()
		c := naive.Add(-time.Duration(offset) * time.Second)
		if !slices.ContainsFunc(candidates, c.Equal) {
			candidates = append(candidates, c)
		}
	}
	slices.SortFunc(candidates, func(a, b time.Time) int { return a.Compare(b) })
	for _, c := range candidates {
		if sameWallClock(c.In(loc), naive) {
			return c
		}
	}
	// Skipped: the latest candidate lies after the gap, in the zone that
	// begins when the gap ends.
	start, _ := candidates[len(candidates)-1].In(loc).ZoneBounds()
	return start
}

func sameWallClock(a, naive time.Time) bool {
	ay, am, ad := a.Date()
	ny, nm, nd := naive.Date()
	return ay == ny && am == nm && ad == nd && a.Hour() == naive.Hour() && a.Minute() == naive.Minute()
}
