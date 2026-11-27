// Package schedule runs scheduled tasks (feature 11 slice 1): an automation
// with a schedule trigger and one step, a library script pinned by its
// SHA-256. The Scheduled tasks page is a view of the same rows the later
// automation work (feature 3) builds on.
package schedule

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/notify"
)

// Schedule kinds.
const (
	KindOnce     = "once"
	KindDaily    = "daily"
	KindWeekly   = "weekly"
	KindMonthly  = "monthly"
	KindInterval = "interval"
)

// Interval bounds, in minutes.
const (
	MinEveryMinutes = 5
	MaxEveryMinutes = 7 * 24 * 60
)

// Schedule says when a task fires, in the zone of its site or organization.
type Schedule struct {
	Kind string `json:"kind"`
	// Date is a once schedule's day, as 2006-01-02.
	Date string `json:"date,omitempty"`
	// At is the wall-clock time as 15:04, for every kind but interval.
	At string `json:"at,omitempty"`
	// Days are a weekly schedule's days, 0 (Sunday) to 6.
	Days []int `json:"days,omitempty"`
	// DayOfMonth is a monthly schedule's day, 1 to 31; in a shorter month
	// it is the last day.
	DayOfMonth int `json:"dayOfMonth,omitempty"`
	// EveryMinutes is an interval schedule's period.
	EveryMinutes int `json:"everyMinutes,omitempty"`
	// Anchor is when an interval counts from; the server sets it.
	Anchor *time.Time `json:"anchor,omitempty"`
}

func parseHM(s string) (h, m int, ok bool) {
	a, b, found := strings.Cut(s, ":")
	if !found || len(a) != 2 || len(b) != 2 {
		return 0, 0, false
	}
	h, e1 := strconv.Atoi(a)
	m, e2 := strconv.Atoi(b)
	return h, m, e1 == nil && e2 == nil && h >= 0 && h < 24 && m >= 0 && m < 60
}

// Clean validates the schedule and returns its normal form.
func (s Schedule) Clean(now time.Time) (Schedule, error) {
	if s.Kind != KindInterval {
		if _, _, ok := parseHM(s.At); !ok {
			return s, apperr.Invalid("schedule", "Enter the time as hours and minutes, such as 22:00.")
		}
	}
	switch s.Kind {
	case KindOnce:
		if _, err := time.Parse("2006-01-02", s.Date); err != nil {
			return s, apperr.Invalid("schedule", "Enter the date as year-month-day.")
		}
		s.Days, s.DayOfMonth, s.EveryMinutes, s.Anchor = nil, 0, 0, nil
	case KindDaily:
		s.Date, s.Days, s.DayOfMonth, s.EveryMinutes, s.Anchor = "", nil, 0, 0, nil
	case KindWeekly:
		days := []int{}
		for _, d := range s.Days {
			if d < 0 || d > 6 {
				return s, apperr.Invalid("schedule", "Days are 0 (Sunday) to 6 (Saturday).")
			}
			if !slices.Contains(days, d) {
				days = append(days, d)
			}
		}
		if len(days) == 0 {
			return s, apperr.Invalid("schedule", "Choose at least one day.")
		}
		slices.Sort(days)
		s.Date, s.Days, s.DayOfMonth, s.EveryMinutes, s.Anchor = "", days, 0, 0, nil
	case KindMonthly:
		if s.DayOfMonth < 1 || s.DayOfMonth > 31 {
			return s, apperr.Invalid("schedule", "Choose a day of the month from 1 to 31.")
		}
		s.Date, s.Days, s.EveryMinutes, s.Anchor = "", nil, 0, nil
	case KindInterval:
		if s.EveryMinutes < MinEveryMinutes || s.EveryMinutes > MaxEveryMinutes {
			return s, apperr.Invalid("schedule", fmt.Sprintf("An interval is %d minutes to 7 days.", MinEveryMinutes))
		}
		s.Date, s.At, s.Days, s.DayOfMonth = "", "", nil, 0
		if s.Anchor == nil {
			a := now.UTC().Truncate(time.Minute)
			s.Anchor = &a
		}
	default:
		return s, apperr.Invalid("schedule", "Choose once, daily, weekly, monthly or an interval.")
	}
	return s, nil
}

func lastDay(y int, m time.Month) int { return time.Date(y, m+1, 0, 12, 0, 0, 0, time.UTC).Day() }

// Next is the first occurrence after the instant, in loc, and false when
// there is none (a once schedule that has passed). Wall-clock times follow
// ADR-0053's daylight-saving rules.
func (s Schedule) Next(loc *time.Location, after time.Time) (time.Time, bool) {
	switch s.Kind {
	case KindInterval:
		if s.Anchor == nil || s.EveryMinutes < 1 {
			return time.Time{}, false
		}
		every := time.Duration(s.EveryMinutes) * time.Minute
		if after.Before(*s.Anchor) {
			return *s.Anchor, true
		}
		k := after.Sub(*s.Anchor)/every + 1
		return s.Anchor.Add(k * every), true
	case KindOnce:
		d, err := time.Parse("2006-01-02", s.Date)
		h, m, ok := parseHM(s.At)
		if err != nil || !ok {
			return time.Time{}, false
		}
		t := notify.WallInstant(loc, d.Year(), d.Month(), d.Day(), h, m)
		return t, t.After(after)
	}
	h, m, ok := parseHM(s.At)
	if !ok {
		return time.Time{}, false
	}
	start := after.In(loc)
	// Looking back a day covers a wall time that is later in UTC than it
	// reads; 13 months covers a monthly schedule.
	for i := -1; i <= 400; i++ {
		d := time.Date(start.Year(), start.Month(), start.Day()+i, 12, 0, 0, 0, loc)
		switch s.Kind {
		case KindWeekly:
			if !slices.Contains(s.Days, int(d.Weekday())) {
				continue
			}
		case KindMonthly:
			if d.Day() != min(s.DayOfMonth, lastDay(d.Year(), d.Month())) {
				continue
			}
		}
		if t := notify.WallInstant(loc, d.Year(), d.Month(), d.Day(), h, m); t.After(after) {
			return t, true
		}
	}
	return time.Time{}, false
}

// LastDue is the latest occurrence at or before now that follows prev (the
// occurrence that fell due), and how many fell due, prev included.
func (s Schedule) LastDue(loc *time.Location, prev, now time.Time) (last time.Time, n int) {
	if s.Kind == KindInterval && s.Anchor != nil && s.EveryMinutes > 0 && !prev.Before(*s.Anchor) {
		every := time.Duration(s.EveryMinutes) * time.Minute
		k := now.Sub(prev) / every
		return prev.Add(k * every), int(k) + 1
	}
	last, n = prev, 1
	for n < 20000 {
		nx, ok := s.Next(loc, last)
		if !ok || nx.After(now) {
			break
		}
		last, n = nx, n+1
	}
	return last, n
}
