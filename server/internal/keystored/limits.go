package keystored

import (
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/keystore"
)

// Limits are the caps on plaintext-returning calls (ADR-0081 section 7).
// Zero fields take the keystore package's values.
type Limits struct {
	OrgHour, OrgDay, TotalHour int
}

func (l Limits) orDefault() Limits {
	if l.OrgHour == 0 {
		l.OrgHour = keystore.OrgReadsPerHour
	}
	if l.OrgDay == 0 {
		l.OrgDay = keystore.OrgReadsPerDay
	}
	if l.TotalHour == 0 {
		l.TotalHour = keystore.TotalReadsPerHour
	}
	return l
}

// readCounters count the calls that returned a key. They are rebuilt from the
// log at start, so a restart does not reset them.
type readCounters struct {
	mu  sync.Mutex
	lim Limits
	at  map[string][]time.Time // by organization
	all []time.Time
}

func newReadCounters(l Limits, entries []keystore.LogEntry, now time.Time) *readCounters {
	c := &readCounters{lim: l.orDefault(), at: map[string][]time.Time{}}
	for _, e := range entries {
		if e.Plaintext && now.Sub(e.At) < 24*time.Hour {
			c.at[e.Org] = append(c.at[e.Org], e.At)
			c.all = append(c.all, e.At)
		}
	}
	return c
}

func within(ts []time.Time, now time.Time, d time.Duration) int {
	n := 0
	for _, t := range ts {
		if now.Sub(t) < d {
			n++
		}
	}
	return n
}

// check says whether one more call may return a key for org now.
func (c *readCounters) check(org string, now time.Time) *Error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case within(c.at[org], now, time.Hour) >= c.lim.OrgHour:
		return fail(keystore.CodeLimit, "this organization's keys were read too often in the last hour")
	case within(c.at[org], now, 24*time.Hour) >= c.lim.OrgDay:
		return fail(keystore.CodeLimit, "this organization's keys were read too often in the last day")
	case within(c.all, now, time.Hour) >= c.lim.TotalHour:
		return fail(keystore.CodeLimit, "the keystore returned too many keys in the last hour")
	}
	return nil
}

func (c *readCounters) add(org string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cut := now.Add(-24 * time.Hour)
	trim := func(ts []time.Time) []time.Time {
		i := 0
		for i < len(ts) && ts[i].Before(cut) {
			i++
		}
		return ts[i:]
	}
	c.at[org] = append(trim(c.at[org]), now)
	c.all = append(trim(c.all), now)
}
