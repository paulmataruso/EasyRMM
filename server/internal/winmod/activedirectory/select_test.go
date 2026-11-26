package activedirectory

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func cand(n byte, mut func(*Candidate)) Candidate {
	t := time.Date(2026, 11, 26, 10, 0, int(n), 0, time.UTC)
	c := Candidate{DeviceID: uuid.UUID{15: n}, Online: true, Health: HealthHealthy, LastSeen: &t}
	if mut != nil {
		mut(&c)
	}
	return c
}

// The controller choice of ADR-0075 section 3: pinned, then PDC emulator,
// then the latest heartbeat; never offline or read-only; health ranks first.
func TestSelect(t *testing.T) {
	a, b, c := cand(1, nil), cand(2, func(c *Candidate) { c.PDC = true }), cand(3, nil)
	off := func(x Candidate) Candidate { x.Online = false; return x }
	ro := func(x Candidate) Candidate { x.ReadOnly = true; return x }
	health := func(x Candidate, h string) Candidate { x.Health = h; return x }
	for _, tc := range []struct {
		name   string
		cands  []Candidate
		pinned uuid.UUID
		want   byte
		why    string
	}{
		{"the pinned one", []Candidate{a, b, c}, a.DeviceID, 1, "pinned"},
		{"the PDC emulator when nothing is pinned", []Candidate{a, b, c}, uuid.Nil, 2, "pdc"},
		{"the latest heartbeat otherwise", []Candidate{a, c}, uuid.Nil, 3, "heartbeat"},
		{"an offline pin is passed over", []Candidate{off(a), b, c}, a.DeviceID, 2, "pdc"},
		{"a read-only pin is passed over", []Candidate{ro(a), c}, a.DeviceID, 3, "heartbeat"},
		{"an offline PDC is passed over", []Candidate{a, off(b)}, uuid.Nil, 1, "heartbeat"},
		{"a read-only controller is never chosen", []Candidate{ro(b), a}, uuid.Nil, 1, "heartbeat"},
		{"healthy before unknown", []Candidate{health(b, HealthUnknown), a}, uuid.Nil, 1, "heartbeat"},
		{"unknown before unhealthy", []Candidate{health(b, HealthUnhealthy), health(a, HealthUnknown)}, uuid.Nil, 1, "heartbeat_unknown"},
		{"an unhealthy one only when no other qualifies", []Candidate{health(a, HealthUnhealthy), off(c)}, uuid.Nil, 1, "heartbeat_unhealthy"},
		{"an unhealthy pin gives way to a healthy controller", []Candidate{health(a, HealthUnhealthy), c}, a.DeviceID, 3, "heartbeat"},
	} {
		got, why := Select(tc.cands, tc.pinned)
		if got == nil || got.DeviceID[15] != tc.want || why != tc.why {
			t.Errorf("%s: got %v, %q; want %d, %q", tc.name, got, why, tc.want, tc.why)
		}
	}
	// The same heartbeat falls back to the lowest id, so the choice is stable.
	same := time.Now()
	x, y := cand(5, func(c *Candidate) { c.LastSeen = &same }), cand(4, func(c *Candidate) { c.LastSeen = &same })
	if got, _ := Select([]Candidate{x, y}, uuid.Nil); got.DeviceID[15] != 4 {
		t.Errorf("tie: %v", got)
	}
	// None qualifies.
	if got, why := Select([]Candidate{off(a), ro(c)}, uuid.Nil); got != nil || why != "none_qualifies" {
		t.Errorf("none: %v %q", got, why)
	}
	if got, _ := Select(nil, uuid.Nil); got != nil {
		t.Error("no controllers")
	}
}
