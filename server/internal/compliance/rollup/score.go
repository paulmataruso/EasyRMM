package rollup

import (
	"math"
	"sort"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
)

// The weighted score (ADR-0082). It is the one score in EasyRMM: security
// posture and the compliance screens both read it, and both judge a result
// with the same rules as Compute (judge, EffectiveState). A control's weight
// counts in the score's denominator unless it does not apply; it counts in the
// numerator only when the control passes. Unknown, stale and not supported
// never pass, and no weight is ever dropped to make the score look better.

// Item is one control's latest result on one computer, with its weight.
type Item struct {
	ID     string
	Label  string
	Weight int
	Result Result
	// Detail is what the source says about it (what is missing, why it
	// failed); it is shown beside the reason.
	Detail string
}

// Reason says why a control is not passing: a failing control, or one the
// scan cannot tell about.
type Reason struct {
	ControlID string `json:"controlId"`
	Label     string `json:"label"`
	// State is the control's effective state (stale when it is older than the
	// freshness window).
	State  string `json:"state"`
	Word   string `json:"word"`
	Weight int    `json:"weight"`
	Detail string `json:"detail,omitempty"`
}

// Score is the weighted result of a set of controls.
type Score struct {
	// Word is "meets" when every control that applies passes, "does not
	// meet" when one fails, otherwise "cannot tell" (compliance.Word*).
	Word string `json:"word"`
	// Percent is the passing weight over the weight that applies, rounded
	// down; nil when nothing applies.
	Percent *int `json:"percent"`
	// Passing and Applicable are those weights.
	Passing    int `json:"passingWeight"`
	Applicable int `json:"applicableWeight"`
	// Meeting, Failing, CannotTell and NotApplicable count controls.
	Meeting       int `json:"meeting"`
	Failing       int `json:"failing"`
	CannotTell    int `json:"cannotTell"`
	NotApplicable int `json:"notApplicable"`
	// Reasons lists the failing controls first, then the ones that cannot be
	// told, heaviest first.
	Reasons []Reason `json:"reasons"`
}

// ScoreOf weighs the items at now. A freshness window of zero means results
// never go stale. A weight below 1 counts as 1.
func ScoreOf(items []Item, now time.Time, fresh time.Duration) Score {
	s := Score{Reasons: []Reason{}}
	var fail, unknown []Reason
	for _, it := range items {
		w := it.Weight
		if w < 1 {
			w = 1
		}
		st := EffectiveState(it.Result, now, fresh)
		r := Reason{ControlID: it.ID, Label: it.Label, State: st, Weight: w, Detail: it.Detail}
		switch judge(st, it.Result) {
		case vNA:
			s.NotApplicable++
		case vPass:
			s.Meeting++
			s.Passing += w
			s.Applicable += w
		case vFail:
			s.Failing++
			s.Applicable += w
			r.Word = compliance.WordDoesNotMeet
			fail = append(fail, r)
		default:
			s.CannotTell++
			s.Applicable += w
			r.Word = compliance.WordCannotTell
			unknown = append(unknown, r)
		}
	}
	byWeight := func(l []Reason) {
		sort.SliceStable(l, func(i, j int) bool {
			if l[i].Weight != l[j].Weight {
				return l[i].Weight > l[j].Weight
			}
			return l[i].ControlID < l[j].ControlID
		})
	}
	byWeight(fail)
	byWeight(unknown)
	s.Reasons = append(append(s.Reasons, fail...), unknown...)
	if s.Applicable > 0 {
		p := int(math.Floor(float64(s.Passing) * 100 / float64(s.Applicable)))
		s.Percent = &p
	}
	switch {
	case s.Failing > 0:
		s.Word = compliance.WordDoesNotMeet
	case s.CannotTell > 0 || s.Applicable == 0:
		s.Word = compliance.WordCannotTell
	default:
		s.Word = compliance.WordMeets
	}
	return s
}
