// Package assess is the compliance assessment workspace (ADR-0078, slice C5): assessments and
// their workflow, the scan-to-objective roll-up, the SPRS score range and its gate, the plan of
// action and milestones, the system security plan, and evidence. The pure parts (this file,
// poam.go, rollup.go, workflow.go) hold the rules and have no database; service.go and the rest
// hold the database work.
package assess

import (
	"sort"
	"time"
)

// Determination values, for an objective, a requirement and a point on the score.
const (
	Met           = "met"
	NotMet        = "not_met"
	NotApplicable = "not_applicable"
	NotAssessed   = "not_assessed"
)

// BaseScore is where the DoD methodology's score starts: 110 requirements, one point each at
// best, and the weights of those not implemented are subtracted.
const BaseScore = 110

// Gate numbers of 32 CFR 170.21 as read on 2026-11-26 (the paragraph was re-read from the eCFR):
// a Level 2 conditional status needs the score divided by 110 to reach 0.8, which is 88, and a
// plan of action closed out within 180 days.
const (
	GateMinScore   = 88
	POAMClosedDays = 180
	// The one requirement whose plan-of-action item may carry more than one point: encryption is
	// employed but not FIPS-validated (a point value of 3).
	encryptionReq = "3.13.11"
)

// Req is one requirement as the score and the plan of action read it. ID is the NIST SP 800-171
// number ("3.1.1"), whatever the framework's own id looks like.
type Req struct {
	ID string
	// Weight is the methodology's point value (3.12.4 has none: 0). Partial is the value of the
	// methodology's partial-credit case (3.5.3, 3.13.11), or 0 when the requirement has none.
	Weight  int
	Partial int
	// Barred requirements may never be on a plan of action (the six of 170.21(a)(2)(iii)).
	Barred bool
	Status string
	// PartlyDone says a partial-credit requirement is only partly implemented.
	PartlyDone bool
	// L1 marks the 17 practices of Level 1.
	L1 bool
}

// Deduction is what a requirement takes off the score. When unassessedFail is true a requirement
// not assessed counts as not met.
func (r Req) Deduction(unassessedFail bool) int {
	switch r.Status {
	case NotMet:
		return r.notMetPoints()
	case NotAssessed:
		if unassessedFail {
			return r.notMetPoints()
		}
	}
	return 0
}

func (r Req) notMetPoints() int {
	if r.PartlyDone && r.Partial > 0 {
		return r.Partial
	}
	return r.Weight
}

// Range is the score, as two bounds.
type Range struct {
	// Low counts every requirement not yet assessed as failing; High counts them as passing.
	Low  int `json:"low"`
	High int `json:"high"`
	// Number is the score, only when the two bounds are equal: nothing is left unassessed.
	Number     *int `json:"number"`
	NotMet     int  `json:"notMet"`
	Unassessed int  `json:"unassessed"`
	Met        int  `json:"met"`
	// SSPMissing says the plan requirement (3.12.4) is not met: the methodology gives it no value, but
	// without a system security plan an assessment cannot be completed.
	SSPMissing bool `json:"sspMissing"`
	// L1Met counts the Level 1 practices met.
	L1Met int `json:"l1Met"`
	L1Of  int `json:"l1Of"`
}

// ComputeRange computes the lower and upper bound of the score. It never posts anywhere.
func ComputeRange(reqs []Req) Range {
	lo, hi := BaseScore, BaseScore
	out := Range{}
	for _, r := range reqs {
		lo -= r.Deduction(true)
		hi -= r.Deduction(false)
		switch r.Status {
		case Met, NotApplicable:
			out.Met++
		case NotMet:
			out.NotMet++
		default:
			out.Unassessed++
		}
		if r.ID == "3.12.4" && r.Status != Met && r.Status != NotApplicable {
			out.SSPMissing = true
		}
		if r.L1 {
			out.L1Of++
			if r.Status == Met || r.Status == NotApplicable {
				out.L1Met++
			}
		}
	}
	out.Low, out.High = lo, hi
	if lo == hi {
		n := lo
		out.Number = &n
	}
	return out
}

// Blocker is a requirement that stops the conditional-status rule from being met, and why.
type Blocker struct {
	ReqID  string `json:"reqId"`
	Reason string `json:"reason"`
}

// GateSide is the gate read one way: with the unassessed requirements failing (the lower bound)
// or passing (the upper bound).
type GateSide struct {
	Score    int       `json:"score"`
	ScoreOK  bool      `json:"scoreOk"`
	Blockers []Blocker `json:"blockers"`
	Within   bool      `json:"within"`
}

// Gate is the Level 2 conditional-status rule of 32 CFR 170.21, read both ways. It is a reading of
// the rule, not a status: EasyRMM grants nothing.
type Gate struct {
	MinScore int      `json:"minScore"`
	Low      GateSide `json:"low"`
	High     GateSide `json:"high"`
	// Overdue are plan-of-action items still open after their 180 days.
	Overdue []string `json:"overdue"`
	// Outcome: "within" when the lower bound is within the rule, "possible" when only the upper
	// bound is, "outside" otherwise.
	Outcome string `json:"outcome"`
}

// POAMItem is what the gate reads of a plan-of-action item.
type POAMItem struct {
	ReqID    string
	Status   string
	ClosesBy time.Time
}

// ComputeGate reads the rule. A requirement that is not met (or, in the lower reading, not yet
// assessed) must be allowed on a plan of action: at most one point, the 3.13.11 exception, and
// none of the six barred ones. The score must reach the minimum.
func ComputeGate(reqs []Req, items []POAMItem, now time.Time) Gate {
	g := Gate{MinScore: GateMinScore}
	side := func(unassessedFail bool) GateSide {
		s := GateSide{Score: BaseScore, Blockers: []Blocker{}}
		for _, r := range reqs {
			s.Score -= r.Deduction(unassessedFail)
			failing := r.Status == NotMet || (unassessedFail && r.Status == NotAssessed)
			if !failing {
				continue
			}
			if ok, why := Eligible(r); !ok {
				s.Blockers = append(s.Blockers, Blocker{ReqID: r.ID, Reason: why})
			}
		}
		sort.Slice(s.Blockers, func(i, j int) bool { return s.Blockers[i].ReqID < s.Blockers[j].ReqID })
		s.ScoreOK = s.Score >= GateMinScore
		s.Within = s.ScoreOK && len(s.Blockers) == 0
		return s
	}
	g.Low, g.High = side(true), side(false)
	g.Overdue = []string{}
	for _, it := range items {
		if (it.Status == "open" || it.Status == "in_progress") && !it.ClosesBy.IsZero() && now.After(it.ClosesBy.AddDate(0, 0, 1)) {
			g.Overdue = append(g.Overdue, it.ReqID)
		}
	}
	sort.Strings(g.Overdue)
	switch {
	case g.Low.Within && len(g.Overdue) == 0:
		g.Outcome = "within"
	case g.High.Within:
		g.Outcome = "possible"
	default:
		g.Outcome = "outside"
	}
	return g
}
