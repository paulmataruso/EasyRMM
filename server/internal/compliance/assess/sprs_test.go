package assess

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

type fixture struct {
	Total   int            `json:"total"`
	Weights map[string]int `json:"weights"`
	Partial map[string]int `json:"partial"`
}

// reqs builds the 110 requirements from the DoD methodology fixture (the same one the pack test checks the packs against).
func reqs(t *testing.T, status string) []Req {
	t.Helper()
	b, err := os.ReadFile("../packs/testdata/dod-sprs-weights-v1.2.1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx fixture
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	barred := map[string]bool{"3.1.20": true, "3.1.22": true, "3.12.4": true, "3.10.3": true, "3.10.4": true, "3.10.5": true}
	var out []Req
	for id, w := range fx.Weights {
		out = append(out, Req{ID: id, Weight: w, Partial: fx.Partial[id], Barred: barred[id], Status: status})
	}
	return out
}

func with(rs []Req, id string, f func(*Req)) []Req {
	for i := range rs {
		if rs[i].ID == id {
			f(&rs[i])
		}
	}
	return rs
}

func TestWeightsSumTo313AndTheRangeEndsAreRight(t *testing.T) {
	rs := reqs(t, NotAssessed)
	if len(rs) != 110 {
		t.Fatalf("%d requirements", len(rs))
	}
	var sum int
	for _, r := range rs {
		sum += r.Weight
	}
	if sum != 313 {
		t.Fatalf("weights sum to %d, the methodology's total is 313", sum)
	}
	r := ComputeRange(rs)
	if r.Low != 110-313 || r.High != 110 || r.Number != nil || r.Unassessed != 110 {
		t.Errorf("all unassessed: %+v", r)
	}
	if r := ComputeRange(reqs(t, Met)); r.Low != 110 || r.High != 110 || r.Number == nil || *r.Number != 110 {
		t.Errorf("all met: %+v", r)
	}
	if r := ComputeRange(reqs(t, NotMet)); r.Number == nil || *r.Number != 110-313 {
		t.Errorf("all not met: %+v", r)
	}
	if r := ComputeRange(reqs(t, NotApplicable)); r.Number == nil || *r.Number != 110 {
		t.Errorf("all not applicable: %+v", r)
	}
}

func TestRangeLogic(t *testing.T) {
	rs := reqs(t, Met)
	with(rs, "3.1.1", func(r *Req) { r.Status = NotMet })      // 5
	with(rs, "3.1.3", func(r *Req) { r.Status = NotAssessed }) // 1
	with(rs, "3.3.2", func(r *Req) { r.Status = NotAssessed }) // 3
	r := ComputeRange(rs)
	if r.High != 105 || r.Low != 101 {
		t.Errorf("range %d..%d, want 101..105", r.Low, r.High)
	}
	if r.Number != nil {
		t.Error("a single number was given while two requirements are unassessed")
	}
	with(rs, "3.1.3", func(r *Req) { r.Status = Met })
	with(rs, "3.3.2", func(r *Req) { r.Status = Met })
	if r := ComputeRange(rs); r.Number == nil || *r.Number != 105 {
		t.Errorf("with nothing unassessed: %+v", r)
	}
}

func TestPartialCreditCases(t *testing.T) {
	for _, id := range []string{"3.5.3", "3.13.11"} {
		rs := with(reqs(t, Met), id, func(r *Req) { r.Status = NotMet })
		if r := ComputeRange(rs); *r.Number != 105 {
			t.Errorf("%s not met: %d, want 105", id, *r.Number)
		}
		rs = with(rs, id, func(r *Req) { r.PartlyDone = true })
		if r := ComputeRange(rs); *r.Number != 107 {
			t.Errorf("%s partly: %d, want 107 (3 points off)", id, *r.Number)
		}
	}
	// A requirement with no partial case is not helped by the flag.
	rs := with(reqs(t, Met), "3.1.1", func(r *Req) { r.Status = NotMet; r.PartlyDone = true })
	if r := ComputeRange(rs); *r.Number != 105 {
		t.Errorf("3.1.1 flagged partly: %d", *r.Number)
	}
}

func TestSSPRequirementHasNoValueButBlocks(t *testing.T) {
	rs := with(reqs(t, Met), "3.12.4", func(r *Req) { r.Status = NotMet })
	r := ComputeRange(rs)
	if *r.Number != 110 || !r.SSPMissing {
		t.Errorf("3.12.4 not met: %+v", r)
	}
}

func TestPOAMEligibility(t *testing.T) {
	byID := map[string]Req{}
	for _, r := range reqs(t, NotMet) {
		byID[r.ID] = r
	}
	for _, id := range []string{"3.1.20", "3.1.22", "3.12.4", "3.10.3", "3.10.4", "3.10.5"} {
		if ok, _ := Eligible(byID[id]); ok {
			t.Errorf("%s may never be on a plan of action", id)
		}
	}
	// Barred means barred even at one point.
	if byID["3.1.20"].Weight != 1 {
		t.Fatal("the fixture changed")
	}
	if ok, _ := Eligible(byID["3.1.1"]); ok {
		t.Error("a five-point requirement was allowed")
	}
	if ok, _ := Eligible(byID["3.3.2"]); ok {
		t.Error("a three-point requirement was allowed")
	}
	if ok, why := Eligible(byID["3.1.3"]); !ok {
		t.Errorf("a one-point requirement was refused: %s", why)
	}
	// 3.13.11: only when encryption is employed but not FIPS-validated.
	e := byID["3.13.11"]
	if ok, _ := Eligible(e); ok {
		t.Error("3.13.11 with no encryption at all (5 points) was allowed")
	}
	e.PartlyDone = true
	if ok, _ := Eligible(e); !ok {
		t.Error("3.13.11 with encryption that is not FIPS-validated (3 points) was refused")
	}
	m := byID["3.5.3"]
	m.PartlyDone = true
	if ok, _ := Eligible(m); ok {
		t.Error("3.5.3 partly done (3 points) was allowed: only 3.13.11 is the exception")
	}
}

func TestGateConditions(t *testing.T) {
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	// Everything met but two one-point requirements not met: 108, no blockers.
	rs := with(reqs(t, Met), "3.1.3", func(r *Req) { r.Status = NotMet })
	rs = with(rs, "3.1.4", func(r *Req) { r.Status = NotMet })
	g := ComputeGate(rs, nil, now)
	if g.Outcome != "within" || g.Low.Score != 108 || len(g.Low.Blockers) != 0 {
		t.Errorf("two one-point items: %+v", g)
	}
	// A barred requirement not met blocks, however high the score.
	g = ComputeGate(with(reqs(t, Met), "3.10.4", func(r *Req) { r.Status = NotMet }), nil, now)
	if g.Outcome != "outside" || len(g.Low.Blockers) != 1 || g.Low.Blockers[0].ReqID != "3.10.4" {
		t.Errorf("a barred requirement: %+v", g)
	}
	// A five-point requirement not met blocks.
	g = ComputeGate(with(reqs(t, Met), "3.1.1", func(r *Req) { r.Status = NotMet }), nil, now)
	if g.Outcome != "outside" {
		t.Errorf("a five-point item: %+v", g)
	}
	// The score must reach 88: 23 one-point requirements not met gives 87.
	rs = reqs(t, Met)
	n := 0
	for i := range rs {
		if rs[i].Weight == 1 && !rs[i].Barred && n < 23 {
			rs[i].Status, n = NotMet, n+1
		}
	}
	if g := ComputeGate(rs, nil, now); g.Low.Score != 87 || g.Low.ScoreOK || g.Outcome != "outside" {
		t.Errorf("23 one-point items: %+v", g.Low)
	}
	rs = reqs(t, Met)
	n = 0
	for i := range rs {
		if rs[i].Weight == 1 && !rs[i].Barred && n < 22 {
			rs[i].Status, n = NotMet, n+1
		}
	}
	if g := ComputeGate(rs, nil, now); g.Low.Score != 88 || !g.Low.ScoreOK || g.Outcome != "within" {
		t.Errorf("22 one-point items (88): %+v", g.Low)
	}
	// Unassessed requirements fail in the lower reading, and pass in the upper: "possible".
	rs = with(reqs(t, Met), "3.1.1", func(r *Req) { r.Status = NotAssessed })
	if g := ComputeGate(rs, nil, now); g.Outcome != "possible" || g.Low.Within || !g.High.Within {
		t.Errorf("one unassessed five-point requirement: %+v", g)
	}
	// 180 days: an open item past its date is overdue and takes the outcome out of "within".
	items := []POAMItem{{ReqID: "3.1.3", Status: "open", ClosesBy: now.AddDate(0, 0, -2)}, {ReqID: "3.1.4", Status: "closed", ClosesBy: now.AddDate(0, 0, -2)}}
	g = ComputeGate(with(reqs(t, Met), "3.1.3", func(r *Req) { r.Status = NotMet }), items, now)
	if len(g.Overdue) != 1 || g.Overdue[0] != "3.1.3" || g.Outcome == "within" {
		t.Errorf("overdue: %+v", g)
	}
	if got := ClosesBy(now).Sub(now); got != 180*24*time.Hour {
		t.Errorf("the clock is %v", got)
	}
}

func TestDraftItemsAreForRequirementsNotMetOnly(t *testing.T) {
	rs := with(reqs(t, Met), "3.1.3", func(r *Req) { r.Status = NotMet })
	with(rs, "3.1.4", func(r *Req) { r.Status = NotAssessed })
	d := DraftItems(rs)
	if len(d) != 1 || d[0].ReqID != "3.1.3" || d[0].Points != 1 || !d[0].Eligible {
		t.Errorf("drafts: %+v", d)
	}
}

func TestL1Count(t *testing.T) {
	rs := reqs(t, Met)
	for i := range rs[:17] {
		rs[i].L1 = true
	}
	rs[0].Status = NotMet
	if r := ComputeRange(rs); r.L1Of != 17 || r.L1Met != 16 {
		t.Errorf("level 1: %d of %d", r.L1Met, r.L1Of)
	}
}
