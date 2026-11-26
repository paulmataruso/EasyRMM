package rollup_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/rollup"
)

var (
	d1, d2, d3 = uuid.MustParse("00000000-0000-0000-0000-000000000001"), uuid.MustParse("00000000-0000-0000-0000-000000000002"), uuid.MustParse("00000000-0000-0000-0000-000000000003")
	now        = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
)

func res(state string) rollup.Result {
	return rollup.Result{State: state, CheckedAt: now.Add(-time.Hour)}
}

func req(class string, rel string, controls ...string) rollup.Requirement {
	r := rollup.Requirement{ID: "r", Class: class}
	for _, c := range controls {
		r.Mappings = append(r.Mappings, rollup.Mapping{ControlID: c, Relation: rel})
	}
	return r
}

func compute(r rollup.Requirement, in, out []uuid.UUID, results map[string]map[uuid.UUID]rollup.Result) rollup.Outcome {
	return rollup.Compute(rollup.Input{Requirements: []rollup.Requirement{r}, Results: results, InScope: in, OutOfScope: out, Now: now, Fresh: 30 * 24 * time.Hour})[0]
}

func TestOneFailingInScopeDeviceFailsTheRequirement(t *testing.T) {
	r := req(compliance.ReqTechnical, compliance.RelSatisfies, "c1")
	o := compute(r, []uuid.UUID{d1, d2}, nil, map[string]map[uuid.UUID]rollup.Result{"c1": {d1: res("in_place"), d2: res("not_in_place")}})
	if o.Status != rollup.DoesNotMeet || len(o.Failing) != 1 || o.Failing[0].DeviceID != d2 || o.Label != compliance.StatusNotMet {
		t.Errorf("%+v", o)
	}
	o = compute(r, []uuid.UUID{d1, d2}, nil, map[string]map[uuid.UUID]rollup.Result{"c1": {d1: res("in_place"), d2: res("in_place")}})
	if o.Status != rollup.Meets || o.Label != compliance.StatusMet || o.Meeting != 2 {
		t.Errorf("%+v", o)
	}
}

func TestOutOfScopeFailureDoesNotCountAndIsListed(t *testing.T) {
	r := req(compliance.ReqTechnical, compliance.RelSatisfies, "c1")
	o := compute(r, []uuid.UUID{d1}, []uuid.UUID{d3}, map[string]map[uuid.UUID]rollup.Result{"c1": {d1: res("in_place"), d3: res("not_in_place")}})
	if o.Status != rollup.Meets || len(o.OutOfScopeFailing) != 1 || o.OutOfScopeFailing[0].DeviceID != d3 || len(o.Failing) != 0 {
		t.Errorf("%+v", o)
	}
}

func TestUnknownStaleAndMissingNeverPass(t *testing.T) {
	r := req(compliance.ReqTechnical, compliance.RelSatisfies, "c1")
	for name, results := range map[string]map[uuid.UUID]rollup.Result{
		"unknown":            {d1: res("in_place"), d2: res("unknown")},
		"not supported":      {d1: res("in_place"), d2: res("not_supported")},
		"missing":            {d1: res("in_place")},
		"stale":              {d1: res("in_place"), d2: {State: "in_place", CheckedAt: now.Add(-31 * 24 * time.Hour)}},
		"managed, no answer": {d1: res("in_place"), d2: {State: "managed_elsewhere", CheckedAt: now}},
	} {
		o := compute(r, []uuid.UUID{d1, d2}, nil, map[string]map[uuid.UUID]rollup.Result{"c1": results})
		if o.Status != rollup.NotAssessed || o.Label != compliance.StatusNotAssessed || o.CannotTell != 1 {
			t.Errorf("%s: %+v", name, o)
		}
	}
	// A failure still wins over what cannot be told.
	o := compute(r, []uuid.UUID{d1, d2}, nil, map[string]map[uuid.UUID]rollup.Result{"c1": {d1: res("unknown"), d2: res("failed")}})
	if o.Status != rollup.DoesNotMeet {
		t.Errorf("%+v", o)
	}
}

func TestManagedElsewhereUsesTheOwnersAnswer(t *testing.T) {
	yes, no := true, false
	r := req(compliance.ReqTechnical, compliance.RelSatisfies, "c1")
	for want, m := range map[rollup.Status]*bool{rollup.Meets: &yes, rollup.DoesNotMeet: &no} {
		o := compute(r, []uuid.UUID{d1}, nil, map[string]map[uuid.UUID]rollup.Result{"c1": {d1: {State: "managed_elsewhere", CheckedAt: now, Owner: &rollup.Owner{Name: "Group Policy", Meets: m}}}})
		if o.Status != want {
			t.Errorf("%v: %+v", want, o)
		}
	}
}

func TestRelatedOnlyIsNeverChecked(t *testing.T) {
	r := req(compliance.ReqTechnical, compliance.RelRelated, "c1", "c2")
	o := compute(r, []uuid.UUID{d1}, nil, map[string]map[uuid.UUID]rollup.Result{"c1": {d1: res("in_place")}, "c2": {d1: res("in_place")}})
	if o.Status != rollup.NotAssessed || !strings.Contains(o.Reason, "related") {
		t.Errorf("%+v", o)
	}
	r = req(compliance.ReqTechnical, compliance.RelEvidence, "c1")
	if o := compute(r, []uuid.UUID{d1}, nil, map[string]map[uuid.UUID]rollup.Result{"c1": {d1: res("in_place")}}); o.Status != rollup.NotAssessed {
		t.Errorf("evidence_for moved a determination: %+v", o)
	}
}

func TestOrganisationalAndEmptyCases(t *testing.T) {
	r := req(compliance.ReqOrganisational, compliance.RelSatisfies, "c1")
	if o := compute(r, []uuid.UUID{d1}, nil, map[string]map[uuid.UUID]rollup.Result{"c1": {d1: res("in_place")}}); o.Status != rollup.NotAssessed || !strings.Contains(o.Reason, "organisational") {
		t.Errorf("a scan alone made an organisational requirement checked: %+v", o)
	}
	none := rollup.Requirement{ID: "x", Class: compliance.ReqTechnical, NoCheckYet: true}
	if o := compute(none, []uuid.UUID{d1}, nil, nil); o.Status != rollup.NotAssessed || o.Reason != "no check yet" {
		t.Errorf("%+v", o)
	}
	if o := compute(rollup.Requirement{ID: "x", Class: compliance.ReqTechnical}, []uuid.UUID{d1}, nil, nil); !strings.Contains(o.Reason, "no control") {
		t.Errorf("%+v", o)
	}
	if o := compute(req(compliance.ReqTechnical, compliance.RelSatisfies, "c1"), nil, nil, nil); o.Status != rollup.NotAssessed || !strings.Contains(o.Reason, "no computers") {
		t.Errorf("%+v", o)
	}
}

func TestNotApplicableNeedsAReason(t *testing.T) {
	r := req(compliance.ReqTechnical, compliance.RelSatisfies, "c1")
	o := compute(r, []uuid.UUID{d1, d2}, nil, map[string]map[uuid.UUID]rollup.Result{"c1": {d1: res("not_applicable"), d2: res("not_applicable")}})
	if o.Status != rollup.NotApplicable || o.Reason == "" {
		t.Errorf("%+v", o)
	}
	o = compute(r, []uuid.UUID{d1, d2}, nil, map[string]map[uuid.UUID]rollup.Result{"c1": {d1: res("not_applicable"), d2: res("in_place")}})
	if o.Status != rollup.Meets {
		t.Errorf("not applicable on one computer, in place on the other: %+v", o)
	}
}

func TestEveryControlMustMeet(t *testing.T) {
	r := req(compliance.ReqTechnical, compliance.RelSatisfies, "c1", "c2")
	o := compute(r, []uuid.UUID{d1}, nil, map[string]map[uuid.UUID]rollup.Result{"c1": {d1: res("in_place")}, "c2": {d1: res("not_in_place")}})
	if o.Status != rollup.DoesNotMeet || len(o.Failing) != 1 || o.Failing[0].ControlID != "c2" {
		t.Errorf("%+v", o)
	}
}

func TestCoverage(t *testing.T) {
	reqs := []rollup.Requirement{
		req(compliance.ReqTechnical, compliance.RelSatisfies, "c"),
		req(compliance.ReqPartly, compliance.RelSatisfies, "c"),
		req(compliance.ReqPartly, compliance.RelRelated, "c"),
		req(compliance.ReqOrganisational, compliance.RelSatisfies, "c"),
		{ID: "z", Class: compliance.ReqTechnical, NoCheckYet: true},
	}
	got := rollup.CoverageOf(reqs)
	if got != (rollup.Coverage{Total: 5, Checked: 1, Partly: 1, Organisational: 1, NoCheckYet: 2}) {
		t.Errorf("%+v", got)
	}
	for _, s := range []rollup.Status{rollup.Meets, rollup.DoesNotMeet, rollup.NotAssessed, rollup.NotApplicable} {
		if strings.Contains(strings.ToLower(s.Label()), "compliant") {
			t.Errorf("%s", s.Label())
		}
	}
}

func TestScoreOf(t *testing.T) {
	now := time.Now()
	ok := func(id string, w int, st string, age time.Duration) rollup.Item {
		return rollup.Item{ID: id, Label: id, Weight: w, Result: rollup.Result{State: st, CheckedAt: now.Add(-age)}}
	}
	fresh := 30 * 24 * time.Hour
	t.Run("equal weights are N of M", func(t *testing.T) {
		s := rollup.ScoreOf([]rollup.Item{ok("a", 1, "in_place", 0), ok("b", 1, "in_place", 0), ok("c", 1, "not_in_place", 0), ok("d", 1, "not_applicable", 0)}, now, fresh)
		if s.Percent == nil || *s.Percent != 66 || s.Word != "does not meet" || s.NotApplicable != 1 || len(s.Reasons) != 1 {
			t.Fatalf("%+v", s)
		}
	})
	t.Run("weights count", func(t *testing.T) {
		s := rollup.ScoreOf([]rollup.Item{ok("a", 3, "in_place", 0), ok("b", 1, "failed", 0)}, now, fresh)
		if *s.Percent != 75 {
			t.Fatalf("%+v", s)
		}
	})
	t.Run("unknown and stale never pass, and cannot tell is not does not meet", func(t *testing.T) {
		s := rollup.ScoreOf([]rollup.Item{ok("a", 1, "in_place", 0), ok("b", 2, "in_place", 31*24*time.Hour), ok("c", 1, "unknown", 0), ok("d", 1, "not_supported", 0)}, now, fresh)
		if s.Word != "cannot tell" || *s.Percent != 20 || s.CannotTell != 3 || s.Reasons[0].ControlID != "b" || s.Reasons[0].State != "stale" {
			t.Fatalf("%+v", s)
		}
	})
	t.Run("all pass meets; nothing applies cannot tell with no score", func(t *testing.T) {
		if s := rollup.ScoreOf([]rollup.Item{ok("a", 1, "in_place", 0)}, now, fresh); s.Word != "meets" || *s.Percent != 100 {
			t.Fatalf("%+v", s)
		}
		if s := rollup.ScoreOf([]rollup.Item{ok("a", 1, "not_applicable", 0)}, now, fresh); s.Word != "cannot tell" || s.Percent != nil {
			t.Fatalf("%+v", s)
		}
	})
	t.Run("managed elsewhere takes the owner's word", func(t *testing.T) {
		yes := true
		it := rollup.Item{ID: "m", Weight: 1, Result: rollup.Result{State: "managed_elsewhere", CheckedAt: now, Owner: &rollup.Owner{Name: "Group Policy", Meets: &yes}}}
		if s := rollup.ScoreOf([]rollup.Item{it}, now, fresh); s.Word != "meets" {
			t.Fatalf("%+v", s)
		}
	})
}
