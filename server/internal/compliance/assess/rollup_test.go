package assess

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/rollup"
)

var (
	dev1 = uuid.MustParse("00000000-0000-4000-8000-000000000001")
	dev2 = uuid.MustParse("00000000-0000-4000-8000-000000000002")
	now  = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
)

func scan(states map[string]map[uuid.UUID]string, in ...uuid.UUID) ScanInput {
	res := map[string]map[uuid.UUID]rollup.Result{}
	for c, m := range states {
		res[c] = map[uuid.UUID]rollup.Result{}
		for d, s := range m {
			res[c][d] = rollup.Result{State: s, CheckedAt: now}
		}
	}
	return ScanInput{Results: res, InScope: in, Now: now, Fresh: 30 * 24 * time.Hour}
}

func TestFromScanByObjective(t *testing.T) {
	reqs := []ReqObjectives{{ID: "R1", Class: compliance.ReqTechnical, Objectives: []Objective{{ID: "a", Controls: []string{"c1"}}, {ID: "b", Controls: []string{"c2"}}, {ID: "c"}}}}
	d := FromScan(reqs, scan(map[string]map[uuid.UUID]string{
		"c1": {dev1: compliance.StateInPlace, dev2: compliance.StateInPlace},
		"c2": {dev1: compliance.StateInPlace, dev2: compliance.StateNotInPlace},
	}, dev1, dev2))
	if d[ObjectiveKey{"R1", "a"}].Value != Met || d[ObjectiveKey{"R1", "b"}].Value != NotMet || d[ObjectiveKey{"R1", "c"}].Value != NotAssessed {
		t.Errorf("determinations: %+v", d)
	}
	// Unknown, stale and not-supported are never met.
	d = FromScan(reqs, scan(map[string]map[uuid.UUID]string{"c1": {dev1: compliance.StateInPlace, dev2: compliance.StateUnknown}}, dev1, dev2))
	if d[ObjectiveKey{"R1", "a"}].Value != NotAssessed {
		t.Errorf("an unknown result: %+v", d[ObjectiveKey{"R1", "a"}])
	}
	stale := scan(map[string]map[uuid.UUID]string{"c1": {dev1: compliance.StateInPlace}}, dev1)
	stale.Now = now.AddDate(0, 0, 60)
	if d := FromScan(reqs, stale); d[ObjectiveKey{"R1", "a"}].Value != NotAssessed {
		t.Errorf("a stale result: %+v", d[ObjectiveKey{"R1", "a"}])
	}
	// No computer in scope: nothing is decided.
	if d := FromScan(reqs, scan(map[string]map[uuid.UUID]string{"c1": {dev1: compliance.StateInPlace}})); d[ObjectiveKey{"R1", "a"}].Value != NotAssessed {
		t.Error("with nothing in scope an objective was decided")
	}
}

func TestAScanNeverGoesBeyondAnObjectiveForANonTechnicalRequirement(t *testing.T) {
	in := scan(map[string]map[uuid.UUID]string{"c1": {dev1: compliance.StateInPlace}}, dev1)
	for _, class := range []string{compliance.ReqPartly, compliance.ReqOrganisational} {
		d := FromScan([]ReqObjectives{{ID: "R", Class: class, ReqLevel: []string{"c1"}}}, in)
		if got := d[ObjectiveKey{"R", WholeRequirement}].Value; got != NotAssessed {
			t.Errorf("%s requirement decided by scan: %s", class, got)
		}
	}
	d := FromScan([]ReqObjectives{{ID: "R", Class: compliance.ReqTechnical, ReqLevel: []string{"c1"}}}, in)
	if d[ObjectiveKey{"R", WholeRequirement}].Value != Met {
		t.Error("a technical requirement whose control meets was not met")
	}
	// A failure still shows for a partly technical requirement.
	bad := scan(map[string]map[uuid.UUID]string{"c1": {dev1: compliance.StateFailed}}, dev1)
	if d := FromScan([]ReqObjectives{{ID: "R", Class: compliance.ReqPartly, ReqLevel: []string{"c1"}}}, bad); d[ObjectiveKey{"R", WholeRequirement}].Value != NotMet {
		t.Error("a failure was hidden")
	}
}

func TestRequirementNeedsEveryObjective(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{Met, Met}, Met},
		{[]string{Met, NotApplicable}, Met},
		{[]string{Met, NotAssessed}, NotAssessed},
		{[]string{Met, NotMet}, NotMet},
		{[]string{NotAssessed, NotMet}, NotMet},
		{[]string{NotApplicable, NotApplicable}, NotApplicable},
		{nil, NotAssessed},
	}
	for _, c := range cases {
		if got := Requirement(c.in); got != c.want {
			t.Errorf("%v: %s, want %s", c.in, got, c.want)
		}
	}
}

func TestEffectiveAndMerge(t *testing.T) {
	soon, past := now.Add(time.Hour), now.Add(-time.Hour)
	if Effective(Row{Determination: Met, Source: SourceAttestation, AttestationExpires: &soon}, now) != Met {
		t.Error("a standing attestation does not count")
	}
	if Effective(Row{Determination: Met, Source: SourceAttestation, AttestationExpires: &past}, now) != NotAssessed {
		t.Error("an expired attestation counts")
	}
	if Effective(Row{Determination: Met, Source: SourceAttestation}, now) != NotAssessed {
		t.Error("an attestation with no date counts")
	}
	if Effective(Row{Determination: NotMet, Source: SourceScan}, now) != NotMet {
		t.Error("a scan result changed")
	}
	att := &Row{Determination: Met, Source: SourceAttestation}
	if keep, _ := Merge(att, Determination{Value: Met}); !keep {
		t.Error("a scan result replaced an attestation")
	}
	if keep, _ := Merge(att, Determination{Value: NotAssessed}); !keep {
		t.Error("an inconclusive scan replaced an attestation")
	}
	if keep, d := Merge(att, Determination{Value: NotMet}); keep || d.Value != NotMet {
		t.Error("a scan finding of not met did not outweigh an attestation")
	}
	if keep, _ := Merge(&Row{Source: SourceScan, Determination: Met}, Determination{Value: NotAssessed}); keep {
		t.Error("an old scan result stood against a newer one")
	}
	if keep, _ := Merge(nil, Determination{Value: Met}); keep {
		t.Error("nothing stored, yet kept")
	}
}

func TestWorkflow(t *testing.T) {
	ok := [][2]string{{Draft, InReview}, {InReview, Draft}, {InReview, Approved}, {Approved, Archived}}
	for _, m := range ok {
		if _, allowed := Allowed(m[0], m[1]); !allowed {
			t.Errorf("%v is part of the workflow", m)
		}
	}
	for _, m := range [][2]string{{Draft, Approved}, {Draft, Archived}, {Approved, Draft}, {Approved, InReview}, {Archived, Draft}, {Archived, Approved}, {InReview, Archived}} {
		if _, allowed := Allowed(m[0], m[1]); allowed {
			t.Errorf("%v is not part of the workflow", m)
		}
	}
	if !Frozen(Approved) || !Frozen(Archived) || Frozen(Draft) || Frozen(InReview) {
		t.Error("Frozen")
	}
}
