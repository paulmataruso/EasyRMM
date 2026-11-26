// Package rollup turns per-device, per-control results into a status per
// requirement (ADR-0078, section 4). It is pure: results and scope in,
// statuses out. A passing control is necessary, never sufficient: a scan
// alone never makes a requirement "met" in the sense of an assessment.
package rollup

import (
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
)

// Status of a requirement as far as the scan can tell.
type Status string

// Statuses.
const (
	Meets         Status = "checked_meets"
	DoesNotMeet   Status = "checked_not_meets"
	NotAssessed   Status = "not_assessed"
	NotApplicable Status = "not_applicable"
)

// Label is the status's wording (section 9).
func (s Status) Label() string {
	switch s {
	case Meets:
		return compliance.StatusMet
	case DoesNotMeet:
		return compliance.StatusNotMet
	case NotApplicable:
		return compliance.StatusNotApplic
	}
	return compliance.StatusNotAssessed
}

// Mapping is a control a requirement is mapped to.
type Mapping struct {
	ControlID string
	Relation  string
}

// Requirement is a requirement and its mappings.
type Requirement struct {
	ID         string
	Class      string
	NoCheckYet bool
	Mappings   []Mapping
}

// Owner says who holds a value another owner manages, and whether that
// value meets the control.
type Owner struct {
	Name  string
	Meets *bool
}

// Result is the latest result of one control on one device.
type Result struct {
	State     string
	CheckedAt time.Time
	Owner     *Owner
}

// Input is what Compute needs.
type Input struct {
	Requirements []Requirement
	// Results are the latest results, by control and device.
	Results map[string]map[uuid.UUID]Result
	// InScope are the devices the assessment covers; OutOfScope are
	// devices that have results but are outside it. Out-of-scope failures
	// are listed and never count.
	InScope, OutOfScope []uuid.UUID
	Now                 time.Time
	// Fresh is how old a result may be before it is stale; zero means never.
	Fresh time.Duration
}

// Finding is a control that does not meet on a device.
type Finding struct {
	DeviceID  uuid.UUID `json:"deviceId"`
	ControlID string    `json:"controlId"`
}

// Outcome is a requirement's roll-up.
type Outcome struct {
	ReqID  string `json:"reqId"`
	Status Status `json:"status"`
	Label  string `json:"label"`
	// Reason says why a requirement is not assessed or not applicable.
	Reason string `json:"reason,omitempty"`
	// Failing are in-scope devices and controls that do not meet.
	Failing []Finding `json:"failing,omitempty"`
	// OutOfScopeFailing are failures on devices outside the scope, listed
	// and not counted.
	OutOfScopeFailing []Finding `json:"outOfScopeFailing,omitempty"`
	// Controls are the controls that decide it (mapped satisfies_objective).
	Controls   []string `json:"controls,omitempty"`
	Meeting    int      `json:"meeting"`
	CannotTell int      `json:"cannotTell"`
}

// EffectiveState is the state a result counts as: stale when older than
// the freshness window.
func EffectiveState(r Result, now time.Time, fresh time.Duration) string {
	if fresh > 0 && !r.CheckedAt.IsZero() && now.Sub(r.CheckedAt) > fresh {
		return compliance.StateStale
	}
	return r.State
}

// verdicts of one result.
type verdict int

const (
	vPass verdict = iota
	vFail
	vUnknown
	vNA
)

func judge(state string, r Result) verdict {
	switch state {
	case compliance.StateInPlace:
		return vPass
	case compliance.StateNotApplicable:
		return vNA
	case compliance.StateNotInPlace, compliance.StatePartly, compliance.StateHalfApplied, compliance.StateFailed:
		return vFail
	case compliance.StateManagedElsewhere:
		// Another owner holds the value: only a stated answer counts.
		if r.Owner != nil && r.Owner.Meets != nil {
			if *r.Owner.Meets {
				return vPass
			}
			return vFail
		}
	}
	return vUnknown // unknown, stale, not_supported and the rest never pass
}

// Compute rolls up every requirement.
func Compute(in Input) []Outcome {
	out := make([]Outcome, 0, len(in.Requirements))
	inScope := append([]uuid.UUID(nil), in.InScope...)
	sort.Slice(inScope, func(i, j int) bool { return inScope[i].String() < inScope[j].String() })
	outScope := append([]uuid.UUID(nil), in.OutOfScope...)
	sort.Slice(outScope, func(i, j int) bool { return outScope[i].String() < outScope[j].String() })
	for _, r := range in.Requirements {
		out = append(out, one(r, in, inScope, outScope))
	}
	return out
}

func one(r Requirement, in Input, inScope, outScope []uuid.UUID) Outcome {
	o := Outcome{ReqID: r.ID}
	set := func(s Status, reason string) Outcome {
		o.Status, o.Label, o.Reason = s, s.Label(), reason
		return o
	}
	if r.Class == compliance.ReqOrganisational {
		return set(NotAssessed, "organisational: needs an attestation or evidence, which a scan cannot give")
	}
	for _, m := range r.Mappings {
		if m.Relation == compliance.RelSatisfies {
			o.Controls = append(o.Controls, m.ControlID)
		}
	}
	sort.Strings(o.Controls)
	if len(o.Controls) == 0 {
		switch {
		case r.NoCheckYet:
			return set(NotAssessed, "no check yet")
		case len(r.Mappings) > 0:
			return set(NotAssessed, "only related controls are mapped, which never show a requirement checked")
		}
		return set(NotAssessed, "no control is mapped")
	}
	if len(inScope) == 0 {
		return set(NotAssessed, "no computers are in scope")
	}
	var fail, unknown, pass, na int
	for _, c := range o.Controls {
		for _, d := range inScope {
			res, ok := in.Results[c][d]
			if !ok {
				unknown++
				continue
			}
			switch judge(EffectiveState(res, in.Now, in.Fresh), res) {
			case vPass:
				pass++
			case vFail:
				fail++
				o.Failing = append(o.Failing, Finding{DeviceID: d, ControlID: c})
			case vNA:
				na++
			default:
				unknown++
			}
		}
		for _, d := range outScope {
			if res, ok := in.Results[c][d]; ok && judge(EffectiveState(res, in.Now, in.Fresh), res) == vFail {
				o.OutOfScopeFailing = append(o.OutOfScopeFailing, Finding{DeviceID: d, ControlID: c})
			}
		}
	}
	o.Meeting, o.CannotTell = pass, unknown
	switch {
	case fail > 0:
		return set(DoesNotMeet, "")
	case unknown > 0:
		return set(NotAssessed, "some results cannot tell: unknown, stale, not supported or missing")
	case pass == 0 && na > 0:
		return set(NotApplicable, "no mapped control applies on any computer in scope")
	}
	return set(Meets, "")
}

// Coverage counts a framework's requirements by what a scan can reach.
type Coverage struct {
	Total int `json:"total"`
	// Checked: technical, with a control that decides it.
	Checked int `json:"checked"`
	// Partly: partly technical, with a control that decides part of it.
	Partly int `json:"partly"`
	// Organisational: not assessed by any scan.
	Organisational int `json:"organisational"`
	// NoCheckYet: technical or partly, with nothing that decides it.
	NoCheckYet int `json:"noCheckYet"`
}

// CoverageOf counts the requirements.
func CoverageOf(reqs []Requirement) Coverage {
	c := Coverage{Total: len(reqs)}
	for _, r := range reqs {
		decides := false
		for _, m := range r.Mappings {
			if m.Relation == compliance.RelSatisfies {
				decides = true
			}
		}
		switch {
		case r.Class == compliance.ReqOrganisational:
			c.Organisational++
		case !decides:
			c.NoCheckYet++
		case r.Class == compliance.ReqPartly:
			c.Partly++
		default:
			c.Checked++
		}
	}
	return c
}
