package assess

import (
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/rollup"
)

// WholeRequirement is the objective id of a requirement whose assessment objectives are not loaded:
// the requirement itself is then the one objective.
const WholeRequirement = "*"

// Objective is one objective of a requirement and the controls that decide it by scan.
type Objective struct {
	ID       string
	Controls []string
}

// ReqObjectives is a requirement with its objectives.
type ReqObjectives struct {
	ID         string
	Class      string
	NoCheckYet bool
	Objectives []Objective
	// ReqLevel are the controls mapped to the requirement as a whole (used when it has no objectives of its own).
	ReqLevel []string
}

// ObjectiveKey names an objective.
type ObjectiveKey struct{ Req, Obj string }

// Determination is a scan's finding on one objective.
type Determination struct {
	Value  string
	Reason string
}

// ScanInput is the results a roll-up reads (the same as rollup's).
type ScanInput struct {
	Results             map[string]map[uuid.UUID]rollup.Result
	InScope, OutOfScope []uuid.UUID
	Now                 time.Time
	Fresh               time.Duration
}

// FromScan decides each objective from the scan: every in-scope computer meeting every mapped
// control gives met; any failure gives not met; anything that cannot tell gives not assessed. A
// scan never makes a requirement met past its objectives: a requirement that is not wholly
// technical keeps its single whole-requirement objective not assessed even when its controls meet.
func FromScan(reqs []ReqObjectives, in ScanInput) map[ObjectiveKey]Determination {
	var flat []rollup.Requirement
	type back struct {
		key       ObjectiveKey
		synthetic bool
		class     string
	}
	var order []back
	for _, r := range reqs {
		objs := r.Objectives
		synthetic := len(objs) == 0
		if synthetic {
			objs = []Objective{{ID: WholeRequirement, Controls: r.ReqLevel}}
		}
		for _, o := range objs {
			id := r.ID + "\x00" + o.ID
			rr := rollup.Requirement{ID: id, Class: r.Class, NoCheckYet: r.NoCheckYet}
			if !synthetic {
				// An objective's own controls decide it, whatever the requirement's class.
				rr.Class = compliance.ReqTechnical
			}
			for _, c := range o.Controls {
				rr.Mappings = append(rr.Mappings, rollup.Mapping{ControlID: c, Relation: compliance.RelSatisfies})
			}
			flat = append(flat, rr)
			order = append(order, back{ObjectiveKey{r.ID, o.ID}, synthetic, r.Class})
		}
	}
	outs := rollup.Compute(rollup.Input{Requirements: flat, Results: in.Results, InScope: in.InScope, OutOfScope: in.OutOfScope, Now: in.Now, Fresh: in.Fresh})
	res := make(map[ObjectiveKey]Determination, len(outs))
	for i, o := range outs {
		d := Determination{Reason: o.Reason}
		switch o.Status {
		case rollup.Meets:
			d.Value = Met
		case rollup.DoesNotMeet:
			d.Value = NotMet
		case rollup.NotApplicable:
			d.Value = NotApplicable
		default:
			d.Value = NotAssessed
		}
		if b := order[i]; d.Value == Met && b.synthetic && b.class != compliance.ReqTechnical {
			d.Value, d.Reason = NotAssessed, "part of this requirement is not something a scan can check"
		}
		res[order[i].key] = d
	}
	return res
}

// Objective results from other sources.
const (
	SourceScan        = "scan"
	SourceAttestation = "attestation"
	SourceUpload      = "upload"
	SourceInterview   = "interview"
)

// Row is a stored objective result.
type Row struct {
	Determination string
	Source        string
	// AttestationExpires is set for an attestation; once it has passed, the row stands for nothing.
	AttestationExpires *time.Time
}

// Effective is what a stored objective result counts as now: an expired attestation is not assessed.
func Effective(r Row, now time.Time) string {
	if r.Source == SourceAttestation && (r.AttestationExpires == nil || !now.Before(*r.AttestationExpires)) {
		return NotAssessed
	}
	return r.Determination
}

// Merge is what a fresh scan finding does to a stored row, and what is kept. A scan finding "not
// met" replaces a person's statement (the evidence of the computers outweighs it); a scan finding
// "met" replaces only an earlier scan result or nothing, so that a person's own call is not
// overwritten, and a finding that cannot tell leaves a person's statement standing.
func Merge(old *Row, scan Determination) (keep bool, d Determination) {
	if old == nil || old.Source == SourceScan {
		return false, scan
	}
	if scan.Value == NotMet {
		return false, scan
	}
	return true, Determination{}
}

// Requirement combines the effective determinations of its objectives: met only when every
// objective is met or not applicable (and at least one is met); any not met gives not met.
func Requirement(objs []string) string {
	if len(objs) == 0 {
		return NotAssessed
	}
	var met, na int
	for _, o := range objs {
		switch o {
		case NotMet:
			return NotMet
		case Met:
			met++
		case NotApplicable:
			na++
		}
	}
	switch {
	case met+na < len(objs):
		return NotAssessed
	case met == 0:
		return NotApplicable
	}
	return Met
}
