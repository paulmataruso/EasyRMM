package assess

import (
	"fmt"
	"time"
)

// Eligible says whether a requirement that is not met may be on a plan of action, and why not
// (32 CFR 170.21(a)(2), as re-read on 2026-11-26): none of the six barred requirements; at most
// one point, except 3.13.11 when encryption is employed but not FIPS-validated (3 points).
func Eligible(r Req) (bool, string) {
	if r.Barred {
		return false, "This requirement may never be on a plan of action (32 CFR 170.21(a)(2)(iii))."
	}
	pts := r.notMetPoints()
	if r.ID == encryptionReq && r.PartlyDone && r.Partial > 0 && pts == r.Partial {
		return true, "Allowed: encryption is employed but not FIPS-validated (3 points), the one exception."
	}
	if pts > 1 {
		return false, fmt.Sprintf("Its value is %d points, and a plan of action item may carry at most 1 (32 CFR 170.21(a)(2)(ii)).", pts)
	}
	return true, "At most one point, and not one of the six barred requirements."
}

// ClosesBy is the end of an item's 180 days.
func ClosesBy(opened time.Time) time.Time { return opened.AddDate(0, 0, POAMClosedDays) }

// POAMDraft is a draft plan-of-action item made from a failing requirement.
type POAMDraft struct {
	ReqID    string
	Points   int
	Eligible bool
	Reason   string
}

// DraftItems lists the requirements that are not met, each with its point value and whether it may
// be on a plan of action. Unassessed requirements are not drafted: nothing says they fail.
func DraftItems(reqs []Req) []POAMDraft {
	var out []POAMDraft
	for _, r := range reqs {
		if r.Status != NotMet {
			continue
		}
		ok, why := Eligible(r)
		out = append(out, POAMDraft{ReqID: r.ID, Points: r.notMetPoints(), Eligible: ok, Reason: why})
	}
	return out
}
