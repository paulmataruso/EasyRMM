// Package fix is the compliance fix queue (ADR-0078, section 6, slice C2):
// one item per failed control on a computer, each fix made under an
// agreement the person gives, through the existing hardening apply and
// undo (ADR-0051 and ADR-0054). It never writes a setting itself and has
// no script of its own: it builds a hardening job that changes one setting,
// reads the job's own report for that setting, and asks the engine for a
// single-control re-scan, because only a scan may move a requirement's
// status.
package fix

import (
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
)

// Risk tiers (section 6). T0 has nothing to change and is never queued.
const (
	T0 = "T0"
	T1 = "T1"
	T2 = "T2"
	T3 = "T3"
)

// TierNumber is a tier as the number the hardening jobs use (0 to 3), and
// false for text that is not a tier.
func TierNumber(t string) (int, bool) {
	switch t {
	case T0:
		return 0, true
	case T1:
		return 1, true
	case T2:
		return 2, true
	case T3:
		return 3, true
	}
	return 0, false
}

// tierName is the tier of a number.
func tierName(n int) string { return [...]string{T0, T1, T2, T3}[max(0, min(n, 3))] }

// Effective is the tier a fix is held to: the library's, raised to the one
// the hardening job holds the setting to, so that the agreement a person
// gives always covers what the job will demand (a job that asked for more
// than the dialog showed would be refused after the person agreed).
func Effective(libraryTier, platform, setting string) string {
	n, _ := TierNumber(libraryTier)
	if platform == "windows" {
		if w, ok := jobs.WindowsSettingTier(setting); ok {
			n = max(n, w)
		}
	}
	return tierName(n)
}

// Bulk says whether a request that holds several items is allowed, by tier
// (section 6, rules 2 to 5): T1 any number; T2 one control on several
// computers; T3 never. It returns the reason when it is not.
func Bulk(tier string, controls map[string]bool, n int) (ok bool, why string) {
	if n <= 1 {
		return true, ""
	}
	switch tier {
	case T1:
		return true, ""
	case T2:
		if len(controls) == 1 {
			return true, ""
		}
		return false, "A change that can break a workflow is made for one control at a time; it may cover several computers."
	}
	return false, "A change that can cut access to a computer is made on one computer at a time."
}
