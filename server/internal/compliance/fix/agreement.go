package fix

import (
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
)

// Agreement is what the person gives with an apply, an undo or an approval:
// that they read the warning, and for a change of tier 3 the computer's name
// typed (section 6, rule 4).
type Agreement struct {
	Agreed bool   `json:"agreed"`
	Typed  string `json:"typed,omitempty"`
}

// Check validates the agreement for an item of a tier on a computer. It
// does not check the step-up, which belongs to the request.
func (a Agreement) Check(tier string, w content.Warning, device string) error {
	f := apperr.Fields{}
	f.Check(a.Agreed, "agreed", "Confirm that you have read the warning.")
	if tier == T3 || w.TypedRequired {
		f.Check(strings.TrimSpace(a.Typed) != "", "typed", "Type the computer's name to confirm.")
		if strings.TrimSpace(a.Typed) != "" {
			f.Check(strings.EqualFold(strings.TrimSpace(a.Typed), device), "typed", "The name typed is not the computer's name.")
		}
	}
	return f.Err()
}
