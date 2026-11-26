// Package compliance holds the vocabulary of the compliance engine
// (ADR-0078): licence classes, result states, controls, packs and the
// wording rules. It has no behavior that needs a database; the library,
// the packs, the scan and the roll-up are in its subpackages.
package compliance

import (
	"encoding/json"
	"slices"
)

// Edition is the build edition: commercial (releases) or dev (everything
// else). It is set at build with a linker variable, and there is no runtime
// switch (ADR-0078, section 10):
//
//	-X github.com/paulmataruso/easyrmm/server/internal/compliance.Edition=commercial
var Edition = EditionDev

// Editions.
const (
	EditionDev        = "dev"
	EditionCommercial = "commercial"
)

// Class is a licence class (section 3). Every control, mapping, pack and
// source carries one.
type Class string

// Licence classes, least restrictive first.
const (
	ClassOriginal            Class = "ORIGINAL"
	ClassPublicDomain        Class = "PUBLIC_DOMAIN"
	ClassOpenLicense         Class = "OPEN_LICENSE"
	ClassAttributionRequired Class = "ATTRIBUTION_REQUIRED"
	ClassNoncommercial       Class = "NONCOMMERCIAL"
	ClassCommercialRequired  Class = "COMMERCIAL_LICENSE_REQUIRED"
	ClassRestricted          Class = "RESTRICTED"
)

const classCount = 7

var classOrder = []Class{ClassOriginal, ClassPublicDomain, ClassOpenLicense, ClassAttributionRequired,
	ClassNoncommercial, ClassCommercialRequired, ClassRestricted}

// Valid says whether c is one of the seven classes.
func (c Class) Valid() bool { return slices.Contains(classOrder, c) }

// Rank orders the classes by restriction: ORIGINAL is 0, RESTRICTED 6. An
// unknown class ranks above them all, so that it is never taken as milder.
func (c Class) Rank() int {
	if i := slices.Index(classOrder, c); i >= 0 {
		return i
	}
	return classCount
}

// AllowedInCommercial says whether a commercial build may carry the class:
// ORIGINAL, PUBLIC_DOMAIN, OPEN_LICENSE and ATTRIBUTION_REQUIRED only.
func (c Class) AllowedInCommercial() bool {
	return c.Valid() && c.Rank() <= ClassAttributionRequired.Rank()
}

// Classes lists the seven classes.
func Classes() []Class { return slices.Clone(classOrder) }

// MostRestrictive is the most restrictive of the classes; ORIGINAL for none.
func MostRestrictive(cs ...Class) Class {
	out := ClassOriginal
	for _, c := range cs {
		if c.Rank() > out.Rank() {
			out = c
		}
	}
	return out
}

// Review states, independent of the class.
const (
	ReviewNone    = "none"
	ReviewNeeded  = "needed"
	ReviewCleared = "cleared"
)

// ValidReview says whether state and ref are consistent: a known state,
// and a reference when cleared.
func ValidReview(state, ref string) bool {
	switch state {
	case ReviewNone, ReviewNeeded:
		return true
	case ReviewCleared:
		return ref != ""
	}
	return false
}

// Allowed says whether an edition may carry content of this class and
// review state. The dev edition carries everything; a commercial one only
// the allowed classes, and nothing whose review is still needed.
func Allowed(edition string, c Class, reviewState, reviewRef string) bool {
	if !c.Valid() || !ValidReview(reviewState, reviewRef) {
		return false
	}
	if edition != EditionCommercial {
		return true
	}
	return c.AllowedInCommercial() && reviewState != ReviewNeeded
}

// Result states: ADR-0054's, plus unknown and stale, which never count as
// passing.
const (
	StateInPlace          = "in_place"
	StatePartly           = "partly"
	StateNotInPlace       = "not_in_place"
	StateNotApplicable    = "not_applicable"
	StateManagedElsewhere = "managed_elsewhere"
	StateNotSupported     = "not_supported"
	StateHalfApplied      = "half_applied"
	StateFailed           = "failed"
	StateUnknown          = "unknown"
	StateStale            = "stale"
)

// ResultStates are the states stored in a result row. Stale is computed
// from the check time when results are read, never stored.
var ResultStates = []string{StateInPlace, StatePartly, StateNotInPlace, StateNotApplicable, StateManagedElsewhere,
	StateNotSupported, StateHalfApplied, StateFailed, StateUnknown}

// Executors a control can name.
const (
	ExecHardening     = "hardening"
	ExecWinmod        = "winmod"
	ExecFacts         = "facts"
	ExecServer        = "server"
	ExecAttestation   = "attestation"
	PlatformWindows   = "windows"
	PlatformLinux     = "linux"
	TierReport        = "T0"
	TierReversible    = "T1"
	TierWorkflow      = "T2"
	TierDangerous     = "T3"
	UndoRestore       = "restore_backup"
	UndoReverse       = "reverse_action"
	UndoNone          = "none"
	RelSatisfies      = "satisfies_objective"
	RelEvidence       = "evidence_for"
	RelRelated        = "related"
	ReqTechnical      = "technical"
	ReqPartly         = "partly"
	ReqOrganisational = "organisational"
)

// Provenance is on every control and mapping (section 5).
type Provenance struct {
	Author             string   `json:"author"`
	AuthoredOn         string   `json:"authored_on"`
	Method             string   `json:"method"`
	Sources            []Locate `json:"sources,omitempty"`
	DerivedFromContent bool     `json:"derived_from_content"`
	Reviewer           string   `json:"reviewer"`
	ReviewedOn         string   `json:"reviewed_on,omitempty"`
	LicenceClass       Class    `json:"licence_class"`
}

// Locate names a source and where in it.
type Locate struct {
	SourceID string `json:"source_id"`
	Locator  string `json:"locator"`
}

// Control is one technical setting or condition (section 3). It carries no
// framework text.
type Control struct {
	ID          string          `json:"id"`
	Version     int             `json:"version"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Platforms   json.RawMessage `json:"platforms"`
	Scopes      []string        `json:"scopes"`
	Severity    string          `json:"severity"`
	Executor    string          `json:"executor"`
	// ExecutorRef names what the check reads: for hardening the platform,
	// module and setting id; for winmod the module and action.
	ExecutorRef json.RawMessage `json:"executor_ref"`
	Detect      json.RawMessage `json:"detect"`
	Expected    json.RawMessage `json:"expected"`
	Applicab    json.RawMessage `json:"applicability,omitempty"`
	Remediation string          `json:"remediation_text"`
	// ApplyRef and UndoRef say how a fix and its undo run (ADR-0054 W2,
	// ADR-0051): the hardening job they would be. Null where there is none.
	ApplyRef       json.RawMessage `json:"apply_ref"`
	UndoRef        json.RawMessage `json:"undo_ref"`
	ApplySupported bool            `json:"apply_supported"`
	UndoKind       string          `json:"undo_kind"`
	RiskTier       string          `json:"risk_tier"`
	WarningID      string          `json:"warning_id,omitempty"`
	NeedsRestart   bool            `json:"needs_restart"`
	Preconditions  []string        `json:"preconditions"`
	Author         string          `json:"author"`
	Provenance     Provenance      `json:"provenance"`
	LicenceClass   Class           `json:"licence_class"`
	ReviewState    string          `json:"review_state"`
}

// HardeningRef is the executor reference of a control read by the
// hardening scripts.
type HardeningRef struct {
	Platform string `json:"platform"`
	Module   string `json:"module"`
	Setting  string `json:"setting"`
}

// Wording (section 9): results say a control meets, does not meet or cannot
// be told; a requirement is checked or not assessed. The words "compliant",
// "certified" and "audit-ready" are never used.
const (
	WordMeets       = "meets"
	WordDoesNotMeet = "does not meet"
	WordCannotTell  = "cannot tell"

	StatusMet         = "checked: all in-scope computers meet"
	StatusNotMet      = "checked: does not meet"
	StatusNotAssessed = "not assessed"
	StatusNotApplic   = "not applicable"

	// Disclaimer is carried by every compliance screen and report.
	Disclaimer = "Assessment aid. It reports what EasyRMM could check on the computers in scope. It is not an assessment, an audit, a certification or legal advice."
	// CISNote is carried wherever a CIS recommendation number appears.
	CISNote = "Cross-reference to CIS recommendation numbers. EasyRMM's checks are independently written and are not CIS content. EasyRMM is not CIS certified."
)

// ResultWord is the wording of a result state.
func ResultWord(state string) string {
	switch state {
	case StateInPlace:
		return WordMeets
	case StateNotInPlace, StatePartly, StateHalfApplied, StateFailed:
		return WordDoesNotMeet
	}
	return WordCannotTell
}
