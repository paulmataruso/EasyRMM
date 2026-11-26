package assess

import (
	"errors"

	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Assessment states.
const (
	Draft    = "draft"
	InReview = "in_review"
	Approved = "approved"
	Archived = "archived"
)

// ErrFrozen is an attempt to change an approved or archived assessment.
var ErrFrozen = errors.New("the assessment is approved and cannot change; start a new draft")

// Frozen says whether an assessment in state s can no longer change.
func Frozen(s string) bool { return s == Approved || s == Archived }

type transition struct{ from, to string }

// transitions are the workflow: draft to in review and back, in review to approved, approved to
// archived. Nothing leaves archived, and nothing is deleted.
var transitions = map[transition]rbac.Permission{
	{Draft, InReview}:    rbac.PermComplianceEdit,
	{InReview, Draft}:    rbac.PermComplianceEdit,
	{InReview, Approved}: rbac.PermComplianceApprove,
	{Approved, Archived}: rbac.PermComplianceApprove,
}

// Allowed says whether a move is part of the workflow and which permission it needs.
func Allowed(from, to string) (rbac.Permission, bool) {
	p, ok := transitions[transition{from, to}]
	return p, ok
}
