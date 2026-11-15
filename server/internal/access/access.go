// Package access describes who is calling a domain service: their resolved
// permissions, the database scope that bounds their queries, and how they
// appear in the audit log.
package access

import (
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Caller is the subject of an operation.
type Caller struct {
	Principal *rbac.Principal
	Scope     database.Scope
	Actor     audit.Actor
	system    bool
}

// User builds a caller for a signed-in user. scope must be derived from the
// principal (auth.DataScope).
func User(p *rbac.Principal, scope database.Scope, actor audit.Actor) Caller {
	return Caller{Principal: p, Scope: scope, Actor: actor}
}

// System builds a caller for internal work (first-run setup, schedulers).
// It holds every permission and sees every tenant.
func System(component string) Caller {
	return Caller{Scope: database.System, Actor: audit.SystemActor(component), system: true}
}

// IsSystem reports whether the caller is internal.
func (c Caller) IsSystem() bool { return c.system }

// Can reports whether the caller holds perm for the resource.
func (c Caller) Can(perm rbac.Permission, r rbac.Resource) bool {
	return c.system || c.Principal.Can(perm, r)
}

// CanGlobal reports whether the caller holds perm platform-wide.
func (c Caller) CanGlobal(perm rbac.Permission) bool {
	return c.system || c.Principal.CanGlobal(perm)
}

// Require returns apperr.ErrForbidden unless the caller holds perm.
func (c Caller) Require(perm rbac.Permission, r rbac.Resource) error {
	if c.Can(perm, r) {
		return nil
	}
	return apperr.Forbidden()
}

// RequireGlobal returns apperr.ErrForbidden unless the caller holds perm
// platform-wide.
func (c Caller) RequireGlobal(perm rbac.Permission) error {
	if c.CanGlobal(perm) {
		return nil
	}
	return apperr.Forbidden()
}
