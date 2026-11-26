// Package devscope is the development-only guard that holds every
// organization but one back from test builds. With EASYRMM_DEV_SCOPE_ORG
// unset it does nothing, which is how production runs.
//
// While it is set, an organization other than the one named gets the stable
// agent builds only, and the server starts no automatic action on its
// devices. Allowed is the one question every automatic behavior asks.
package devscope

import (
	"log/slog"
	"sync/atomic"

	"github.com/google/uuid"
)

// scope is the organization test builds are limited to; nil when unset.
var scope atomic.Pointer[uuid.UUID]

// Set limits test builds to one organization, or with uuid.Nil removes the
// limit. It returns what puts the previous scope back, for tests.
func Set(org uuid.UUID) (restore func()) {
	prev := scope.Load()
	if org == uuid.Nil {
		scope.Store(nil)
	} else {
		scope.Store(&org)
	}
	return func() { scope.Store(prev) }
}

// Active says whether a scope is set.
func Active() bool { return scope.Load() != nil }

// Org is the organization in scope, and whether there is one.
func Org() (uuid.UUID, bool) {
	if p := scope.Load(); p != nil {
		return *p, true
	}
	return uuid.Nil, false
}

// Allowed says whether new behavior, test builds and automatic actions may
// reach the organization: always when no scope is set, otherwise only for
// the organization in scope. An unknown organization (uuid.Nil) is outside
// any scope.
func Allowed(org uuid.UUID) bool {
	p := scope.Load()
	return p == nil || *p == org
}

// Log says at startup which scope the server runs under.
func Log(log *slog.Logger) {
	if org, ok := Org(); ok {
		log.Warn("dev scope is set: test builds and automatic actions reach one organization only; every other organization gets the stable agent builds",
			"organization_id", org)
		return
	}
	log.Info("dev scope is not set")
}
