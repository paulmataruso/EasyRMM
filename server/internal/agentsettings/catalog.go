// Package agentsettings holds the settings that operators set for agents at
// the platform, an organization, a site or one device, and works out what is
// in effect for a device (ADR-0058).
//
// Slice 1 covers the server's side: the catalog, the four scopes with
// precedence and enforcement, who may write each key, the rate limits, the
// audit and the API. What a device's agent holds is not here yet; the one key
// so far, the heartbeat interval, reaches every agent through the answer's
// unsigned heartbeatSeconds, which rc.4 and earlier already obey.
package agentsettings

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Scope is where a value is set. Higher scopes come first.
type Scope string

// The four scopes (ADR-0058). Device groups and tags are not scopes.
const (
	ScopePlatform     Scope = "platform"
	ScopeOrganization Scope = "organization"
	ScopeSite         Scope = "site"
	ScopeDevice       Scope = "device"
)

// scopes lists them from the highest, the order enforcement is judged in.
var scopes = []Scope{ScopePlatform, ScopeOrganization, ScopeSite, ScopeDevice}

// rank is 0 for the platform and 3 for a device.
func (s Scope) rank() int {
	for i, o := range scopes {
		if o == s {
			return i
		}
	}
	return -1
}

// Valid says whether s is one of the four.
func (s Scope) Valid() bool { return s.rank() >= 0 }

// Key is one entry of the catalog. There are no free-form keys.
type Key struct {
	Name  string
	Title string
	// Line is the one line technicians read where the key is set.
	Line string
	// Default is the value in effect where nothing is set.
	Default int
	// Min and Max bound the value, before the platform's own minimum.
	Min, Max int
	// SetAt are the scopes the key may be set at, EnforceAt the ones that
	// may enforce it.
	SetAt, EnforceAt []Scope
	// Permission is what writing the key needs at a scope.
	Permission func(Scope) rbac.Permission
	// Floor is the platform's lowest allowed value for the key, when it has
	// one.
	Floor func(Limits) int
	// Schemas are every version of the key's schema as agents understand it,
	// from the first. A version only widens: it accepts more than the last,
	// never less (a change that would narrow a key is a new key). Ordered by
	// version.
	Schemas []Schema
}

// Schema is one version of a key's value schema (ADR-0058, "Unknown and
// invalid"): the agent reports the version it understands, and the server
// checks a value against the highest version it knows at or below it.
type Schema struct {
	Version int
	// Check refuses a value this version does not allow.
	Check func(json.RawMessage) error
}

// SchemaAtOrBelow is the highest schema version the server knows that is at
// or below v: false when there is none (a key reported at version 0, say).
func (k Key) SchemaAtOrBelow(v int) (Schema, bool) {
	var best Schema
	found := false
	for _, s := range k.Schemas {
		if s.Version <= v && (!found || s.Version > best.Version) {
			best, found = s, true
		}
	}
	return best, found
}

// CatalogVersion is the version of this release's catalog. It rises with
// every release that changes the catalog (a key, a schema version), and a
// document issued under a newer catalog than an instance's own is left in
// place by that instance, as instances of two releases share one database for
// the length of a rolling upgrade.
const CatalogVersion = 1

// intSchema accepts a whole number from lo to hi.
func intSchema(lo, hi int) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		n, err := parseInt(raw)
		if err != nil {
			return err
		}
		if n < lo || n > hi {
			return fmt.Errorf("%d is outside %d to %d", n, lo, hi)
		}
		return nil
	}
}

// HeartbeatKey is the interval agents check in at.
const HeartbeatKey = "agent.heartbeat_seconds"

// Interval bounds the server only ever answers (ADR-0058), and the platform
// limit's own default.
const (
	MinHeartbeatSeconds     = 30
	MaxHeartbeatSeconds     = 300
	DefaultHeartbeatSeconds = 60
)

var catalog = []Key{{
	Name:  HeartbeatKey,
	Title: "Heartbeat interval",
	Line: "Measurements arrive with each heartbeat. At 5 minutes, a 15-minute processor alert judges 3 measurements " +
		"instead of 15, and a device counts as offline only after 15 minutes, so a shorter Offline policy waits that long.",
	Default: DefaultHeartbeatSeconds, Min: MinHeartbeatSeconds, Max: MaxHeartbeatSeconds,
	SetAt:     []Scope{ScopePlatform, ScopeOrganization, ScopeSite, ScopeDevice},
	EnforceAt: []Scope{ScopePlatform, ScopeOrganization},
	Permission: func(s Scope) rbac.Permission {
		if s == ScopePlatform {
			return rbac.PermSettingsManage
		}
		return rbac.PermDeviceConfigure
	},
	Floor:   func(l Limits) int { return l.MinHeartbeatSeconds },
	Schemas: []Schema{{Version: 1, Check: intSchema(MinHeartbeatSeconds, MaxHeartbeatSeconds)}},
}}

// Catalog is every key, in the order the console lists them.
func Catalog() []Key { return append([]Key(nil), catalog...) }

// Lookup finds a key by name.
func Lookup(name string) (Key, bool) {
	for _, k := range catalog {
		if k.Name == name {
			return k, true
		}
	}
	return Key{}, false
}

func has(list []Scope, s Scope) bool {
	for _, o := range list {
		if o == s {
			return true
		}
	}
	return false
}

// CanSetAt says whether the key may be set at the scope.
func (k Key) CanSetAt(s Scope) bool { return has(k.SetAt, s) }

// CanEnforceAt says whether the key may be enforced at the scope.
func (k Key) CanEnforceAt(s Scope) bool { return has(k.EnforceAt, s) }

// Lowest is the smallest value allowed under the limits.
func (k Key) Lowest(l Limits) int {
	if k.Floor == nil {
		return k.Min
	}
	return max(k.Min, k.Floor(l))
}

// Check judges a value against the key's schema and the platform's limits,
// and returns it in its canonical form. A value that is not an integer, or
// is out of bounds, is refused with the reason.
func (k Key) Check(raw json.RawMessage, l Limits) (json.RawMessage, error) {
	n, err := parseInt(raw)
	if err != nil {
		return nil, err
	}
	if n < k.Min || n > k.Max {
		return nil, fmt.Errorf("Use a whole number from %d to %d.", k.Min, k.Max) //nolint:staticcheck // shown to people
	}
	if low := k.Lowest(l); n < low {
		return nil, fmt.Errorf("The platform's shortest allowed value is %d.", low) //nolint:staticcheck // shown to people
	}
	return json.RawMessage(strconv.Itoa(n)), nil
}

// parseInt reads a JSON number that is a whole number: no fraction,
// exponent, string or other type.
func parseInt(raw json.RawMessage) (int, error) {
	raw = bytes.TrimSpace(raw)
	n, err := strconv.ParseInt(string(raw), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("Use a whole number.") //nolint:staticcheck // shown to people
	}
	return int(n), nil
}

func itoa(n int) string { return strconv.Itoa(n) }
