package agentsettings

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Row is one stored value.
type Row struct {
	Scope Scope
	// ID is the organization, site or device the row belongs to; the nil
	// UUID for the platform.
	ID        uuid.UUID
	Name      string
	Value     json.RawMessage
	Enforced  bool
	SetBy     string
	UpdatedAt time.Time
}

// Source says where an effective value comes from.
type Source struct {
	Scope Scope  `json:"scope"`
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
}

func (r Row) source() *Source {
	s := &Source{Scope: r.Scope, Name: r.Name}
	if r.ID != uuid.Nil {
		s.ID = r.ID.String()
	}
	return s
}

// above returns the rows at scopes higher than s.
func above(rows []Row, s Scope) []Row {
	var out []Row
	for _, r := range rows {
		if r.Scope.rank() < s.rank() {
			out = append(out, r)
		}
	}
	return out
}

// Enforcer is the row that enforces the key over everything below it: the
// highest scope's wins when several do. Nil when none does.
func Enforcer(rows []Row) *Row {
	var best *Row
	for i := range rows {
		r := &rows[i]
		if r.Enforced && (best == nil || r.Scope.rank() < best.Scope.rank()) {
			best = r
		}
	}
	return best
}

// Pick is the row in effect: an enforced one wins over everything below it,
// else the nearest scope's. Nil when nothing is set, so the default applies.
func Pick(rows []Row) *Row {
	if e := Enforcer(rows); e != nil {
		return e
	}
	var best *Row
	for i := range rows {
		r := &rows[i]
		if best == nil || r.Scope.rank() > best.Scope.rank() {
			best = r
		}
	}
	return best
}

// Effective is what is in effect for one key at one target.
type Effective struct {
	// Value is the value after the platform's minimum.
	Value json.RawMessage `json:"value"`
	// From is nil for the key's default.
	From *Source `json:"from"`
	// Raised is set when the value set is below the platform's minimum and
	// takes effect as the minimum.
	Raised bool `json:"raised"`
	// Set is the value as set, before it was raised.
	Set json.RawMessage `json:"-"`
}

// Resolve works out the value in effect from the rows of the target's chain.
// A stored value that no longer parses (the catalog changed under it) is
// ignored, so the next one down, or the default, applies.
func (k Key) Resolve(rows []Row, l Limits) Effective {
	for len(rows) > 0 {
		r := Pick(rows)
		n, err := parseInt(r.Value)
		if err != nil {
			rows = without(rows, r)
			continue
		}
		low := k.Lowest(l)
		e := Effective{Value: json.RawMessage(itoa(max(n, low))), From: r.source(), Set: r.Value}
		e.Raised = n < low
		return e
	}
	return Effective{Value: json.RawMessage(itoa(max(k.Default, k.Lowest(l))))}
}

func without(rows []Row, drop *Row) []Row {
	out := make([]Row, 0, len(rows))
	for i := range rows {
		if &rows[i] != drop {
			out = append(out, rows[i])
		}
	}
	return out
}

// Int is the effective value as a whole number, for a key that holds
// one.
func (e Effective) Int() int {
	n, _ := parseInt(e.Value)
	return n
}
