package agentsettings

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func row(s Scope, v string, enforced bool) Row {
	r := Row{Scope: s, Value: json.RawMessage(v), Enforced: enforced, Name: string(s) + " name"}
	if s != ScopePlatform {
		r.ID = uuid.New()
	}
	return r
}

func TestNearestWinsAndEnforcementOverridesIt(t *testing.T) {
	k, _ := Lookup(HeartbeatKey)
	l := DefaultLimits()
	cases := []struct {
		name string
		rows []Row
		want int
		from Scope
	}{
		{"default", nil, 60, ""},
		{"platform", []Row{row(ScopePlatform, "100", false)}, 100, ScopePlatform},
		{"nearest", []Row{row(ScopePlatform, "100", false), row(ScopeSite, "50", false), row(ScopeOrganization, "70", false)}, 50, ScopeSite},
		{"device over all", []Row{row(ScopeDevice, "40", false), row(ScopeSite, "50", false), row(ScopePlatform, "100", false)}, 40, ScopeDevice},
		{"enforced org over site and device", []Row{row(ScopeOrganization, "70", true), row(ScopeSite, "50", false), row(ScopeDevice, "40", false)}, 70, ScopeOrganization},
		{"highest enforced wins", []Row{row(ScopeOrganization, "70", true), row(ScopePlatform, "100", true), row(ScopeSite, "50", true)}, 100, ScopePlatform},
		{"an enforced site over a device", []Row{row(ScopeSite, "50", true), row(ScopeDevice, "40", false)}, 50, ScopeSite},
		{"enforced below an unenforced higher one", []Row{row(ScopePlatform, "100", false), row(ScopeOrganization, "70", true)}, 70, ScopeOrganization},
	}
	for _, c := range cases {
		e := k.Resolve(c.rows, l)
		if e.Int() != c.want {
			t.Errorf("%s: %d, want %d", c.name, e.Int(), c.want)
		}
		if (c.from == "") != (e.From == nil) || (e.From != nil && e.From.Scope != c.from) {
			t.Errorf("%s: from %+v", c.name, e.From)
		}
	}
}

func TestResolveRaisesToThePlatformMinimumAndIgnoresDamagedValues(t *testing.T) {
	k, _ := Lookup(HeartbeatKey)
	l := Limits{MinHeartbeatSeconds: 120}
	e := k.Resolve([]Row{row(ScopeSite, "45", false)}, l)
	if e.Int() != 120 || !e.Raised || string(e.Set) != "45" || e.From.Scope != ScopeSite {
		t.Errorf("raised: %+v", e)
	}
	if e := k.Resolve(nil, l); e.Int() != 120 || e.Raised || e.From != nil {
		t.Errorf("the default under a raised minimum: %+v", e)
	}
	// A stored value the schema no longer reads is skipped for the next one
	// down, and then the default.
	damaged := []Row{row(ScopeDevice, `"fast"`, false), row(ScopeSite, "75", false)}
	if e := k.Resolve(damaged, DefaultLimits()); e.Int() != 75 || e.From.Scope != ScopeSite {
		t.Errorf("damaged device value: %+v", e)
	}
	if e := k.Resolve(damaged[:1], DefaultLimits()); e.Int() != 60 || e.From != nil {
		t.Errorf("only a damaged value: %+v", e)
	}
}

func TestEnforcerAndAbove(t *testing.T) {
	rows := []Row{row(ScopePlatform, "100", false), row(ScopeOrganization, "70", true), row(ScopeSite, "50", false)}
	if e := Enforcer(rows); e == nil || e.Scope != ScopeOrganization {
		t.Errorf("enforcer: %+v", e)
	}
	if Enforcer(above(rows, ScopeOrganization)) != nil {
		t.Error("the organization's own enforcement is not above it")
	}
	if Enforcer(above(rows, ScopeSite)) == nil {
		t.Error("the organization is above the site")
	}
	if len(above(rows, ScopePlatform)) != 0 || len(atOrAbove(rows, ScopeOrganization)) != 2 {
		t.Error("above and at or above")
	}
	if Pick(nil) != nil {
		t.Error("nothing to pick")
	}
	src := rows[0].source()
	if src.ID != "" || src.Scope != ScopePlatform {
		t.Errorf("platform source %+v", src)
	}
	if rows[1].source().ID == "" {
		t.Error("an organization's source has its ID")
	}
}
