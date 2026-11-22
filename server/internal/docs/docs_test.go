package docs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

func TestCleanText(t *testing.T) {
	if got := CleanLine("  Ann\tExample\r\nIT\x00\x1f\x7f "); got != "Ann Example  IT\x7f" {
		t.Errorf("CleanLine %q", got)
	}
	if got := CleanText(" Line one\r\nLine two\rLine\tthree\x01\x02\n "); got != "Line one\nLine two\nLine\tthree" {
		t.Errorf("CleanText %q", got)
	}
}

func TestValidators(t *testing.T) {
	for s, want := range map[string]bool{
		"": true, "+1 555 0100": true, "555-0100 ext. 12": true, "(555) 0100": true,
		"call reception": false, strings.Repeat("5", 51): false, strings.Repeat("5", 50): true,
	} {
		if got := ValidPhone(s); got != want {
			t.Errorf("ValidPhone(%q) = %v", s, got)
		}
	}
	for s, want := range map[string]bool{
		"": true, "help@example.com": true, "Ann.Example+it@sub.example.com": true,
		"help@example": false, "Ann <ann@example.com>": false, "a@example.com, b@example.com": false,
		"not an address": false, "@example.com": false, "ann@": false,
		"o'brien@example.com": true, "zoë@exämple.com": true, "a-b_c@mail-1.example.com": true,
		strings.Repeat("a", 64) + "@example.com": true, strings.Repeat("a", 65) + "@example.com": false,
		"a@" + strings.Repeat("b", 249) + ".com": false, "a@" + strings.Repeat("b", 248) + ".com": true,
		// What a mailto: link would read as more than an address (L2).
		"x?bcc=evil@example.com": false, "a&b@example.com": false, "a=b@example.com": false, "a%40b@example.com": false,
		"a@example.com?subject=x": false, "a@ex_ample.com": false, "a@b@example.com": false,
		".a@example.com": false, "a.@example.com": false, "a..b@example.com": false,
		"a@-example.com": false, "a@example-.com": false, "a@example..com": false, "a b@example.com": false,
	} {
		if got := ValidEmail(s); got != want {
			t.Errorf("ValidEmail(%q) = %v", s, got)
		}
	}
	for in, want := range map[string]string{
		"":                              "",
		"example.com":                   "https://example.com",
		"http://example.com/support":    "http://example.com/support",
		"https://www.example.com:8443/": "https://www.example.com:8443/",
	} {
		if got, ok := NormalizeWebsite(in); !ok || got != want {
			t.Errorf("NormalizeWebsite(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{
		"ftp://example.com", "javascript://example.com/%0aalert(1)", "https://", "https://user:pass@example.com",
		"https://exa mple.com", `https://example.com\path`, "https://example.com/" + strings.Repeat("a", 2000), "https://%zz",
	} {
		if _, ok := NormalizeWebsite(bad); ok {
			t.Errorf("NormalizeWebsite(%q) accepted", bad)
		}
	}
	if len(countries) != 249 || !ValidCountry("GB") || !ValidCountry("US") || ValidCountry("gb") || ValidCountry("UK") || ValidCountry("") {
		t.Errorf("countries: %d", len(countries))
	}
}

func TestCounts(t *testing.T) {
	for _, c := range []struct {
		counts Counts
		want   string
	}{
		{Counts{}, "nothing"},
		{Counts{"contacts": 1}, "1 contact"},
		{Counts{"contacts": 2, "places": 1}, "2 contacts and 1 place"},
		{Counts{"contacts": 0, "places": 3}, "3 places"},
	} {
		if got := c.counts.String(); got != c.want {
			t.Errorf("%v: %q, want %q", c.counts, got, c.want)
		}
	}
	held := Counts{"contacts": 2, "places": 1}
	if held.Total() != 3 || !held.Matches(Counts{"contacts": 2, "places": 1}) || held.Matches(Counts{"contacts": 2}) {
		t.Error("Total or Matches")
	}

	if err := CheckDeletion("site", Counts{"contacts": 0, "places": 0}, nil); err != nil {
		t.Errorf("nothing held, nothing confirmed: %v", err)
	}
	if err := CheckDeletion("site", held, Counts{"contacts": 2, "places": 1}); err != nil {
		t.Errorf("confirmed: %v", err)
	}
	for _, c := range []struct {
		held, confirmed Counts
		code            string
	}{
		{held, nil, "documentation_exists"},
		{held, Counts{"contacts": 2}, "documentation_changed"},
		{Counts{"contacts": 0, "places": 0}, Counts{"contacts": 1}, "documentation_changed"},
	} {
		ae, ok := apperr.As(CheckDeletion("site", c.held, c.confirmed))
		if !ok || ae.Kind != apperr.KindConflict || ae.Code != c.code || ae.Counts["contacts"] != c.held["contacts"] {
			t.Errorf("%v confirmed by %v: %+v", c.held, c.confirmed, ae)
		}
	}
	ae, _ := apperr.As(CheckDeletion("organization", held, nil))
	if !strings.Contains(ae.Message, "This organization holds 2 contacts and 1 place") {
		t.Errorf("message %q", ae.Message)
	}
}

func TestTreeOrder(t *testing.T) {
	id := func(n byte) uuid.UUID { return uuid.UUID{15: n} }
	ptr := func(u uuid.UUID) *uuid.UUID { return &u }
	got := treeOrder([]Place{
		{ID: id(1), Name: "West wing"},
		{ID: id(2), Name: "east wing"},
		{ID: id(3), Name: "Floor 2", ParentID: ptr(id(2))},
		{ID: id(4), Name: "Floor 1", ParentID: ptr(id(2))},
		{ID: id(5), Name: "Server room", ParentID: ptr(id(4))},
		{ID: id(6), Name: "Annex", ParentID: ptr(id(1))},
	})
	var names []string
	for _, p := range got {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "east wing,Floor 1,Server room,Floor 2,West wing,Annex" {
		t.Errorf("tree order %v", names)
	}
}

func TestPlacePatchParent(t *testing.T) {
	var p PlacePatch
	if err := json.Unmarshal([]byte(`{"name":"Room 1"}`), &p); err != nil || p.ParentID.Set {
		t.Errorf("absent: %+v %v", p, err)
	}
	if err := json.Unmarshal([]byte(`{"parentId":null}`), &p); err != nil || !p.ParentID.Set || p.ParentID.ID != nil {
		t.Errorf("null: %+v %v", p, err)
	}
	id := uuid.New()
	if err := json.Unmarshal([]byte(`{"parentId":"`+id.String()+`"}`), &p); err != nil || p.ParentID.ID == nil || *p.ParentID.ID != id {
		t.Errorf("set: %+v %v", p, err)
	}
	if err := json.Unmarshal([]byte(`{"parentId":"nope"}`), &p); err == nil {
		t.Error("a bad identifier read")
	}
}
