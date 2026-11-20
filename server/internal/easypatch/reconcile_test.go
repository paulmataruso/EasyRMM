package easypatch

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestFitName(t *testing.T) {
	long := strings.Repeat("a", 250)
	if got := fitName(long, ""); len(got) != maxName {
		t.Errorf("long name: %d", len(got))
	}
	suffix := " (deleted 2026-11-18 0123abcd)"
	if got := fitName(long, suffix); utf16Len(got) != maxName || !strings.HasSuffix(got, suffix) {
		t.Errorf("long name with a suffix: %q", got)
	}
	// Characters beyond the BMP count twice, as in EasyPatch's .NET strings.
	emoji := strings.Repeat("🙂", 150)
	if got := fitName(emoji, ""); utf16Len(got) > maxName || utf16Len(got) != 200 || len([]rune(got)) != 100 {
		t.Errorf("emoji: %d code units, %d runes", utf16Len(got), len([]rune(got)))
	}
	if got := fitName("  Acme  ", ""); got != "Acme" {
		t.Errorf("trimmed: %q", got)
	}
	// A cut that ends in a space leaves none before the suffix.
	if got := fitName(strings.Repeat("a", 195)+" b", " (x)"); got != strings.Repeat("a", 195)+" (x)" {
		t.Errorf("trailing space: %q", got)
	}
	if utf16Len("\xff") != 1 {
		t.Error("an invalid byte counts as one")
	}
}

func TestNameSet(t *testing.T) {
	ours, other, archived := uuid.New(), uuid.New(), uuid.New()
	rmm := uuid.MustParse("0123abcd-0000-4000-8000-000000000000")
	n := nameSet{all: []*named{
		{id: ours, name: "Acme", active: true},
		{id: other, name: "GLOBEX", active: true},
		{id: archived, name: "Initech", active: false},
	}}
	cases := []struct {
		name   string
		except uuid.UUID
		want   string
	}{
		{"Acme", ours, "Acme"},                      // its own name
		{"Acme", uuid.Nil, "Acme (0123abcd)"},       // held by another
		{"Globex", uuid.Nil, "Globex (0123abcd)"},   // held in another case
		{"Initech", uuid.Nil, "Initech (0123abcd)"}, // held by an archived one
		{"Umbrella", uuid.Nil, "Umbrella"},
	}
	for _, c := range cases {
		if got, err := n.want(c.name, rmm, c.except); err != nil || got != c.want {
			t.Errorf("want(%q): %q, %v", c.name, got, err)
		}
	}
	n.all = append(n.all, &named{id: uuid.New(), name: "Acme (0123abcd)", active: true})
	if _, err := n.want("Acme", rmm, uuid.Nil); err == nil {
		t.Error("both names taken, and no error")
	}

	linked := map[uuid.UUID]bool{ours: true}
	if x := n.adoptable("Acme", rmm, linked); x == nil || x.name != "Acme (0123abcd)" {
		t.Errorf("adoptable by its suffixed name: %+v", x)
	}
	if x := n.adoptable("Globex", rmm, linked); x != nil {
		t.Errorf("adopted by a name in another case: %+v", x)
	}
	if x := n.adoptable("Initech", rmm, linked); x != nil {
		t.Errorf("adopted an archived one: %+v", x)
	}
	if x := n.adoptable("Acme", rmm, map[uuid.UUID]bool{}); x == nil || x.id != ours {
		t.Errorf("adoptable by its name: %+v", x)
	}
}

func TestRemovalText(t *testing.T) {
	for reason, want := range map[string]string{
		RemovalDeleted:  "deleted",
		RemovalOptedOut: "stopped",
		RemovalMoved:    "another organization",
		"other":         "other",
	} {
		if got := reasonText(reason); !strings.Contains(got, want) {
			t.Errorf("%s: %q", reason, got)
		}
	}
	if zone("") != nil || *zone("UTC") != "UTC" {
		t.Error("zone")
	}
	var r ReconcileResult
	r.problem("%s", strings.Repeat("x", 2000))
	if len(r.Problems) != 1 || len(r.Problems[0]) != 1000 {
		t.Errorf("problem: %d", len(r.Problems[0]))
	}
}
