package posture

import (
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/rollup"
)

func TestDefaultWeight(t *testing.T) {
	if DefaultWeight("patching") != 3 || DefaultWeight("rdp") != 2 {
		t.Fatal("a control the table names keeps its weight")
	}
	if DefaultWeight("some-new-module") != 1 {
		t.Fatal("a control the table does not name weighs 1")
	}
}

func TestApplyOverrides(t *testing.T) {
	items := []rollup.Item{
		{ID: "ssh", Weight: 3, Result: rollup.Result{State: compliance.StateInPlace}},
		{ID: "rdp", Weight: 2, Result: rollup.Result{State: compliance.StateNotInPlace}},
		{ID: "uac", Weight: 2, Result: rollup.Result{State: compliance.StateInPlace}},
	}
	if got := applyOverrides(items, nil); len(got) != 3 || got[0].Weight != 3 {
		t.Fatalf("no overrides leave the items alone: %+v", got)
	}
	got := applyOverrides(items, map[string]int{"ssh": 5, "rdp": 0, "nothing-here": 4})
	if len(got) != 2 || got[0].ID != "ssh" || got[0].Weight != 5 || got[1].ID != "uac" || got[1].Weight != 2 {
		t.Fatalf("a weight replaces, 0 leaves out, an unknown control is ignored: %+v", got)
	}
	if items[0].Weight != 3 || len(items) != 3 {
		t.Fatal("the input is not changed")
	}
	// The failing control left out, the computer meets; at its default it does not.
	now := items[0].Result.CheckedAt
	if s := rollup.ScoreOf(items, now, 0); s.Word != compliance.WordDoesNotMeet {
		t.Fatalf("default: %+v", s)
	}
	if s := rollup.ScoreOf(got, now, 0); s.Word != compliance.WordMeets || s.Percent == nil || *s.Percent != 100 {
		t.Fatalf("overridden: %+v", s)
	}
	// Every control left out leaves nothing that applies.
	if s := rollup.ScoreOf(applyOverrides(items, map[string]int{"ssh": 0, "rdp": 0, "uac": 0}), now, 0); s.Percent != nil {
		t.Fatalf("nothing applies: %+v", s)
	}
}

func TestControlIDPattern(t *testing.T) {
	for _, ok := range []string{"ssh", "disk-encryption", "log-collection"} {
		if !controlIDPattern.MatchString(ok) {
			t.Errorf("%q should be a control id", ok)
		}
	}
	for _, bad := range []string{"", "SSH", "1ssh", "a b", "a;drop"} {
		if controlIDPattern.MatchString(bad) {
			t.Errorf("%q should not be a control id", bad)
		}
	}
}
