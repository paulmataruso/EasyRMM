package compliance

import "testing"

func TestClassOrderAndEditions(t *testing.T) {
	want := []Class{ClassOriginal, ClassPublicDomain, ClassOpenLicense, ClassAttributionRequired, ClassNoncommercial, ClassCommercialRequired, ClassRestricted}
	got := Classes()
	for i, c := range want {
		if got[i] != c || c.Rank() != i || !c.Valid() {
			t.Errorf("class %d: %s rank %d", i, c, c.Rank())
		}
	}
	if Class("MIT").Valid() || Class("").Valid() || Class("MIT").Rank() <= ClassRestricted.Rank() {
		t.Error("an unknown class must be invalid and rank above every class")
	}
	if MostRestrictive() != ClassOriginal || MostRestrictive(ClassPublicDomain, ClassRestricted, ClassOriginal) != ClassRestricted {
		t.Error("MostRestrictive")
	}
	for _, c := range Classes() {
		restricted := c == ClassNoncommercial || c == ClassCommercialRequired || c == ClassRestricted
		if c.AllowedInCommercial() == restricted {
			t.Errorf("%s: allowed in commercial = %v", c, c.AllowedInCommercial())
		}
		if !Allowed(EditionDev, c, ReviewNone, "") {
			t.Errorf("dev must carry %s", c)
		}
		if Allowed(EditionCommercial, c, ReviewNone, "") == restricted {
			t.Errorf("commercial and %s", c)
		}
	}
	if Allowed("anything", Class("MIT"), ReviewNone, "") {
		t.Error("an unknown class is never allowed")
	}
}

func TestReviewState(t *testing.T) {
	cases := []struct {
		edition, state, ref string
		want                bool
	}{
		{EditionCommercial, ReviewNeeded, "", false},
		{EditionCommercial, ReviewCleared, "", false},
		{EditionCommercial, ReviewCleared, "counsel-2026-01", true},
		{EditionCommercial, ReviewNone, "", true},
		{EditionDev, ReviewNeeded, "", true},
		{EditionDev, "maybe", "", false},
	}
	for _, c := range cases {
		if got := Allowed(c.edition, ClassOriginal, c.state, c.ref); got != c.want {
			t.Errorf("%s %s %q: %v", c.edition, c.state, c.ref, got)
		}
	}
}

func TestWording(t *testing.T) {
	for state, word := range map[string]string{
		StateInPlace: WordMeets, StateNotInPlace: WordDoesNotMeet, StatePartly: WordDoesNotMeet, StateHalfApplied: WordDoesNotMeet,
		StateFailed: WordDoesNotMeet, StateUnknown: WordCannotTell, StateStale: WordCannotTell, StateNotSupported: WordCannotTell,
		StateManagedElsewhere: WordCannotTell,
	} {
		if got := ResultWord(state); got != word {
			t.Errorf("%s: %q, want %q", state, got, word)
		}
	}
	for _, s := range []string{WordMeets, WordDoesNotMeet, WordCannotTell, StatusMet, StatusNotMet, StatusNotAssessed, Disclaimer, CISNote} {
		for _, banned := range []string{"compliant", "certified", "audit-ready", "CIS Level"} {
			if containsFold(s, banned) && (banned != "certified" || s != CISNote && s != Disclaimer) {
				t.Errorf("%q contains %q", s, banned)
			}
		}
	}
}

func containsFold(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
