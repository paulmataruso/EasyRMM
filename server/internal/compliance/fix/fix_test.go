package fix

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
)

type libControl struct {
	ID             string              `json:"id"`
	Platforms      struct{ OS string } `json:"platforms"`
	RiskTier       string              `json:"risk_tier"`
	WarningID      *string             `json:"warning_id"`
	ApplySupported bool                `json:"apply_supported"`
	UndoKind       string              `json:"undo_kind"`
	ApplyRef       *struct {
		Settings []string `json:"settings"`
	} `json:"apply_ref"`
	ExecutorRef struct {
		Setting string `json:"setting"`
	} `json:"executor_ref"`
}

func library(t *testing.T) []libControl {
	t.Helper()
	var out []libControl
	for _, f := range []string{"controls/windows.json", "controls/linux.json"} {
		b, err := fs.ReadFile(content.FS, f)
		if err != nil {
			t.Fatal(err)
		}
		var file struct {
			Controls []libControl `json:"controls"`
		}
		if err := json.Unmarshal(b, &file); err != nil {
			t.Fatal(err)
		}
		out = append(out, file.Controls...)
	}
	return out
}

// Every control has a tier, and every control that can be applied has a
// warning of that tier, whose agreement needs are those of the tier.
func TestTierTableHasEveryControl(t *testing.T) {
	ws, err := content.Warnings()
	if err != nil {
		t.Fatal(err)
	}
	cs := library(t)
	if len(cs) < 200 {
		t.Fatalf("only %d controls", len(cs))
	}
	for _, c := range cs {
		if _, ok := TierNumber(c.RiskTier); !ok {
			t.Errorf("%s: tier %q", c.ID, c.RiskTier)
			continue
		}
		if !c.ApplySupported {
			continue
		}
		if c.WarningID == nil {
			t.Errorf("%s: no warning", c.ID)
			continue
		}
		w, ok := ws[*c.WarningID]
		if !ok {
			t.Errorf("%s: warning %s is not defined", c.ID, *c.WarningID)
			continue
		}
		eff := Effective(c.RiskTier, c.Platforms.OS, c.ExecutorRef.Setting)
		if eff != c.RiskTier {
			t.Errorf("%s: the library says %s but the hardening job holds it to %s", c.ID, c.RiskTier, eff)
		}
		if w.Tier != eff {
			t.Errorf("%s: tier %s but warning %s is for %s", c.ID, eff, w.ID, w.Tier)
		}
		if (eff == T3) != (w.TypedRequired && w.StepUpRequired) {
			t.Errorf("%s: the typed text and step-up belong to tier 3 alone", c.ID)
		}
	}
}

func TestWarningHashCoversTheText(t *testing.T) {
	ws, err := content.Warnings()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for id, w := range ws {
		if w.SHA256 == "" || w.SHA256 != w.Hash() {
			t.Errorf("%s: hash %q", id, w.SHA256)
		}
		if other, dup := seen[w.SHA256]; dup {
			t.Errorf("%s and %s share a hash", id, other)
		}
		seen[w.SHA256] = id
		for _, edit := range []func(*content.Warning){
			func(x *content.Warning) { x.Version++ },
			func(x *content.Warning) { x.Paragraphs = append([]string{"x"}, x.Paragraphs...) },
			func(x *content.Warning) { x.Title += "!" },
			func(x *content.Warning) { x.UndoNote += "!" },
		} {
			c := w
			c.Paragraphs = append([]string{}, w.Paragraphs...)
			edit(&c)
			if c.Hash() == w.Hash() {
				t.Errorf("%s: a change to the text did not change the hash", id)
			}
		}
		for _, p := range w.Paragraphs {
			for _, banned := range []string{"compliant", "certified", "CIS"} {
				if strings.Contains(p, banned) {
					t.Errorf("%s says %q", id, banned)
				}
			}
		}
	}
	for _, tier := range []string{T1, T2, T3} {
		if ws["warn."+strings.ToLower(tier)+".v1"].Tier != tier {
			t.Errorf("no warning for %s", tier)
		}
	}
}

// The tier 3 dialog refuses a wrong typed text, and every tier needs the
// agreement.
func TestAgreementRules(t *testing.T) {
	ws, _ := content.Warnings()
	t3, t2 := ws["warn.t3.v1"], ws["warn.t2.v1"]
	cases := []struct {
		name string
		a    Agreement
		tier string
		w    content.Warning
		ok   bool
	}{
		{"not agreed", Agreement{}, T2, t2, false},
		{"T2 agreed", Agreement{Agreed: true}, T2, t2, true},
		{"T3 without the name", Agreement{Agreed: true}, T3, t3, false},
		{"T3 wrong name", Agreement{Agreed: true, Typed: "OTHER-HOST"}, T3, t3, false},
		{"T3 name", Agreement{Agreed: true, Typed: " hq-win "}, T3, t3, true},
		{"T3 name but not agreed", Agreement{Typed: "HQ-WIN"}, T3, t3, false},
	}
	for _, c := range cases {
		if err := c.a.Check(c.tier, c.w, "HQ-WIN"); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// There is no bulk path above T1.
func TestBulkRules(t *testing.T) {
	one := map[string]bool{"a": true}
	two := map[string]bool{"a": true, "b": true}
	for _, c := range []struct {
		tier string
		ctl  map[string]bool
		n    int
		ok   bool
	}{
		{T1, two, 5, true}, {T2, one, 5, true}, {T2, two, 2, false}, {T3, one, 2, false}, {T3, one, 1, true}, {T2, two, 1, true},
	} {
		if ok, why := Bulk(c.tier, c.ctl, c.n); ok != c.ok || (!ok && why == "") {
			t.Errorf("%s %d controls %d items: %v %q", c.tier, len(c.ctl), c.n, ok, why)
		}
	}
}

// A Linux control's apply is a module's, so no per-control fix is offered.
func TestLinuxHasNoPerControlFix(t *testing.T) {
	for _, c := range library(t) {
		if c.Platforms.OS == "linux" && c.ApplyRef != nil && len(c.ApplyRef.Settings) == 1 {
			t.Errorf("%s names a setting; the queue would apply it without the script taking setting ids", c.ID)
		}
		if c.Platforms.OS == "windows" && c.ApplySupported && (c.ApplyRef == nil || len(c.ApplyRef.Settings) != 1) {
			t.Errorf("%s has no single setting to apply", c.ID)
		}
	}
}
