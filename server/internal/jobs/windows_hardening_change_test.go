package jobs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

// Every setting has a tier, and the tiers are the ones ADR-0078 names.
func TestWindowsTiers(t *testing.T) {
	for _, m := range WindowsHardeningModules {
		if _, ok := windowsModuleTiers[m]; !ok {
			t.Errorf("module %s has no tier", m)
		}
	}
	for id := range windowsSettingTiers {
		if !slices.ContainsFunc(windowsSettings, func(s windowsSetting) bool { return s.ID == id }) {
			t.Errorf("tier of %s, which is not a setting", id)
		}
	}
	for _, c := range []struct {
		h    Hardening
		want int
	}{
		{Hardening{Modules: []string{"autoplay"}}, tierSafe},
		{Hardening{Modules: []string{"autoplay", "uac"}}, tierWorkflow},
		{Hardening{Modules: []string{"firewall"}}, tierDangerous},
		{Hardening{Modules: []string{"bitlocker"}}, tierReport},
		{Hardening{Modules: []string{"rdp"}}, tierDangerous},
		{Hardening{Modules: []string{"rdp"}, Settings: []string{"rdp-secure-rpc"}}, tierWorkflow},
		{Hardening{Modules: []string{"rdp"}, Settings: []string{"rdp-nla"}}, tierDangerous},
		{Hardening{Modules: []string{"accounts"}, Settings: []string{"accounts-min-length"}}, tierWorkflow},
		{Hardening{Modules: []string{"accounts"}, Settings: []string{"accounts-lockout-threshold"}}, tierDangerous},
	} {
		if got := c.h.windowsTier(); got != c.want {
			t.Errorf("%v %v: tier %d, want %d", c.h.Modules, c.h.Settings, got, c.want)
		}
	}
}

func TestWindowsChangeArguments(t *testing.T) {
	h := Hardening{Platform: HardeningWindows, Mode: HardeningApply, Settings: []string{"wdigest-logon-credential", "autoplay-autorun"}}
	f := apperr.Fields{}
	h.validate(f)
	if f.Err() != nil {
		t.Fatal(f.Err())
	}
	// The settings file's order, the modules of the settings, in the script's.
	if !slices.Equal(h.Modules, []string{"wdigest", "autoplay"}) || !slices.Equal(h.Settings, []string{"wdigest-logon-credential", "autoplay-autorun"}) {
		t.Errorf("modules %v settings %v", h.Modules, h.Settings)
	}
	want := []string{"apply", "--settings", "wdigest-logon-credential,autoplay-autorun", "guard-minutes=10"}
	if got := h.windowsArgs(); !slices.Equal(got, want) {
		t.Errorf("args %q, want %q", got, want)
	}
	if got := h.windowsLabel(); got != "Apply Windows hardening: 2 settings of wdigest, autoplay" {
		t.Errorf("label %q", got)
	}
	undo := Hardening{Platform: HardeningWindows, Mode: HardeningUndo, Modules: []string{"uac", "autoplay"}, Options: HardeningOptions{WindowsHardeningOptions: WindowsHardeningOptions{DomainController: true}}}
	f = apperr.Fields{}
	undo.validate(f)
	if f.Err() != nil {
		t.Fatal(f.Err())
	}
	if got := undo.windowsArgs(); !slices.Equal(got, []string{"undo", "uac,autoplay", "domain-controller"}) {
		t.Errorf("undo args %q", got)
	}
	if got := (Hardening{Mode: HardeningConfirm}).windowsArgs(); !slices.Equal(got, []string{"confirm"}) {
		t.Errorf("confirm args %q", got)
	}
	// A check takes no guard.
	chk := Hardening{Platform: HardeningWindows, Mode: HardeningCheck, Modules: []string{"uac"}}
	if got := chk.windowsArgs(); !slices.Equal(got, []string{"check", "uac"}) {
		t.Errorf("check args %q", got)
	}
}

type stepUpStub struct{ err error }

func (s stepUpStub) VerifyStepUp(context.Context) error {
	return s.err
}

func TestWindowsChangeGuard(t *testing.T) {
	s := &Service{}
	one, two := []uuid.UUID{uuid.New()}, []uuid.UUID{uuid.New(), uuid.New()}
	safe := Hardening{Platform: HardeningWindows, Mode: HardeningApply, Modules: []string{"autoplay"}}
	danger := Hardening{Platform: HardeningWindows, Mode: HardeningApply, Modules: []string{"firewall"}}
	field := func(err error, f string) {
		t.Helper()
		if e, ok := apperr.As(err); !ok || e.Fields[f] == "" {
			t.Errorf("want an error for %s, got %v", f, err)
		}
	}
	_, err := s.windowsChangeGuard(access.Caller{}, one, safe, HardeningConfirmation{})
	field(err, "confirm.agreed")
	ch, err := s.windowsChangeGuard(access.Caller{}, two, safe, HardeningConfirmation{Agreed: true})
	if err != nil || ch.tier != tierSafe || ch.guard != GuardMinutes {
		t.Errorf("safe change on two computers: %+v, %v", ch, err)
	}
	undo := safe
	undo.Mode = HardeningUndo
	if ch, err = s.windowsChangeGuard(access.Caller{}, one, undo, HardeningConfirmation{Agreed: true}); err != nil || ch.guard != 0 {
		t.Errorf("undo takes no guard: %+v, %v", ch, err)
	}
	// Tier 3: one computer, the name typed, then a step-up, which is not
	// built yet.
	_, err = s.windowsChangeGuard(access.Caller{}, two, danger, HardeningConfirmation{Agreed: true, Typed: "X"})
	field(err, "deviceIds")
	_, err = s.windowsChangeGuard(access.Caller{}, one, danger, HardeningConfirmation{Agreed: true})
	field(err, "confirm.typed")
	_, err = s.windowsChangeGuard(access.Caller{}, one, danger, HardeningConfirmation{Agreed: true, Typed: "HQ-WIN"})
	if e, ok := apperr.As(err); !ok || e.Code != "step_up_required" || !strings.Contains(e.Message, "ADR-0055") {
		t.Errorf("tier 3 without step-up: %v", err)
	}
	s.SetStepUp(stepUpStub{err: errors.New("too old")})
	ch, err = s.windowsChangeGuard(access.Caller{}, one, danger, HardeningConfirmation{Agreed: true, Typed: "HQ-WIN"})
	if err != nil || ch.tier != tierDangerous {
		t.Fatalf("tier 3 with a step-up check: %+v, %v", ch, err)
	}
	ts := []target{{org: uuid.New(), name: "HQ-WIN"}}
	if err := ch.check(context.Background(), access.Caller{}, ts); err == nil || err.Error() != "too old" {
		t.Errorf("a failed step-up must stop the change, got %v", err)
	}
	ch.typed = "OTHER"
	if err := ch.check(context.Background(), access.Caller{}, ts); err == nil || !strings.Contains(err.Error(), "validation") {
		t.Errorf("a wrong name must stop the change, got %v", err)
	}
}

// A result that left settings out says nothing is in place.
func TestOmittedSettingsAreUnknown(t *testing.T) {
	full := WindowsFinding{Settings: []HardeningSetting{{ID: "autoplay-autorun", State: "in_place"}}}
	if !full.Complete() || full.SettingState("autoplay-autorun") != "in_place" {
		t.Errorf("a complete result: %+v", full)
	}
	for _, omitted := range []string{"in_place", "all"} {
		cut := WindowsFinding{SettingsOmitted: omitted, Settings: []HardeningSetting{{ID: "autoplay-all-drives", State: "not_in_place"}}}
		if cut.Complete() {
			t.Errorf("%s: a cut result is not complete", omitted)
		}
		if got := cut.SettingState("autoplay-autorun"); got != "unknown" {
			t.Errorf("%s: a setting left out is %q, want unknown", omitted, got)
		}
	}
	if got := full.SettingState("no-such-setting"); got != "unknown" {
		t.Errorf("a setting never asked for is %q", got)
	}
	mods := []HardeningModuleResult{
		{Module: "uac", State: "in_place", HardeningFinding: HardeningFinding{WindowsFinding: full}},
		{Module: "ntlm", State: "partly", HardeningFinding: HardeningFinding{WindowsFinding: WindowsFinding{SettingsOmitted: "all"}}},
	}
	if got := IncompleteModules(mods); !slices.Equal(got, []string{"ntlm"}) {
		t.Errorf("modules to run again: %v", got)
	}
}

func TestWindowsApplyResultIsRead(t *testing.T) {
	h := Hardening{Platform: HardeningWindows, Mode: HardeningApply, Settings: []string{"autoplay-autorun"}, Modules: []string{"autoplay"}}
	line := func(extra string) string {
		return HardeningResultPrefix + `{"version":1,"mode":"apply","platform":` + windowsPlatform + `,"modules":[{"module":"autoplay","state":"in_place","outcome":"applied","recorded":true,"done":["autoplay-autorun"],"settings":[` +
			`{"id":"autoplay-autorun","state":"in_place","value":"1","outcome":"applied","before":"0","changedAt":"2026-11-26T10:00:00Z"}` + extra + `],"managed":[],"notes":[]}]}`
	}
	r, err := parseHardeningResult(line(""), h)
	if err != nil {
		t.Fatal(err)
	}
	if ids := r.armedSettings(); !slices.Equal(ids, []string{"autoplay-autorun"}) {
		t.Errorf("armed %v", ids)
	}
	for name, extra := range map[string]string{
		"a setting that was not asked for": `,{"id":"autoplay-all-drives","state":"in_place"}`,
		"an outcome that is not one":       `,{"id":"autoplay-autorun","state":"in_place","outcome":"wiped"}`,
		"a time that is not a time":        `,{"id":"autoplay-autorun","state":"in_place","changedAt":"soon"}`,
	} {
		if _, err := parseHardeningResult(line(extra), h); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The apply and undo logic of the script, on any PowerShell 7: its
// functions run against a registry that is a hashtable. Skipped where
// pwsh is not installed; GitHub's Linux runners have it.
func TestWindowsScriptApplyUndoFlow(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh is not installed")
	}
	dir, _ := filepath.Abs("hardening")
	harness, _ := filepath.Abs(filepath.Join("testdata", "windows-flow-harness.ps1"))
	out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", harness,
		"-Script", filepath.Join(dir, "windows.ps1"), "-Settings", filepath.Join(dir, "windows-settings.json")).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "windows-flow-expected.txt"))
	if err != nil {
		t.Fatal(err)
	}
	norm := func(b []byte) string { return strings.ReplaceAll(strings.TrimSpace(string(b)), "\r\n", "\n") }
	if norm(out) != norm(want) {
		t.Errorf("the flow printed\n%s\nwant\n%s", out, want)
	}
}
