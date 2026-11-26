package jobs

import (
	"errors"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestLinuxSettingsList(t *testing.T) {
	if len(linuxSettings) < 100 {
		t.Fatalf("%d settings", len(linuxSettings))
	}
	for name, doc := range map[string]string{
		"a duplicate":     `{"version":1,"settings":[{"id":"ssh-a","module":"ssh","what":"x"},{"id":"ssh-a","module":"ssh","what":"x"}]}`,
		"a bad id":        `{"version":1,"settings":[{"id":"SSH_a","module":"ssh","what":"x"}]}`,
		"another module":  `{"version":1,"settings":[{"id":"ssh-a","module":"sudo","what":"x"}]}`,
		"an unknown mod":  `{"version":1,"settings":[{"id":"nope-a","module":"nope","what":"x"}]}`,
		"no description":  `{"version":1,"settings":[{"id":"ssh-a","module":"ssh","what":""}]}`,
		"version 2":       `{"version":2,"settings":[{"id":"ssh-a","module":"ssh","what":"x"}]}`,
		"an unknown key":  `{"version":1,"settings":[{"id":"ssh-a","module":"ssh","what":"x","kind":"y"}]}`,
		"no settings":     `{"version":1,"settings":[]}`,
		"not JSON at all": `{`,
	} {
		if _, err := parseLinuxSettings([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Every ID the script names in a line of its own is in the list, and every
// module has some.
func TestLinuxScriptIDsAreListed(t *testing.T) {
	listed := map[string]bool{}
	mods := map[string]bool{}
	for _, s := range linuxSettings {
		listed[s.ID] = true
		mods[s.Module] = true
	}
	re := regexp.MustCompile(`(?m)\b(?:set_ok|set_bad|setting) ([a-z]+-[a-z0-9-]+) `)
	found := 0
	for _, m := range re.FindAllStringSubmatch(hardeningScript, -1) {
		found++
		if !listed[m[1]] {
			t.Errorf("the script reports %s, which linux-settings.json does not list", m[1])
		}
	}
	if found < 50 {
		t.Errorf("only %d IDs found in the script", found)
	}
	for _, m := range HardeningModules {
		if m != "mac" && m != "integrity" && !mods[m] {
			t.Errorf("module %s has no settings", m)
		}
	}
	if _, err := os.Stat("hardening/linux-settings.json"); err != nil {
		t.Error(err)
	}
}

func TestParseLinuxSettings(t *testing.T) {
	job := Hardening{Mode: HardeningCheck, Modules: []string{"ssh", "sudo"}}
	platform := map[string]any{"id": "debian", "versionId": "12", "family": "debian", "container": "none", "support": "full"}
	sudo := map[string]any{"module": "sudo", "state": "in_place"}
	parse := func(ssh map[string]any) (*hardeningResult, error) {
		return parseHardeningResult(result(t, map[string]any{"version": 1, "mode": "check", "platform": platform, "modules": []any{ssh, sudo}}), job)
	}
	setting := func(over map[string]any) map[string]any {
		s := map[string]any{"id": "ssh-x11-forwarding", "state": "not_in_place", "value": "yes", "want": "no"}
		for k, v := range over {
			s[k] = v
		}
		return s
	}
	mod := func(settings ...any) map[string]any {
		return map[string]any{"module": "ssh", "state": "partly", "missing": []string{"X11Forwarding no (now yes)"}, "settings": settings}
	}

	// A table: what the script prints per setting to what the server keeps.
	r, err := parse(mod(
		setting(nil),
		setting(map[string]any{"id": "ssh-login-grace-time", "state": "in_place", "value": "30", "want": "30"}),
		setting(map[string]any{"id": "ssh-ciphers", "state": "in_place", "value": nil, "want": "no weak algorithms"}),
		setting(map[string]any{"id": "ssh-kex", "state": "reported", "value": "a\x1b[2J  b"}),
	))
	if err != nil {
		t.Fatal(err)
	}
	got := r.Modules[0].Settings
	if len(got) != 4 || got[0].ID != "ssh-x11-forwarding" || got[0].State != "not_in_place" || got[0].Value != "yes" || got[0].Want != "no" ||
		got[1].State != "in_place" || got[2].Value != "" || got[2].Want != "no weak algorithms" || strings.ContainsRune(got[3].Value, 0x1b) {
		t.Errorf("settings %+v", got)
	}
	if r.Modules[0].Missing[0] == "" {
		t.Error("the text list is kept beside the settings")
	}

	// Text the computer supplied is cut to its limit, not refused.
	if r, err = parse(mod(setting(map[string]any{"value": strings.Repeat("x", maxSettingText+50)}))); err != nil || len(r.Modules[0].Settings[0].Value) != maxSettingText {
		t.Errorf("a long value: %v", err)
	}

	// A result from a script before C0, and one with a cut list.
	if r, err = parse(map[string]any{"module": "ssh", "state": "partly", "missing": []string{"X11Forwarding no (now yes)"}}); err != nil || r.Modules[0].Settings != nil {
		t.Errorf("an old result: %v %+v", err, r)
	}
	if r, err = parse(map[string]any{"module": "ssh", "state": "partly", "missing": []string{"a"}, "settings": []any{setting(nil)}, "settingsOmitted": "in_place"}); err != nil || r.Modules[0].SettingsOmitted != "in_place" {
		t.Errorf("a cut list: %v", err)
	}
	if _, err = parse(map[string]any{"module": "ssh", "state": "partly", "missing": []string{"a"}, "settingsOmitted": "all"}); err != nil {
		t.Errorf("no list: %v", err)
	}

	for name, m := range map[string]map[string]any{
		"an unknown id":       mod(setting(map[string]any{"id": "ssh-nope"})),
		"another module's id": mod(setting(map[string]any{"id": "sudo-use-pty"})),
		"a Windows state":     mod(setting(map[string]any{"state": "managed_elsewhere"})),
		"an unknown state":    mod(setting(map[string]any{"state": "hardened"})),
		"a Windows field":     mod(setting(map[string]any{"item": "x"})),
		"too many":            mod(slices.Repeat([]any{setting(nil)}, maxSettings+1)...),
		"a bad omitted":       {"module": "ssh", "state": "partly", "missing": []string{"a"}, "settingsOmitted": "some"},
		"notes":               {"module": "ssh", "state": "partly", "missing": []string{"a"}, "notes": []string{"x"}},
		"managed":             {"module": "ssh", "state": "partly", "missing": []string{"a"}, "managed": []any{map[string]any{"id": "ssh", "owner": "x", "state": "in_place"}}},
	} {
		if _, err := parse(m); !errors.Is(err, errHardeningResult) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
