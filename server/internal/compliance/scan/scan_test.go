package scan_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/scan"
)

var at = time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)

func mod(name, state, detail string) scan.ModuleRow {
	return scan.ModuleRow{Module: name, State: state, Detail: json.RawMessage(detail), CheckedAt: at}
}

func ctrl(id, platform, module, setting string) scan.Control {
	return scan.Control{ID: id, Version: 1, Platform: platform, Module: module, Setting: setting}
}

func states(rows []scan.Row) map[string]string {
	m := map[string]string{}
	for _, r := range rows {
		m[r.ControlID] = r.State
	}
	return m
}

func TestIngestSettingStates(t *testing.T) {
	controls := []scan.Control{
		ctrl("a", "windows", "accounts", "accounts-history"),
		ctrl("b", "windows", "accounts", "accounts-guest"),
		ctrl("c", "windows", "accounts", "accounts-min-length"),
		ctrl("d", "windows", "accounts", "accounts-complexity"),
		ctrl("e", "windows", "accounts", "accounts-max-age"),
		ctrl("f", "windows", "accounts", "accounts-min-age"),
		ctrl("g", "windows", "accounts", "accounts-reversible"),
	}
	detail := `{"settings":[
		{"id":"accounts-history","state":"in_place","value":"24","want":"24"},
		{"id":"accounts-guest","state":"not_in_place","value":"1","want":"0"},
		{"id":"accounts-min-length","state":"managed_elsewhere","value":"8"},
		{"id":"accounts-complexity","state":"reported"},
		{"id":"accounts-max-age","state":"check_only"},
		{"id":"accounts-min-age","state":"not_applicable"}],
		"managed":[{"id":"accounts-min-length","owner":"Group Policy","policy":"MinimumPasswordLength","value":"14","state":"in_place"}]}`
	got := scan.Ingest(controls, map[string]scan.ModuleRow{"accounts": mod("accounts", "partly", detail)})
	want := map[string]string{"a": "in_place", "b": "not_in_place", "c": "managed_elsewhere", "d": "not_supported", "e": "unknown", "f": "not_applicable", "g": "unknown"}
	for id, st := range states(got) {
		if want[id] != st {
			t.Errorf("%s: %s, want %s", id, st, want[id])
		}
	}
	for _, r := range got {
		switch r.ControlID {
		case "a":
			if string(r.Observed) != `{"item":"","value":"24"}` || string(r.Expected) != `{"want":"24"}` || r.ControlVersion != 1 || !r.CheckedAt.Equal(at) {
				t.Errorf("a: %s %s %v", r.Observed, r.Expected, r.CheckedAt)
			}
		case "c":
			var o struct {
				Name  string `json:"name"`
				Meets bool   `json:"meets"`
			}
			if json.Unmarshal(r.Owner, &o) != nil || o.Name != "Group Policy" || !o.Meets {
				t.Errorf("owner %s", r.Owner)
			}
		}
	}
}

// What a check did not say is unknown, never in place.
func TestIngestNeverInventsAPass(t *testing.T) {
	controls := []scan.Control{ctrl("x", "linux", "ssh", "ssh-x11-forwarding"), ctrl("y", "linux", "kernel", "kernel-a")}
	cases := map[string]map[string]scan.ModuleRow{
		"no module row":             {},
		"module without settings":   {"ssh": mod("ssh", "in_place", `{"missing":[]}`)},
		"setting absent":            {"ssh": mod("ssh", "partly", `{"settings":[{"id":"ssh-other","state":"in_place"}]}`)},
		"unreadable detail":         {"ssh": mod("ssh", "in_place", `not json`)},
		"all settings omitted":      {"ssh": mod("ssh", "in_place", `{"settings":[],"settingsOmitted":"all"}`)},
		"in-place settings omitted": {"ssh": mod("ssh", "in_place", `{"settings":[{"id":"ssh-other","state":"not_in_place"}],"settingsOmitted":"in_place"}`)},
		"unknown setting state":     {"ssh": mod("ssh", "in_place", `{"settings":[{"id":"ssh-x11-forwarding","state":"great"}]}`)},
	}
	for name, mods := range cases {
		for _, r := range scan.Ingest(controls[:1], mods) {
			if r.State != compliance.StateUnknown {
				t.Errorf("%s: %s", name, r.State)
			}
		}
	}
	// Omitted settings are flagged so that a smaller job may fetch them.
	rows := scan.Ingest(controls, map[string]scan.ModuleRow{"ssh": mod("ssh", "in_place", `{"settings":[],"settingsOmitted":"all"}`)})
	if got := scan.TruncatedModules(controls, rows); len(got) != 1 || got[0] != "ssh" {
		t.Errorf("truncated modules %v", got)
	}
	rows = scan.Ingest(controls[:1], map[string]scan.ModuleRow{"ssh": mod("ssh", "in_place", `{"missing":[]}`)})
	if len(scan.TruncatedModules(controls, rows)) != 0 {
		t.Error("a result from before slice C0 is not a truncated one")
	}
}

func TestIngestModuleStates(t *testing.T) {
	controls := []scan.Control{ctrl("x", "windows", "defender", "defender-realtime")}
	for state, want := range map[string]string{"not_applicable": "not_applicable", "not_supported": "not_supported", "failed": "failed", "half_applied": "unknown"} {
		got := scan.Ingest(controls, map[string]scan.ModuleRow{"defender": mod("defender", state, `{"settings":[]}`)})
		if got[0].State != want {
			t.Errorf("module %s: %s, want %s", state, got[0].State, want)
		}
	}
	// Another antivirus holds the module: the owner is named.
	detail := `{"settings":[],"managed":[{"id":"defender","owner":"Other antivirus","policy":"","value":"","state":"managed_elsewhere"}]}`
	got := scan.Ingest(controls, map[string]scan.ModuleRow{"defender": mod("defender", "managed_elsewhere", detail)})
	if got[0].State != "managed_elsewhere" || len(got[0].Owner) == 0 {
		t.Errorf("%+v", got[0])
	}
}

func TestModulesFollowTheScriptsOrder(t *testing.T) {
	controls := []scan.Control{ctrl("1", "windows", "uac", "uac-on"), ctrl("2", "windows", "accounts", "accounts-history"),
		ctrl("3", "linux", "sudo", "sudo-use-pty"), ctrl("4", "linux", "ssh", "ssh-ciphers"), ctrl("5", "windows", "uac", "uac-installer-detection")}
	if got := scan.Modules(controls, "windows"); len(got) != 2 || got[0] != "accounts" || got[1] != "uac" {
		t.Errorf("%v", got)
	}
	if got := scan.Modules(controls, "linux"); len(got) != 2 || got[0] != "ssh" || got[1] != "sudo" {
		t.Errorf("%v", got)
	}
	if !scan.HasPlatform(controls, "linux") || scan.HasPlatform(controls[:2], "linux") {
		t.Error("HasPlatform")
	}
}
