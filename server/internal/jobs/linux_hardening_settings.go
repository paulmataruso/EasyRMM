package jobs

import (
	"bytes"
	_ "embed" // the Linux settings list
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// linuxSettingsJSON lists every setting the Linux script reports by id,
// the counterpart of windows-settings.json (ADR-0078, slice C0).
//
//go:embed hardening/linux-settings.json
var linuxSettingsJSON []byte

// linuxSetting is a row of linux-settings.json: one setting the script
// reports, in the module that checks it.
type linuxSetting struct {
	ID     string `json:"id"`
	Module string `json:"module"`
	What   string `json:"what"`
}

var linuxSettings = mustLinuxSettings(linuxSettingsJSON)

func mustLinuxSettings(b []byte) []linuxSetting {
	s, err := parseLinuxSettings(b)
	if err != nil {
		panic("jobs: linux-settings.json: " + err.Error())
	}
	return s
}

// linuxSettingStates are the states the Linux script reports a setting in:
// in effect, not in effect (apply would change it, or refuses to), reported
// and left alone (built into the kernel, a Kubernetes node), or not
// applicable (the kernel has no such parameter).
var linuxSettingStates = []string{"in_place", "not_in_place", "reported", "not_applicable"}

// parseLinuxSettings reads the list and checks what the server relies on:
// each ID once, well formed and starting with its module, a known module
// and a description.
func parseLinuxSettings(b []byte) ([]linuxSetting, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var file struct {
		Version  int            `json:"version"`
		Settings []linuxSetting `json:"settings"`
	}
	if err := dec.Decode(&file); err != nil {
		return nil, err
	}
	if file.Version != 1 || len(file.Settings) == 0 {
		return nil, fmt.Errorf("version 1 with settings expected")
	}
	seen := map[string]bool{}
	for _, s := range file.Settings {
		switch {
		case !settingID.MatchString(s.ID) || seen[s.ID]:
			return nil, fmt.Errorf("%q: not an ID, or listed twice", s.ID)
		case !slices.Contains(HardeningModules, s.Module) || !strings.HasPrefix(s.ID, s.Module+"-"):
			return nil, fmt.Errorf("%s: unknown module %q, or the ID does not start with it", s.ID, s.Module)
		case s.What == "" || !shortText(s.What, 120):
			return nil, fmt.Errorf("%s: no description", s.ID)
		}
		seen[s.ID] = true
	}
	return file.Settings, nil
}

// tidyLinux tidies the text of the settings a Linux result read from the
// computer (tidyText).
func (r *hardeningResult) tidyLinux() {
	for i := range r.Modules {
		for j := range r.Modules[i].Settings {
			st := &r.Modules[i].Settings[j]
			st.Value = tidyText(st.Value, maxSettingText)
			st.Want = tidyText(st.Want, maxSettingText)
		}
	}
}

// validLinuxSettings checks a Linux module's settings: ones of that module
// in a known state, within their limits, and nothing else of Windows'.
// Results of a script that predates C0 have none, and are valid.
func (f WindowsFinding) validLinuxSettings(module string) bool {
	if f.Managed != nil || f.Notes != nil || f.Exposure != nil ||
		len(f.Settings) > maxSettings || !slices.Contains([]string{"", "in_place", "all"}, f.SettingsOmitted) {
		return false
	}
	for _, s := range f.Settings {
		known := slices.ContainsFunc(linuxSettings, func(l linuxSetting) bool { return l.ID == s.ID && l.Module == module })
		if !known || !slices.Contains(linuxSettingStates, s.State) || s.Item != "" || s.Note != "" ||
			s.Reasons != nil || s.MDM != nil || !shortText(s.Value, maxSettingText) || !shortText(s.Want, maxSettingText) {
			return false
		}
	}
	return true
}
