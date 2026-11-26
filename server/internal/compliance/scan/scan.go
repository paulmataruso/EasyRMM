// Package scan plans compliance scans and ingests their answers
// (ADR-0078, section 4). A scan makes no new kind of job: it asks the
// existing hardening check (Windows, ADR-0054, and Linux, ADR-0051) to read
// the modules its controls name, one job per platform for all devices, and
// then reads what the check stored, setting by setting.
package scan

import (
	"encoding/json"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
)

// Control is what the scan needs of a library control: the setting its
// check reads.
type Control struct {
	ID       string
	Version  int
	Platform string
	Module   string
	Setting  string
}

// Modules are the modules a platform's controls name, in the order the
// scripts list them, so a job asks only for what the scan needs.
func Modules(controls []Control, platform string) []string {
	all := jobs.HardeningModules
	if platform == compliance.PlatformWindows {
		all = jobs.WindowsHardeningModules
	}
	var out []string
	for _, m := range all {
		for _, c := range controls {
			if c.Platform == platform && c.Module == m {
				out = append(out, m)
				break
			}
		}
	}
	return out
}

// ModuleRow is what a hardening check stored for one module of a device.
type ModuleRow struct {
	Module    string
	State     string
	Detail    json.RawMessage
	CheckedAt time.Time
	JobID     *uuid.UUID
}

// Row is one control's result on one device, as the ingester reads it.
type Row struct {
	ControlID      string
	ControlVersion int
	State          string
	Observed       json.RawMessage
	Expected       json.RawMessage
	Owner          json.RawMessage
	CheckedAt      time.Time
	JobID          *uuid.UUID
	// Truncated says the answer was left out because the result was too
	// long, so a smaller job may read it.
	Truncated bool
}

// Ingest maps a device's stored module results to control results.
//
// A setting's state is the check's own. Whatever the check did not say is
// unknown, never in place: a module with no row, a setting absent from a
// result that has settings, a module whose result has no settings (stored
// before ADR-0078 slice C0), and every setting of a result whose settings
// were omitted for length (settingsOmitted "all"), or those left out when
// "in_place". Such rows say Truncated where a smaller job may help.
func Ingest(controls []Control, modules map[string]ModuleRow) []Row {
	rows := make([]Row, 0, len(controls))
	parsed := map[string]*jobs.HardeningFinding{}
	for _, c := range controls {
		r := Row{ControlID: c.ID, ControlVersion: c.Version, State: compliance.StateUnknown}
		m, ok := modules[c.Module]
		if !ok {
			rows = append(rows, r)
			continue
		}
		r.CheckedAt, r.JobID = m.CheckedAt, m.JobID
		f, seen := parsed[c.Module]
		if !seen {
			f = new(jobs.HardeningFinding)
			if json.Unmarshal(m.Detail, f) != nil {
				f = nil
			}
			parsed[c.Module] = f
		}
		if f == nil {
			rows = append(rows, r)
			continue
		}
		switch m.State {
		case compliance.StateNotApplicable, compliance.StateNotSupported, compliance.StateFailed:
			r.State = m.State
			rows = append(rows, r)
			continue
		}
		var s *jobs.HardeningSetting
		for i := range f.Settings {
			if f.Settings[i].ID == c.Setting {
				s = &f.Settings[i]
				break
			}
		}
		if s == nil {
			r.Truncated = f.SettingsOmitted != ""
			if m.State == compliance.StateManagedElsewhere {
				if mg := managedFor(f, c.Module, ""); mg != nil {
					r.State = compliance.StateManagedElsewhere
					r.Owner = ownerJSON(mg)
				}
			}
			rows = append(rows, r)
			continue
		}
		r.Observed = raw(map[string]any{"value": s.Value, "item": s.Item})
		r.Expected = raw(map[string]any{"want": s.Want})
		switch s.State {
		case compliance.StateInPlace:
			r.State = compliance.StateInPlace
		case compliance.StateNotInPlace:
			r.State = compliance.StateNotInPlace
		case compliance.StateNotApplicable:
			r.State = compliance.StateNotApplicable
		case compliance.StateManagedElsewhere:
			r.State = compliance.StateManagedElsewhere
			if mg := managedFor(f, c.Setting, s.Item); mg != nil {
				r.Owner = ownerJSON(mg)
			}
		case "reported":
			// Read and shown, never judged: the check does not say it meets.
			r.State = compliance.StateNotSupported
		default: // check_only, unknown, or a state this server does not know
			r.State = compliance.StateUnknown
		}
		rows = append(rows, r)
	}
	return rows
}

func managedFor(f *jobs.HardeningFinding, id, item string) *jobs.HardeningManaged {
	for i := range f.Managed {
		if f.Managed[i].ID == id && (item == "" || f.Managed[i].Item == item || f.Managed[i].Item == "") {
			return &f.Managed[i]
		}
	}
	return nil
}

func ownerJSON(m *jobs.HardeningManaged) json.RawMessage {
	return raw(map[string]any{"name": m.Owner, "policy": m.Policy, "value": m.Value, "meets": m.State == compliance.StateInPlace})
}

func raw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// TruncatedModules lists the modules whose result lacked a setting because
// the result was too long.
func TruncatedModules(controls []Control, rows []Row) []string {
	byID := map[string]Control{}
	for _, c := range controls {
		byID[c.ID] = c
	}
	set := map[string]bool{}
	for _, r := range rows {
		if r.Truncated {
			set[byID[r.ControlID].Module] = true
		}
	}
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// Platforms of devices a scan reaches.
var Platforms = []string{compliance.PlatformWindows, compliance.PlatformLinux}

// HasPlatform says whether any control is for the platform.
func HasPlatform(controls []Control, platform string) bool {
	return slices.ContainsFunc(controls, func(c Control) bool { return c.Platform == platform })
}
