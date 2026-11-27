// Package logmeasure holds the log measuring scripts of ADR-0060 (slice 1)
// and reads their output. The scripts are added to the script library by
// hand, from Library (the console's script editor or the API): they read
// what a computer's logs hold for the last days, per source, code and audit
// subcategory, and report events and estimated bytes in all and as the
// collector's default filters would keep them. Nothing here collects logs.
package logmeasure

import (
	_ "embed" // the two scripts
	"encoding/json"
	"fmt"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Schema is the output's schema field.
const Schema = "easyrmm.logmeasure/1"

var (
	//go:embed measure_logs.ps1
	powershellScript string
	//go:embed measure_logs.sh
	shScript string
)

// Entry is one script for the library.
type Entry struct {
	Name           string
	Description    string
	Shell          string
	Body           string
	TimeoutSeconds int
}

// Library is the measuring scripts, one per platform. A big domain
// controller's Security log takes minutes to read, hence the timeout.
func Library() []Entry {
	return []Entry{
		{
			Name:           "Measure logs (Windows)",
			Description:    "ADR-0060 sizing: events and estimated bytes of the last 7 days per source, event ID and audit subcategory, in all and with the default filters. Changes nothing. Arguments: -Days, -MaxEventsPerChannel, -MaxCodes.",
			Shell:          agentproto.ShellPowerShell,
			Body:           powershellScript,
			TimeoutSeconds: 3600,
		},
		{
			Name:           "Measure logs (Linux)",
			Description:    "ADR-0060 sizing: events and estimated bytes of the last 7 days per source, code and subcategory, in all and with the default filters. Changes nothing. Run as root. Argument: days.",
			Shell:          agentproto.ShellSh,
			Body:           shScript,
			TimeoutSeconds: 1800,
		},
	}
}

// Row is the events and bytes of one code or subcategory.
type Row struct {
	Code           string `json:"code"`
	Name           string `json:"name"`
	Events         int64  `json:"events"`
	Bytes          int64  `json:"bytes"`
	FilteredEvents int64  `json:"filteredEvents"`
	FilteredBytes  int64  `json:"filteredBytes"`
}

// Source is what one source holds.
type Source struct {
	Source         string   `json:"source"`
	Present        bool     `json:"present"`
	Channels       []string `json:"channels"`
	Truncated      bool     `json:"truncated"`
	Notes          []string `json:"notes"`
	Events         int64    `json:"events"`
	Bytes          int64    `json:"bytes"`
	FilteredEvents int64    `json:"filteredEvents"`
	FilteredBytes  int64    `json:"filteredBytes"`
	Codes          []Row    `json:"codes"`
	CodesOmitted   int      `json:"codesOmitted"`
	Subcategories  []Row    `json:"subcategories"`
}

// Report is one computer's measurement.
type Report struct {
	Schema      string   `json:"schema"`
	Platform    string   `json:"platform"`
	Hostname    string   `json:"hostname"`
	Days        int      `json:"days"`
	GeneratedAt string   `json:"generatedAt"`
	BytesModel  string   `json:"bytesModel"`
	Sources     []Source `json:"sources"`
}

// sourceNames are ADR-0060's built-in sources, by platform.
var sourceNames = map[string][]string{
	"windows": {"windows.security", "windows.system", "windows.application", "windows.defender",
		"windows.powershell", "windows.sysmon", "windows.rdp", "windows.wmi"},
	"linux": {"linux.auth", "linux.system", "linux.av", "linux.audit", "linux.file"},
}

// Parse reads a script's output and checks it: the schema, every source of
// the platform once and in order, filtered counts within the totals, and,
// where no code was left out, the codes adding up to the source's totals.
func Parse(out []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("logmeasure: not JSON: %w", err)
	}
	if r.Schema != Schema {
		return nil, fmt.Errorf("logmeasure: schema %q, want %q", r.Schema, Schema)
	}
	names, ok := sourceNames[r.Platform]
	if !ok {
		return nil, fmt.Errorf("logmeasure: unknown platform %q", r.Platform)
	}
	if r.Days < 1 {
		return nil, fmt.Errorf("logmeasure: days %d", r.Days)
	}
	if len(r.Sources) != len(names) {
		return nil, fmt.Errorf("logmeasure: %d sources, want %d", len(r.Sources), len(names))
	}
	for i := range r.Sources {
		if err := r.Sources[i].check(names[i]); err != nil {
			return nil, err
		}
	}
	return &r, nil
}

func (s *Source) check(want string) error {
	if s.Source != want {
		return fmt.Errorf("logmeasure: source %q where %q is expected", s.Source, want)
	}
	if s.Events < 0 || s.Bytes < 0 || s.FilteredEvents < 0 || s.FilteredBytes < 0 ||
		s.FilteredEvents > s.Events || s.FilteredBytes > s.Bytes {
		return fmt.Errorf("logmeasure: %s: filtered counts are not within the totals", s.Source)
	}
	if !s.Present && s.Events != 0 {
		return fmt.Errorf("logmeasure: %s: absent but holds %d events", s.Source, s.Events)
	}
	if s.Codes == nil || s.Subcategories == nil || s.Notes == nil || s.Channels == nil {
		return fmt.Errorf("logmeasure: %s: a list is null, not empty", s.Source)
	}
	var sum Row
	for _, c := range s.Codes {
		if c.Code == "" || c.FilteredEvents > c.Events || c.FilteredBytes > c.Bytes {
			return fmt.Errorf("logmeasure: %s: bad code row %q", s.Source, c.Code)
		}
		sum.Events += c.Events
		sum.Bytes += c.Bytes
		sum.FilteredEvents += c.FilteredEvents
		sum.FilteredBytes += c.FilteredBytes
	}
	if s.CodesOmitted == 0 && (sum.Events != s.Events || sum.Bytes != s.Bytes ||
		sum.FilteredEvents != s.FilteredEvents || sum.FilteredBytes != s.FilteredBytes) {
		return fmt.Errorf("logmeasure: %s: codes do not add up to the source", s.Source)
	}
	for _, c := range s.Subcategories {
		if c.Name == "" || c.FilteredEvents > c.Events || c.FilteredBytes > c.Bytes {
			return fmt.Errorf("logmeasure: %s: bad subcategory row %q", s.Source, c.Name)
		}
	}
	return nil
}
