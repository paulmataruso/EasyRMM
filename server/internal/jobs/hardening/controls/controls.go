// Package controls holds the related-controls tables of the Windows
// hardening modules (ADR-0054): for each module, the NIST SP 800-53 Rev. 5
// controls, the NIST SP 800-171 Rev. 2 and Rev. 3 requirements and the
// ISO/IEC 27001:2022 Annex A controls that DISA's and NIST's published
// mappings relate the module's STIG rules to.
//
// The tables are generated from cites.json (the rules each module meets,
// differs from on purpose, leaves unset or reports) and the data extracted
// from DISA's and NIST's files under data/ (see data/SOURCES.md), and are
// embedded as related.json. They say which controls a module's settings
// relate to; they are not an assessment and say nothing about compliance.
package controls

import (
	_ "embed" // the generated tables
	"encoding/json"
	"fmt"
	"slices"
)

//go:embed related.json
var relatedJSON []byte

// Control is a NIST SP 800-53 Rev. 5 base control and its title from NIST's
// catalog.
type Control struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Related is what a module's settings relate to, each list sorted.
type Related struct {
	// SP80053R5 are NIST SP 800-53 Rev. 5 base controls, such as AC-7.
	SP80053R5 []Control `json:"sp80053R5"`
	// SP800171R2 are NIST SP 800-171 Rev. 2 requirements, such as 3.1.8.
	SP800171R2 []string `json:"sp800171R2"`
	// SP800171R3 are NIST SP 800-171 Rev. 3 requirements, such as 03.01.08.
	SP800171R3 []string `json:"sp800171R3"`
	// ISO27001 are ISO/IEC 27001:2022 Annex A control numbers, such as
	// A.8.5, from NIST's crosswalk; numbers only.
	ISO27001 []string `json:"iso27001"`
}

// Source is one of the files the tables were built from.
type Source struct {
	// Name says what the source is, such as "DISA STIG: Microsoft Windows
	// 11".
	Name string `json:"name"`
	// Version is the source's own version or release, such as "V2R11".
	Version string `json:"version"`
	// Date is the source's date (YYYY-MM-DD, or YYYY-MM).
	Date string `json:"date"`
	// URL is where the file was downloaded from.
	URL string `json:"url"`
	// Note is the publisher's own caveat about the mapping, where it has one.
	Note string `json:"note,omitempty"`
}

// moduleRelated is one module's entry in related.json.
type moduleRelated struct {
	Module string `json:"module"`
	Related
}

// table is related.json.
type table struct {
	Sources []Source        `json:"sources"`
	Modules []moduleRelated `json:"modules"`
}

var tables = mustParse(relatedJSON)

func mustParse(b []byte) table {
	t, err := parseTable(b)
	if err != nil {
		panic(err)
	}
	return t
}

func parseTable(b []byte) (table, error) {
	var t table
	if err := json.Unmarshal(b, &t); err != nil {
		return table{}, fmt.Errorf("related.json: %w", err)
	}
	if len(t.Modules) == 0 {
		return table{}, fmt.Errorf("related.json: no modules")
	}
	return t, nil
}

// For returns what a Windows hardening module's settings relate to, and
// false for a module the tables do not know.
func For(module string) (Related, bool) {
	for _, m := range tables.Modules {
		if m.Module == module {
			return Related{
				SP80053R5:  slices.Clone(m.SP80053R5),
				SP800171R2: slices.Clone(m.SP800171R2),
				SP800171R3: slices.Clone(m.SP800171R3),
				ISO27001:   slices.Clone(m.ISO27001),
			}, true
		}
	}
	return Related{}, false
}

// Sources returns the files the tables were built from, with their versions,
// for the console's Related controls panel.
func Sources() []Source {
	return slices.Clone(tables.Sources)
}
