// Package templates holds the skeletons of the documents the assessment workspace starts from
// (ADR-0078, slice C5): a system security plan, a policy and a procedure, in EasyRMM's own words.
// There is no DoD template for a system security plan or a plan of action; the headings follow the
// fields of NIST's OSCAL system security plan model and the topics the requirement's own text
// names. Nothing here is copied from a third-party document, so there is no attribution to keep.
package templates

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed *.json
var files embed.FS

// FS is the embedded templates.
var FS fs.FS = files

// Section is one section of a template. Generate names a section EasyRMM writes from the
// assessment ("scope", "requirements", "poam", "score"); an empty one is for a person to write,
// and Body then holds prompts.
type Section struct {
	ID       string `json:"id"`
	Heading  string `json:"heading"`
	Body     string `json:"body"`
	Generate string `json:"generate"`
}

// Template is a document skeleton.
type Template struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	Title        string    `json:"title"`
	Author       string    `json:"author"`
	LicenceClass string    `json:"licence_class"`
	Sections     []Section `json:"sections"`
}

// All reads every template, ordered by id.
func All() ([]Template, error) {
	ents, err := fs.ReadDir(FS, ".")
	if err != nil {
		return nil, err
	}
	var out []Template
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := fs.ReadFile(FS, e.Name())
		if err != nil {
			return nil, err
		}
		var t Template
		if err := json.Unmarshal(b, &t); err != nil {
			return nil, fmt.Errorf("template %s: %w", e.Name(), err)
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Get finds a template by id.
func Get(id string) (*Template, error) {
	all, err := All()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, fmt.Errorf("no template %q", id)
}
