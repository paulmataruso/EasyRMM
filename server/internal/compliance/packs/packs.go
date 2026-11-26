// Package packs reads, checks and stores the content packs of the
// compliance engine (ADR-0078, sections 3 to 6 and 10). A pack is data
// only: frameworks, requirements, mappings and profiles. It cannot add a
// control, a detection command or a fix.
package packs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/library"
)

// File is a pack file of the content package.
type File struct {
	Pack            Header           `json:"pack"`
	Framework       *Framework       `json:"framework,omitempty"`
	Requirements    []Requirement    `json:"requirements,omitempty"`
	Objectives      []Objective      `json:"objectives,omitempty"`
	Mappings        []Mapping        `json:"mappings,omitempty"`
	Profiles        []Profile        `json:"profiles,omitempty"`
	MappingDefaults *MappingDefaults `json:"mapping_defaults,omitempty"`
}

// Header is the pack's own record.
type Header struct {
	Key          string           `json:"key"`
	Version      string           `json:"version"`
	Kind         string           `json:"kind"`
	Title        string           `json:"title"`
	LicenceClass compliance.Class `json:"licence_class"`
	SourceID     string           `json:"source_id"`
	ReviewState  string           `json:"review_state"`
	ReviewRef    string           `json:"review_ref,omitempty"`
}

// Text policies of a framework.
const (
	TextFull   = "full"
	TextTitles = "ids_and_own_titles"
	TextIDs    = "ids_only"
)

// Framework is the framework a pack carries.
type Framework struct {
	Key            string `json:"key"`
	Version        string `json:"version"`
	Title          string `json:"title"`
	Publisher      string `json:"publisher"`
	SourceID       string `json:"source_id"`
	TextPolicy     string `json:"text_policy"`
	WeightsSource  string `json:"weights_source,omitempty"`
	WeightsChecked bool   `json:"weights_verified,omitempty"`
}

// Requirement is one requirement of a framework.
type Requirement struct {
	ReqID    string         `json:"req_id"`
	ParentID *string        `json:"parent_id"`
	TitleOwn string         `json:"title_own"`
	TextFull *string        `json:"text_full"`
	Class    string         `json:"class"`
	Weight   *int           `json:"weight"`
	Flags    map[string]any `json:"flags"`
}

// NoCheckYet says the requirement is technical and has no control yet, on
// purpose and in the open.
func (r Requirement) NoCheckYet() bool { b, _ := r.Flags["no_check_yet"].(bool); return b }

// Objective is an assessment objective of a requirement.
type Objective struct {
	ReqID   string   `json:"req_id"`
	ObjID   string   `json:"obj_id"`
	Text    string   `json:"text"`
	Methods []string `json:"methods"`
}

// Mapping maps a requirement (or an objective) to controls. ControlIDs
// stand for one mapping row each.
type Mapping struct {
	ReqID      string                 `json:"req_id"`
	ObjID      *string                `json:"obj_id,omitempty"`
	ControlIDs []string               `json:"control_ids"`
	Relation   string                 `json:"relation"`
	Note       string                 `json:"note"`
	Licence    compliance.Class       `json:"licence_class,omitempty"`
	Prov       *compliance.Provenance `json:"provenance,omitempty"`
}

// MappingDefaults are what a mapping takes where it says nothing.
type MappingDefaults struct {
	LicenceClass compliance.Class      `json:"licence_class"`
	Provenance   compliance.Provenance `json:"provenance"`
}

// Profile is a named list of controls for a platform.
type Profile struct {
	Key          string           `json:"key"`
	Version      string           `json:"version"`
	Title        string           `json:"title"`
	Platform     json.RawMessage  `json:"platform"`
	FrameworkKey *string          `json:"framework_key"`
	Controls     []ProfileControl `json:"controls"`
}

// ProfileControl is a control in a profile, with a stricter value.
type ProfileControl struct {
	ControlID string          `json:"control_id"`
	Params    json.RawMessage `json:"params"`
}

// Parse reads a pack file. Unknown fields are refused, which is how a pack
// that carries a script or a check is refused.
func Parse(b []byte) (File, error) {
	var f File
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return File{}, err
	}
	return f, nil
}

// MappingRow is one expanded mapping.
type MappingRow struct {
	ReqID, ControlID, Relation, Note string
	ObjID                            *string
	Licence                          compliance.Class
	Prov                             compliance.Provenance
}

// Rows expands the mappings, one row per control, with the defaults filled
// in.
func (f File) Rows() []MappingRow {
	var out []MappingRow
	for _, m := range f.Mappings {
		lic, prov := m.Licence, compliance.Provenance{}
		if m.Prov != nil {
			prov = *m.Prov
		}
		if f.MappingDefaults != nil {
			if lic == "" {
				lic = f.MappingDefaults.LicenceClass
			}
			if m.Prov == nil {
				prov = f.MappingDefaults.Provenance
			}
		}
		for _, c := range m.ControlIDs {
			out = append(out, MappingRow{ReqID: m.ReqID, ControlID: c, Relation: m.Relation, Note: m.Note, ObjID: m.ObjID, Licence: lic, Prov: prov})
		}
	}
	return out
}

// Class is the most restrictive class of what the pack holds: its mappings
// and its source.
func (f File) Class(sourceClass compliance.Class) compliance.Class {
	cs := []compliance.Class{sourceClass}
	for _, m := range f.Rows() {
		cs = append(cs, m.Licence)
	}
	return compliance.MostRestrictive(cs...)
}

// Validate checks a pack against the library and the edition. sources maps
// source ids to their licence class. It returns every problem.
func Validate(f File, idx library.Index, sources map[string]compliance.Class, edition string) []error {
	var errs []error
	bad := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("pack %s: %s", f.Pack.Key, fmt.Sprintf(format, a...)))
	}
	h := f.Pack
	if !h.LicenceClass.Valid() {
		bad("unknown licence class %q", h.LicenceClass)
		return errs
	}
	if !compliance.ValidReview(h.ReviewState, h.ReviewRef) {
		bad("review state %q with reference %q is not valid", h.ReviewState, h.ReviewRef)
	}
	if !slices.Contains([]string{"framework", "profile", "xref"}, h.Kind) {
		bad("kind %q: a pack carries a framework, a profile or a cross-reference; controls come from the library", h.Kind)
	}
	srcClass, ok := sources[h.SourceID]
	if !ok {
		bad("source %q is not in sources.json", h.SourceID)
	}
	if got := f.Class(srcClass); got.Rank() > h.LicenceClass.Rank() {
		bad("declares class %s but holds %s", h.LicenceClass, got)
	}
	if !compliance.Allowed(edition, h.LicenceClass, h.ReviewState, h.ReviewRef) {
		bad("class %s with review %s is not allowed in a %s build", h.LicenceClass, h.ReviewState, edition)
	}
	reqs := map[string]Requirement{}
	if fw := f.Framework; fw != nil {
		if !slices.Contains([]string{TextFull, TextTitles, TextIDs}, fw.TextPolicy) {
			bad("unknown text policy %q", fw.TextPolicy)
		}
		if _, ok := sources[fw.SourceID]; !ok {
			bad("framework source %q is not in sources.json", fw.SourceID)
		}
		for _, r := range f.Requirements {
			if _, dup := reqs[r.ReqID]; dup {
				bad("requirement %s listed twice", r.ReqID)
			}
			reqs[r.ReqID] = r
			if r.TitleOwn == "" {
				bad("requirement %s has no title of our own", r.ReqID)
			}
			if r.TextFull != nil && fw.TextPolicy != TextFull {
				bad("requirement %s carries full text, but the framework's text policy is %s", r.ReqID, fw.TextPolicy)
			}
			if !slices.Contains([]string{compliance.ReqTechnical, compliance.ReqPartly, compliance.ReqOrganisational}, r.Class) {
				bad("requirement %s has unknown class %q", r.ReqID, r.Class)
			}
		}
	} else if len(f.Requirements)+len(f.Mappings)+len(f.Objectives) > 0 {
		bad("requirements and mappings without a framework")
	}
	objs := map[string]bool{}
	for _, o := range f.Objectives {
		if _, ok := reqs[o.ReqID]; !ok {
			bad("objective %s names unknown requirement %s", o.ObjID, o.ReqID)
		}
		objs[o.ReqID+"\x00"+o.ObjID] = true
	}
	mapped := map[string]bool{}
	for _, m := range f.Rows() {
		mapped[m.ReqID] = true
		if _, ok := reqs[m.ReqID]; !ok {
			bad("mapping names unknown requirement %s", m.ReqID)
		}
		if m.ObjID != nil && !objs[m.ReqID+"\x00"+*m.ObjID] {
			bad("mapping names unknown objective %s of %s", *m.ObjID, m.ReqID)
		}
		if _, ok := idx[m.ControlID]; !ok {
			bad("mapping %s names unknown control %s", m.ReqID, m.ControlID)
		}
		if !slices.Contains([]string{compliance.RelSatisfies, compliance.RelEvidence, compliance.RelRelated}, m.Relation) {
			bad("mapping %s to %s has unknown relation %q", m.ReqID, m.ControlID, m.Relation)
		}
		if !m.Licence.Valid() || m.Prov.Author == "" || m.Prov.DerivedFromContent {
			bad("mapping %s to %s needs a licence class and a provenance with an author and derived_from_content false", m.ReqID, m.ControlID)
		}
	}
	for _, r := range f.Requirements {
		if r.Class == compliance.ReqTechnical && !mapped[r.ReqID] && !r.NoCheckYet() {
			bad("technical requirement %s has no control and is not marked no_check_yet", r.ReqID)
		}
	}
	for _, p := range f.Profiles {
		for _, c := range p.Controls {
			if _, ok := idx[c.ControlID]; !ok {
				bad("profile %s names unknown control %s", p.Key, c.ControlID)
			}
		}
	}
	return errs
}
