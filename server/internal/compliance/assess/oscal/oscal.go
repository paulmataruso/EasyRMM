// Package oscal writes an assessment as NIST OSCAL JSON: a system security plan and a plan of
// action and milestones (ADR-0078, section 12). The version is pinned; changing it takes an ADR
// amendment. Every file written is validated in tests against NIST's published JSON schema of the
// same version, which is vendored in testdata at a pinned checksum.
package oscal

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess/report"
)

// Version is the OSCAL version written, confirmed against NIST's release page (v1.1.2) on
// 2026-11-26.
const Version = "1.1.2"

// profileHref names the requirement set: NIST publishes an OSCAL catalog for SP 800-171
// Revision 3 only, so Revision 2 is referred to by its publication, and each requirement is named
// by its number under the prefix below.
const profileHref = "https://doi.org/10.6028/NIST.SP.800-171r2"

// ControlPrefix begins the control-id of a requirement ("sp800-171r2_3.1.1"): an OSCAL token
// starts with a letter.
const ControlPrefix = "sp800-171r2_"

// ns derives the stable identifiers an export uses, so that the same assessment gives the same
// uuids each time.
var ns = uuid.MustParse("7d1c8a52-4c3e-5d0b-9a77-3f1e2b6c9d10")

func id(parts ...string) string { return uuid.NewSHA1(ns, []byte(strings.Join(parts, "|"))).String() }

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func metadata(r *report.Report, kind string) map[string]any {
	return map[string]any{
		"title":         r.Title + " (" + kind + ")",
		"last-modified": stamp(r.Generated),
		"version":       "1",
		"oscal-version": Version,
		"remarks":       r.Disclaimer,
	}
}

// implementationState is OSCAL's implementation-status for a requirement's status.
func implementationState(q report.Requirement) string {
	switch q.Status {
	case "met":
		return "implemented"
	case "not_applicable":
		return "not-applicable"
	case "not_met":
		if q.Partial {
			return "partial"
		}
		return "planned"
	}
	return "planned"
}

// SSP writes the system security plan.
func SSP(r *report.Report) ([]byte, error) {
	comp := id(r.AssessmentID, "component")
	impl := []any{}
	for _, q := range r.Requirements {
		item := map[string]any{
			"uuid":       id(r.AssessmentID, "req", q.NistID),
			"control-id": ControlPrefix + q.NistID,
			"props": []any{
				map[string]any{"name": "implementation-status", "value": implementationState(q)},
				map[string]any{"name": "assessment-status", "value": q.Status},
			},
		}
		if q.Statement != "" {
			item["remarks"] = q.Statement
		}
		impl = append(impl, item)
	}
	var body strings.Builder
	for _, s := range r.Scope {
		body.WriteString(s.Name + " (" + s.Kind + "): " + s.Category + "\n")
	}
	boundary := strings.TrimSpace(body.String())
	if boundary == "" {
		boundary = "The scope has not been recorded yet."
	}
	doc := map[string]any{"system-security-plan": map[string]any{
		"uuid":           id(r.AssessmentID, "ssp"),
		"metadata":       metadata(r, "system security plan"),
		"import-profile": map[string]any{"href": profileHref},
		"system-characteristics": map[string]any{
			"system-ids":  []any{map[string]any{"id": r.AssessmentID}},
			"system-name": r.OrgName,
			"description": "The covered systems of " + r.OrgName + ", as scoped in the assessment " + r.Title + ".",
			"system-information": map[string]any{"information-types": []any{map[string]any{
				"title":       "Controlled unclassified information",
				"description": "Information the organization handles under its contracts that needs safeguarding.",
			}}},
			"status":                 map[string]any{"state": "operational"},
			"authorization-boundary": map[string]any{"description": boundary},
		},
		"system-implementation": map[string]any{
			"users": []any{map[string]any{"uuid": id(r.AssessmentID, "user"), "title": "Authorized users of the covered systems"}},
			"components": []any{map[string]any{
				"uuid": comp, "type": "this-system", "title": r.OrgName + " covered systems",
				"description": "The computers and services in the recorded scope.", "status": map[string]any{"state": "operational"},
			}},
		},
		"control-implementation": map[string]any{
			"description":              "How each of the 110 requirements is implemented, as stated by the organization and checked where EasyRMM could.",
			"implemented-requirements": impl,
		},
	}}
	return json.MarshalIndent(doc, "", "  ")
}

// ErrNoItems is an export of a plan of action with no items: OSCAL requires at least one.
var ErrNoItems = errors.New("the plan of action has no items to export")

// POAM writes the plan of action and milestones. A risk stands for each item's weakness.
func POAM(r *report.Report) ([]byte, error) {
	if len(r.POAM) == 0 {
		return nil, ErrNoItems
	}
	risks := []any{}
	items := []any{}
	for _, p := range r.POAM {
		riskID := id(r.AssessmentID, "risk", p.NistID)
		desc := p.Weakness
		if strings.TrimSpace(desc) == "" {
			desc = "Requirement " + p.NistID + " is not met."
		}
		risk := map[string]any{
			"uuid": riskID, "title": "Requirement " + p.NistID + " is not met", "description": desc,
			"statement": "The requirement is worth " + strconv.Itoa(p.Points) + " point(s) on the score.", "status": riskStatus(p.Status),
			"props": []any{map[string]any{"name": "point-value", "value": strconv.Itoa(p.Points)}},
		}
		if p.ClosesBy != "" {
			risk["deadline"] = p.ClosesBy + "T00:00:00Z"
		}
		var mile []any
		for i, m := range p.Milestones {
			mile = append(mile, map[string]any{"uuid": id(r.AssessmentID, "milestone", p.NistID, strconv.Itoa(i)), "title": m.Title, "description": m.Title + " (" + m.Status + ")"})
		}
		if mile != nil {
			risk["remediations"] = []any{map[string]any{
				"uuid": id(r.AssessmentID, "response", p.NistID), "lifecycle": "planned", "title": "Plan", "description": desc, "tasks": tasks(r, p, mile),
			}}
		}
		risks = append(risks, risk)
		props := []any{map[string]any{"name": "may-be-on-a-plan-of-action", "value": boolStr(p.Eligible)}}
		if p.ClosesBy != "" {
			props = append(props, map[string]any{"name": "closes-by", "value": p.ClosesBy})
		}
		items = append(items, map[string]any{
			"uuid": id(r.AssessmentID, "poam-item", p.NistID), "title": "Requirement " + p.NistID, "description": desc,
			"related-risks": []any{map[string]any{"risk-uuid": riskID}},
			"props":         props,
		})
	}
	root := map[string]any{
		"uuid":       id(r.AssessmentID, "poam"),
		"metadata":   metadata(r, "plan of action and milestones"),
		"import-ssp": map[string]any{"href": "ssp.oscal.json"},
		"poam-items": items,
	}
	if len(risks) > 0 {
		root["risks"] = risks
	}
	return json.MarshalIndent(map[string]any{"plan-of-action-and-milestones": root}, "", "  ")
}

func tasks(r *report.Report, p report.POAMItem, _ []any) []any {
	var out []any
	for i, m := range p.Milestones {
		t := map[string]any{"uuid": id(r.AssessmentID, "task", p.NistID, strconv.Itoa(i)), "type": "milestone", "title": m.Title}
		if m.Due != "" {
			t["timing"] = map[string]any{"within-date-range": map[string]any{"start": m.Due + "T00:00:00Z", "end": m.Due + "T00:00:00Z"}}
		}
		out = append(out, t)
	}
	return out
}

func riskStatus(s string) string {
	switch s {
	case "closed":
		return "closed"
	case "in_progress":
		return "investigating"
	case "accepted":
		return "deviation-approved"
	}
	return "open"
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
