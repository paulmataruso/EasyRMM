package oscal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess/report"
)

// NIST's published schemas, vendored unchanged and pinned (testdata/README.md).
var pinned = map[string]string{
	"testdata/oscal_ssp_schema.json":  "08d3faeb12f0fab7705dec15fb648c72400c7ab6ac0056222d49d21507e02a69",
	"testdata/oscal_poam_schema.json": "906725163d767036c6189aec51252109b203214e121fc1acaff494b4d2dfbc04",
}

func validate(t *testing.T, schemaFile string, doc []byte) {
	t.Helper()
	raw, err := os.ReadFile(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	if h := sha256.Sum256(raw); hex.EncodeToString(h[:]) != pinned[schemaFile] {
		t.Fatalf("%s is not the pinned NIST schema (sha256 %x)", schemaFile, h)
	}
	sch, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	anchors(sch)
	sch.(map[string]any)["$schema"] = "https://json-schema.org/draft/2019-09/schema"
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2019)
	id := sch.(map[string]any)["$id"].(string)
	if err := c.AddResource(id, sch); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(id)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(inst); err != nil {
		t.Errorf("not valid OSCAL %s: %v", Version, err)
	}
}

// anchors turns the schema's draft-07 plain-name identifiers ("$id": "#name") into 2019-09 anchors,
// which the validator understands. It changes nothing else, and the vendored file stays as NIST wrote it.
func anchors(v any) {
	switch x := v.(type) {
	case map[string]any:
		if id, ok := x["$id"].(string); ok && strings.HasPrefix(id, "#") {
			delete(x, "$id")
			x["$anchor"] = strings.TrimPrefix(id, "#")
		}
		for _, c := range x {
			anchors(c)
		}
	case []any:
		for _, c := range x {
			anchors(c)
		}
	}
}

func sample() *report.Report {
	n := 110
	_ = n
	return &report.Report{
		AssessmentID: "5b0f5c46-3c1d-4d34-8d0f-0d3bb3a8c0aa", OrgName: "Example Co", Title: "Spring 2027 assessment", State: "draft",
		Generated: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC), Disclaimer: "Assessment aid.",
		Scope: []report.ScopeItem{{Name: "HQ-WIN", Kind: "computer", Category: "cui"}},
		Requirements: []report.Requirement{
			{ID: "AC.L2-3.1.1", NistID: "3.1.1", Status: "met", Statement: "Accounts are limited to named people."},
			{ID: "IA.L2-3.5.3", NistID: "3.5.3", Status: "not_met", Partial: true},
			{ID: "AC.L2-3.1.2", NistID: "3.1.2", Status: "not_assessed"},
			{ID: "AC.L2-3.1.12", NistID: "3.1.12", Status: "not_applicable"},
		},
		POAM: []report.POAMItem{
			{ID: "x", ReqID: "IA.L2-3.5.3", NistID: "3.5.3", Points: 3, Status: "open", ClosesBy: "2027-05-25",
				Milestones: []report.Milestone{{Title: "Enrol the general users", Due: "2027-03-01", Status: "open"}}},
			{ID: "y", ReqID: "AC.L2-3.1.7", NistID: "3.1.7", Points: 1, Status: "draft", Eligible: true},
		},
	}
}

func TestSSPValidatesAgainstNIST(t *testing.T) {
	b, err := SSP(sample())
	if err != nil {
		t.Fatal(err)
	}
	validate(t, "testdata/oscal_ssp_schema.json", b)
	var m map[string]map[string]any
	_ = json.Unmarshal(b, &m)
	if m["system-security-plan"]["metadata"].(map[string]any)["oscal-version"] != "1.1.2" {
		t.Error("the version is not the pinned one")
	}
	if strings.Contains(strings.ToLower(string(b)), "compliant") || strings.Contains(strings.ToLower(string(b)), "certified") {
		t.Error("forbidden wording in the export")
	}
}

func TestSSPWithNothingValidates(t *testing.T) {
	r := sample()
	r.Scope, r.POAM = nil, nil
	b, err := SSP(r)
	if err != nil {
		t.Fatal(err)
	}
	validate(t, "testdata/oscal_ssp_schema.json", b)
}

func TestPOAMValidatesAgainstNIST(t *testing.T) {
	b, err := POAM(sample())
	if err != nil {
		t.Fatal(err)
	}
	validate(t, "testdata/oscal_poam_schema.json", b)
	r := sample()
	r.POAM = nil
	if _, err := POAM(r); !errors.Is(err, ErrNoItems) {
		t.Errorf("an empty plan of action: %v", err)
	}
}

func TestSameAssessmentSameIdentifiers(t *testing.T) {
	a, _ := SSP(sample())
	b, _ := SSP(sample())
	if !bytes.Equal(a, b) {
		t.Error("an export of the same assessment changed")
	}
}
