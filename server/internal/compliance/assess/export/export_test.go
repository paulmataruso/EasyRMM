package export

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess/report"
)

func sample() *report.Report {
	n := 101
	return &report.Report{
		AssessmentID: "5b0f5c46-3c1d-4d34-8d0f-0d3bb3a8c0aa", OrgName: "Example Co", Title: "Spring 2027 (draft)", State: "draft", Framework: "cmmc-l2", Version: "2.0",
		Generated: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC), Disclaimer: "Assessment aid.",
		Scope: []report.ScopeItem{{Name: "HQ-WIN", Kind: "computer", Category: "cui"}},
		Requirements: []report.Requirement{
			{ID: "AC.L2-3.1.1", NistID: "3.1.1", Title: "Authorized access only", Family: "AC", Status: "met", Weight: 5, Statement: "=HYPERLINK(\"http://x\")", Evidence: []report.EvidenceRef{{ID: "e1", SHA256: "ab"}}},
			{ID: "AC.L2-3.1.3", NistID: "3.1.3", Title: "Control the flow, (and) \\ more", Family: "AC", Status: "not_met", Weight: 1},
		},
		POAM:  []report.POAMItem{{ID: "p1", ReqID: "AC.L2-3.1.3", NistID: "3.1.3", Points: 1, Eligible: true, Status: "open", OpenedOn: "2026-11-26", ClosesBy: "2027-05-25", Milestones: []report.Milestone{{Title: "Roll out", Due: "2027-03-01", Status: "open"}}}},
		SSP:   []report.Section{{Heading: "Scope", Body: "Line one.\nLine two with a long tail " + strings.Repeat("word ", 40)}},
		Score: report.Score{Low: 101, High: 101, Number: &n, GateMin: 88, GateOutcome: "within"},
	}
}

func TestCSVGuardsFormulas(t *testing.T) {
	b, err := Requirements(sample())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), ",=HYPERLINK") || !strings.Contains(string(b), "'=HYPERLINK") {
		t.Errorf("a formula was not defused:\n%s", b)
	}
	p, err := POAM(sample())
	if err != nil || !strings.Contains(string(p), "Roll out (2027-03-01, open)") {
		t.Errorf("poam csv: %v\n%s", err, p)
	}
}

func TestPDFIsWellFormed(t *testing.T) {
	b := PDF(sample())
	if !bytes.HasPrefix(b, []byte("%PDF-1.4")) || !bytes.HasSuffix(b, []byte("%%EOF\n")) {
		t.Fatal("not a PDF")
	}
	if !bytes.Contains(b, []byte("Score: 101")) || !bytes.Contains(b, []byte(`\(and\) \\ more`)) {
		t.Error("the content or its escaping is wrong")
	}
	if p, err := exec.LookPath("pdftotext"); err == nil {
		f := t.TempDir() + "/r.pdf"
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(p, f, "-").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Spring 2027") || !strings.Contains(string(out), "Line two with a long tail") {
			t.Errorf("pdftotext could not read it: %v\n%s", err, out)
		}
	}
	// A long report runs to more pages without breaking the file.
	r := sample()
	for i := 0; i < 400; i++ {
		r.SSP = append(r.SSP, report.Section{Heading: "H", Body: "text"})
	}
	if big := PDF(r); !bytes.Contains(big, []byte("/Count ")) || bytes.Contains(big, []byte("/Count 1 ")) {
		t.Error("a long report fits on one page")
	}
}

func TestBundleListsEachFileWithItsHash(t *testing.T) {
	b, err := Bundle(sample())
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		files[f.Name], _ = io.ReadAll(rc)
		rc.Close()
	}
	var man struct {
		Files []ManifestEntry `json:"files"`
	}
	if err := json.Unmarshal(files["MANIFEST.json"], &man); err != nil || len(man.Files) != 6 {
		t.Fatalf("manifest: %v %+v", err, man)
	}
	for _, e := range man.Files {
		h := sha256.Sum256(files[e.Name])
		if e.SHA256 != hex.EncodeToString(h[:]) || e.Size != len(files[e.Name]) {
			t.Errorf("%s: the manifest does not match the file", e.Name)
		}
	}
	// Without plan-of-action items the OSCAL plan file is left out, not faked.
	r := sample()
	r.POAM = nil
	b, err = Bundle(r)
	if err != nil {
		t.Fatal(err)
	}
	zr, _ = zip.NewReader(bytes.NewReader(b), int64(len(b)))
	for _, f := range zr.File {
		if f.Name == "poam.oscal.json" {
			t.Error("an empty plan of action was exported as OSCAL")
		}
	}
	b2, _ := Bundle(sample())
	b3, _ := Bundle(sample())
	if !bytes.Equal(b2, b3) {
		t.Error("the same assessment gave a different bundle")
	}
}
