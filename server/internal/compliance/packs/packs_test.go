package packs_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/library"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/packs"
)

func idx(t *testing.T) library.Index {
	t.Helper()
	var files []library.File
	for _, p := range []string{"controls/windows.json", "controls/linux.json"} {
		b, _ := fs.ReadFile(content.FS, p)
		f, err := library.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	i, err := library.Build(files...)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func pack(t *testing.T, name string) packs.File {
	t.Helper()
	b, err := fs.ReadFile(content.FS, "packs/"+name+".json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := packs.Parse(b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

func sources(t *testing.T) map[string]compliance.Class {
	t.Helper()
	srcs, err := content.ReadSources(content.FS)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]compliance.Class{}
	for _, s := range srcs {
		m[s.ID] = s.LicenceClass
	}
	return m
}

func errsHave(errs []error, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), sub) {
			return true
		}
	}
	return false
}

// The loader reads every pack in the content and finds nothing wrong with it.
func TestEveryEmbeddedPackValidates(t *testing.T) {
	m, _ := content.ReadManifest(content.FS)
	i, srcs := idx(t), sources(t)
	n := 0
	for _, e := range m.Files {
		if e.Kind != content.KindPack {
			continue
		}
		n++
		f := pack(t, strings.TrimSuffix(strings.TrimPrefix(e.Path, "packs/"), ".json"))
		if errs := packs.Validate(f, i, srcs, compliance.EditionDev); len(errs) > 0 {
			t.Errorf("%s: %v", e.Path, errs)
		}
		if f.Pack.LicenceClass != e.LicenceClass || f.Pack.ReviewState != e.ReviewState {
			t.Errorf("%s: manifest and file disagree", e.Path)
		}
	}
	if n < 13 {
		t.Errorf("%d packs", n)
	}
}

// No pack in a commercial build holds restricted content: every pack that
// holds a restricted class or an open review is refused by the check and by
// the loader's rule, and what the check accepts holds none.
func TestNoRestrictedContentInACommercialBuild(t *testing.T) {
	i, srcs := idx(t), sources(t)
	m, _ := content.ReadManifest(content.FS)
	commercial := packs.Lint(content.FS, compliance.EditionCommercial)
	for _, e := range m.Files {
		if e.Kind != content.KindPack {
			continue
		}
		f := pack(t, strings.TrimSuffix(strings.TrimPrefix(e.Path, "packs/"), ".json"))
		refused := errsHave(commercial, e.Path) || errsHave(commercial, "pack "+f.Pack.Key+":")
		holds := f.Class(srcs[f.Pack.SourceID])
		restricted := !holds.AllowedInCommercial() || f.Pack.ReviewState == compliance.ReviewNeeded
		if restricted && !refused {
			t.Errorf("%s holds %s with review %s and a commercial build accepts it", e.Path, holds, f.Pack.ReviewState)
		}
		if !restricted && refused {
			t.Errorf("%s is refused in a commercial build without a reason: %v", e.Path, commercial)
		}
		for _, row := range f.Rows() {
			if !row.Licence.AllowedInCommercial() && !refused {
				t.Errorf("%s: mapping %s class %s", e.Path, row.ReqID, row.Licence)
			}
		}
		if errs := packs.Validate(f, i, srcs, compliance.EditionCommercial); (len(errs) > 0) != restricted {
			t.Errorf("%s: Validate in commercial gave %v, restricted = %v", e.Path, errs, restricted)
		}
	}
	// What a release would carry: everything the check accepts. The two packs waiting for review are the only ones out.
	if !errsHave(commercial, "packs/cis-xref.json") || !errsHave(commercial, "packs/gdpr-indicative.json") {
		t.Errorf("%v", commercial)
	}
	for _, c := range []compliance.Class{compliance.ClassNoncommercial, compliance.ClassCommercialRequired, compliance.ClassRestricted} {
		// A deliberately restricted fixture pack is refused whatever else it holds.
		f := pack(t, "nist-csf-2")
		f.Pack.LicenceClass = c
		if errs := packs.Validate(f, i, srcs, compliance.EditionCommercial); !errsHave(errs, "not allowed in a commercial build") {
			t.Errorf("%s: %v", c, errs)
		}
		if errs := packs.Validate(f, i, srcs, compliance.EditionDev); errsHave(errs, "not allowed") {
			t.Errorf("%s in dev: %v", c, errs)
		}
	}
	// A mapping that is restricted lifts the pack's class above what it declares.
	f := pack(t, "nist-csf-2")
	f.MappingDefaults.LicenceClass = compliance.ClassRestricted
	if errs := packs.Validate(f, i, srcs, compliance.EditionDev); !errsHave(errs, "declares class PUBLIC_DOMAIN but holds RESTRICTED") {
		t.Errorf("%v", errs)
	}
}

func TestValidateRefusals(t *testing.T) {
	i, srcs := idx(t), sources(t)
	cases := map[string]struct {
		mutate func(f *packs.File)
		want   string
	}{
		"unknown control in a mapping": {func(f *packs.File) { f.Mappings[0].ControlIDs = []string{"win.nope.nothing"} }, "unknown control win.nope.nothing"},
		"unknown requirement":          {func(f *packs.File) { f.Mappings[0].ReqID = "9.9.9" }, "unknown requirement 9.9.9"},
		"unknown relation":             {func(f *packs.File) { f.Mappings[0].Relation = "proves" }, "unknown relation"},
		"technical without a control": {func(f *packs.File) {
			f.Requirements[0].Class = "technical"
			f.Requirements[0].Flags = map[string]any{}
			f.Mappings = nil
		}, "technical requirement"},
		"full text under ids_only":        {func(f *packs.File) { f.Framework.TextPolicy = packs.TextIDs }, "carries full text"},
		"a pack that adds a control kind": {func(f *packs.File) { f.Pack.Kind = "library" }, "controls come from the library"},
		"source unknown":                  {func(f *packs.File) { f.Pack.SourceID = "nowhere" }, "not in sources.json"},
		"class unknown":                   {func(f *packs.File) { f.Pack.LicenceClass = "MIT" }, "unknown licence class"},
		"cleared without a reference":     {func(f *packs.File) { f.Pack.ReviewState = compliance.ReviewCleared }, "review state"},
		"mapping derived from content":    {func(f *packs.File) { f.MappingDefaults.Provenance.DerivedFromContent = true }, "derived_from_content false"},
		"profile with an unknown control": {func(f *packs.File) {
			f.Profiles = []packs.Profile{{Key: "p", Controls: []packs.ProfileControl{{ControlID: "x.y.z"}}}}
		}, "profile p names unknown control"},
		"requirement without a title": {func(f *packs.File) { f.Requirements[0].TitleOwn = "" }, "no title of our own"},
		"requirement twice":           {func(f *packs.File) { f.Requirements = append(f.Requirements, f.Requirements[0]) }, "listed twice"},
		"unknown objective":           {func(f *packs.File) { o := "3.1.1[z]"; f.Mappings[0].ObjID = &o }, "unknown objective"},
	}
	for name, c := range cases {
		f := pack(t, "nist-800-171r2")
		c.mutate(&f)
		if errs := packs.Validate(f, i, srcs, compliance.EditionDev); !errsHave(errs, c.want) {
			t.Errorf("%s: want %q, got %v", name, c.want, errs)
		}
	}
	if errs := packs.Validate(pack(t, "nist-800-171r2"), i, srcs, compliance.EditionDev); len(errs) != 0 {
		t.Errorf("the unchanged pack: %v", errs)
	}
}

// A pack is data. One that carries a script, a detection command or a check of its own does not parse.
func TestPackCannotCarryExecutableContent(t *testing.T) {
	for _, field := range []string{"script", "detect", "command", "controls", "executor", "apply"} {
		b := `{"pack":{"key":"x","version":"1","kind":"framework","title":"t","licence_class":"ORIGINAL","source_id":"s","review_state":"none"},"` + field + `":"rm -rf /"}`
		if _, err := packs.Parse([]byte(b)); err == nil {
			t.Errorf("a pack with %q parsed", field)
		}
	}
	b := `{"pack":{"key":"x","version":"1","kind":"framework","title":"t","licence_class":"ORIGINAL","source_id":"s","review_state":"none"},"mappings":[{"req_id":"1","control_ids":["a"],"relation":"related","script":"x"}]}`
	if _, err := packs.Parse([]byte(b)); err == nil {
		t.Error("a mapping with a script parsed")
	}
}

// The NIST 800-171 catalog is ours, from NIST's public requirements.
func TestNIST800171Catalogue(t *testing.T) {
	f := pack(t, "nist-800-171r2")
	if len(f.Requirements) != 110 {
		t.Fatalf("%d requirements, want 110", len(f.Requirements))
	}
	fam := map[string]int{}
	var technical, organisational, sum int
	for _, r := range f.Requirements {
		if r.TextFull == nil || *r.TextFull == "" || r.TitleOwn == "" || r.Weight == nil {
			t.Errorf("%s: incomplete", r.ReqID)
			continue
		}
		fam[r.Flags["family"].(string)]++
		sum += *r.Weight
		switch r.Class {
		case compliance.ReqTechnical:
			technical++
		case compliance.ReqOrganisational:
			organisational++
		}
	}
	want := map[string]int{"AC": 22, "AT": 3, "AU": 9, "CM": 9, "IA": 11, "IR": 3, "MA": 6, "MP": 9, "PS": 2, "PE": 6, "RA": 3, "CA": 4, "SC": 16, "SI": 7}
	for k, n := range want {
		if fam[k] != n {
			t.Errorf("family %s has %d, want %d", k, fam[k], n)
		}
	}
	if technical == 0 || organisational == 0 {
		t.Errorf("classes: %d technical, %d organisational", technical, organisational)
	}
	// The weights are checked against a fixture of the DoD methodology's published table (our own
	// transcription of the numbers, verified against Version 1.2.1, Annex A).
	if !f.Framework.WeightsChecked {
		t.Error("the weights are verified against the DoD methodology, and the pack must say so")
	}
	if sum != 313 {
		t.Errorf("weights total %d, want 313", sum)
	}
	fx := sprsFixture(t)
	for _, r := range f.Requirements {
		if want := fx.Weights[r.ReqID]; *r.Weight != want {
			t.Errorf("%s: weight %d, the methodology says %d", r.ReqID, *r.Weight, want)
		}
		if p, ok := fx.Partial[r.ReqID]; ok && r.Flags["partial_points"] != float64(p) {
			t.Errorf("%s: partial credit %v, want %d", r.ReqID, r.Flags["partial_points"], p)
		}
	}
	if fx.Total != 313 {
		t.Errorf("fixture total %d", fx.Total)
	}
	var fixtureSum int
	for _, w := range fx.Weights {
		fixtureSum += w
	}
	if fixtureSum != 313 || len(fx.Weights) != 110 {
		t.Errorf("fixture: %d requirements totalling %d", len(fx.Weights), fixtureSum)
	}
	t.Logf("weights total %d (verified: %v)", sum, f.Framework.WeightsChecked)
}

func TestCMMCPacks(t *testing.T) {
	l1, l2 := pack(t, "cmmc-l1"), pack(t, "cmmc-l2")
	if len(l1.Requirements) != 17 || len(l2.Requirements) != 110 {
		t.Errorf("%d level 1 practices, %d level 2", len(l1.Requirements), len(l2.Requirements))
	}
	for _, r := range l1.Requirements {
		if !strings.Contains(r.ReqID, ".L1-") {
			t.Errorf("%s", r.ReqID)
		}
	}
	level1 := 0
	for _, r := range l2.Requirements {
		if strings.Contains(r.ReqID, ".L1-") {
			level1++
		}
	}
	if level1 != 17 {
		t.Errorf("%d level 1 practices inside level 2", level1)
	}
}

// A requirement mapped only as related is never checked; the data keeps the claim narrow.
func TestSatisfiesMappingsAreFew(t *testing.T) {
	f := pack(t, "nist-800-171r2")
	sat := map[string]bool{}
	for _, m := range f.Mappings {
		if m.Relation == compliance.RelSatisfies {
			sat[m.ReqID] = true
		}
	}
	for _, r := range f.Requirements {
		if sat[r.ReqID] && r.Class == compliance.ReqOrganisational {
			t.Errorf("%s is organisational but a control satisfies it", r.ReqID)
		}
	}
	for _, name := range []string{"stig-windows-11", "stig-windows-server-2025", "nist-800-53r5", "nist-csf-2", "hipaa-security", "gdpr-indicative", "soc2-tsc-indicative", "cis-xref"} {
		for _, m := range pack(t, name).Mappings {
			if m.Relation != compliance.RelRelated {
				t.Errorf("%s maps %s as %s; generated and indicative mappings are related only", name, m.ReqID, m.Relation)
			}
		}
	}
}

func TestIndicativeAndCISWording(t *testing.T) {
	for _, name := range []string{"gdpr-indicative", "soc2-tsc-indicative"} {
		f := pack(t, name)
		if !strings.Contains(f.Framework.Title, "indicative mapping by EasyRMM, not an audit criterion") {
			t.Errorf("%s title: %q", name, f.Framework.Title)
		}
	}
	cis := pack(t, "cis-xref")
	if cis.Pack.ReviewState != compliance.ReviewNeeded || cis.Framework.TextPolicy != packs.TextIDs {
		t.Errorf("cis-xref: review %s, policy %s", cis.Pack.ReviewState, cis.Framework.TextPolicy)
	}
	b, _ := json.Marshal(cis)
	for _, banned := range []string{"CIS Level", "CIS compliant", "CIS certified"} {
		if strings.Contains(string(b), banned) {
			t.Errorf("cis-xref says %q", banned)
		}
	}
	for _, r := range cis.Requirements {
		if r.TextFull != nil || r.Flags["xref"] == nil {
			t.Errorf("%s: a CIS entry is a number and our title only", r.ReqID)
		}
	}
}

// Lint over a fixture with a restricted pack, as the build runs it.
func TestLintCatchesARestrictedPackInACommercialBuild(t *testing.T) {
	m := fstest.MapFS{}
	_ = fs.WalkDir(content.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := fs.ReadFile(content.FS, p)
			m[p] = &fstest.MapFile{Data: b}
		}
		return nil
	})
	body := `{"pack":{"key":"fixture-restricted","version":"1","kind":"framework","title":"A fixture","licence_class":"RESTRICTED","source_id":"nist-csf-2","review_state":"none"},` +
		`"framework":{"key":"fixture-restricted","version":"1","title":"t","publisher":"p","source_id":"nist-csf-2","text_policy":"ids_only"},"requirements":[]}`
	m["packs/fixture-restricted.json"] = &fstest.MapFile{Data: []byte(body)}
	mf, notice, err := content.Update(m)
	if err != nil {
		t.Fatal(err)
	}
	m["manifest.json"].Data, m["NOTICE.generated"].Data = mf, notice
	if errs := packs.Lint(m, compliance.EditionDev); len(errs) != 0 {
		t.Errorf("dev: %v", errs)
	}
	errs := packs.Lint(m, compliance.EditionCommercial)
	if !errsHave(errs, "packs/fixture-restricted.json: licence class RESTRICTED is not allowed in a commercial build") {
		t.Errorf("%v", errs)
	}
}

type sprsFx struct {
	Total   int            `json:"total"`
	Weights map[string]int `json:"weights"`
	Partial map[string]int `json:"partial"`
}

func sprsFixture(t *testing.T) sprsFx {
	t.Helper()
	b, err := os.ReadFile("testdata/dod-sprs-weights-v1.2.1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx sprsFx
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	return fx
}

// The Level 2 pack carries the same weights under CMMC's practice ids, and the six practices a
// plan of action may never hold are data.
func TestCMMCL2WeightsAndBarred(t *testing.T) {
	fx := sprsFixture(t)
	l2 := pack(t, "cmmc-l2")
	barred := map[string]bool{}
	var sum int
	for _, r := range l2.Requirements {
		n, _ := r.Flags["nist"].(string)
		if *r.Weight != fx.Weights[n] {
			t.Errorf("%s: weight %d, want %d", r.ReqID, *r.Weight, fx.Weights[n])
		}
		sum += *r.Weight
		if r.Flags["poam_barred"] == true {
			barred[n] = true
		}
	}
	if sum != 313 {
		t.Errorf("level 2 weights total %d", sum)
	}
	for _, id := range []string{"3.1.20", "3.1.22", "3.12.4", "3.10.3", "3.10.4", "3.10.5"} {
		if !barred[id] {
			t.Errorf("%s is not marked barred from a plan of action", id)
		}
	}
	if len(barred) != 6 {
		t.Errorf("%d barred, want 6", len(barred))
	}
}
