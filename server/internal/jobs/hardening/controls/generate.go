package controls

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// The files Generate reads, relative to the package directory.
const (
	CitesFile     = "cites.json"
	RelatedFile   = "related.json"
	cciFile       = "data/cci.csv"
	titlesFile    = "data/sp800-53r5-controls.csv"
	appendixDFile = "data/sp800-171r2-appendix-d.csv"
	rev3File      = "data/sp800-171r3-source-controls.csv"
	isoFile       = "data/iso27001-2022-from-sp800-53r5.csv"
	sourcesFile   = "data/sources.csv"
)

// STIGFile is the data file holding a STIG release's rules, such as
// data/stig-win11-v2r11.csv for the release key win11-v2r11.
func STIGFile(release string) string { return "data/stig-" + release + ".csv" }

// The data files' header lines.
var (
	stigHeader      = []string{"version", "rule", "ccis"}
	cciHeader       = []string{"cci", "sp80053r5", "sp80053r4"}
	titlesHeader    = []string{"control", "title"}
	appendixDHeader = []string{"requirements", "controls"}
	rev3Header      = []string{"requirement", "controls"}
	isoHeader       = []string{"control", "annexA"}
	sourcesHeader   = []string{"key", "kind", "name", "version", "date", "url", "sha256", "note"}
)

// Cites is cites.json: the STIG rules each Windows module cites, as in
// ADR-0054's What each module cites.
type Cites struct {
	// Releases maps a rule-ID prefix (WN11, WNDF-AV) to the release key of
	// the STIG release the IDs come from (win11-v2r11).
	Releases map[string]string `json:"releases"`
	Modules  []CitedModule     `json:"modules"`
}

// CitedModule is one module's rules. A module that changes settings has
// Meets, Differs and NotSet; a report-only module has only Reports.
type CitedModule struct {
	Module  string   `json:"module"`
	Meets   []string `json:"meets,omitempty"`
	Differs []string `json:"differs,omitempty"`
	NotSet  []string `json:"notSet,omitempty"`
	Reports []string `json:"reports,omitempty"`
}

// Counted returns the rules whose CCIs count towards the module's related
// controls: those it meets or differs from on purpose, or for a report-only
// module those it reports. Rules it leaves unset never count.
func (m CitedModule) Counted() []string {
	if len(m.Reports) > 0 {
		return slices.Clone(m.Reports)
	}
	return slices.Concat(m.Meets, m.Differs)
}

// All returns every rule the module names, in any list.
func (m CitedModule) All() []string {
	return slices.Concat(m.Meets, m.Differs, m.NotSet, m.Reports)
}

// ReleaseOf returns the release key a rule ID belongs to by its prefix,
// the longest prefix that matches.
func (c Cites) ReleaseOf(id string) (string, bool) {
	best := ""
	for prefix := range c.Releases {
		if strings.HasPrefix(id, prefix+"-") && len(prefix) > len(best) {
			best = prefix
		}
	}
	if best == "" {
		return "", false
	}
	return c.Releases[best], true
}

// ParseCites reads and checks cites.json.
func ParseCites(b []byte) (Cites, error) {
	var c Cites
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Cites{}, fmt.Errorf("%s: %w", CitesFile, err)
	}
	if len(c.Releases) == 0 || len(c.Modules) == 0 {
		return Cites{}, fmt.Errorf("%s: no releases or no modules", CitesFile)
	}
	seen := map[string]bool{}
	for _, m := range c.Modules {
		if m.Module == "" || seen[m.Module] {
			return Cites{}, fmt.Errorf("%s: module %q is empty or named twice", CitesFile, m.Module)
		}
		seen[m.Module] = true
		if len(m.Reports) > 0 && len(m.Meets)+len(m.Differs)+len(m.NotSet) > 0 {
			return Cites{}, fmt.Errorf("%s: %s both reports and sets rules", CitesFile, m.Module)
		}
		for _, list := range [][]string{m.Meets, m.Differs, m.NotSet, m.Reports} {
			if len(dedupe(list)) != len(list) {
				return Cites{}, fmt.Errorf("%s: %s names a rule twice in one list", CitesFile, m.Module)
			}
			for _, id := range list {
				if _, ok := c.ReleaseOf(id); !ok {
					return Cites{}, fmt.Errorf("%s: %s: no release for %s", CitesFile, m.Module, id)
				}
			}
		}
	}
	return c, nil
}

// stigRule is a STIG rule from a data/stig-*.csv file.
type stigRule struct {
	version string   // WN11-SO-000010
	id      string   // DISA's rule ID, SV-253256r991589_rule
	ccis    []string // CCI-000366
}

// loadSTIG reads a STIG release's rules, keyed by version ID.
func loadSTIG(fsys fs.FS, release string) (map[string]stigRule, error) {
	rows, err := readCSV(fsys, STIGFile(release), stigHeader)
	if err != nil {
		return nil, err
	}
	out := make(map[string]stigRule, len(rows))
	for _, r := range rows {
		if _, dup := out[r[0]]; dup || r[0] == "" || r[1] == "" {
			return nil, fmt.Errorf("%s: rule %q %q is unnamed or listed twice", STIGFile(release), r[0], r[1])
		}
		out[r[0]] = stigRule{version: r[0], id: r[1], ccis: splitList(r[2])}
	}
	return out, nil
}

type cciRefs struct{ rev5, rev4 []string }

type appendixDRow struct{ requirements, controls []string }

// inputs is everything Generate reads.
type inputs struct {
	cites     Cites
	rules     map[string]map[string]stigRule // release key → version → rule
	ccis      map[string]cciRefs
	titles    map[string]string   // base control → title
	appendixD []appendixDRow      // Rev. 2 rows, controls normalized
	rev3      map[string][]string // Rev. 3 requirement → source controls, normalized
	iso       map[string][]string // control → Annex A numbers
	sources   []Source
}

// Generate builds related.json from cites.json and the files under data/ in
// fsys (the package directory) by ADR-0054's rules. The same files give the
// same bytes.
func Generate(fsys fs.FS) ([]byte, error) {
	in, err := load(fsys)
	if err != nil {
		return nil, err
	}
	out := table{Sources: in.sources, Modules: []moduleRelated{}}
	for _, m := range in.cites.Modules {
		r, err := in.relate(m)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m.Module, err)
		}
		out.Modules = append(out.Modules, moduleRelated{Module: m.Module, Related: r})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func load(fsys fs.FS) (*inputs, error) {
	b, err := fs.ReadFile(fsys, CitesFile)
	if err != nil {
		return nil, err
	}
	in := &inputs{rules: map[string]map[string]stigRule{}}
	if in.cites, err = ParseCites(b); err != nil {
		return nil, err
	}
	for _, release := range slices.Sorted(maps.Values(in.cites.Releases)) {
		if in.rules[release], err = loadSTIG(fsys, release); err != nil {
			return nil, err
		}
	}
	for _, step := range []func(fs.FS) error{in.loadCCIs, in.loadTitles, in.loadAppendixD, in.loadRev3, in.loadISO, in.loadSources} {
		if err := step(fsys); err != nil {
			return nil, err
		}
	}
	return in, nil
}

func (in *inputs) loadCCIs(fsys fs.FS) error {
	rows, err := readCSV(fsys, cciFile, cciHeader)
	if err != nil {
		return err
	}
	in.ccis = make(map[string]cciRefs, len(rows))
	for _, r := range rows {
		in.ccis[r[0]] = cciRefs{rev5: splitList(r[1]), rev4: splitList(r[2])}
	}
	return nil
}

func (in *inputs) loadTitles(fsys fs.FS) error {
	rows, err := readCSV(fsys, titlesFile, titlesHeader)
	if err != nil {
		return err
	}
	in.titles = make(map[string]string, len(rows))
	for _, r := range rows {
		base, el, ok := element(r[0])
		if !ok || base != el {
			return fmt.Errorf("%s: %q is not a base control", titlesFile, r[0])
		}
		in.titles[base] = r[1]
	}
	return nil
}

func (in *inputs) loadAppendixD(fsys fs.FS) error {
	rows, err := readCSV(fsys, appendixDFile, appendixDHeader)
	if err != nil {
		return err
	}
	for _, r := range rows {
		ctls, err := elements(splitList(r[1]))
		if err != nil {
			return fmt.Errorf("%s: %w", appendixDFile, err)
		}
		in.appendixD = append(in.appendixD, appendixDRow{requirements: splitList(r[0]), controls: ctls})
	}
	return nil
}

func (in *inputs) loadRev3(fsys fs.FS) error {
	rows, err := readCSV(fsys, rev3File, rev3Header)
	if err != nil {
		return err
	}
	in.rev3 = make(map[string][]string, len(rows))
	for _, r := range rows {
		ctls, err := elements(splitList(r[1]))
		if err != nil {
			return fmt.Errorf("%s: %w", rev3File, err)
		}
		in.rev3[r[0]] = ctls
	}
	return nil
}

func (in *inputs) loadISO(fsys fs.FS) error {
	rows, err := readCSV(fsys, isoFile, isoHeader)
	if err != nil {
		return err
	}
	in.iso = make(map[string][]string, len(rows))
	for _, r := range rows {
		_, el, ok := element(r[0])
		if !ok {
			return fmt.Errorf("%s: %q is not a control", isoFile, r[0])
		}
		in.iso[el] = append(in.iso[el], splitList(r[1])...)
	}
	return nil
}

func (in *inputs) loadSources(fsys fs.FS) error {
	rows, err := readCSV(fsys, sourcesFile, sourcesHeader)
	if err != nil {
		return err
	}
	cited := slices.Collect(maps.Values(in.cites.Releases))
	for _, r := range rows {
		// The older Windows releases only give data/equivalents.csv.
		if r[1] == "stig" && !slices.Contains(cited, r[0]) {
			continue
		}
		in.sources = append(in.sources, Source{Name: r[2], Version: r[3], Date: r[4], URL: r[5], Note: r[7]})
	}
	return nil
}

// rule looks a cited rule up in the release its prefix names.
func (in *inputs) rule(id string) (stigRule, error) {
	release, _ := in.cites.ReleaseOf(id) // ParseCites checked every ID has one
	r, ok := in.rules[release][id]
	if !ok {
		return stigRule{}, fmt.Errorf("%s is not in %s", id, STIGFile(release))
	}
	return r, nil
}

// relate applies ADR-0054's rules to one module.
func (in *inputs) relate(m CitedModule) (Related, error) {
	ccis := map[string]bool{}
	for _, id := range m.Counted() {
		r, err := in.rule(id)
		if err != nil {
			return Related{}, err
		}
		for _, c := range r.ccis {
			ccis[c] = true
		}
	}
	bases := map[string]bool{} // Rev. 5 base controls
	rev5 := map[string]bool{}  // Rev. 5 controls and enhancements
	rev4 := map[string]bool{}  // Rev. 4 controls and enhancements
	for _, c := range slices.Sorted(maps.Keys(ccis)) {
		refs, ok := in.ccis[c]
		if !ok {
			return Related{}, fmt.Errorf("%s is not in %s", c, cciFile)
		}
		for _, idx := range refs.rev5 {
			base, el, ok := element(idx)
			if !ok {
				return Related{}, fmt.Errorf("%s: %q is not a control", c, idx)
			}
			bases[base], rev5[el] = true, true
		}
		for _, idx := range refs.rev4 {
			_, el, ok := element(idx)
			if !ok {
				return Related{}, fmt.Errorf("%s: %q is not a control", c, idx)
			}
			rev4[el] = true
		}
	}

	r := Related{SP80053R5: []Control{}}
	for _, base := range slices.SortedFunc(maps.Keys(bases), compareNatural) {
		title, ok := in.titles[base]
		if !ok {
			return Related{}, fmt.Errorf("%s is not in %s", base, titlesFile)
		}
		r.SP80053R5 = append(r.SP80053R5, Control{ID: base, Title: title})
	}
	var r2 []string
	for _, row := range in.appendixD {
		if slices.ContainsFunc(row.controls, func(c string) bool { return rev4[c] }) {
			r2 = append(r2, row.requirements...)
		}
	}
	r.SP800171R2 = sortedSet(r2)
	var r3 []string
	for req, ctls := range in.rev3 {
		if slices.ContainsFunc(ctls, func(c string) bool { return rev5[c] }) {
			r3 = append(r3, req)
		}
	}
	r.SP800171R3 = sortedSet(r3)
	var iso []string
	for base := range bases {
		iso = append(iso, in.iso[base]...)
	}
	r.ISO27001 = sortedSet(iso)
	return r, nil
}

// elementPattern matches a control or enhancement as DISA's CCI list writes
// it (AC-7 a, AC-6 (9), IA-5 (1) (a)), as SP 800-171 Rev. 2's Appendix D
// writes it (AC-6(1)) and as NIST's catalogs and crosswalk write it
// (AC-02(03), AC-07).
var elementPattern = regexp.MustCompile(`^([A-Z]{2})-0*([0-9]+)(?:\s*\(0*([0-9]+)\))?`)

// element reads a control reference and returns its base control (AC-6) and
// the control or enhancement it names (AC-6 or AC-6(9)); statement parts
// (a, b, 1) are dropped.
func element(ref string) (base, element string, ok bool) {
	m := elementPattern.FindStringSubmatch(strings.TrimSpace(ref))
	if m == nil {
		return "", "", false
	}
	base = m[1] + "-" + m[2]
	if m[3] == "" {
		return base, base, true
	}
	return base, base + "(" + m[3] + ")", true
}

func elements(refs []string) ([]string, error) {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		_, el, ok := element(ref)
		if !ok {
			return nil, fmt.Errorf("%q is not a control", ref)
		}
		out = append(out, el)
	}
	return out, nil
}

// readCSV reads a data file and checks its header line.
func readCSV(fsys fs.FS, name string, header []string) ([][]string, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = len(header)
	got, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: empty", name)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if !slices.Equal(got, header) {
		return nil, fmt.Errorf("%s: header %v, want %v", name, got, header)
	}
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return rows, nil
}

// splitList splits a semicolon-separated field.
func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ";") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func dedupe(list []string) []string {
	return slices.Compact(slices.Sorted(slices.Values(list)))
}

// sortedSet returns the distinct values in natural order, never nil.
func sortedSet(list []string) []string {
	out := slices.Compact(slices.SortedFunc(slices.Values(list), compareNatural))
	if out == nil {
		return []string{}
	}
	return out
}

// compareNatural orders strings with their digit runs compared as numbers,
// so that AC-2 comes before AC-17 and 3.1.8 before 3.1.10.
// Strings equal but for leading zeros (AC-02, AC-2) fall back to their
// bytes, so that only equal strings compare equal.
func compareNatural(a, b string) int {
	x, y := a, b
	for x != "" && y != "" {
		rx, ry := run(x), run(y)
		if c := compareRun(rx, ry); c != 0 {
			return c
		}
		x, y = x[len(rx):], y[len(ry):]
	}
	if c := len(x) - len(y); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func run(s string) string {
	digit := isDigit(s[0])
	i := 1
	for i < len(s) && isDigit(s[i]) == digit {
		i++
	}
	return s[:i]
}

func compareRun(a, b string) int {
	if isDigit(a[0]) && isDigit(b[0]) {
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if len(a) != len(b) {
			return len(a) - len(b)
		}
	}
	return strings.Compare(a, b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
