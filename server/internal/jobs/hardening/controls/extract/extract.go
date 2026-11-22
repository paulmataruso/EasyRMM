// Package extract turns DISA's and NIST's downloaded files into the compact
// data files under the controls package's data/ directory (see
// data/SOURCES.md): STIG rule IDs and CCIs, the CCI list's SP 800-53
// references, SP 800-53 Rev. 5 titles, SP 800-171 Rev. 2 Appendix D's rows,
// SP 800-171 Rev. 3's source controls, NIST's crosswalk to ISO/IEC
// 27001:2022, and which rule of each older Windows STIG checks what a cited
// rule checks.
//
// It is run by hand through cmd/gencontrols, never by the tests or the
// server, and refuses a file whose SHA-256 is not the one recorded in
// Pinned. No rule titles, discussions or check text are written: EasyRMM
// uses DISA's IDs, never their text.
package extract

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/jobs/hardening/controls"
)

// Kind says how a source is read.
type Kind string

// The kinds of source.
const (
	KindSTIG      Kind = "stig"      // a DISA STIG zip holding an XCCDF file
	KindCCI       Kind = "cci"       // DISA's CCI list zip
	KindCatalog   Kind = "catalog"   // NIST's SP 800-53 Rev. 5 OSCAL catalog
	KindRev3      Kind = "rev3"      // NIST's SP 800-171 Rev. 3 OSCAL catalog
	KindAppendixD Kind = "appendixD" // the SP 800-171 Rev. 2 PDF
	KindCrosswalk Kind = "crosswalk" // NIST's OLIR crosswalk to ISO/IEC 27001:2022
)

// Source is a downloaded file the extraction reads.
type Source struct {
	// Key names the source in data/sources.csv; for a STIG it is the
	// release key (win11-v2r11), which also names its data file.
	Key  string
	Kind Kind
	// File is the file's name in the source directory.
	File   string
	URL    string
	SHA256 string
	// Name is how the console names the source.
	Name string
	// Version is the version the file must carry (a STIG's V2R11, the CCI
	// list's 2025-01-23, the catalog's 5.2.0), or the source's version
	// where the file does not say.
	Version string
	// Date is the source's date where the file does not say.
	Date string
	// Note is the publisher's caveat about its mapping, quoted.
	Note string
}

// Equivalents maps a release whose rules are cited to the releases in
// which data/equivalents.csv finds the rule that checks the same thing.
var Equivalents = map[string][]string{
	"win11-v2r11": {"win10-v3r6"},
	"ws2025-v1r4": {"ws2022-v2r11", "ws2019-v3r9", "ws2016-v2r10"},
}

// Options says where the files are.
type Options struct {
	// SourceDir holds the downloaded files under their File names.
	SourceDir string
	// PackageDir is the controls package directory: cites.json is read
	// from it and data/ written in it.
	PackageDir string
	// Sources are the files to read; Pinned when nil.
	Sources []Source
	// PDFText returns a PDF's text laid out as on the page; pdftotext
	// -layout when nil.
	PDFText func(ctx context.Context, pdf []byte) (string, error)

	// reads are the rules matched by reading; readMatches when nil.
	reads []readMatch
}

// extraction is what was read from the sources.
type extraction struct {
	stigs     map[string]stigRelease
	ccis      map[string]cciRefs
	titles    []baseControl
	rev3      []rev3Requirement
	appendixD []appendixDRow
	crosswalk []crosswalkRow
	sources   [][]string // data/sources.csv rows
}

// Run checks every source's SHA-256, reads them and writes the data files.
func Run(ctx context.Context, o Options) error {
	if o.Sources == nil {
		o.Sources = Pinned
	}
	if o.PDFText == nil {
		o.PDFText = pdftotext
	}
	if o.reads == nil {
		o.reads = readMatches
	}
	pkg, err := os.OpenRoot(o.PackageDir)
	if err != nil {
		return err
	}
	defer pkg.Close()
	b, err := pkg.ReadFile(controls.CitesFile)
	if err != nil {
		return err
	}
	cites, err := controls.ParseCites(b)
	if err != nil {
		return err
	}
	ex, err := read(ctx, os.DirFS(o.SourceDir), o)
	if err != nil {
		return err
	}
	files, err := ex.files(cites, o.reads)
	if err != nil {
		return err
	}
	if err := pkg.MkdirAll("data", 0o750); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if err := pkg.WriteFile(name, files[name], 0o644); err != nil { //nolint:gosec // data files checked into the repository
			return err
		}
	}
	return nil
}

func read(ctx context.Context, src fs.FS, o Options) (*extraction, error) {
	ex := &extraction{stigs: map[string]stigRelease{}}
	for _, s := range o.Sources {
		b, err := fs.ReadFile(src, s.File)
		if err != nil {
			return nil, err
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != s.SHA256 {
			return nil, fmt.Errorf("refusing %s: its SHA-256 is %x, not the recorded %s", s.File, sum, s.SHA256)
		}
		version, date, err := ex.add(ctx, s, b, o.PDFText)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.File, err)
		}
		if s.Version != "" && version != "" && version != s.Version {
			return nil, fmt.Errorf("%s: version %s, not the recorded %s", s.File, version, s.Version)
		}
		if version == "" {
			version = s.Version
		}
		if date == "" {
			date = s.Date
		}
		ex.sources = append(ex.sources, []string{s.Key, string(s.Kind), s.Name, version, date, s.URL, s.SHA256, s.Note})
	}
	return ex, nil
}

// add reads one source and returns the version and date the file carries,
// if it carries them.
func (ex *extraction) add(ctx context.Context, s Source, b []byte, pdfText func(context.Context, []byte) (string, error)) (version, date string, err error) {
	switch s.Kind {
	case KindSTIG:
		r, err := parseSTIGZip(b)
		if err != nil {
			return "", "", err
		}
		ex.stigs[s.Key] = r
		return r.version, r.date, nil
	case KindCCI:
		var c cciList
		c, err = parseCCIZip(b)
		ex.ccis = c.refs
		return c.version, c.date, err
	case KindCatalog:
		var c catalogInfo
		ex.titles, c, err = parseCatalog(b)
		return c.version, c.date, err
	case KindRev3:
		var c catalogInfo
		ex.rev3, c, err = parseRev3(b)
		return c.version, c.date, err
	case KindAppendixD:
		text, err := pdfText(ctx, b)
		if err != nil {
			return "", "", err
		}
		ex.appendixD, err = parseAppendixD(text)
		return "", "", err
	case KindCrosswalk:
		ex.crosswalk, err = parseCrosswalk(b)
		return "", "", err
	}
	return "", "", fmt.Errorf("unknown kind %q", s.Kind)
}

// files renders the data files, keyed by their path in the package.
func (ex *extraction) files(cites controls.Cites, reads []readMatch) (map[string][]byte, error) {
	if ex.ccis == nil || ex.titles == nil || ex.rev3 == nil || ex.appendixD == nil || ex.crosswalk == nil {
		return nil, errors.New("a source of every kind is needed")
	}
	out := map[string][]byte{}
	used := map[string]bool{}
	for release, r := range ex.stigs {
		rows := make([][]string, 0, len(r.rules))
		for _, rule := range r.rules {
			rows = append(rows, []string{rule.version, rule.id, strings.Join(rule.ccis, ";")})
			for _, c := range rule.ccis {
				used[c] = true
			}
		}
		out[controls.STIGFile(release)] = render([]string{"version", "rule", "ccis"}, rows)
	}

	var cciRows [][]string
	for _, c := range slices.Sorted(maps.Keys(used)) {
		refs, ok := ex.ccis[c]
		if !ok {
			return nil, fmt.Errorf("%s is used by a STIG but not in the CCI list", c)
		}
		cciRows = append(cciRows, []string{c, strings.Join(refs.rev5, ";"), strings.Join(refs.rev4, ";")})
	}
	out["data/cci.csv"] = render([]string{"cci", "sp80053r5", "sp80053r4"}, cciRows)

	var rows [][]string
	for _, c := range ex.titles {
		rows = append(rows, []string{c.id, c.title})
	}
	out["data/sp800-53r5-controls.csv"] = render([]string{"control", "title"}, rows)

	rows = nil
	for _, r := range ex.appendixD {
		rows = append(rows, []string{strings.Join(r.requirements, ";"), strings.Join(r.controls, ";")})
	}
	out["data/sp800-171r2-appendix-d.csv"] = render([]string{"requirements", "controls"}, rows)

	rows = nil
	for _, r := range ex.rev3 {
		rows = append(rows, []string{r.id, strings.Join(r.controls, ";")})
	}
	out["data/sp800-171r3-source-controls.csv"] = render([]string{"requirement", "controls"}, rows)

	rows = nil
	for _, r := range ex.crosswalk {
		rows = append(rows, []string{r.control, strings.Join(r.annexA, ";")})
	}
	out["data/iso27001-2022-from-sp800-53r5.csv"] = render([]string{"control", "annexA"}, rows)

	eq, err := equivalents(cites, ex.stigs, reads)
	if err != nil {
		return nil, err
	}
	out["data/equivalents.csv"] = render([]string{"rule", "release", "equivalent", "matchedBy"}, eq)

	out["data/sources.csv"] = render([]string{"key", "kind", "name", "version", "date", "url", "sha256", "note"}, ex.sources)
	return out, nil
}

// render writes a CSV file with its header line.
func render(header []string, rows [][]string) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write(header) // a bytes.Buffer does not fail
	_ = w.WriteAll(rows)
	return buf.Bytes()
}

// pdftotext runs poppler's pdftotext on a PDF given on its standard input.
func pdftotext(ctx context.Context, pdf []byte) (string, error) {
	cmd := exec.CommandContext(ctx, "pdftotext", "-layout", "-enc", "UTF-8", "-", "-")
	cmd.Stdin = bytes.NewReader(pdf)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("pdftotext: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// zipMember returns the one member of a zip whose name ends in suffix.
func zipMember(b []byte, suffix string) ([]byte, error) {
	zr, err := newZip(b)
	if err != nil {
		return nil, err
	}
	var found []byte
	for _, f := range zr.File {
		if !strings.HasSuffix(path.Base(f.Name), suffix) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("more than one *%s in the zip", suffix)
		}
		if found, err = readZipFile(f); err != nil {
			return nil, err
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no *%s in the zip", suffix)
	}
	return found, nil
}
