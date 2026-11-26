// Package content is the embedded content of the compliance engine
// (ADR-0078, section 10): controls, packs and sources, each file declared in
// manifest.json with its licence class, source, review state, author and
// SHA-256. Check is the build check cmd/packlint runs; the pack loader
// repeats parts of it at run time.
package content

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
)

//go:embed manifest.json sources.json NOTICE.generated controls packs
var embedded embed.FS

// FS is the embedded content.
var FS fs.FS = embedded

// ReleasePublicKey is the release key's ed25519 public key in hex, set at
// build with a linker variable. A commercial build refuses content whose
// manifest is not signed by it.
var ReleasePublicKey = ""

// Entry is one file of the manifest.
type Entry struct {
	Path               string           `json:"path"`
	Kind               string           `json:"kind"`
	LicenceClass       compliance.Class `json:"licence_class"`
	SourceID           string           `json:"source_id"`
	ReviewState        string           `json:"review_state"`
	ReviewRef          string           `json:"review_ref,omitempty"`
	Author             string           `json:"author"`
	DerivedFromContent bool             `json:"derived_from_content"`
	SHA256             string           `json:"sha256"`
}

// Manifest is manifest.json.
type Manifest struct {
	Version int     `json:"version"`
	Files   []Entry `json:"files"`
}

// Kinds of content file.
const (
	KindLibrary = "library"
	KindPack    = "pack"
	KindSources = "sources"
)

// Source is a row of sources.json.
type Source struct {
	ID           string           `json:"id"`
	Title        string           `json:"title"`
	Publisher    string           `json:"publisher"`
	URL          string           `json:"url"`
	LicenceClass compliance.Class `json:"licence_class"`
	LicenceSPDX  *string          `json:"licence_spdx"`
	LicenceNote  string           `json:"licence_note"`
	Attribution  *string          `json:"attribution"`
	RetrievedAt  string           `json:"retrieved_at"`
	SHA256       *string          `json:"sha256"`
	ReviewState  string           `json:"review_state"`
	ReviewRef    string           `json:"review_ref,omitempty"`
}

// ReadManifest reads manifest.json.
func ReadManifest(fsys fs.FS) (Manifest, error) {
	b, err := fs.ReadFile(fsys, "manifest.json")
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("manifest.json: %w", err)
	}
	if m.Version != 1 {
		return Manifest{}, errors.New("manifest.json: version 1 expected")
	}
	return m, nil
}

// ReadSources reads sources.json.
func ReadSources(fsys fs.FS) ([]Source, error) {
	b, err := fs.ReadFile(fsys, "sources.json")
	if err != nil {
		return nil, err
	}
	return parseSources(b)
}

func parseSources(b []byte) ([]Source, error) {
	var f struct {
		Sources []Source `json:"sources"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("sources.json: %w", err)
	}
	return f.Sources, nil
}

// Sum is the SHA-256 of b in hex.
func Sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// files lists the content files of fsys that must be in the manifest: the
// controls and packs directories and sources.json.
func files(fsys fs.FS) ([]string, error) {
	out := []string{"sources.json"}
	for _, dir := range []string{"controls", "packs"} {
		ents, err := fs.ReadDir(fsys, dir)
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			out = append(out, path.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// bannedMarkers are plain strings that must not appear in the text fields
// of content (section 10, step 5). A backstop only: the control is the
// licence class, the named author and the second person's review.
var bannedMarkers = []string{"Center for Internet Security", "CIS Benchmark", "Wazuh", "GNU General Public License", "GPL"}

// textKeys are the fields the marker scan reads. The cross-reference number
// fields are not among them.
var textKeys = map[string]bool{"title": true, "title_own": true, "description": true, "rationale": true, "remediation_text": true,
	"note": true, "text": true, "text_full": true, "summary": true, "method": true}

// Check is the build check of section 10, steps 1 to 5, over a content tree
// (the embedded one, or a directory): every file is in the manifest with a
// matching hash; the edition's class rule; no review still needed in a
// commercial edition; NOTICE regenerates without a difference; and no
// banned marker in a text field. It returns every problem it finds.
func Check(fsys fs.FS, edition string) []error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	m, err := ReadManifest(fsys)
	if err != nil {
		return []error{err}
	}
	listed := map[string]Entry{}
	for _, e := range m.Files {
		if _, dup := listed[e.Path]; dup {
			bad("%s: listed twice in the manifest", e.Path)
		}
		listed[e.Path] = e
	}
	onDisk, err := files(fsys)
	if err != nil {
		return append(errs, err)
	}
	for _, p := range onDisk {
		e, ok := listed[p]
		if !ok {
			bad("%s: not in manifest.json (every content file is declared there)", p)
			continue
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			bad("%s: %v", p, err)
			continue
		}
		if Sum(b) != e.SHA256 {
			bad("%s: SHA-256 does not match the manifest", p)
		}
		errs = append(errs, checkEntry(e, edition)...)
		if marker, field := scanMarkers(b); marker != "" {
			bad("%s: banned marker %q in field %q", p, marker, field)
		}
		errs = append(errs, checkProvenance(p, b)...)
	}
	for p := range listed {
		if !slices.Contains(onDisk, p) {
			bad("%s: in the manifest but not in the content", p)
		}
	}
	if want, err := Notice(fsys); err != nil {
		bad("NOTICE.generated: %v", err)
	} else if got, _ := fs.ReadFile(fsys, "NOTICE.generated"); string(got) != want {
		bad("NOTICE.generated is out of date (run packlint -update)")
	}
	return errs
}

func checkEntry(e Entry, edition string) []error {
	var errs []error
	switch {
	case !e.LicenceClass.Valid():
		errs = append(errs, fmt.Errorf("%s: unknown licence class %q", e.Path, e.LicenceClass))
	case !compliance.ValidReview(e.ReviewState, e.ReviewRef):
		errs = append(errs, fmt.Errorf("%s: review state %q with reference %q is not valid", e.Path, e.ReviewState, e.ReviewRef))
	case !compliance.Allowed(edition, e.LicenceClass, e.ReviewState, e.ReviewRef):
		if e.ReviewState == compliance.ReviewNeeded {
			errs = append(errs, fmt.Errorf("%s: review is still needed, which fails a %s build until it is cleared with a reference", e.Path, edition))
		} else {
			errs = append(errs, fmt.Errorf("%s: licence class %s is not allowed in a %s build", e.Path, e.LicenceClass, edition))
		}
	}
	if e.Author == "" || e.DerivedFromContent || e.SourceID == "" {
		errs = append(errs, fmt.Errorf("%s: needs a named author, a source, and derived_from_content false", e.Path))
	}
	return errs
}

// checkProvenance refuses a control or mapping that asserts it was derived
// from content, wherever the file has a provenance block.
func checkProvenance(p string, b []byte) []error {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return []error{fmt.Errorf("%s: not JSON", p)}
	}
	var errs []error
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if d, ok := x["derived_from_content"].(bool); ok && d {
				errs = append(errs, fmt.Errorf("%s: an item asserts derived_from_content true", p))
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(v)
	return errs
}

// scanMarkers returns the first banned marker found in a text field of the
// JSON file, and the field.
func scanMarkers(b []byte) (marker, field string) {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return "", ""
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if s, ok := x[k].(string); ok && textKeys[k] && marker == "" {
					for _, m := range bannedMarkers {
						if strings.Contains(s, m) {
							marker, field = m, k
							return
						}
					}
				}
				walk(x[k])
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(v)
	return marker, field
}

// Notice builds NOTICE.generated: the attribution of every OPEN_LICENSE and
// ATTRIBUTION_REQUIRED source.
func Notice(fsys fs.FS) (string, error) {
	srcs, err := ReadSources(fsys)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("Notices for content embedded in the compliance engine (generated by packlint; do not edit).\n")
	n := 0
	for _, s := range srcs {
		if s.LicenceClass != compliance.ClassOpenLicense && s.LicenceClass != compliance.ClassAttributionRequired {
			continue
		}
		n++
		spdx := ""
		if s.LicenceSPDX != nil {
			spdx = *s.LicenceSPDX
		}
		att := s.Title + " by " + s.Publisher
		if s.Attribution != nil && *s.Attribution != "" {
			att = *s.Attribution
		}
		fmt.Fprintf(&b, "\n%s\n  Licence: %s %s\n  Source: %s\n", att, s.LicenceClass, spdx, s.URL)
	}
	if n == 0 {
		b.WriteString("\nNo third-party content that needs attribution is embedded.\n")
	}
	return b.String(), nil
}

// VerifySignature checks the manifest's detached ed25519 signature
// (manifest.sig, hex) against the release public key. A dev edition takes
// an unsigned manifest; a commercial one requires a valid signature.
func VerifySignature(fsys fs.FS, edition, publicKeyHex string) error {
	sig, err := fs.ReadFile(fsys, "manifest.sig")
	if err != nil {
		if edition == compliance.EditionCommercial {
			return errors.New("content: the manifest is not signed")
		}
		return nil
	}
	pub, err := hex.DecodeString(strings.TrimSpace(publicKeyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("content: no valid release public key to check the manifest's signature")
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil {
		return errors.New("content: manifest.sig is not hex")
	}
	b, err := fs.ReadFile(fsys, "manifest.json")
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, raw) {
		return errors.New("content: the manifest's signature does not verify")
	}
	return nil
}

// Update rewrites manifest.json (hashes; new files take their class and
// source from their own header, with the author EasyRMM and a review state
// of the header's) and NOTICE.generated for the content in files, which
// returns the new contents of both. Existing entries keep what a person
// recorded. It is what packlint -update writes.
func Update(fsys fs.FS) (manifest, notice []byte, err error) {
	old, err := ReadManifest(fsys)
	if err != nil {
		old = Manifest{Version: 1}
	}
	have := map[string]Entry{}
	for _, e := range old.Files {
		have[e.Path] = e
	}
	paths, err := files(fsys)
	if err != nil {
		return nil, nil, err
	}
	m := Manifest{Version: 1}
	for _, p := range paths {
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, nil, err
		}
		e, ok := have[p]
		if !ok {
			e, err = headerEntry(p, b)
			if err != nil {
				return nil, nil, err
			}
		}
		e.SHA256 = Sum(b)
		m.Files = append(m.Files, e)
	}
	manifest, err = json.MarshalIndent(m, "", " ")
	if err != nil {
		return nil, nil, err
	}
	manifest = append(manifest, '\n')
	n, err := Notice(fsys)
	return manifest, []byte(n), err
}

// headerEntry builds a manifest entry for a new file from its header.
func headerEntry(p string, b []byte) (Entry, error) {
	e := Entry{Path: p, Author: "EasyRMM", ReviewState: compliance.ReviewNone}
	if p == "sources.json" {
		srcs, err := parseSources(b)
		if err != nil {
			return e, err
		}
		cs := make([]compliance.Class, 0, len(srcs))
		for _, s := range srcs {
			cs = append(cs, s.LicenceClass)
		}
		e.Kind, e.LicenceClass, e.SourceID = KindSources, compliance.MostRestrictive(cs...), "easyrmm-hardening"
		return e, nil
	}
	var h struct {
		Library *struct {
			LicenceClass compliance.Class `json:"licence_class"`
			SourceID     string           `json:"source_id"`
			ReviewState  string           `json:"review_state"`
		} `json:"library"`
		Pack *struct {
			LicenceClass compliance.Class `json:"licence_class"`
			SourceID     string           `json:"source_id"`
			ReviewState  string           `json:"review_state"`
		} `json:"pack"`
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return e, fmt.Errorf("%s: %w", p, err)
	}
	switch {
	case h.Library != nil:
		e.Kind, e.LicenceClass, e.SourceID, e.ReviewState = KindLibrary, h.Library.LicenceClass, h.Library.SourceID, h.Library.ReviewState
	case h.Pack != nil:
		e.Kind, e.LicenceClass, e.SourceID, e.ReviewState = KindPack, h.Pack.LicenceClass, h.Pack.SourceID, h.Pack.ReviewState
	default:
		return e, fmt.Errorf("%s: neither a library nor a pack header", p)
	}
	return e, nil
}
