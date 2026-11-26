package packs

import (
	"fmt"
	"io/fs"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/library"
)

// Lint is the whole build check of ADR-0078 section 10 over a content tree:
// content.Check (manifest, hashes, edition, NOTICE, markers) and then each
// library file and pack, parsed and validated as the loader would, with the
// manifest's class matching the file's own. It returns every problem.
func Lint(fsys fs.FS, edition string) []error {
	errs := content.Check(fsys, edition)
	m, err := content.ReadManifest(fsys)
	if err != nil {
		return append(errs, err)
	}
	srcs, err := content.ReadSources(fsys)
	if err != nil {
		return append(errs, err)
	}
	srcClass := map[string]compliance.Class{}
	for _, s := range srcs {
		srcClass[s.ID] = s.LicenceClass
	}
	var libs []library.File
	for _, e := range m.Files {
		if e.Kind != content.KindLibrary {
			continue
		}
		b, err := fs.ReadFile(fsys, e.Path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		f, err := library.Parse(b)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Path, err))
			continue
		}
		if e.LicenceClass != f.Library.LicenceClass {
			errs = append(errs, fmt.Errorf("%s: the manifest says class %s, the file says %s", e.Path, e.LicenceClass, f.Library.LicenceClass))
		}
		errs = append(errs, library.Validate(f)...)
		libs = append(libs, f)
	}
	idx, err := library.Build(libs...)
	if err != nil {
		return append(errs, err)
	}
	for _, e := range m.Files {
		if e.Kind != content.KindPack {
			continue
		}
		b, err := fs.ReadFile(fsys, e.Path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		f, err := Parse(b)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Path, err))
			continue
		}
		if e.LicenceClass != f.Pack.LicenceClass || e.ReviewState != f.Pack.ReviewState {
			errs = append(errs, fmt.Errorf("%s: the manifest says class %s and review %s, the file says %s and %s",
				e.Path, e.LicenceClass, e.ReviewState, f.Pack.LicenceClass, f.Pack.ReviewState))
		}
		errs = append(errs, Validate(f, idx, srcClass, edition)...)
	}
	return errs
}
