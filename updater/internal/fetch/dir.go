package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// Dir is a directory holding versions as a release attaches them
// (easyrmm-<version>-manifest.json, its .sigstore.json and
// easyrmm-<version>-deploy.tar.gz). Only the updater's test builds read
// one: what they download in a test that has no published build to
// download. It is no more trusted than a download.
type Dir string

// Versions lists the versions whose manifest the directory holds.
func (d Dir) Versions(context.Context) ([]release.Version, error) {
	entries, err := os.ReadDir(string(d))
	if err != nil {
		return nil, err
	}
	var vs []release.Version
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name(), "easyrmm-")
		if !ok || !strings.HasSuffix(rest, "-manifest.json") {
			continue
		}
		if v, err := release.ParseVersion(strings.TrimSuffix(rest, "-manifest.json")); err == nil {
			vs = append(vs, v)
		}
	}
	return vs, nil
}

func (d Dir) open(name string) (*os.File, error) {
	f, err := os.Open(filepath.Join(string(d), name)) //nolint:gosec // a name built from a parsed version
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", name, ErrNotFound)
	}
	return f, err
}

func (d Dir) read(name string, limit int64) ([]byte, error) {
	f, err := d.open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readAll(f, limit, name)
}

// Manifest reads a version's manifest and its attestation.
func (d Dir) Manifest(_ context.Context, v release.Version) ([]byte, []byte, error) {
	m, err := d.read(manifestName(v), release.MaxManifestBytes)
	if err != nil {
		return nil, nil, err
	}
	a, err := d.read(attestationName(v), release.MaxSigstoreBundleBytes)
	if err != nil {
		return nil, nil, err
	}
	return m, a, nil
}

// Bundle copies a version's deployment bundle to w.
func (d Dir) Bundle(_ context.Context, v release.Version, w io.Writer) error {
	f, err := d.open(bundleName(v))
	if err != nil {
		return err
	}
	defer f.Close()
	return copyLimited(w, f, MaxBundleBytes, bundleName(v))
}
