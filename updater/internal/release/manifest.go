package release

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// MaxManifestBytes bounds a manifest; a real one is about 2 KiB.
const MaxManifestBytes = 1 << 20

// Manifest is what a build publishes beside its deployment bundle
// (ADR-0052), in schemaVersion 2 of docs/architecture/edge-manifest.md:
// its version and commit, the bundle's SHA-256, every image the bundle
// runs by tag and digest, PostgreSQL's major version, and whether
// Authentik is part of the release. Only a manifest whose attestation
// verified is trusted (Verifier.Verify); ParseManifest alone checks its
// form. Fields the updater does not use (the engine's version and agent
// packages, Authentik's version) are allowed and not read.
type Manifest struct {
	Version Version
	Commit  string
	// Bundle is the deployment bundle's file name and SHA-256 (hex).
	BundleFile   string
	BundleSHA256 string
	// Server is EasyRMM's server image, repository:tag@sha256:digest, its
	// tag the version without "v".
	Server string
	// Engine, Postgres, MeshCentral and Authentik are the other images, by
	// tag and digest. Authentik is "" when the release has none.
	Engine, Postgres, MeshCentral, Authentik string
	// PostgresMajor is the PostgreSQL major version the release runs.
	PostgresMajor int
	// AllImages is every image the bundle's docker-compose.yml names, in
	// every profile: sorted, each once.
	AllImages []string
}

// SchemaVersion is the manifest's form the updater reads. Manifests of
// releases up to v1.0.0-rc.4 have none, and lack what it needs.
const SchemaVersion = 2

type manifestJSON struct {
	SchemaVersion int    `json:"schemaVersion"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	Bundle        struct {
		File   string `json:"file"`
		SHA256 string `json:"sha256"`
	} `json:"bundle"`
	EasyRMM struct {
		Version string `json:"version"`
		Image   string `json:"image"`
	} `json:"easyrmm"`
	EasyPatch struct {
		Image string `json:"image"`
	} `json:"easypatch"`
	Postgres struct {
		Major int    `json:"major"`
		Image string `json:"image"`
	} `json:"postgres"`
	MeshCentral struct {
		Image string `json:"image"`
	} `json:"meshcentral"`
	Authentik *struct {
		Included *bool  `json:"included"`
		Image    string `json:"image"`
	} `json:"authentik"`
	Images []string `json:"images"`
}

var (
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// imageRE is a repository (with its registry, and port), a tag and a
	// SHA-256 digest: an image named so that it cannot change.
	imageRE = regexp.MustCompile(`^([a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+|[a-z0-9]+(?:[._-][a-z0-9]+)*):([A-Za-z0-9_][A-Za-z0-9._-]{0,127})@sha256:[0-9a-f]{64}$`)
)

// ParseManifest reads a manifest and checks its form: schemaVersion 2,
// every field the updater uses present and well formed, every image by tag
// and digest and listed in "images", and the server's image tagged with
// the manifest's version. It does not make the manifest trusted.
func ParseManifest(data []byte) (*Manifest, error) {
	if len(data) > MaxManifestBytes {
		return nil, fmt.Errorf("the manifest is %d bytes, more than %d", len(data), MaxManifestBytes)
	}
	var j manifestJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&j); err != nil {
		return nil, fmt.Errorf("the manifest is not valid JSON: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("the manifest has data after its JSON object")
	}
	if j.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("the manifest's schemaVersion is %d, not %d: releases up to v1.0.0-rc.4 are upgraded by hand", j.SchemaVersion, SchemaVersion)
	}
	v, err := ParseVersion(j.Version)
	if err != nil {
		return nil, fmt.Errorf("the manifest's version: %w", err)
	}
	if j.EasyRMM.Version != j.Version {
		return nil, fmt.Errorf("the manifest's easyrmm.version %q is not its version %s", j.EasyRMM.Version, v)
	}
	m := &Manifest{
		Version:       v,
		Commit:        j.Commit,
		BundleFile:    j.Bundle.File,
		BundleSHA256:  j.Bundle.SHA256,
		Server:        j.EasyRMM.Image,
		Engine:        j.EasyPatch.Image,
		Postgres:      j.Postgres.Image,
		MeshCentral:   j.MeshCentral.Image,
		PostgresMajor: j.Postgres.Major,
		AllImages:     j.Images,
	}
	switch a := j.Authentik; {
	case a == nil || a.Included == nil:
		return nil, fmt.Errorf("the manifest does not say whether Authentik is included")
	case *a.Included && a.Image == "":
		return nil, fmt.Errorf("the manifest includes Authentik without its image")
	case !*a.Included && a.Image != "":
		return nil, fmt.Errorf("the manifest names Authentik's image without including it")
	default:
		m.Authentik = a.Image
	}
	if !commitRE.MatchString(m.Commit) {
		return nil, fmt.Errorf("the manifest's commit %q is not 40 hexadecimal digits", m.Commit)
	}
	if want := "easyrmm-" + v.String() + "-deploy.tar.gz"; m.BundleFile != want {
		return nil, fmt.Errorf("the manifest's bundle is %q, want %q", m.BundleFile, want)
	}
	if !sha256RE.MatchString(m.BundleSHA256) {
		return nil, fmt.Errorf("the manifest's bundle SHA-256 %q is not 64 hexadecimal digits", m.BundleSHA256)
	}
	if m.PostgresMajor < 1 {
		return nil, fmt.Errorf("the manifest does not name PostgreSQL's major version")
	}
	for _, img := range m.AllImages {
		if !imageRE.MatchString(img) {
			return nil, fmt.Errorf("the manifest's image %q is not named by tag and digest", img)
		}
	}
	if len(m.AllImages) == 0 || !slices.IsSorted(m.AllImages) || len(slices.Compact(slices.Clone(m.AllImages))) != len(m.AllImages) {
		return nil, fmt.Errorf("the manifest's images are not a sorted list, each once")
	}
	named := []struct{ what, ref string }{
		{"server", m.Server}, {"patching engine", m.Engine}, {"PostgreSQL", m.Postgres}, {"MeshCentral", m.MeshCentral},
	}
	if m.Authentik != "" {
		named = append(named, struct{ what, ref string }{"Authentik", m.Authentik})
	}
	for _, img := range named {
		if !slices.Contains(m.AllImages, img.ref) {
			return nil, fmt.Errorf("the manifest's %s image %q is not among its images", img.what, img.ref)
		}
	}
	if tag := imageRE.FindStringSubmatch(m.Server)[2]; tag != v.ImageTag() {
		return nil, fmt.Errorf("the manifest's server image is tagged %q, want %q for %s", tag, v.ImageTag(), v)
	}
	return m, nil
}

// ServerRepository is the server image without its tag and digest, as
// .env's EASYRMM_IMAGE names it.
func (m *Manifest) ServerRepository() string {
	return imageRE.FindStringSubmatch(m.Server)[1]
}

// ServerTagAndDigest is the server image's tag and digest (1.2.3@sha256:…),
// what .env's EASYRMM_VERSION is set to so that Compose runs exactly that
// image.
func (m *Manifest) ServerTagAndDigest() string {
	return strings.TrimPrefix(m.Server, m.ServerRepository()+":")
}

// Images lists the images a deployment runs, sorted, each once: every
// image of the bundle, less Authentik's when the deployment does not run
// it (its COMPOSE_PROFILES does not name authentik).
func (m *Manifest) Images(withAuthentik bool) []string {
	var imgs []string
	for _, img := range m.AllImages {
		if withAuthentik || img != m.Authentik {
			imgs = append(imgs, img)
		}
	}
	return imgs
}
