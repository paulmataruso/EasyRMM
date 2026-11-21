package releasetest

import (
	"encoding/json"
	"slices"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// Digest is a digest for images a test names but never pulls.
const Digest = "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// Manifest is a manifest in the form of docs/architecture/edge-manifest.md,
// as a test sets it out before encoding it with JSON.
type Manifest struct {
	Version, Commit, BundleSHA256 string
	// Server is the server's repository: its image is tagged with the
	// version, and named by ServerDigest.
	Server, ServerDigest string
	// Engine, Postgres, MeshCentral and Authentik are images by tag and
	// digest; Authentik "" leaves it out.
	Engine, Postgres, MeshCentral, Authentik string
	PostgresMajor                            int
	// UpgradeFrom is the required upgrade stop, "" for none.
	UpgradeFrom string
}

// NewManifest is a manifest of version for commit, with images that exist
// nowhere.
func NewManifest(version, commit string) Manifest {
	return Manifest{
		Version: version, Commit: commit, BundleSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		Server: "ghcr.io/paulmataruso/easyrmm-server", ServerDigest: Digest,
		Engine:        "ghcr.io/paulmataruso/easypatch-server:1.12.1" + Digest,
		Postgres:      "postgres:18.6-alpine3.24" + Digest,
		MeshCentral:   "ghcr.io/ylianst/meshcentral:1.3.1" + Digest,
		Authentik:     "ghcr.io/goauthentik/server:2026.8.5" + Digest,
		PostgresMajor: 18,
	}
}

// ServerImage is the server's image by tag and digest.
func (m Manifest) ServerImage() string {
	return m.Server + ":" + release.MustParseVersion(m.Version).ImageTag() + m.ServerDigest
}

// Fields is the manifest as a JSON object, for a test to change.
func (m Manifest) Fields() map[string]any {
	images := []string{m.ServerImage(), m.Engine, m.Postgres, m.MeshCentral}
	authentik := map[string]any{"included": false}
	if m.Authentik != "" {
		images = append(images, m.Authentik)
		authentik = map[string]any{"included": true, "version": "2026.8.5", "image": m.Authentik}
	}
	slices.Sort(images)
	images = slices.Compact(images)
	f := map[string]any{
		"schemaVersion": release.SchemaVersion,
		"version":       m.Version,
		"commit":        m.Commit,
		"bundle":        map[string]any{"file": "easyrmm-" + m.Version + "-deploy.tar.gz", "sha256": m.BundleSHA256},
		"easyrmm":       map[string]any{"version": m.Version, "image": m.ServerImage()},
		"easypatch":     map[string]any{"version": "1.12.1", "image": m.Engine, "agentPackages": []any{}},
		"postgres":      map[string]any{"major": m.PostgresMajor, "image": m.Postgres},
		"meshcentral":   map[string]any{"image": m.MeshCentral},
		"authentik":     authentik,
		"images":        images,
	}
	if m.UpgradeFrom != "" {
		f["upgradeFrom"] = m.UpgradeFrom
	}
	return f
}

// JSON is the manifest encoded.
func (m Manifest) JSON() []byte {
	b, err := json.MarshalIndent(m.Fields(), "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}
