//go:build integration

package release_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// The manifest scripts/release/manifest.sh writes for an edge build and
// for a release, from the repository's docker-compose.yml pinned as
// bundle.sh pins it, is one ParseManifest reads, field for field: the
// interface of docs/architecture/edge-manifest.md from both of its sides.
func TestParseManifestFromTheScript(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	const (
		d1     = "@sha256:1111111111111111111111111111111111111111111111111111111111111111"
		d2     = "@sha256:2222222222222222222222222222222222222222222222222222222222222222"
		engine = "ghcr.io/paulmataruso/easypatch-server:1.12.1" + d2
	)
	compose, err := os.ReadFile(filepath.Join(root, "deploy", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	enginePin := regexp.MustCompile(`(?m)^    image: \$\{EASYPATCH_IMAGE:-[^}]*\}:\$\{EASYPATCH_VERSION:-[^}]*\}$`)
	if n := len(enginePin.FindAll(compose, -1)); n != 3 {
		t.Fatalf("the compose file names the engine %d times, not 3", n)
	}
	work := t.TempDir()
	pinned := filepath.Join(work, "docker-compose.yml")
	if err := os.WriteFile(pinned, enginePin.ReplaceAll(compose, []byte("    image: "+engine)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"v1.0.1-edge.415.1", "v1.0.0-rc.4.edge.412.1", "v1.0.1", "v1.1.0-rc.2"} {
		v := release.MustParseVersion(version)
		server := "ghcr.io/paulmataruso/easyrmm-server:" + v.ImageTag() + d1
		bundle := filepath.Join(work, "easyrmm-"+version+"-deploy.tar.gz")
		if err := os.WriteFile(bundle, []byte("the bundle of "+version), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(filepath.Join(root, "scripts", "release", "manifest.sh"), version, testCommit, bundle, pinned)
		cmd.Env = append(os.Environ(), "EASYRMM_IMAGE_PIN="+server, "EASYPATCH_IMAGE_PIN="+engine)
		cmd.Stderr = &testWriter{t}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: manifest.sh: %v", version, err)
		}
		m, err := release.ParseManifest(out)
		if err != nil {
			t.Fatalf("%s: %v\n%s", version, err, out)
		}
		sum := sha256.Sum256([]byte("the bundle of " + version))
		if m.Version.String() != version || m.Commit != testCommit || m.BundleFile != filepath.Base(bundle) ||
			m.BundleSHA256 != hex.EncodeToString(sum[:]) || m.Server != server || m.Engine != engine ||
			m.Postgres == "" || m.MeshCentral == "" || m.Authentik == "" || m.PostgresMajor < 18 || !m.UpgradeFrom.IsZero() {
			t.Errorf("%s: parsed %+v", version, m)
		}
		if got := m.Images(true); !slices.Equal(got, m.AllImages) || len(got) != 5 {
			t.Errorf("%s: images %v, all %v", version, got, m.AllImages)
		}
	}
}

type testWriter struct{ t *testing.T }

func (w *testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}
