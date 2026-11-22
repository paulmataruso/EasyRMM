//go:build integration

package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"

	"github.com/paulmataruso/easyrmm/updater/internal/fetch"
	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// The updater against what main's CI published (ADR-0052, Verification).
// testdata/published holds, byte for byte:
//
//   - edge/: the edge build v1.0.0-rc.4.edge.174.1 as CI pushed it to
//     ghcr.io/paulmataruso/easyrmm-deploy (run 44907702690, commit
//     8e1abd2): its OCI manifest and its three layers, the bundle, the
//     manifest and the manifest's Sigstore bundle;
//   - edge-server-image.sigstore.json: the attestation of that build's
//     server image, by the same workflow at the same commit;
//   - release-v1.0.0-rc.4.sigstore.json: the attestation of release
//     v1.0.0-rc.4's files, by the release workflow at its tag;
//   - trusted_root.json: Sigstore's public-good trusted root, as its TUF
//     repository served it on 21 November 2026.
//
// Checking them needs nothing online: an attestation carries its
// certificate, the certificate transparency log's timestamp and its entry
// in the transparency log with the proof of inclusion, all checked against
// the trusted root.
const (
	publishedDir      = "testdata/published"
	publishedEdge     = "v1.0.0-rc.4.edge.174.1"
	publishedCommit   = "8e1abd2fbf36472f106f9f00a98887c965a0a445"
	publishedServer   = "ghcr.io/paulmataruso/easyrmm-server:1.0.0-rc.4.edge.174.1@sha256:b8aa1cce040d5ab243d49ca32bedd41002f775421225f659e43e29a6cbb40888"
	publishedBundle   = "dfc51dc8fd138accccc2b08b2945a4a105e887873b802e1deaab6f37e2dbd9f7"
	publishedWorkflow = "https://github.com/paulmataruso/EasyRMM/.github/workflows/ci.yml@refs/heads/main"
	edgeRepository    = "paulmataruso/easyrmm-deploy"
	ociManifestType   = "application/vnd.oci.image.manifest.v1+json"
	bundleLayer       = "application/vnd.easyrmm.deploy.bundle.v1.tar+gzip"
	manifestLayer     = "application/vnd.easyrmm.deploy.manifest.v1+json"
	attestationLayer  = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

// errStepOneDone ends an attempt at its pull, once the check (step 1) has
// passed: the deployment the test host runs is a fake one.
var errStepOneDone = errors.New("the test stops the attempt at the pull")

// stepOne runs Docker itself for `docker compose config --images` in the
// new version's deployment, as the updater does on a host, and ends the
// attempt at the pull; everything else goes to the fake.
type stepOne struct {
	fake *fakeDocker

	mu sync.Mutex
	// newDir is the new version's deploy directory; calls lists the
	// commands run in it.
	newDir string
	calls  []string
	// env is the new deployment's .env at the pull.
	env []byte
}

func (s *stepOne) Run(ctx context.Context, dir string, stdin []byte, args ...string) ([]byte, error) {
	s.mu.Lock()
	isNew := dir != "" && dir == s.newDir
	if isNew {
		s.calls = append(s.calls, strings.Join(args, " "))
	}
	s.mu.Unlock()
	switch {
	case isNew && slices.Equal(args, []string{"compose", "config", "--images"}):
		return ExecRunner{}.Run(ctx, dir, stdin, args...)
	case isNew && slices.Equal(args, []string{"compose", "pull", "--quiet"}):
		env, err := os.ReadFile(filepath.Join(dir, ".env"))
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.env = env
		s.mu.Unlock()
		return nil, errStepOneDone
	}
	return s.fake.Run(ctx, dir, stdin, args...)
}

// publishedHost is a test host running v1.0.0-rc.4 on the edge channel,
// whose .env has the settings setup.sh writes and docker compose
// requires, with source and verifier for the updater's.
func publishedHost(t *testing.T, source fetch.Source, verifier func() (*release.Verifier, error), target string) (*testHost, *stepOne) {
	t.Helper()
	h := newTestHost(t, "v1.0.0-rc.4", release.ChannelEdge)
	envPath := filepath.Join(h.deploy("v1.0.0-rc.4"), ".env")
	writeFile(t, envPath, readFile(t, envPath)+"POSTGRES_PASSWORD=placeholder\nEASYRMM_DB_APP_PASSWORD=placeholder\n"+
		"EASYRMM_DB_OWNER_PASSWORD=placeholder\nEASYRMM_PUBLIC_URL=https://rmm.example.com\n", 0o600)
	s := &stepOne{fake: h.docker, newDir: h.deploy(target)}
	h.u.Docker = Docker{R: s}
	h.u.Source = source
	h.u.Verifier = verifier
	return h, s
}

// checkStepOne checks that an upgrade to target passed its check and the
// pull ended it: the bundle verified and unpacked, the server named by the
// manifest's digest in .env, and docker compose naming exactly the
// manifest's images (the updater's own comparison, which would have
// failed the check otherwise).
func checkStepOne(t *testing.T, h *testHost, s *stepOne, err error, server string) {
	t.Helper()
	if !errors.Is(err, errStepOneDone) {
		t.Fatalf("the upgrade did not reach its pull: %v", err)
	}
	if a := h.state().Attempt; a.Step != StepPull {
		t.Errorf("the attempt ended at %s", a.Step)
	}
	repo, tagAndDigest, _ := strings.Cut(server, ":")
	if !bytes.Contains(s.env, []byte("\nEASYRMM_IMAGE="+repo+"\n")) || !bytes.Contains(s.env, []byte("\nEASYRMM_VERSION="+tagAndDigest+"\n")) {
		t.Errorf("the new deployment's .env does not name %s:\n%s", server, s.env)
	}
	if !slices.Contains(s.calls, "compose config --images") {
		t.Errorf("docker compose never named the new deployment's images: %v", s.calls)
	}
	if n := h.docker.called("compose stop"); n != 0 {
		t.Errorf("stopped %d times", n)
	}
}

// ociRegistry serves OCI artifacts as ghcr.io does, without sign-in: a
// tag's manifest, and blobs by digest.
type ociRegistry struct {
	manifests map[string][]byte
	blobs     map[string][]byte
}

func (r *ociRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rest, ok := strings.CutPrefix(req.URL.Path, "/v2/"+edgeRepository+"/")
	if tag, isManifest := strings.CutPrefix(rest, "manifests/"); ok && isManifest && r.manifests[tag] != nil {
		w.Header().Set("Content-Type", ociManifestType)
		_, _ = w.Write(r.manifests[tag])
		return
	}
	if digest, isBlob := strings.CutPrefix(rest, "blobs/"); ok && isBlob && r.blobs[digest] != nil {
		_, _ = w.Write(r.blobs[digest])
		return
	}
	http.NotFound(w, req)
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// published is the edge build's files, by layer media type.
func published(t *testing.T) (oci []byte, layers map[string][]byte) {
	t.Helper()
	dir := filepath.Join(publishedDir, "edge")
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	prefix := "easyrmm-" + publishedEdge
	return read("oci-manifest.json"), map[string][]byte{
		bundleLayer:      read(prefix + "-deploy.tar.gz"),
		manifestLayer:    read(prefix + "-manifest.json"),
		attestationLayer: read(prefix + "-manifest.json.sigstore.json"),
	}
}

// push serves layers under tag, with the published OCI manifest's layers
// pointed at them.
func (r *ociRegistry) push(t *testing.T, tag string, oci []byte, layers map[string][]byte) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(oci, &m); err != nil {
		t.Fatal(err)
	}
	for _, l := range m["layers"].([]any) {
		layer := l.(map[string]any)
		data := layers[layer["mediaType"].(string)]
		layer["digest"], layer["size"] = digestOf(data), len(data)
		r.blobs[digestOf(data)] = data
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	r.manifests[tag] = out
}

// publishedVerifier trusts Sigstore's public-good instance through the
// trusted root in testdata.
func publishedVerifier() (*release.Verifier, error) {
	trusted, err := root.NewTrustedRootFromPath(filepath.Join(publishedDir, "trusted_root.json"))
	if err != nil {
		return nil, err
	}
	return release.NewVerifier(trusted)
}

// The edge build as published passes the updater's check: its manifest
// attested by main's CI for its commit, verified against the public-good
// trusted root, the bundle by the manifest's SHA-256, and the deployment
// it unpacks naming exactly the manifest's images, the server by digest.
// Each change to what was published is refused before anything stops.
func TestPublishedEdgeBuild(t *testing.T) {
	oci, layers := published(t)
	if got := digestOf(oci); got != "sha256:6b26078c6628b954b133923720fd7dbf2a64a5f484d3a20c228f507efff0d88c" {
		t.Fatalf("the OCI manifest in testdata is %s, not the one ghcr.io served", got)
	}
	readSigstore := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(publishedDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	withLayer := func(mediaType string, data []byte) map[string][]byte {
		changed := map[string][]byte{}
		for k, v := range layers {
			changed[k] = v
		}
		changed[mediaType] = data
		return changed
	}
	manifest := layers[manifestLayer]
	// One byte: the line break after the opening brace, a space, which
	// leaves the JSON the same.
	oneByte := bytes.Clone(manifest)
	if i := bytes.IndexByte(oneByte, '\n'); oneByte[0] != '{' || i != 1 {
		t.Fatalf("the manifest starts %q", oneByte[:8])
	}
	oneByte[1] = ' '
	// The digest of release v1.0.0-rc.4's server, a genuine image, in
	// place of the edge build's, under the same tag.
	otherServer := bytes.ReplaceAll(manifest, []byte("@sha256:b8aa1cce040d5ab243d49ca32bedd41002f775421225f659e43e29a6cbb40888"),
		[]byte("@sha256:c7fd9e9693d3bde48b413a0d1121a16570d93030f281305a7dd05e1c59aa3367"))
	if bytes.Count(otherServer, []byte("c7fd9e96")) != 2 {
		t.Fatal("the manifest names its server other than twice")
	}
	// Another archive for the same version, well formed.
	swapped := tarGz(t, bundleFiles(publishedEdge))
	notAttested := "the manifest of " + publishedEdge + " is not attested by " + publishedWorkflow + ": "

	for _, tc := range []struct {
		name string
		// serve fills the registry; target is the version asked for.
		serve  func(r *ociRegistry)
		target string
		want   []string
	}{
		{name: "as published", serve: func(r *ociRegistry) {
			r.push(t, publishedEdge, oci, layers)
		}},
		{name: "a manifest byte changed", serve: func(r *ociRegistry) {
			r.push(t, publishedEdge, oci, withLayer(manifestLayer, oneByte))
		}, want: []string{notAttested, "provided artifact digest does not match any digest in statement"}},
		{name: "another server image digest", serve: func(r *ociRegistry) {
			r.push(t, publishedEdge, oci, withLayer(manifestLayer, otherServer))
		}, want: []string{notAttested, "provided artifact digest does not match any digest in statement"}},
		{name: "the bundle swapped", serve: func(r *ociRegistry) {
			r.push(t, publishedEdge, oci, withLayer(bundleLayer, swapped))
		}, want: []string{"the bundle's SHA-256 is " + strings.TrimPrefix(digestOf(swapped), "sha256:") + ", not the manifest's " + publishedBundle}},
		{name: "the bundle changed under the OCI manifest", serve: func(r *ociRegistry) {
			r.push(t, publishedEdge, oci, layers)
			r.blobs["sha256:"+publishedBundle] = swapped
		}, want: []string{"the " + bundleLayer + " layer is " + digestOf(swapped) + ", not the sha256:" + publishedBundle + " its OCI manifest names"}},
		{name: "the Sigstore bundle of release v1.0.0-rc.4", serve: func(r *ociRegistry) {
			r.push(t, publishedEdge, oci, withLayer(attestationLayer, readSigstore("release-v1.0.0-rc.4.sigstore.json")))
		}, want: []string{notAttested}},
		{name: "the Sigstore bundle of the build's server image", serve: func(r *ociRegistry) {
			r.push(t, publishedEdge, oci, withLayer(attestationLayer, readSigstore("edge-server-image.sigstore.json")))
		}, want: []string{notAttested, "provided artifact digest does not match any digest in statement"}},
		{name: "the build under a newer version's tag", target: "v1.0.0-rc.4.edge.175.1", serve: func(r *ociRegistry) {
			r.push(t, "v1.0.0-rc.4.edge.175.1", oci, layers)
		}, want: []string{"the verified manifest is of " + publishedEdge + ", not of v1.0.0-rc.4.edge.175.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := &ociRegistry{manifests: map[string][]byte{}, blobs: map[string][]byte{}}
			tc.serve(reg)
			srv := httptest.NewServer(reg)
			defer srv.Close()
			target := cmp(tc.target, publishedEdge)
			source := fetch.Channel{
				Releases: fetch.Dir(t.TempDir()),
				Edge:     &fetch.Registry{Base: srv.URL, Repository: edgeRepository, Client: srv.Client()},
				Channel:  release.ChannelEdge,
			}
			h, s := publishedHost(t, source, publishedVerifier, target)
			err := h.upgrade(Request{Version: release.MustParseVersion(target)})
			if tc.want == nil {
				checkStepOne(t, h, s, err, publishedServer)
				return
			}
			if err == nil {
				t.Fatal("taken")
			}
			t.Logf("refused: %v", err)
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the refusal does not say %q", w)
				}
			}
			// Refused at the check: nothing unpacked, nothing run from
			// the new version, nothing stopped.
			if a := h.state().Attempt; a.Step != StepCheck || a.Result != ResultFailed {
				t.Errorf("the attempt: %+v", a)
			}
			if len(s.calls) != 0 {
				t.Errorf("run in the new deployment: %v", s.calls)
			}
			if n := h.docker.called("compose stop"); n != 0 {
				t.Errorf("stopped %d times", n)
			}
			if _, err := os.Lstat(filepath.Dir(h.deploy(target))); err == nil {
				t.Error("the new version's directory was left")
			}
		})
	}
}

func cmp(s, otherwise string) string {
	if s != "" {
		return s
	}
	return otherwise
}

// With EASYRMM_TEST_PUBLISHED=1, the edge build ghcr.io's edge tag names
// now, as a host's updater takes it: the tag read and every layer fetched
// by the updater's own client, the attestation verified against the
// public-good trusted root fetched through TUF as a release build does,
// `check`'s report, the upgrade's check, and the server image pulled by the
// manifest's digest, which Docker checks. It needs the internet.
func TestPublishedEdgeNow(t *testing.T) {
	if os.Getenv("EASYRMM_TEST_PUBLISHED") != "1" {
		t.Skip("EASYRMM_TEST_PUBLISHED=1 runs it against ghcr.io, GitHub and Sigstore")
	}
	ctx := context.Background()
	client := &http.Client{Timeout: 5 * time.Minute}
	edge := fetch.NewRegistry(client)
	source := fetch.Channel{Releases: fetch.NewGitHub(client), Edge: edge, Channel: release.ChannelEdge}
	// As cmd/easyrmm-updater's newVerifier: the root sigstore-go embeds,
	// the rest fetched, checked and cached.
	verifier := func() (*release.Verifier, error) {
		trusted, err := root.FetchTrustedRootWithOptions(tuf.DefaultOptions().WithCachePath(filepath.Join(t.TempDir(), "tuf")))
		if err != nil {
			return nil, err
		}
		return release.NewVerifier(trusted)
	}
	vs, err := edge.Versions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	target := vs[0]
	t.Logf("ghcr.io/%s:%s is %s", edgeRepository, fetch.EdgeTag, target)

	h, s := publishedHost(t, source, verifier, target.String())
	r, err := h.u.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var report bytes.Buffer
	r.Write(&report)
	t.Logf("check:\n%s", report.String())
	if r.VerifyErr != nil || r.Newest.String() != target.String() {
		t.Fatalf("check: newest %s, %v", r.Newest, r.VerifyErr)
	}
	m := r.Manifest
	t.Logf("verified: %s, commit %s, bundle %s (%s), server %s", m.Version, m.Commit, m.BundleFile, m.BundleSHA256, m.Server)

	err = h.upgrade(Request{Version: target})
	checkStepOne(t, h, s, err, m.Server)

	out, err := exec.CommandContext(ctx, "docker", "pull", "--quiet", m.Server).CombinedOutput()
	if err != nil {
		t.Fatalf("docker pull %s: %v\n%s", m.Server, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", m.Server).Run() })
	_, digest, _ := strings.Cut(m.Server, "@")
	repo, _, _ := strings.Cut(m.Server, ":")
	digests, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{join .RepoDigests \"\\n\"}}", m.Server).Output()
	if err != nil || !slices.Contains(strings.Fields(string(digests)), repo+"@"+digest) {
		t.Errorf("the pulled image's digests: %q (%v), not %s", digests, err, digest)
	}
	t.Logf("pulled %s", fmt.Sprintf("%s@%s", repo, digest))
}
