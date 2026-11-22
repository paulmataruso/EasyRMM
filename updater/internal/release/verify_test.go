package release_test

import (
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
	"github.com/paulmataruso/easyrmm/updater/internal/release/releasetest"
)

const (
	commit      = "7fc6602ea97f32b40fa0bf4496e58694d536be7c"
	otherCommit = "1df9b49a5f0c1d4a7e7b1d6e3f1c8a2b9c0d1e2f"
)

var (
	instanceOnce sync.Once
	instance     *releasetest.Sigstore
	instanceErr  error
)

// testSigstore is one virtual Sigstore for the package's tests: making one
// generates several keys.
func testSigstore(t *testing.T) *releasetest.Sigstore {
	t.Helper()
	instanceOnce.Do(func() { instance, instanceErr = releasetest.New() })
	if instanceErr != nil {
		t.Fatal(instanceErr)
	}
	return instance
}

func manifest(t *testing.T, version, commit string) []byte {
	t.Helper()
	return releasetest.NewManifest(version, commit).JSON()
}

func verifier(t *testing.T, trusted root.TrustedMaterial) *release.Verifier {
	t.Helper()
	v, err := release.NewVerifier(trusted)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func attest(t *testing.T, s *releasetest.Sigstore, m []byte, c releasetest.Claims) []byte {
	t.Helper()
	b, err := s.Attest(c, releasetest.File{Name: "manifest.json", Contents: m})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyAccepts(t *testing.T) {
	s := testSigstore(t)
	v := verifier(t, s.TrustedRoot())
	for _, tc := range []struct {
		version string
		channel release.Channel
	}{
		{"v1.0.0", release.ChannelStable},
		{"v1.0.0", release.ChannelPreRelease},
		{"v1.0.0", release.ChannelEdge},
		{"v1.0.1-rc.2", release.ChannelPreRelease},
		{"v1.0.1-rc.2", release.ChannelEdge},
		{"v1.0.1-rc.2.edge.412.1", release.ChannelEdge},
		{"v1.0.1-edge.415.2", release.ChannelEdge},
	} {
		m := manifest(t, tc.version, commit)
		b := attest(t, s, m, releasetest.For(release.MustParseVersion(tc.version), commit))
		got, err := v.Verify(m, b, tc.channel)
		if err != nil {
			t.Errorf("%s on %s: %v", tc.version, tc.channel, err)
			continue
		}
		if got.Version.String() != tc.version || got.Commit != commit {
			t.Errorf("%s: verified %+v", tc.version, got)
		}
	}
}

// The root of trust written out and read back, as an updater built for
// tests reads it on another machine, verifies the same.
func TestTrustedRootJSON(t *testing.T) {
	s := testSigstore(t)
	data, err := s.TrustedRootJSON()
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	m := manifest(t, "v1.0.0", commit)
	if _, err := verifier(t, trusted).Verify(m, attest(t, s, m, releasetest.For(release.MustParseVersion("v1.0.0"), commit)), release.ChannelStable); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRefusesEveryMismatch(t *testing.T) {
	s := testSigstore(t)
	v := verifier(t, s.TrustedRoot())
	edge := release.MustParseVersion("v1.0.1-edge.415.1")
	other := "https://github.com/paulmataruso/EasyRMM/.github/workflows/docker-build.yml@refs/heads/main"
	for name, tc := range map[string]struct {
		version string
		change  func(*releasetest.Claims)
		want    string
	}{
		"another issuer":                 {"v1.0.0", func(c *releasetest.Claims) { c.Issuer = "https://accounts.google.com" }, "issuer"},
		"another repository (by its ID)": {"v1.0.0", func(c *releasetest.Claims) { c.RepositoryID = "1458774021" }, "SourceRepositoryIdentifier"},
		"a self-hosted runner":           {"v1.0.0", func(c *releasetest.Claims) { c.RunnerEnvironment = "self-hosted" }, "RunnerEnvironment"},
		"another workflow's identity":    {"v1.0.0", func(c *releasetest.Claims) { c.SAN = other }, "SAN"},
		"another build configuration":    {"v1.0.0", func(c *releasetest.Claims) { c.BuildConfigURI = other }, "BuildConfigURI"},
		"another source ref":             {"v1.0.0", func(c *releasetest.Claims) { c.SourceRef = "refs/heads/main" }, "SourceRepositoryRef"},
		"a manual trigger":               {"v1.0.0", func(c *releasetest.Claims) { c.Trigger = "workflow_dispatch" }, "BuildTrigger"},
		"another commit":                 {"v1.0.0", func(c *releasetest.Claims) { c.Commit = otherCommit }, "SourceRepositoryDigest"},
		"a tag naming another version": {"v1.0.0", func(c *releasetest.Claims) {
			*c = releasetest.For(release.MustParseVersion("v1.0.1"), commit)
		}, "SAN"},
		"a release made by CI on main": {"v1.0.0", func(c *releasetest.Claims) { *c = releasetest.For(edge, commit) }, "SAN"},
		"an edge build made by the release workflow": {"v1.0.1-edge.415.1", func(c *releasetest.Claims) {
			*c = releasetest.For(release.MustParseVersion("v1.0.1"), commit)
		}, "SAN"},
		"a branch's workflow calling main's": {"v1.0.1-edge.415.1", func(c *releasetest.Claims) {
			c.BuildConfigURI = "https://github.com/paulmataruso/EasyRMM/.github/workflows/ci.yml@refs/heads/feature"
			c.SourceRef = "refs/heads/feature"
		}, "SourceRepositoryRef"},
		"a pull request's run": {"v1.0.1-edge.415.1", func(c *releasetest.Claims) { c.Trigger = "pull_request" }, "BuildTrigger"},
	} {
		version := release.MustParseVersion(tc.version)
		claims := releasetest.For(version, commit)
		tc.change(&claims)
		m := manifest(t, tc.version, commit)
		_, err := v.Verify(m, attest(t, s, m, claims), release.ChannelEdge)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error about %s", name, err, tc.want)
		}
	}
}

func TestVerifyRefusesTheWrongFiles(t *testing.T) {
	s := testSigstore(t)
	v := verifier(t, s.TrustedRoot())
	version := release.MustParseVersion("v1.0.0")
	m := manifest(t, "v1.0.0", commit)
	good := attest(t, s, m, releasetest.For(version, commit))

	tampered := []byte(strings.Replace(string(m), "1.12.1", "1.12.2", 1))
	if _, err := v.Verify(tampered, good, release.ChannelStable); err == nil {
		t.Error("a changed manifest verified")
	}
	otherBuild := manifest(t, "v1.0.0", otherCommit)
	if _, err := v.Verify(m, attest(t, s, otherBuild, releasetest.For(version, otherCommit)), release.ChannelStable); err == nil {
		t.Error("the attestation of another build's manifest verified")
	}
	if _, err := v.Verify(m, []byte(`{"mediaType": "nonsense"}`), release.ChannelStable); err == nil {
		t.Error("a malformed attestation verified")
	}
	if _, err := v.Verify(m, []byte(strings.Repeat(" ", release.MaxSigstoreBundleBytes+1)), release.ChannelStable); err == nil {
		t.Error("an oversized attestation was read")
	}
	if _, err := v.Verify([]byte("{}"), good, release.ChannelStable); err == nil {
		t.Error("a malformed manifest verified")
	}
	// Signed by another Sigstore instance than the one trusted.
	stranger, err := releasetest.New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(m, attest(t, stranger, m, releasetest.For(version, commit)), release.ChannelStable); err == nil {
		t.Error("an attestation from an untrusted instance verified")
	}
}

// A release's attestation names every file of the release, the manifest
// among them; the manifest verifies when it is one of the subjects, and
// not when only the release's other files are.
func TestVerifyReleaseAttestationOfEveryFile(t *testing.T) {
	s := testSigstore(t)
	v := verifier(t, s.TrustedRoot())
	version := release.MustParseVersion("v1.0.0")
	m := manifest(t, "v1.0.0", commit)
	others := []releasetest.File{
		{Name: "easyrmm-v1.0.0-deploy.tar.gz", Contents: []byte("bundle")},
		{Name: "easyrmm-agent-windows-amd64.exe", Contents: []byte("agent")},
	}
	all := append(slices.Clone(others), releasetest.File{Name: "easyrmm-v1.0.0-manifest.json", Contents: m})
	b, err := s.Attest(releasetest.For(version, commit), all...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(m, b, release.ChannelStable); err != nil {
		t.Fatal(err)
	}
	b, err = s.Attest(releasetest.For(version, commit), others...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(m, b, release.ChannelStable); err == nil {
		t.Error("an attestation that does not name the manifest verified it")
	}
}

func TestVerifyRefusesVersionsOutsideTheChannel(t *testing.T) {
	s := testSigstore(t)
	v := verifier(t, s.TrustedRoot())
	for _, tc := range []struct {
		version string
		channel release.Channel
	}{
		{"v1.0.1-rc.1", release.ChannelStable},
		{"v1.0.1-edge.415.1", release.ChannelStable},
		{"v1.0.1-edge.415.1", release.ChannelPreRelease},
		{"v1.0.1-rc.1.edge.2.1", release.ChannelPreRelease},
	} {
		version := release.MustParseVersion(tc.version)
		m := manifest(t, tc.version, commit)
		_, err := v.Verify(m, attest(t, s, m, releasetest.For(version, commit)), tc.channel)
		if err == nil || !strings.Contains(err.Error(), "channel does not take") {
			t.Errorf("%s on %s: %v", tc.version, tc.channel, err)
		}
	}
}

func TestWorkflowFor(t *testing.T) {
	if got := release.WorkflowFor(release.MustParseVersion("v1.0.0-rc.4")).URI(); got !=
		"https://github.com/paulmataruso/EasyRMM/.github/workflows/release.yml@refs/tags/easyrmm-v1.0.0-rc.4" {
		t.Errorf("release candidate: %s", got)
	}
	if got := release.WorkflowFor(release.MustParseVersion("v1.0.0-rc.4.edge.2.1")).URI(); got !=
		"https://github.com/paulmataruso/EasyRMM/.github/workflows/ci.yml@refs/heads/main" {
		t.Errorf("edge build: %s", got)
	}
}
