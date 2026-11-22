package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

func versions(vs []release.Version) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.String())
	}
	slices.Sort(out)
	return out
}

func newGitHub(t *testing.T, files map[string]string) *GitHub {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/paulmataruso/EasyRMM/releases", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("per_page") != "100" || r.Header.Get("User-Agent") != userAgent {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `[
			{"tag_name": "easyrmm-v1.0.0", "draft": false},
			{"tag_name": "easyrmm-v1.0.1-rc.1", "draft": false, "prerelease": true},
			{"tag_name": "easyrmm-v1.0.1", "draft": true},
			{"tag_name": "easyrmm-v1.0.1-rc.1.edge.4.1", "draft": false},
			{"tag_name": "easyrmm-v1.0.2-beta", "draft": false},
			{"tag_name": "easypatch-v1.10.0", "draft": false},
			{"tag_name": "v1.0.3", "draft": false}
		]`)
	})
	mux.HandleFunc("GET /paulmataruso/EasyRMM/releases/download/{tag}/{file}", func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.PathValue("tag")+"/"+r.PathValue("file")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	g := NewGitHub(srv.Client())
	g.API, g.Download = srv.URL, srv.URL
	return g
}

func TestGitHub(t *testing.T) {
	ctx := context.Background()
	v := release.MustParseVersion("v1.0.0")
	g := newGitHub(t, map[string]string{
		"easyrmm-v1.0.0/easyrmm-v1.0.0-manifest.json":               "manifest",
		"easyrmm-v1.0.0/easyrmm-v1.0.0-manifest.json.sigstore.json": "attestation",
		"easyrmm-v1.0.0/easyrmm-v1.0.0-deploy.tar.gz":               "bundle",
	})
	vs, err := g.Versions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := versions(vs); !slices.Equal(got, []string{"v1.0.0", "v1.0.1-rc.1"}) {
		t.Errorf("Versions = %v: drafts, edge versions and other tags must be left out", got)
	}
	m, a, err := g.Manifest(ctx, v)
	if err != nil || string(m) != "manifest" || string(a) != "attestation" {
		t.Errorf("Manifest = %q, %q, %v", m, a, err)
	}
	var buf bytes.Buffer
	if err := g.Bundle(ctx, v, &buf); err != nil || buf.String() != "bundle" {
		t.Errorf("Bundle = %q, %v", buf.String(), err)
	}
	if _, _, err := g.Manifest(ctx, release.MustParseVersion("v1.0.1-rc.1")); !errors.Is(err, ErrNotFound) {
		t.Errorf("a release without files: %v", err)
	}
	if err := g.Bundle(ctx, release.MustParseVersion("v2.0.0"), io.Discard); !errors.Is(err, ErrNotFound) {
		t.Errorf("a missing bundle: %v", err)
	}
	if _, _, err := g.Manifest(ctx, release.MustParseVersion("v1.0.1-edge.4.1")); err == nil {
		t.Error("an edge build was looked for among releases")
	}
}

func TestGitHubRefusesBadAnswers(t *testing.T) {
	ctx := context.Background()
	for name, handler := range map[string]http.HandlerFunc{
		"an error": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "rate limited", http.StatusForbidden) },
		"not JSON": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "<html>") },
		"too large": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte(" "), maxIndexBytes+1))
		},
		"an object": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"message": "Not Found"}`) },
		"cut short ": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, "[")
		},
	} {
		srv := httptest.NewServer(handler)
		g := NewGitHub(srv.Client())
		g.API, g.Download = srv.URL, srv.URL
		if vs, err := g.Versions(ctx); err == nil {
			t.Errorf("%s: Versions = %v", name, vs)
		}
		srv.Close()
	}
	// An oversized manifest is not read.
	g := newGitHub(t, map[string]string{
		"easyrmm-v1.0.0/easyrmm-v1.0.0-manifest.json": strings.Repeat("x", release.MaxManifestBytes+1),
	})
	if _, _, err := g.Manifest(ctx, release.MustParseVersion("v1.0.0")); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("an oversized manifest: %v", err)
	}
	// Nor a missing attestation.
	g = newGitHub(t, map[string]string{"easyrmm-v1.0.0/easyrmm-v1.0.0-manifest.json": "{}"})
	if _, _, err := g.Manifest(ctx, release.MustParseVersion("v1.0.0")); !errors.Is(err, ErrNotFound) {
		t.Errorf("a missing attestation: %v", err)
	}
	// The connection refused.
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	g = NewGitHub(http.DefaultClient)
	g.API, g.Download = srv.URL, srv.URL
	if _, err := g.Versions(ctx); err == nil {
		t.Error("a refused connection listed versions")
	}
	if err := g.Bundle(ctx, release.MustParseVersion("v1.0.0"), io.Discard); err == nil {
		t.Error("a refused connection gave a bundle")
	}
}

// registry is a fake OCI registry asking for a token, as ghcr.io does.
type registry struct {
	blobs     map[string][]byte // digest -> contents
	manifests map[string][]byte // tag -> OCI manifest
	tokens    int
	noToken   bool
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// artifact is an edge build's OCI artifact: its version annotation and
// its layers by media type.
type artifact struct {
	version string
	layers  map[string][]byte
}

func edgeArtifact(v string) artifact {
	return artifact{version: v, layers: map[string][]byte{
		bundleType:      []byte("bundle of " + v),
		manifestType:    []byte("manifest of " + v),
		attestationType: []byte("attestation of " + v),
	}}
}

func (r *registry) push(tag string, a artifact) {
	type layer struct {
		MediaType   string            `json:"mediaType"`
		Digest      string            `json:"digest"`
		Size        int               `json:"size"`
		Annotations map[string]string `json:"annotations"`
	}
	var layers []layer
	for _, mt := range []string{bundleType, manifestType, attestationType, "application/octet-stream"} {
		b, ok := a.layers[mt]
		if !ok {
			continue
		}
		d := digestOf(b)
		r.blobs[d] = b
		layers = append(layers, layer{mt, d, len(b), map[string]string{"org.opencontainers.image.title": "a file"}})
	}
	m, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": ociManifestType, "artifactType": artifactType,
		"config":      map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "digest": digestOf([]byte("{}")), "size": 2},
		"layers":      layers,
		"annotations": map[string]string{versionAnnotation: a.version},
	})
	r.manifests[tag] = m
}

func newRegistry(t *testing.T) (*registry, *Registry) {
	t.Helper()
	fake := &registry{blobs: map[string][]byte{}, manifests: map[string][]byte{}}
	mux := http.NewServeMux()
	var srv *httptest.Server
	authorized := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") == "Bearer pull-token" {
			return true
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="ghcr.io",scope="repository:paulmataruso/easyrmm-deploy:pull"`, srv.URL))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		fake.tokens++
		if r.URL.Query().Get("scope") != "repository:paulmataruso/easyrmm-deploy:pull" || r.URL.Query().Get("service") != "ghcr.io" {
			http.Error(w, "bad scope", http.StatusBadRequest)
			return
		}
		if fake.noToken {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		_, _ = io.WriteString(w, `{"token": "pull-token"}`)
	})
	mux.HandleFunc("GET /v2/paulmataruso/easyrmm-deploy/manifests/{tag}", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		m, ok := fake.manifests[r.PathValue("tag")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(m)
	})
	mux.HandleFunc("GET /v2/paulmataruso/easyrmm-deploy/blobs/{digest}", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r) {
			return
		}
		b, ok := fake.blobs[r.PathValue("digest")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	reg := NewRegistry(srv.Client())
	reg.Base = srv.URL
	return fake, reg
}

func TestRegistry(t *testing.T) {
	ctx := context.Background()
	fake, reg := newRegistry(t)
	fake.push("v1.0.1-edge.7.1", edgeArtifact("v1.0.1-edge.7.1"))
	fake.push(EdgeTag, edgeArtifact("v1.0.1-edge.7.1"))
	vs, err := reg.Versions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := versions(vs); !slices.Equal(got, []string{"v1.0.1-edge.7.1"}) {
		t.Errorf("Versions = %v", got)
	}
	v := vs[0]
	m, a, err := reg.Manifest(ctx, v)
	if err != nil || string(m) != "manifest of v1.0.1-edge.7.1" || string(a) != "attestation of v1.0.1-edge.7.1" {
		t.Errorf("Manifest = %q, %q, %v", m, a, err)
	}
	var buf bytes.Buffer
	if err := reg.Bundle(ctx, v, &buf); err != nil || buf.String() != "bundle of v1.0.1-edge.7.1" {
		t.Errorf("Bundle = %q, %v", buf.String(), err)
	}
	if fake.tokens != 1 {
		t.Errorf("asked for %d tokens, want 1 reused", fake.tokens)
	}
	if _, _, err := reg.Manifest(ctx, release.MustParseVersion("v1.0.1-edge.8.1")); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unpublished version: %v", err)
	}
}

func TestRegistryRefuses(t *testing.T) {
	ctx := context.Background()
	v := release.MustParseVersion("v1.0.1-edge.7.1")

	fake, reg := newRegistry(t)
	a := edgeArtifact(v.String())
	fake.push(v.String(), a)
	// A blob that is not what its digest says.
	fake.blobs[digestOf(a.layers[bundleType])] = []byte("changed")
	if err := reg.Bundle(ctx, v, io.Discard); err == nil || !strings.Contains(err.Error(), "not the") {
		t.Errorf("a blob changed in the registry: %v", err)
	}

	// Artifacts without exactly the three layers, or of another type.
	for name, change := range map[string]func(*artifact){
		"no manifest layer": func(a *artifact) { delete(a.layers, manifestType) },
		"no attestation":    func(a *artifact) { delete(a.layers, attestationType) },
		"a fourth layer":    func(a *artifact) { a.layers["application/octet-stream"] = []byte("x") },
		"the bundle replaced": func(a *artifact) {
			a.layers["application/octet-stream"] = a.layers[bundleType]
			delete(a.layers, bundleType)
		},
	} {
		fake, reg = newRegistry(t)
		a := edgeArtifact(v.String())
		change(&a)
		fake.push(v.String(), a)
		if _, _, err := reg.Manifest(ctx, v); err == nil || !strings.Contains(err.Error(), "exactly") {
			t.Errorf("%s: %v", name, err)
		}
	}
	fake, reg = newRegistry(t)
	fake.push(v.String(), edgeArtifact(v.String()))
	fake.manifests[v.String()] = []byte(strings.Replace(string(fake.manifests[v.String()]), artifactType, "application/vnd.other", 1))
	if _, _, err := reg.Manifest(ctx, v); err == nil || !strings.Contains(err.Error(), "not an EasyRMM deployment artifact") {
		t.Errorf("another artifact type: %v", err)
	}

	// The edge tag naming no version, or no edge tag.
	fake.push(EdgeTag, edgeArtifact(""))
	if _, err := reg.Versions(ctx); err == nil {
		t.Error("an edge tag without a version gave one")
	}
	fake.push(EdgeTag, edgeArtifact("edge-1df9b49"))
	if _, err := reg.Versions(ctx); err == nil {
		t.Error("an edge tag naming no version gave one")
	}
	delete(fake.manifests, EdgeTag)
	if _, err := reg.Versions(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("no edge tag: %v", err)
	}
	fake.manifests[EdgeTag] = []byte("not json")
	if _, err := reg.Versions(ctx); err == nil {
		t.Error("a malformed OCI manifest was read")
	}

	// A layer with a bad digest, or larger than allowed, or missing.
	for name, layer := range map[string]string{
		"a bad digest":      `{"mediaType": "` + bundleType + `", "digest": "md5:abc", "size": 1}`,
		"an oversized blob": `{"mediaType": "` + bundleType + `", "digest": "sha256:` + strings.Repeat("0", 64) + `", "size": 999999999999}`,
		"a missing blob":    `{"mediaType": "` + bundleType + `", "digest": "sha256:` + strings.Repeat("0", 64) + `", "size": 1}`,
	} {
		other := func(mt string) string {
			return `{"mediaType": "` + mt + `", "digest": "sha256:` + strings.Repeat("1", 64) + `", "size": 1}`
		}
		fake.manifests[v.String()] = []byte(`{"mediaType": "` + ociManifestType + `", "artifactType": "` + artifactType + `", "layers": [` +
			layer + `, ` + other(manifestType) + `, ` + other(attestationType) + `]}`)
		err := reg.Bundle(ctx, v, io.Discard)
		if err == nil || (name == "a missing blob" && !errors.Is(err, ErrNotFound)) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A token service that gives no token.
	fake, reg = newRegistry(t)
	fake.noToken = true
	fake.push(EdgeTag, edgeArtifact(v.String()))
	if _, err := reg.Versions(ctx); err == nil {
		t.Error("a registry without a token was read")
	}
}

func TestRegistryChallenges(t *testing.T) {
	for _, challenge := range []string{
		"", "Basic realm=\"x\"", `Bearer service="ghcr.io"`, `Bearer realm="ftp://x/token"`, `Bearer realm="x`,
		`Bearer realm`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", challenge)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}))
		reg := NewRegistry(srv.Client())
		reg.Base = srv.URL
		if _, err := reg.Versions(context.Background()); err == nil {
			t.Errorf("challenge %q: read", challenge)
		}
		srv.Close()
	}
	// A registry that keeps refusing after the token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = io.WriteString(w, `{"access_token": "t"}`)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+r.Host+`/token"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()
	reg := NewRegistry(srv.Client())
	reg.Base = srv.URL
	if _, err := reg.Versions(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("refused twice: %v", err)
	}
	// Errors other than 404 and 401 are errors too.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv2.Close()
	reg = NewRegistry(srv2.Client())
	reg.Base = srv2.URL
	if _, err := reg.Versions(context.Background()); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("a registry that is down: %v", err)
	}
}

func TestChannel(t *testing.T) {
	ctx := context.Background()
	fake, reg := newRegistry(t)
	fake.push(EdgeTag, edgeArtifact("v1.0.1-edge.7.1"))
	fake.push("v1.0.1-edge.7.1", edgeArtifact("v1.0.1-edge.7.1"))
	g := newGitHub(t, map[string]string{
		"easyrmm-v1.0.0/easyrmm-v1.0.0-manifest.json":               "release manifest",
		"easyrmm-v1.0.0/easyrmm-v1.0.0-manifest.json.sigstore.json": "release attestation",
		"easyrmm-v1.0.0/easyrmm-v1.0.0-deploy.tar.gz":               "release bundle",
	})
	for ch, want := range map[release.Channel][]string{
		release.ChannelStable:     {"v1.0.0", "v1.0.1-rc.1"},
		release.ChannelPreRelease: {"v1.0.0", "v1.0.1-rc.1"},
		release.ChannelEdge:       {"v1.0.0", "v1.0.1-edge.7.1", "v1.0.1-rc.1"},
	} {
		c := Channel{Releases: g, Edge: reg, Channel: ch}
		vs, err := c.Versions(ctx)
		if err != nil || !slices.Equal(versions(vs), want) {
			t.Errorf("%s: Versions = %v, %v; want %v", ch, versions(vs), err, want)
		}
	}
	c := Channel{Releases: g, Edge: reg, Channel: release.ChannelEdge}
	if m, _, err := c.Manifest(ctx, release.MustParseVersion("v1.0.0")); err != nil || string(m) != "release manifest" {
		t.Errorf("a release's manifest from the edge channel: %q, %v", m, err)
	}
	var buf bytes.Buffer
	if err := c.Bundle(ctx, release.MustParseVersion("v1.0.1-edge.7.1"), &buf); err != nil || buf.String() != "bundle of v1.0.1-edge.7.1" {
		t.Errorf("an edge bundle: %q, %v", buf.String(), err)
	}
	// A broken edge source fails the edge channel, and only it.
	delete(fake.manifests, EdgeTag)
	if _, err := c.Versions(ctx); err == nil {
		t.Error("the edge channel listed versions without its edge tag")
	}
	stable := Channel{Releases: g, Edge: reg, Channel: release.ChannelStable}
	if _, err := stable.Versions(ctx); err != nil {
		t.Errorf("the stable channel needs no edge tag: %v", err)
	}
	broken := Channel{Releases: NewGitHub(http.DefaultClient), Channel: release.ChannelStable}
	broken.Releases.(*GitHub).API = "http://127.0.0.1:1"
	if _, err := broken.Versions(ctx); err == nil {
		t.Error("a release list that cannot be read listed versions")
	}
}

func TestDir(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"easyrmm-v1.0.0-manifest.json":               "manifest",
		"easyrmm-v1.0.0-manifest.json.sigstore.json": "attestation",
		"easyrmm-v1.0.0-deploy.tar.gz":               "bundle",
		"easyrmm-v1.0.1-manifest.json":               "manifest without the rest",
		"easyrmm-latest-manifest.json":               "not a version",
		"README":                                     "x",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d := Dir(dir)
	vs, err := d.Versions(ctx)
	if err != nil || !slices.Equal(versions(vs), []string{"v1.0.0", "v1.0.1"}) {
		t.Fatalf("Versions = %v, %v", versions(vs), err)
	}
	m, a, err := d.Manifest(ctx, vs[0])
	if err != nil || string(m) != "manifest" || string(a) != "attestation" {
		t.Errorf("Manifest = %q, %q, %v", m, a, err)
	}
	var buf bytes.Buffer
	if err := d.Bundle(ctx, vs[0], &buf); err != nil || buf.String() != "bundle" {
		t.Errorf("Bundle = %q, %v", buf.String(), err)
	}
	if _, _, err := d.Manifest(ctx, vs[1]); !errors.Is(err, ErrNotFound) {
		t.Errorf("no attestation: %v", err)
	}
	if err := d.Bundle(ctx, vs[1], io.Discard); !errors.Is(err, ErrNotFound) {
		t.Errorf("no bundle: %v", err)
	}
	if _, _, err := d.Manifest(ctx, release.MustParseVersion("v2.0.0")); !errors.Is(err, ErrNotFound) {
		t.Errorf("no manifest: %v", err)
	}
	if _, err := Dir(filepath.Join(dir, "missing")).Versions(ctx); err == nil {
		t.Error("a missing directory listed versions")
	}
}
