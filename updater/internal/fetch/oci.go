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
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// EdgeTag is the tag of the newest edge build, moved only after it passed
// the test on main.
const EdgeTag = "edge"

// Registry is the edge builds' OCI artifact, laid out as
// docs/architecture/edge-manifest.md says: one tag per version
// (ghcr.io/paulmataruso/easyrmm-deploy:v1.0.1-edge.415.1) and EdgeTag on
// the newest. Each is an OCI image manifest of artifactType
// application/vnd.easyrmm.deploy.v1 with exactly three layers, the bundle,
// the manifest and the manifest's Sigstore bundle, each taken by its media
// type. Nothing in it is trusted before the manifest's attestation
// verifies. The registry's anonymous pull token is asked for when the
// registry asks for one.
type Registry struct {
	// Base is https://ghcr.io; Repository is owner/name.
	Base, Repository string
	Client           *http.Client

	mu    sync.Mutex
	token string
}

// NewRegistry is the edge artifact on ghcr.io.
func NewRegistry(client *http.Client) *Registry {
	return &Registry{Base: "https://ghcr.io", Repository: "paulmataruso/easyrmm-deploy", Client: client}
}

// The artifact's media types.
const (
	ociManifestType   = "application/vnd.oci.image.manifest.v1+json"
	artifactType      = "application/vnd.easyrmm.deploy.v1"
	bundleType        = "application/vnd.easyrmm.deploy.bundle.v1.tar+gzip"
	manifestType      = "application/vnd.easyrmm.deploy.manifest.v1+json"
	attestationType   = "application/vnd.dev.sigstore.bundle.v0.3+json"
	versionAnnotation = "org.opencontainers.image.version"
)

type ociLayer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type ociManifest struct {
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType"`
	Layers       []ociLayer        `json:"layers"`
	Annotations  map[string]string `json:"annotations"`
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Versions is the build EdgeTag names, by the artifact's version
// annotation: which version to verify, not a version trusted.
func (r *Registry) Versions(ctx context.Context) ([]release.Version, error) {
	m, err := r.resolve(ctx, EdgeTag)
	if err != nil {
		return nil, err
	}
	v, err := release.ParseVersion(m.Annotations[versionAnnotation])
	if err != nil {
		return nil, fmt.Errorf("the %s tag of %s: %w", EdgeTag, r.Repository, err)
	}
	return []release.Version{v}, nil
}

// Manifest downloads an edge build's manifest and its attestation.
func (r *Registry) Manifest(ctx context.Context, v release.Version) ([]byte, []byte, error) {
	m, err := r.resolve(ctx, v.String())
	if err != nil {
		return nil, nil, err
	}
	var out [2][]byte
	for i, f := range []struct {
		mediaType string
		limit     int64
	}{{manifestType, release.MaxManifestBytes}, {attestationType, release.MaxSigstoreBundleBytes}} {
		var buf bytes.Buffer
		if err := r.layer(ctx, m, f.mediaType, f.limit, &buf); err != nil {
			return nil, nil, err
		}
		out[i] = buf.Bytes()
	}
	return out[0], out[1], nil
}

// Bundle downloads an edge build's deployment bundle.
func (r *Registry) Bundle(ctx context.Context, v release.Version, w io.Writer) error {
	m, err := r.resolve(ctx, v.String())
	if err != nil {
		return err
	}
	return r.layer(ctx, m, bundleType, MaxBundleBytes, w)
}

// resolve fetches the OCI manifest a tag names and checks its form.
func (r *Registry) resolve(ctx context.Context, tag string) (*ociManifest, error) {
	ref := r.Repository + ":" + tag
	resp, err := r.get(ctx, "/manifests/"+url.PathEscape(tag), ociManifestType)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	defer resp.Body.Close()
	body, err := readAll(resp.Body, maxIndexBytes, ref)
	if err != nil {
		return nil, err
	}
	var m ociManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("%s is not an OCI image manifest: %w", ref, err)
	}
	if m.MediaType != ociManifestType || m.ArtifactType != artifactType {
		return nil, fmt.Errorf("%s is a %q of %q, not an EasyRMM deployment artifact", ref, m.MediaType, m.ArtifactType)
	}
	types := map[string]int{}
	for _, l := range m.Layers {
		types[l.MediaType]++
	}
	if len(m.Layers) != 3 || types[bundleType] != 1 || types[manifestType] != 1 || types[attestationType] != 1 {
		return nil, fmt.Errorf("%s does not have exactly a bundle, a manifest and its Sigstore bundle", ref)
	}
	return &m, nil
}

// layer writes the layer of mediaType, checking it against its digest as
// it arrives.
func (r *Registry) layer(ctx context.Context, m *ociManifest, mediaType string, limit int64, w io.Writer) error {
	i := slices.IndexFunc(m.Layers, func(l ociLayer) bool { return l.MediaType == mediaType })
	l := m.Layers[i]
	if !digestRE.MatchString(l.Digest) {
		return fmt.Errorf("the %s layer has the digest %q", mediaType, l.Digest)
	}
	if l.Size > limit {
		return fmt.Errorf("the %s layer is %d bytes, more than %d", mediaType, l.Size, limit)
	}
	resp, err := r.get(ctx, "/blobs/"+l.Digest, "")
	if err != nil {
		return fmt.Errorf("the %s layer: %w", mediaType, err)
	}
	defer resp.Body.Close()
	h := sha256.New()
	if err := copyLimited(io.MultiWriter(w, h), resp.Body, limit, "the "+mediaType+" layer"); err != nil {
		return err
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != l.Digest {
		return fmt.Errorf("the %s layer is %s, not the %s its OCI manifest names", mediaType, got, l.Digest)
	}
	return nil
}

// get asks the registry for a path under /v2/<repository>, with the pull
// token it asks for when it asks for one.
func (r *Registry) get(ctx context.Context, path, accept string) (*http.Response, error) {
	u := r.Base + "/v2/" + r.Repository + path
	for try := 0; ; try++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		r.mu.Lock()
		if r.token != "" {
			req.Header.Set("Authorization", "Bearer "+r.token)
		}
		r.mu.Unlock()
		resp, err := r.Client.Do(req)
		if err != nil {
			return nil, err
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			return resp, nil
		case resp.StatusCode == http.StatusUnauthorized && try == 0:
			challenge := resp.Header.Get("WWW-Authenticate")
			_ = resp.Body.Close()
			if err := r.authorize(ctx, challenge); err != nil {
				return nil, err
			}
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, errors.New(resp.Status)
	}
}

// authorize gets an anonymous pull token as a Bearer challenge asks.
func (r *Registry) authorize(ctx context.Context, challenge string) error {
	params, ok := parseBearer(challenge)
	if !ok || params["realm"] == "" {
		return fmt.Errorf("the registry asks for sign-in the updater cannot give (%q)", challenge)
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || (realm.Scheme != "https" && realm.Scheme != "http") {
		return fmt.Errorf("the registry's token service %q is not a web address", params["realm"])
	}
	q := realm.Query()
	for _, k := range []string{"service", "scope"} {
		if params[k] != "" {
			q.Set(k, params[k])
		}
	}
	realm.RawQuery = q.Encode()
	resp, err := get(ctx, r.Client, realm.String(), nil)
	if err != nil {
		return fmt.Errorf("the registry's pull token: %w", err)
	}
	defer resp.Body.Close()
	body, err := readAll(resp.Body, 64<<10, "the registry's pull token")
	if err != nil {
		return err
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return fmt.Errorf("the registry's pull token: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.token = tok.Token
	if r.token == "" {
		r.token = tok.AccessToken
	}
	if r.token == "" {
		return fmt.Errorf("the registry gave no pull token")
	}
	return nil
}

// parseBearer parses `Bearer k="v",k="v"`.
func parseBearer(h string) (map[string]string, bool) {
	rest, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return nil, false
	}
	params := map[string]string{}
	for rest != "" {
		k, after, ok := strings.Cut(rest, "=\"")
		if !ok {
			return nil, false
		}
		v, after, ok := strings.Cut(after, "\"")
		if !ok {
			return nil, false
		}
		params[strings.TrimSpace(k)] = v
		rest = strings.TrimPrefix(strings.TrimSpace(after), ",")
	}
	return params, true
}
