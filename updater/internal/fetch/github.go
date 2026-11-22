package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// GitHub is the repository's GitHub releases: the release list from the
// API, the files from their download links. No sign-in: the repository is
// public, and the list is asked for at most once an hour.
type GitHub struct {
	// API is https://api.github.com, Download https://github.com.
	API, Download string
	// Repository is owner/name.
	Repository string
	Client     *http.Client
}

// NewGitHub is this repository's releases on github.com.
func NewGitHub(client *http.Client) *GitHub {
	return &GitHub{API: "https://api.github.com", Download: "https://github.com", Repository: release.Repository, Client: client}
}

// Versions lists the published releases and release candidates whose tags
// have the release form; drafts and other tags (EasyPatch's old releases)
// are not versions.
func (g *GitHub) Versions(ctx context.Context) ([]release.Version, error) {
	resp, err := get(ctx, g.Client, g.API+"/repos/"+g.Repository+"/releases?per_page=100", http.Header{
		"Accept":               {"application/vnd.github+json"},
		"X-Github-Api-Version": {"2022-11-28"},
	})
	if err != nil {
		return nil, fmt.Errorf("listing releases: %w", err)
	}
	defer resp.Body.Close()
	body, err := readAll(resp.Body, maxIndexBytes, "the release list")
	if err != nil {
		return nil, err
	}
	var list []struct {
		Tag   string `json:"tag_name"`
		Draft bool   `json:"draft"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("the release list is not what GitHub returns: %w", err)
	}
	var vs []release.Version
	for _, r := range list {
		rest, ok := strings.CutPrefix(r.Tag, "easyrmm-")
		if r.Draft || !ok {
			continue
		}
		v, err := release.ParseVersion(rest)
		if err != nil || v.Kind() == release.KindEdge {
			continue
		}
		vs = append(vs, v)
	}
	return vs, nil
}

func (g *GitHub) file(ctx context.Context, v release.Version, name string) (*http.Response, error) {
	if v.Kind() == release.KindEdge {
		return nil, fmt.Errorf("%s is an edge build, which has no GitHub release", v)
	}
	return get(ctx, g.Client, g.Download+"/"+g.Repository+"/releases/download/"+v.Tag()+"/"+name, nil)
}

// Manifest downloads the release's manifest and its attestation.
func (g *GitHub) Manifest(ctx context.Context, v release.Version) ([]byte, []byte, error) {
	var out [2][]byte
	for i, f := range []struct {
		name  string
		limit int64
	}{{manifestName(v), release.MaxManifestBytes}, {attestationName(v), release.MaxSigstoreBundleBytes}} {
		resp, err := g.file(ctx, v, f.name)
		if err != nil {
			return nil, nil, err
		}
		out[i], err = readAll(resp.Body, f.limit, f.name)
		_ = resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
	}
	return out[0], out[1], nil
}

// Bundle downloads the release's deployment bundle.
func (g *GitHub) Bundle(ctx context.Context, v release.Version, w io.Writer) error {
	resp, err := g.file(ctx, v, bundleName(v))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return copyLimited(w, resp.Body, MaxBundleBytes, bundleName(v))
}
