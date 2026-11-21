// Package fetch downloads what a build publishes (ADR-0052): releases from
// their GitHub release, edge builds from the OCI artifact
// ghcr.io/paulmataruso/easyrmm-deploy. Nothing fetched is trusted: the
// release package verifies the manifest against its attestation, and the
// bundle against the manifest's SHA-256.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// Sizes past which a download is refused: a manifest and its attestation
// are kilobytes, a deployment bundle (the Compose files, the guides and the
// updater for two architectures) tens of megabytes.
const (
	MaxBundleBytes = 512 << 20
	// maxIndexBytes bounds a release list or an OCI manifest.
	maxIndexBytes = 4 << 20
)

// The files of a version, as a release attaches them and the edge
// artifact's layers name them.
func manifestName(v release.Version) string    { return "easyrmm-" + v.String() + "-manifest.json" }
func attestationName(v release.Version) string { return manifestName(v) + ".sigstore.json" }
func bundleName(v release.Version) string      { return "easyrmm-" + v.String() + "-deploy.tar.gz" }

// Source is where versions come from.
type Source interface {
	// Versions lists the versions offered, unverified.
	Versions(ctx context.Context) ([]release.Version, error)
	// Manifest downloads a version's manifest and the Sigstore bundle of
	// its attestation.
	Manifest(ctx context.Context, v release.Version) (manifest, attestation []byte, err error)
	// Bundle writes a version's deployment bundle to w.
	Bundle(ctx context.Context, v release.Version, w io.Writer) error
}

// Channel is the source for a channel: releases from GitHub, and on the
// edge channel also the newest edge build.
type Channel struct {
	Releases Source
	Edge     Source
	Channel  release.Channel
}

// Versions lists what the channel offers. On the edge channel an edge
// artifact that cannot be read is an error, as a release list is.
func (c Channel) Versions(ctx context.Context) ([]release.Version, error) {
	vs, err := c.Releases.Versions(ctx)
	if err != nil {
		return nil, err
	}
	if c.Channel == release.ChannelEdge {
		edge, err := c.Edge.Versions(ctx)
		if err != nil {
			return nil, err
		}
		vs = append(vs, edge...)
	}
	return vs, nil
}

func (c Channel) source(v release.Version) Source {
	if v.Kind() == release.KindEdge {
		return c.Edge
	}
	return c.Releases
}

// Manifest downloads from where the version's kind is published.
func (c Channel) Manifest(ctx context.Context, v release.Version) ([]byte, []byte, error) {
	return c.source(v).Manifest(ctx, v)
}

// Bundle downloads from where the version's kind is published.
func (c Channel) Bundle(ctx context.Context, v release.Version, w io.Writer) error {
	return c.source(v).Bundle(ctx, v, w)
}

// ErrNotFound is a version, or one of its files, that is not published.
var ErrNotFound = errors.New("not published")

// get fetches url and returns the response for the caller to read and
// close, or an error for anything but 200.
func get(ctx context.Context, client *http.Client, url string, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s: %w", url, ErrNotFound)
	}
	return nil, fmt.Errorf("%s: %s", url, resp.Status)
}

// userAgent names the updater to the servers it downloads from, and
// nothing about the installation.
const userAgent = "easyrmm-updater"

// readAll reads at most limit bytes, and fails when there are more.
func readAll(r io.Reader, limit int64, what string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", what, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", what, limit)
	}
	return b, nil
}

// copyLimited copies at most limit bytes, and fails when there are more.
func copyLimited(w io.Writer, r io.Reader, limit int64, what string) error {
	n, err := io.Copy(w, io.LimitReader(r, limit+1))
	if err != nil {
		return fmt.Errorf("downloading %s: %w", what, err)
	}
	if n > limit {
		return fmt.Errorf("%s is larger than %d bytes", what, limit)
	}
	return nil
}
