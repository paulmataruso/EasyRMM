//go:build !updatertest

package main

import (
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"

	"github.com/paulmataruso/easyrmm/updater/internal/fetch"
	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// testBuildNote is what the version says of a test build: nothing, in a
// release build.
const testBuildNote = ""

// newSource is where the channel's versions are published: releases on
// GitHub, edge builds on ghcr.io.
func newSource(ch release.Channel) fetch.Source {
	client := &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: time.Minute,
		IdleConnTimeout:       time.Minute,
	}}
	return fetch.Channel{Releases: fetch.NewGitHub(client), Edge: fetch.NewRegistry(client), Channel: ch}
}

// newVerifier trusts Sigstore's public-good instance, through TUF: the
// root embedded in sigstore-go to start, the rest fetched, checked and
// cached under the state directory.
func newVerifier(stateDir string) func() (*release.Verifier, error) {
	return func() (*release.Verifier, error) {
		opts := tuf.DefaultOptions().WithCachePath(filepath.Join(stateDir, "tuf"))
		trusted, err := root.FetchTrustedRootWithOptions(opts)
		if err != nil {
			return nil, err
		}
		return release.NewVerifier(trusted)
	}
}
