//go:build updatertest

package main

import (
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/paulmataruso/easyrmm/updater/internal/fetch"
	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// A test build (the build tag updatertest, which release builds lack, and
// bundle.sh refuses) trusts the Sigstore instance a test made, and takes
// its versions from a directory the test fills. It applies every check a
// release build does to what that instance certifies.
const (
	testTrustedRoot = "/etc/easyrmm/updater-test/trusted-root.json"
	testReleases    = "/var/lib/easyrmm-updater-test/releases"
	testBuildNote   = " (TEST BUILD: trusts " + testTrustedRoot + ", reads " + testReleases + ")"
)

func newSource(release.Channel) fetch.Source { return fetch.Dir(testReleases) }

func newVerifier(string) func() (*release.Verifier, error) {
	return func() (*release.Verifier, error) {
		trusted, err := root.NewTrustedRootFromPath(testTrustedRoot)
		if err != nil {
			return nil, err
		}
		return release.NewVerifier(trusted)
	}
}
