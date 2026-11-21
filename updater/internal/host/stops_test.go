package host

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
	"github.com/paulmataruso/easyrmm/updater/internal/release/releasetest"
)

// Required upgrade stops (ADR-0052): a manifest's upgradeFrom is the
// lowest version a deployment must run before it installs that one.

func stopAt(version string) func(*releasetest.Manifest, *releasetest.Claims) {
	return func(m *releasetest.Manifest, _ *releasetest.Claims) { m.UpgradeFrom = version }
}

// A release and an edge build are refused from below their stop, before
// anything stops, naming the version to install first, and are not counted
// as failing; asked for once the deployment runs the stop, they are taken.
func TestUpgradeStopRefusesBelowIt(t *testing.T) {
	for _, target := range []string{"v1.2.0", "v1.2.1-edge.9.1"} {
		t.Run(target, func(t *testing.T) {
			h := newTestHost(t, "v1.0.0", release.ChannelEdge)
			h.offer("v1.1.0", nil) // no upgradeFrom: taken from anything older
			h.offer(target, stopAt("v1.1.0"))
			v := release.MustParseVersion(target)
			err := h.upgrade(Request{Version: v})
			if err == nil || !strings.Contains(err.Error(), target+" installs only over v1.1.0 or later, and v1.0.0 runs: install v1.1.0 first (easyrmm-updater upgrade v1.1.0)") {
				t.Fatalf("got %v", err)
			}
			if n := h.docker.called("compose stop"); n != 0 {
				t.Errorf("stopped %d times", n)
			}
			st := h.state()
			if st.Running != "" || st.HasFailed(target) || st.Attempt.Step != StepCheck || st.Attempt.Result != ResultFailed {
				t.Errorf("state %+v, attempt %+v", st, st.Attempt)
			}
			if _, err := os.Lstat(filepath.Join(h.root, "easyrmm-"+target)); err == nil {
				t.Error("the refused version was unpacked")
			}
			// From the stop itself: taken.
			if err := h.upgrade(Request{Version: release.MustParseVersion("v1.1.0")}); err != nil {
				t.Fatal(err)
			}
			if err := h.upgrade(Request{Version: v}); err != nil {
				t.Fatalf("from the stop: %v", err)
			}
			if got := h.state().Running; got != target {
				t.Errorf("running %s", got)
			}
		})
	}
}

// An automatic upgrade installs the stop first, as a version of its own,
// and the next run goes on to the version that named it.
func TestUpgradeAutomaticInstallsTheStopFirst(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	h.offer("v1.1.1", nil)
	h.offer("v1.2.0", stopAt("v1.1.0"))
	if err := h.upgrade(Request{Automatic: true}); err != nil {
		t.Fatal(err)
	}
	if got := h.state().Running; got != "v1.1.0" {
		t.Fatalf("the first run installed %s, not the stop", got)
	}
	if err := h.upgrade(Request{Automatic: true}); err != nil {
		t.Fatal(err)
	}
	if got := h.state().Running; got != "v1.2.0" {
		t.Fatalf("the next run installed %s", got)
	}
	// A stop that failed is not tried again on its own.
	h2 := newTestHost(t, "v1.0.0", release.ChannelStable)
	h2.offer("v1.1.0", nil)
	h2.offer("v1.2.0", stopAt("v1.1.0"))
	if err := os.Mkdir(h2.u.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	st := h2.state()
	st.MarkFailed("v1.1.0")
	if err := st.save(h2.u.StateDir); err != nil {
		t.Fatal(err)
	}
	if err := h2.upgrade(Request{Automatic: true}); err != nil || h2.docker.called("compose stop") != 0 {
		t.Errorf("after the stop failed: %v", err)
	}
}

// The stop is the lowest version the deployment's own channel offers at or
// above upgradeFrom and below the version that names it: on the stable
// channel, a full release that carries the change rather than the release
// candidate named. Only when the channel offers none does the updater take
// another channel's, the release candidate, which the stable channel would
// otherwise refuse.
func TestUpgradeStopOnTheDeploymentsChannel(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0-rc.2", nil)
	h.offer("v1.1.0", nil)
	h.offer("v1.2.0", stopAt("v1.1.0-rc.2"))
	err := h.upgrade(Request{})
	if err == nil || !strings.Contains(err.Error(), "install v1.1.0 first") {
		t.Fatalf("got %v", err)
	}
	// Asked for by name, the candidate is still not the stable channel's.
	if err := h.upgrade(Request{Version: release.MustParseVersion("v1.1.0-rc.2")}); err == nil || !strings.Contains(err.Error(), "channel does not take") {
		t.Errorf("the candidate on stable: %v", err)
	}
	if err := h.upgrade(Request{Automatic: true}); err != nil {
		t.Fatal(err)
	}
	if got := h.state().Running; got != "v1.1.0" {
		t.Fatalf("the stop installed is %s", got)
	}

	// No full release at or above it: the candidate, on any channel.
	h = newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0-rc.2", nil)
	h.offer("v1.2.0", stopAt("v1.1.0-rc.2"))
	if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "install v1.1.0-rc.2 first (easyrmm-updater upgrade v1.1.0-rc.2)") {
		t.Fatalf("got %v", err)
	}
	if err := h.upgrade(Request{Version: release.MustParseVersion("v1.1.0-rc.2")}); err != nil {
		t.Fatalf("the stop asked for by name on stable: %v", err)
	}
	if err := h.upgrade(Request{Automatic: true}); err != nil {
		t.Fatal(err)
	}
	if got := h.state().Running; got != "v1.2.0" {
		t.Fatalf("running %s", got)
	}
	// Automatic, on another host: the candidate first.
	h = newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0-rc.2", nil)
	h.offer("v1.2.0", stopAt("v1.1.0-rc.2"))
	if err := h.upgrade(Request{Automatic: true}); err != nil {
		t.Fatal(err)
	}
	if got := h.state().Running; got != "v1.1.0-rc.2" {
		t.Fatalf("the stop installed is %s", got)
	}
}

// Stops chain: each stop's own upgradeFrom is followed, the lowest first.
func TestUpgradeStopsChain(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	h.offer("v1.2.0", stopAt("v1.1.0"))
	h.offer("v1.3.0", stopAt("v1.2.0"))
	if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "v1.3.0 installs only over v1.2.0 or later, and v1.0.0 runs: install v1.1.0 first") {
		t.Fatalf("got %v", err)
	}
	for _, want := range []string{"v1.1.0", "v1.2.0", "v1.3.0"} {
		if err := h.upgrade(Request{Automatic: true}); err != nil {
			t.Fatal(err)
		}
		if got := h.state().Running; got != want {
			t.Fatalf("running %s, want %s", got, want)
		}
	}
}

// upgradeFrom is compared with the lower of the running server's version
// and the updater's own, which came with the bundle the deployment was last
// set up from: a server image changed by hand above it does not count.
func TestUpgradeStopComparesTheLowerVersion(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	h.offer("v1.2.0", stopAt("v1.1.0"))
	// The server's image changed by hand to the stop, the bundle and
	// the updater still v1.0.0's.
	h.u.Self = release.MustParseVersion("v1.0.0")
	envPath := filepath.Join(h.deploy("v1.0.0"), ".env")
	writeFile(t, envPath, regexp.MustCompile(`(?m)^EASYRMM_VERSION=.*$`).ReplaceAllString(readFile(t, envPath), "EASYRMM_VERSION=1.1.0"), 0o600)
	err := h.upgrade(Request{Version: release.MustParseVersion("v1.2.0")})
	if err == nil || !strings.Contains(err.Error(), "this deployment was set up from v1.0.0's bundle, though its server runs v1.1.0 (an image changed by hand); the required upgrade stop, v1.1.0, is not above the running server") {
		t.Fatalf("got %v", err)
	}
	if err := h.upgrade(Request{Automatic: true}); err == nil || !strings.Contains(err.Error(), "upgrade by hand") || h.docker.called("compose stop") != 0 {
		t.Fatalf("automatic: %v", err)
	}
	// Set up from the stop's bundle (its updater): taken.
	h.u.Self = release.MustParseVersion("v1.1.0")
	if err := h.upgrade(Request{Version: release.MustParseVersion("v1.2.0")}); err != nil {
		t.Fatal(err)
	}
	// An updater newer than the server (one kept after a rollback) does
	// not raise the version compared.
	h = newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.2.0", stopAt("v1.1.0"))
	h.u.Self = release.MustParseVersion("v1.3.0")
	if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "and v1.0.0 runs") {
		t.Fatalf("got %v", err)
	}
	// A clone's updater, which has no version, leaves the server's.
	h.u.Self = release.Version{}
	if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "and v1.0.0 runs: install v1.1.0 first") {
		t.Fatalf("got %v", err)
	}
}

// check names the stop the newest version needs.
func TestCheckNamesTheStop(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	h.offer("v1.2.0", stopAt("v1.1.0"))
	r, err := h.u.Check(context.Background())
	if err != nil || r.VerifyErr != nil {
		t.Fatal(err, r.VerifyErr)
	}
	var out bytes.Buffer
	r.Write(&out)
	if !strings.Contains(out.String(), "must first upgrade to v1.1.0, a required upgrade stop: easyrmm-updater upgrade v1.1.0") {
		t.Errorf("check:\n%s", out.String())
	}
}

// The error a stop refuses with, for each case.
func TestStopError(t *testing.T) {
	v := release.MustParseVersion
	for _, c := range []struct {
		e    StopError
		want string
	}{
		{StopError{Version: v("v2.0.0"), UpgradeFrom: v("v1.5.0"), Stop: v("v1.5.0")},
			"v2.0.0 installs only over v1.5.0 or later, and the running version is not one the updater knows: install v1.5.0 first (easyrmm-updater upgrade v1.5.0)"},
		{StopError{Version: v("v2.0.0"), UpgradeFrom: v("v1.5.0"), Stop: v("v1.5.1"), Server: v("v1.4.0"), Floor: v("v1.4.0")},
			"v2.0.0 installs only over v1.5.0 or later, and v1.4.0 runs: install v1.5.1 first (easyrmm-updater upgrade v1.5.1)"},
	} {
		if got := c.e.Error(); got != c.want {
			t.Errorf("got  %s\nwant %s", got, c.want)
		}
	}
	if !needsStop(release.Version{}, v("v1.0.0")) || needsStop(v("v1.0.0"), release.Version{}) ||
		needsStop(v("v1.0.0"), v("v1.0.0")) || !needsStop(v("v1.0.0-rc.1"), v("v1.0.0")) {
		t.Error("needsStop")
	}
}
