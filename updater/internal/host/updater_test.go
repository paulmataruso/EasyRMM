package host

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/updater/internal/fetch"
	"github.com/paulmataruso/easyrmm/updater/internal/release"
	"github.com/paulmataruso/easyrmm/updater/internal/release/releasetest"
)

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestUpgrade(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	h.offer("v1.0.1", nil)
	h.docker.fail = func(dir string, args []string) error {
		// The hold is written before the new version starts, and the
		// engine's worker starts only once the rest runs, its agent
		// updates held.
		call := strings.Join(args, " ")
		if dir == h.deploy("v1.1.0") && strings.HasPrefix(call, "compose up") {
			held := h.u.Config.Deployment == h.deploy("v1.0.0") && h.statusDir().Held()
			worker := strings.HasSuffix(call, " "+workerService)
			if !held {
				t.Errorf("%s while not held", call)
			}
			if _, err := os.Stat(h.statusDir().path(AgentUpdatesHeldFile)); worker != (err == nil) {
				t.Errorf("%s: agent updates held: %v", call, err == nil)
			}
			if !worker && h.docker.running[workerService] != "" {
				t.Errorf("the worker runs from %s during the held start", h.docker.running[workerService])
			}
		}
		return nil
	}
	if err := h.upgrade(Request{Automatic: true}); err != nil {
		t.Fatal(err)
	}
	st := h.state()
	if st.Running != "v1.1.0" || st.Previous != "v1.0.0" || st.Attempt.Result != ResultSucceeded || st.Attempt.Step != StepFinished ||
		st.Attempt.By != "a test" || st.Attempt.From != "v1.0.0" || st.Attempt.To != "v1.1.0" {
		t.Fatalf("state %+v, attempt %+v", st, st.Attempt)
	}
	if h.u.Config.Deployment != h.deploy("v1.1.0") || !strings.Contains(readFile(t, h.u.Config.Path), "deployment = "+h.deploy("v1.1.0")) ||
		!strings.Contains(readFile(t, h.u.Config.Path), "# the updater\n") {
		t.Errorf("the configuration names %s:\n%s", h.u.Config.Deployment, readFile(t, h.u.Config.Path))
	}
	for svc, dir := range h.docker.running {
		if dir != h.deploy("v1.1.0") {
			t.Errorf("%s runs from %s", svc, dir)
		}
	}
	if got := readFile(t, filepath.Join(h.dataRoot, "server", "ran")); got != "v1.1.0" {
		t.Errorf("the data root says %q ran", got)
	}
	// .env carried across, with the server by its digest, and setup.sh run.
	env := []byte(readFile(t, filepath.Join(h.deploy("v1.1.0"), ".env")))
	if envValue(env, "EASYRMM_VERSION") != "1.1.0"+releasetest.Digest || envValue(env, "EASYRMM_IMAGE") != serverRepo ||
		envValue(env, "EASYRMM_SECRET_KEY") != "secret" || envValue(env, "SETUP_RAN") != "yes" {
		t.Errorf("the new .env:\n%s", env)
	}
	if m := mode(t, filepath.Join(h.deploy("v1.1.0"), ".env")); m != 0o600 {
		t.Errorf("the new .env has mode %o", m)
	}
	// The status directory: readable by the server's and the engine's users.
	sd := h.statusDir()
	if sd.Held() {
		t.Error("still held")
	}
	until, err := time.Parse(time.RFC3339, strings.TrimSpace(readFile(t, sd.path(AgentUpdatesHeldFile))))
	if err != nil || !until.Equal(h.now.Add(RollbackWindow)) || !strings.HasSuffix(strings.TrimSpace(readFile(t, sd.path(AgentUpdatesHeldFile))), "Z") {
		t.Errorf("agent updates held until %v (%v)", until, err)
	}
	for path, want := range map[string]os.FileMode{
		filepath.Dir(string(sd)): 0o755, string(sd): 0o755, sd.path(AgentUpdatesHeldFile): 0o644, sd.path(StatusFile): 0o644,
	} {
		if got := mode(t, path); got != want {
			t.Errorf("%s has mode %o, want %o", path, got, want)
		}
	}
	status := readFile(t, sd.path(StatusFile))
	for _, want := range []string{`"running": "v1.1.0"`, `"previous": "v1.0.0"`, `"result": "succeeded"`, `"rollback": {`, `"to": "v1.0.0"`} {
		if !strings.Contains(status, want) {
			t.Errorf("status.json lacks %s:\n%s", want, status)
		}
	}
	// A backup of v1.0.0, and the rollback it allows.
	if st.Rollback == nil || st.Rollback.To != "v1.0.0" || st.Rollback.From != "v1.1.0" || !st.Rollback.Until.Equal(h.now.Add(RollbackWindow)) {
		t.Fatalf("rollback point %+v", st.Rollback)
	}
	b, err := openBackup(st.Rollback.Backup)
	if err != nil {
		t.Fatal(err)
	}
	if b.Meta.Version != "v1.0.0" || b.Meta.Deployment != h.deploy("v1.0.0") ||
		readFile(t, filepath.Join(b.Dir, "data", "server", "data")) != "the data of v1.0.0" ||
		!strings.Contains(readFile(t, filepath.Join(b.Dir, "tree", "deploy", ".env")), "EASYRMM_SECRET_KEY=secret") ||
		readFile(t, filepath.Join(b.Dir, "updater.conf")) == "" {
		t.Errorf("backup %+v", b.Meta)
	}
	if _, err := os.Stat(filepath.Join(b.Dir, "data", "updater")); err == nil {
		t.Error("the backup holds the updater's own directory")
	}
	if m := mode(t, b.Dir); m != 0o700 {
		t.Errorf("the backup has mode %o", m)
	}
	// The updater replaced itself with the bundle's.
	if got := readFile(t, h.u.Install.Binary); got != "updater of v1.1.0" || mode(t, h.u.Install.Binary) != 0o755 {
		t.Errorf("installed updater %q", got)
	}
	for _, u := range unitFiles {
		if got := readFile(t, filepath.Join(h.u.Install.UnitDir, u)); !strings.HasSuffix(got, "of v1.1.0") {
			t.Errorf("%s: %q", u, got)
		}
	}
	if !slices.Equal(h.installs, []string{"daemon-reload"}) {
		t.Errorf("systemctl %v", h.installs)
	}
	if _, err := os.Stat(filepath.Join(h.u.StateDir, "downloads")); err == nil {
		t.Error("the download is left")
	}

	// Nothing newer: nothing done.
	calls := len(h.docker.calls)
	if err := h.upgrade(Request{Automatic: true}); err != nil {
		t.Fatal(err)
	}
	if h.docker.called("compose stop") != 1 || h.state().Attempt.To != "v1.1.0" || len(h.docker.calls) == calls {
		t.Errorf("upgraded again: %v", h.docker.calls[calls:])
	}
	// Versions never go down, even asked by name.
	if err := h.upgrade(Request{Version: release.MustParseVersion("v1.0.1")}); err == nil || !strings.Contains(err.Error(), "never go down") {
		t.Errorf("an older version asked for: %v", err)
	}

	// The next upgrade removes the bundle directories other than the
	// current and the previous one.
	h.offer("v1.2.0", nil)
	if err := h.upgrade(Request{}); err != nil {
		t.Fatal(err)
	}
	// v1.0.0's was installed by hand: its .env goes, which holds the key,
	// and nothing else.
	for v, kept := range map[string]bool{"v1.1.0": true, "v1.2.0": true} {
		if _, err := os.Stat(h.deploy(v)); (err == nil) != kept {
			t.Errorf("%s kept: %v", v, err == nil)
		}
	}
	if _, err := os.Stat(filepath.Join(h.deploy("v1.0.0"), ".env")); err == nil {
		t.Error("v1.0.0's .env is left")
	}
	if _, err := os.Stat(filepath.Join(h.deploy("v1.0.0"), "docker-compose.yml")); err != nil {
		t.Error("v1.0.0's directory, which the updater did not unpack, was removed")
	}
	if st := h.state(); !slices.Equal(st.Unpacked, []string{filepath.Join(h.root, "easyrmm-v1.1.0"), filepath.Join(h.root, "easyrmm-v1.2.0")}) {
		t.Errorf("unpacked %v", st.Unpacked)
	}
	// The third upgrade removes v1.1.0's directory, which it unpacked.
	h.offer("v1.3.0", nil)
	if err := h.upgrade(Request{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "easyrmm-v1.1.0")); err == nil {
		t.Error("v1.1.0's directory is left")
	}
	if st := h.state(); !slices.Equal(st.Deployments, []string{h.deploy("v1.2.0"), h.deploy("v1.3.0")}) {
		t.Errorf("deployments %v", st.Deployments)
	}
	// Two backups kept.
	entries, err := os.ReadDir(h.u.Config.BackupDir)
	if err != nil || len(entries) != 2 {
		t.Errorf("backups %v, %v", entries, err)
	}
}

func TestUpgradeWithAuthentik(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	envPath := filepath.Join(h.deploy("v1.0.0"), ".env")
	writeFile(t, envPath, readFile(t, envPath)+"COMPOSE_PROFILES=authentik\n", 0o600)
	h.offer("v1.1.0", func(m *releasetest.Manifest, _ *releasetest.Claims) { m.Authentik = "" })
	if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "Authentik") {
		t.Fatalf("a release without Authentik for a deployment with it: %v", err)
	}
	h.offer("v1.2.0", nil)
	if err := h.upgrade(Request{}); err != nil {
		t.Fatal(err)
	}
	// Authentik's setup, which nothing depends on, ran on its own.
	if h.docker.called(h.deploy("v1.2.0")+": compose wait authentik-setup") != 1 || h.docker.running["authentik-setup"] != h.deploy("v1.2.0") {
		t.Errorf("authentik-setup: %v", h.docker.calls)
	}
}

func TestUpgradeAutomatic(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	h.u.Config.AutoUpgrade = false
	if err := h.upgrade(Request{Automatic: true}); err != nil || h.docker.called("compose stop") != 0 {
		t.Fatalf("automatic upgrades off: %v", err)
	}
	h.u.Config.AutoUpgrade = true
	h.now = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	if err := h.upgrade(Request{Automatic: true}); err != nil || h.docker.called("compose stop") != 0 {
		t.Fatalf("outside the hours: %v", err)
	}
	// A version asked for by name needs no hours.
	if err := h.upgrade(Request{Version: release.MustParseVersion("v1.1.0")}); err != nil {
		t.Fatal(err)
	}
	if h.state().Running != "v1.1.0" {
		t.Errorf("running %s", h.state().Running)
	}
}

func TestUpgradeChannels(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0-rc.1", nil)
	h.offer("v1.0.1-edge.7.1", nil)
	if err := h.upgrade(Request{}); err != nil || h.docker.called("compose stop") != 0 {
		t.Fatalf("stable took a candidate or an edge build: %v", err)
	}
	for _, v := range []string{"v1.1.0-rc.1", "v1.0.1-edge.7.1"} {
		if err := h.upgrade(Request{Version: release.MustParseVersion(v)}); err == nil || !strings.Contains(err.Error(), "channel does not take") {
			t.Errorf("%s asked for on stable: %v", v, err)
		}
	}
	h.u.Config.Channel = release.ChannelPreRelease
	if err := h.upgrade(Request{}); err != nil {
		t.Fatal(err)
	}
	if h.state().Running != "v1.1.0-rc.1" {
		t.Errorf("pre-release runs %s", h.state().Running)
	}
}

// A version whose attestation does not verify is refused before anything
// stops, and automatic upgrades skip it; a newer one is taken.
func TestUpgradeRefusesUnverified(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", func(_ *releasetest.Manifest, c *releasetest.Claims) { c.RunnerEnvironment = "self-hosted" })
	err := h.upgrade(Request{Automatic: true})
	if err == nil || !strings.Contains(err.Error(), "RunnerEnvironment") {
		t.Fatalf("a self-hosted build: %v", err)
	}
	st := h.state()
	if st.Attempt.Result != ResultFailed || st.Attempt.Step != StepCheck || !st.HasFailed("v1.1.0") || st.Running != "" {
		t.Errorf("state %+v, attempt %+v", st, st.Attempt)
	}
	if h.docker.called("compose stop") != 0 || h.docker.called("compose pull") != 0 {
		t.Error("an unverified version was pulled or stopped the deployment")
	}
	if _, err := os.Stat(filepath.Join(h.root, "easyrmm-v1.1.0")); err == nil {
		t.Error("an unverified bundle was unpacked")
	}
	if err := h.upgrade(Request{Automatic: true}); err != nil || h.state().Attempt.ID != st.Attempt.ID {
		t.Errorf("a failed version tried again: %v", err)
	}
	h.offer("v1.1.1", nil)
	if err := h.upgrade(Request{Automatic: true}); err != nil {
		t.Fatal(err)
	}
	if h.state().Running != "v1.1.1" {
		t.Errorf("running %s", h.state().Running)
	}
}

func TestUpgradeRefusesBeforeStopping(t *testing.T) {
	for name, tc := range map[string]struct {
		change    func(*releasetest.Manifest, *releasetest.Claims)
		breakHost func(*testHost)
		want      string
		transient bool
	}{
		"a changed bundle": {
			breakHost: func(h *testHost) {
				writeFile(h.t, filepath.Join(h.releases, "easyrmm-v1.1.0-deploy.tar.gz"), "changed", 0o644)
			},
			want: "SHA-256",
		},
		"another PostgreSQL": {
			change: func(m *releasetest.Manifest, _ *releasetest.Claims) {
				m.PostgresMajor, m.Postgres = 19, "postgres:19.0-alpine"+releasetest.Digest
			},
			want: "PostgreSQL 19",
		},
		"images other than the manifest's": {
			change: func(m *releasetest.Manifest, _ *releasetest.Claims) {
				m.MeshCentral = "ghcr.io/ylianst/meshcentral:1.3.2" + releasetest.Digest
			},
			want: "not the manifest's",
		},
		"the network down": {
			breakHost: func(h *testHost) {
				if err := os.Remove(filepath.Join(h.releases, "easyrmm-v1.1.0-deploy.tar.gz")); err != nil {
					h.t.Fatal(err)
				}
			},
			want: "not published", transient: true,
		},
		"a pull that fails": {
			breakHost: func(h *testHost) {
				h.docker.fail = failing(func(_, call string) bool { return call == "compose pull --quiet" })
			},
			want: "docker failed", transient: true,
		},
		"no room for images": {
			breakHost: func(h *testHost) {
				h.docker.fail = failing(func(_, call string) bool { return strings.Contains(call, "DockerRootDir") })
			},
			want: "docker failed", transient: true,
		},
		"userns-remap": {
			breakHost: func(h *testHost) { h.docker.security = `["name=seccomp,profile=builtin","name=userns"]` },
			want:      "userns-remap",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "v1.0.0", release.ChannelStable)
			h.offer("v1.1.0", tc.change)
			if tc.breakHost != nil {
				tc.breakHost(h)
			}
			err := h.upgrade(Request{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if name == "the network down" && !errors.Is(err, fetch.ErrNotFound) {
				t.Errorf("%v is not ErrNotFound", err)
			}
			if h.docker.called("compose stop") != 0 {
				t.Error("the deployment stopped")
			}
			st := h.state()
			if name != "userns-remap" && st.HasFailed("v1.1.0") == tc.transient {
				t.Errorf("marked failed: %v", st.Failed)
			}
			if _, err := os.Stat(filepath.Join(h.root, "easyrmm-v1.1.0")); err == nil {
				t.Error("the new bundle's directory is left")
			}
			for svc, dir := range h.docker.running {
				if dir != h.deploy("v1.0.0") {
					t.Errorf("%s runs from %s", svc, dir)
				}
			}
		})
	}
}

// A failure after the backup restores it: the data root as it was, the
// failed one kept aside, the previous version started, the audit IDs past
// the failed ones and the rollback recorded.
func TestUpgradeFailureRestores(t *testing.T) {
	for name, tc := range map[string]struct {
		fail func(h *testHost, dir, call string) bool
		step string
		// head is the discarded database's audit chain head, as the
		// restore reads it: its last ID and hash; "" when PostgreSQL does
		// not start to be read.
		head, headHash string
	}{
		"the held start": {
			fail: func(h *testHost, dir, call string) bool {
				return dir == h.deploy("v1.1.0") && strings.HasPrefix(call, "compose up") && strings.Contains(call, " server")
			},
			// The new server never started: the head is the backup's.
			step: StepStart, head: "42", headHash: testAuditHead,
		},
		"the server's readiness on loopback": {
			fail: func(h *testHost, dir, call string) bool {
				return dir == h.deploy("v1.1.0") && call == "compose exec -T server easyrmm-server healthcheck"
			},
			step: StepStart, head: "57", headHash: newerAuditHead,
		},
		"the worker": {
			fail: func(h *testHost, dir, call string) bool {
				return dir == h.deploy("v1.1.0") && strings.HasPrefix(call, "compose up") && strings.HasSuffix(call, " "+workerService)
			},
			step: StepConfirm, head: "57", headHash: newerAuditHead,
		},
		"PostgreSQL does not start": {
			fail: func(h *testHost, dir, call string) bool {
				return dir == h.deploy("v1.1.0") && strings.HasPrefix(call, "compose up")
			},
			step: StepStart,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "v1.0.0", release.ChannelStable)
			h.offer("v1.1.0", nil)
			h.docker.fail = func(dir string, args []string) error {
				if tc.fail(h, dir, strings.Join(args, " ")) {
					// The new version had written to the data root.
					writeFile(t, filepath.Join(h.dataRoot, "server", "data"), "written by v1.1.0", 0o600)
					return errors.New("container easyrmm-server-1 is unhealthy")
				}
				return nil
			}
			err := h.upgrade(Request{Automatic: true})
			if err == nil || !strings.Contains(err.Error(), "rolled-back") || !strings.Contains(err.Error(), "unhealthy") {
				t.Fatalf("got %v", err)
			}
			st := h.state()
			if st.Attempt.Result != ResultRolledBack || st.Running != "v1.0.0" || !st.HasFailed("v1.1.0") || st.Rollback != nil {
				t.Errorf("state %+v, attempt %+v", st, st.Attempt)
			}
			if got := readFile(t, filepath.Join(h.dataRoot, "server", "data")); got != "the data of v1.0.0" {
				t.Errorf("the data root holds %q", got)
			}
			failed, _ := filepath.Glob(filepath.Join(h.dataRoot, ".failed-*-v1.1.0"))
			if len(failed) != 1 || readFile(t, filepath.Join(failed[0], "server", "data")) != "written by v1.1.0" || mode(t, failed[0]) != 0o700 {
				t.Errorf("the failed data root kept aside: %v", failed)
			}
			for svc, dir := range h.docker.running {
				if dir != h.deploy("v1.0.0") {
					t.Errorf("%s runs from %s", svc, dir)
				}
			}
			if h.docker.running["server"] == "" || h.docker.running[workerService] == "" {
				t.Errorf("not everything runs: %v", h.docker.running)
			}
			if h.u.Config.Deployment != h.deploy("v1.0.0") || h.statusDir().Held() {
				t.Errorf("deployment %s, held %v", h.u.Config.Deployment, h.statusDir().Held())
			}
			if _, err := os.Stat(filepath.Join(h.root, "easyrmm-v1.1.0")); err == nil {
				t.Error("the failed bundle's directory is left")
			}
			// The audit IDs moved past the discarded ones, and the
			// rollback recorded, before the previous server started.
			last := h.docker.vars[len(h.docker.vars)-1]
			sql := h.docker.psql[len(h.docker.psql)-1]
			if !strings.Contains(sql, "setval") || !strings.Contains(sql, "easyrmm_audit_append") || !strings.Contains(sql, "'updater.rolled_back'") {
				t.Errorf("SQL %s", sql)
			}
			if tc.head != "" {
				if last["skip_to"] != tc.head || last["margin"] != "0" || !strings.Contains(last["details"], `"discardedHead":"`+tc.headHash+`"`) {
					t.Errorf("vars %v", last)
				}
			} else if last["skip_to"] != "0" || last["margin"] != "1000000" || !strings.Contains(last["details"], `"discardedHead":"unknown"`) {
				t.Errorf("vars %v", last)
			}
			if last["discarded"] != "v1.1.0" || !strings.Contains(last["details"], `"to":"v1.0.0"`) {
				t.Errorf("vars %v", last)
			}
			// The next successful upgrade removes the failed data root.
			h.docker.fail = nil
			h.now = h.now.Add(time.Hour)
			h.offer("v1.1.1", nil)
			if err := h.upgrade(Request{Automatic: true}); err != nil {
				t.Fatal(err)
			}
			if failed, _ := filepath.Glob(filepath.Join(h.dataRoot, ".failed-*")); len(failed) != 0 {
				t.Errorf("failed data roots left: %v", failed)
			}
		})
	}
}

// A failure after the deployment stopped and before its backup completed
// starts it again where it stopped.
func TestUpgradeFailureBeforeTheBackup(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	// The backup's directory cannot be made: a file has its name.
	writeFile(t, filepath.Join(h.u.Config.BackupDir, h.now.Format("20060102T150405Z")+"-v1.0.0"), "x", 0o600)
	err := h.upgrade(Request{})
	if err == nil || !strings.Contains(err.Error(), "rolled-back") || !strings.Contains(err.Error(), "backing up") {
		t.Fatalf("got %v", err)
	}
	if h.docker.running["server"] != h.deploy("v1.0.0") || h.state().Attempt.Step != StepBackup {
		t.Errorf("running %v, attempt %+v", h.docker.running, h.state().Attempt)
	}
	if h.docker.called("encode(entry_hash") != 0 && len(h.docker.psql) != 0 {
		t.Error("a restore ran without a backup")
	}
}

func TestUpgradeRollbackFails(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.offer("v1.1.0", nil)
	h.docker.fail = failing(func(_, call string) bool {
		return strings.HasPrefix(call, "compose up") && strings.Contains(call, "server")
	})
	err := h.upgrade(Request{})
	if err == nil || !strings.Contains(err.Error(), "rollback-failed") || !strings.Contains(err.Error(), "the backup: "+h.u.Config.BackupDir) {
		t.Fatalf("got %v", err)
	}
	if st := h.state(); st.Attempt.Result != ResultRollbackFailed {
		t.Errorf("attempt %+v", st.Attempt)
	}
}

// setup.sh failing restores the backup and starts the previous version.
func TestUpgradeSetupFails(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	files := bundleFiles("v1.1.0")
	files["easyrmm-v1.1.0/deploy/scripts/setup.sh"] = "#!/bin/sh\necho 'error: something' >&2\nexit 1\n"
	h.offerFiles("v1.1.0", files, nil)
	err := h.upgrade(Request{})
	if err == nil || !strings.Contains(err.Error(), "rolled-back") || !strings.Contains(err.Error(), "setup.sh --upgrade failed (exit status 1)") {
		t.Fatalf("got %v", err)
	}
	st := h.state()
	if st.Attempt.Step != StepRestore || st.Running != "v1.0.0" || h.docker.running["server"] != h.deploy("v1.0.0") || h.statusDir().Held() {
		t.Errorf("attempt %+v, running %v", st.Attempt, h.docker.running)
	}
}

// A bundle that sets up a deployment running other images than the
// manifest's is refused, and the previous version restored.
func TestUpgradeSetupChangesImages(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	files := bundleFiles("v1.1.0")
	files["easyrmm-v1.1.0/deploy/scripts/setup.sh"] = "#!/bin/sh\necho 'COMPOSE_PROFILES=authentik' >> .env\n"
	h.offerFiles("v1.1.0", files, nil)
	if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "not the manifest's") {
		t.Fatalf("got %v", err)
	}
	if h.docker.running["server"] != h.deploy("v1.0.0") {
		t.Errorf("running %v", h.docker.running)
	}
}

func TestRollback(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	ctx := context.Background()
	if _, err := h.u.PlanRollback(ctx, false); !errors.Is(err, errNoRollback) {
		t.Errorf("before any upgrade: %v", err)
	}
	h.offer("v1.1.0", nil)
	if err := h.upgrade(Request{}); err != nil {
		t.Fatal(err)
	}
	// Written since the upgrade, and lost by the rollback.
	writeFile(t, filepath.Join(h.dataRoot, "server", "data"), "written by v1.1.0", 0o600)
	h.now = h.now.Add(2 * time.Hour)
	plan, err := h.u.PlanRollback(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.To != "v1.0.0" || plan.From != "v1.1.0" || plan.Loss == nil || plan.Loss.DeviceCount != 2 || plan.Loss.Jobs != 7 || plan.Loss.Audit != 31 {
		t.Fatalf("plan %+v, loss %+v, %v", plan, plan.Loss, plan.LossErr)
	}
	if s := plan.Loss.String(); !strings.Contains(s, "2 devices") || !strings.Contains(s, "desk-1, desk-2") {
		t.Errorf("loss %q", s)
	}
	if err := h.u.Rollback(ctx, "root on the host", false); err != nil {
		t.Fatal(err)
	}
	st := h.state()
	if st.Running != "v1.0.0" || st.Rollback != nil || st.Attempt.Action != "rollback" || st.Attempt.Result != ResultRolledBack || !st.HasFailed("v1.1.0") {
		t.Errorf("state %+v, attempt %+v", st, st.Attempt)
	}
	if got := readFile(t, filepath.Join(h.dataRoot, "server", "data")); got != "the data of v1.0.0" {
		t.Errorf("the data root holds %q", got)
	}
	if h.u.Config.Deployment != h.deploy("v1.0.0") || h.docker.running["server"] != h.deploy("v1.0.0") {
		t.Errorf("deployment %s, running %v", h.u.Config.Deployment, h.docker.running)
	}
	if got := readFile(t, h.u.Install.Binary); got != "updater of v1.1.0" {
		t.Errorf("the updater went back to %q", got)
	}
	if _, err := h.u.PlanRollback(ctx, false); !errors.Is(err, errNoRollback) {
		t.Errorf("after the rollback: %v", err)
	}
	if err := h.u.Rollback(ctx, "x", false); !errors.Is(err, errNoRollback) {
		t.Errorf("a second rollback: %v", err)
	}
	// Automatic upgrades skip the version rolled back.
	if err := h.upgrade(Request{Automatic: true}); err != nil || h.state().Running != "v1.0.0" {
		t.Errorf("upgraded again to a version rolled back: %v", err)
	}
	// Asked for by name, it is taken.
	if err := h.upgrade(Request{Version: release.MustParseVersion("v1.1.0")}); err != nil || h.state().Running != "v1.1.0" {
		t.Errorf("asked for by name: %v, %s", err, h.state().Running)
	}
}

func TestRollbackRefused(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	ctx := context.Background()
	h.offer("v1.1.0", nil)
	if err := h.upgrade(Request{}); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(RollbackWindow)
	if _, err := h.u.PlanRollback(ctx, false); err == nil || !strings.Contains(err.Error(), "until") {
		t.Errorf("after 24 hours: %v", err)
	}
	if err := h.u.Rollback(ctx, "x", false); err == nil || !strings.Contains(err.Error(), "until") {
		t.Errorf("after 24 hours: %v", err)
	}
	h.now = h.now.Add(-time.Hour)
	// The updater's record says what the upgrade installed, but the
	// deployment was upgraded by hand since: .env and the server say so,
	// and the record is not acted on.
	envPath := filepath.Join(h.deploy("v1.1.0"), ".env")
	env := readFile(t, envPath)
	writeFile(t, envPath, strings.Replace(env, "EASYRMM_VERSION=1.1.0", "EASYRMM_VERSION=1.1.1", 1), 0o600)
	// With the server down, only .env says so.
	running := h.docker.running
	h.docker.running = map[string]string{}
	for _, err := range []error{h.u.Rollback(ctx, "x", false), planErr(h.u.PlanRollback(ctx, false))} {
		if err == nil || !strings.Contains(err.Error(), "the server says unknown, .env names v1.1.1, the updater last brought up v1.1.0, not v1.1.0 alone") {
			t.Errorf("upgraded by hand, the server down: %v", err)
		}
	}
	h.docker.running = running
	for _, err := range []error{h.u.Rollback(ctx, "x", false), planErr(h.u.PlanRollback(ctx, false))} {
		if err == nil || !strings.Contains(err.Error(), "the server says v1.1.1, .env names v1.1.1, the updater last brought up v1.1.1, not v1.1.0 alone") {
			t.Errorf("upgraded by hand since: %v", err)
		}
	}
	// A server that says it runs another version than .env names is not
	// acted on either.
	writeFile(t, envPath, env, 0o600)
	h.docker.serverSays = "v1.0.0"
	if err := h.u.Rollback(ctx, "x", false); err == nil || !strings.Contains(err.Error(), "the server says it runs v1.0.0, and the deployment's .env names v1.1.0") {
		t.Errorf("a server misreporting its version: %v", err)
	}
	h.docker.serverSays = ""
	st := h.state()
	st.Running = "v1.1.0"
	if err := st.save(h.u.StateDir); err != nil {
		t.Fatal(err)
	}
	// A backup that is not the one recorded.
	b, err := openBackup(st.Rollback.Backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(b.Dir, "backup.json")); err != nil {
		t.Fatal(err)
	}
	if err := h.u.Rollback(ctx, "x", false); err == nil || !strings.Contains(err.Error(), "not complete") {
		t.Errorf("an incomplete backup: %v", err)
	}
}

func planErr(_ *RollbackPlan, err error) error { return err }

func TestUpgradeLock(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	unlock, err := h.u.lock()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "another attempt") {
		t.Errorf("while locked: %v", err)
	}
	if err := h.u.Rollback(context.Background(), "x", false); err == nil || !strings.Contains(err.Error(), "another attempt") {
		t.Errorf("while locked: %v", err)
	}
	unlock()
	h.offer("v1.1.0", nil)
	if err := h.upgrade(Request{}); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeUnknownRunningVersion(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	envPath := filepath.Join(h.deploy("v1.0.0"), ".env")
	env, err := setEnv([]byte(readFile(t, envPath)), "EASYRMM_VERSION", "latest")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, envPath, string(env), 0o600)
	h.offer("v1.1.0", nil)
	if err := h.upgrade(Request{Automatic: true}); err == nil || !strings.Contains(err.Error(), "not one the updater knows") {
		t.Errorf("automatic, from an unknown version: %v", err)
	}
	if err := h.upgrade(Request{Version: release.MustParseVersion("v1.1.0")}); err != nil {
		t.Fatal(err)
	}
}

func TestStatusAndCheck(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	ctx := context.Background()
	h.offer("v1.1.0", nil)
	h.offer("v1.2.0-rc.1", nil)
	r, err := h.u.Check(ctx)
	if err != nil || r.VerifyErr != nil {
		t.Fatal(err, r.VerifyErr)
	}
	var out bytes.Buffer
	r.Write(&out)
	for _, want := range []string{"Running:  v1.0.0", "Offered:  v1.1.0\n", "Newest:   v1.1.0, verified (commit " + testCommit, "easyrmm-updater upgrade v1.1.0"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("check lacks %q:\n%s", want, out.String())
		}
	}
	if h.docker.called("compose stop") != 0 {
		t.Error("check changed something")
	}
	// Unverified: said so.
	h.offer("v1.1.1", func(_ *releasetest.Manifest, c *releasetest.Claims) {
		c.Commit = "1df9b49a5f0c1d4a7e7b1d6e3f1c8a2b9c0d1e2f"
	})
	if r, err = h.u.Check(ctx); err != nil || r.VerifyErr == nil {
		t.Fatalf("an unverified newest version: %v, %v", err, r.VerifyErr)
	}
	out.Reset()
	r.Write(&out)
	if !strings.Contains(out.String(), "v1.1.1, NOT verified") {
		t.Errorf("check:\n%s", out.String())
	}

	if err := h.upgrade(Request{Version: release.MustParseVersion("v1.1.0")}); err != nil {
		t.Fatal(err)
	}
	s, err := h.u.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	s.Write(&out)
	for _, want := range []string{
		"Running:     v1.1.0 (the server says v1.1.0)", "Previous:    v1.0.0", "automatic upgrades on, from 02:00 to 05:00",
		"Last attempt: upgrade v1.0.0 to v1.1.0, by a test", "Roll back:   to v1.0.0", "2 devices enrolled since",
		"Held:        false", "agent updates held until " + h.now.Add(RollbackWindow).Format(time.RFC3339), "-v1.0.0: v1.0.0, taken",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, out.String())
		}
	}
	// Up to date, then a version that failed.
	if r, err = h.u.Check(ctx); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	r.Write(&out)
	if !strings.Contains(out.String(), "newer than the running version") {
		t.Errorf("check:\n%s", out.String())
	}
	st := h.state()
	st.MarkFailed("v1.1.1")
	if err := st.save(h.u.StateDir); err != nil {
		t.Fatal(err)
	}
	if r, err = h.u.Check(ctx); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	r.Write(&out)
	if !strings.Contains(out.String(), "automatic upgrades skip it") {
		t.Errorf("check:\n%s", out.String())
	}
}

func TestReplaceFromRefusesAMissingBinary(t *testing.T) {
	dir := t.TempDir()
	in := Install{Binary: filepath.Join(dir, "sbin"), UnitDir: dir}
	if err := in.replaceFrom(context.Background(), filepath.Join(dir, "deploy")); err == nil {
		t.Error("installed nothing without an error")
	}
	if !strings.HasSuffix(bundledBinary("/x/deploy"), "easyrmm-updater-linux-"+runtime.GOARCH) {
		t.Error(bundledBinary("/x/deploy"))
	}
}
