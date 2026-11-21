package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// refusedBeforeStopping checks that an upgrade was refused at its check,
// with nothing stopped and nothing counted against the version.
func (h *testHost) refusedBeforeStopping(err error, want string) {
	h.t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		h.t.Fatalf("got %v, want %q", err, want)
	}
	st := h.state()
	if h.docker.called("compose stop") != 0 || st.HasFailed("v1.1.0") || st.Attempt.Step != StepCheck || st.Attempt.Result != ResultFailed {
		h.t.Errorf("stopped %d times, attempt %+v, failed %v", h.docker.called("compose stop"), st.Attempt, st.Failed)
	}
	if h.docker.running["server"] != h.deploy("v1.0.0") {
		h.t.Errorf("running %v", h.docker.running)
	}
}

// A data-root entry that is a link, or a mount point anywhere in the data
// root, is refused before anything stops: a backup would copy the link,
// not what it leads to, and a restore would put the link back over the
// failed version's data, or fail to move a mount point aside.
func TestDataRootLinksAndMountPoints(t *testing.T) {
	t.Run("a link", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		elsewhere := filepath.Join(t.TempDir(), "server")
		if err := os.Rename(filepath.Join(h.dataRoot, "server"), elsewhere); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(h.dataRoot, "server")); err != nil {
			t.Fatal(err)
		}
		h.offer("v1.1.0", nil)
		h.refusedBeforeStopping(h.upgrade(Request{}), filepath.Join(h.dataRoot, "server")+" is a link (to "+elsewhere+")")
	})
	for name, mount := range map[string]func(h *testHost) string{
		"a mount point":            func(h *testHost) string { return filepath.Join(h.dataRoot, "postgres") },
		"a mount point deeper":     func(h *testHost) string { return filepath.Join(h.dataRoot, "postgres", "18") },
		"a mount point with space": func(h *testHost) string { return filepath.Join(h.dataRoot, "my disk") },
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "v1.0.0", release.ChannelStable)
			point := mount(h)
			if err := os.MkdirAll(point, 0o700); err != nil {
				t.Fatal(err)
			}
			h.mounts(point)
			h.offer("v1.1.0", nil)
			h.refusedBeforeStopping(h.upgrade(Request{}), point+" is a mount point in the data root")
		})
	}
	t.Run("allowed", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		// The data root itself, what lies above it and the updater's own
		// directory may be mount points; links deeper down are the
		// services' own.
		if err := os.Symlink("/etc", filepath.Join(h.dataRoot, "server", "etc")); err != nil {
			t.Fatal(err)
		}
		h.mounts("/", filepath.Dir(h.dataRoot), h.dataRoot, filepath.Join(h.dataRoot, "updater", "status"), "/elsewhere")
		h.offer("v1.1.0", nil)
		if err := h.upgrade(Request{}); err != nil {
			t.Fatal(err)
		}
	})
}

// mounts lists points as the host's mount points.
func (h *testHost) mounts(points ...string) {
	h.t.Helper()
	var b strings.Builder
	for i, p := range points {
		fmt.Fprintf(&b, "%d 1 8:1 / %s rw,relatime shared:1 - ext4 /dev/sda1 rw\n", 30+i, strings.ReplaceAll(p, " ", `\040`))
	}
	path := filepath.Join(h.t.TempDir(), "mountinfo")
	writeFile(h.t, path, b.String(), 0o644)
	was := mountInfo
	mountInfo = path
	h.t.Cleanup(func() { mountInfo = was })
}

// The room needed on each filesystem is added up: the backup, a restore's
// copy of the data root, the images and the bundle all on one disk need
// all of it.
func TestRoomAddsUpPerFilesystem(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	writeFile(t, filepath.Join(h.dataRoot, "postgres", "18", "docker", "base"), strings.Repeat("x", 4<<20), 0o600)
	size, err := checkDataRoot(h.dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	// Room for each need alone, not for all of them.
	room := size + minImageSpace + 2*bundleSpace
	was := freeSpace
	freeSpace = func(string) (int64, error) { return room, nil }
	t.Cleanup(func() { freeSpace = was })
	h.offer("v1.1.0", nil)
	err = h.upgrade(Request{})
	h.refusedBeforeStopping(err, "the upgrade needs")
	for _, want := range []string{"the backup", "a restore's copy of the data root", "the new images", "the bundle's download", "the unpacked bundle"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v lacks %q", err, want)
		}
	}
	// With room for all of it, taken.
	room = 2*size + minImageSpace + 2*bundleSpace + 1<<20
	if err := h.upgrade(Request{}); err != nil {
		t.Fatal(err)
	}
}

// A backup that fails is removed before the previous version starts again;
// one that ran out of room does not count against the version, which the
// next attempt tries again.
func TestFailedBackupIsRemoved(t *testing.T) {
	t.Run("a copy that fails", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		h.offer("v1.1.0", nil)
		// The deployment's docker/ is missing: the backup copies the data
		// root, then fails.
		if err := os.RemoveAll(filepath.Join(h.root, "easyrmm-v1.0.0", "docker")); err != nil {
			t.Fatal(err)
		}
		err := h.upgrade(Request{})
		if err == nil || !strings.Contains(err.Error(), "backing up") {
			t.Fatalf("got %v", err)
		}
		if left, _ := filepath.Glob(filepath.Join(h.u.Config.BackupDir, "*")); len(left) != 0 {
			t.Errorf("left %v", left)
		}
		if h.docker.running["server"] != h.deploy("v1.0.0") || !h.state().HasFailed("v1.1.0") {
			t.Errorf("running %v, failed %v", h.docker.running, h.state().Failed)
		}
	})
	t.Run("no room", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		h.offer("v1.1.0", nil)
		cp := filepath.Join(t.TempDir(), "cp")
		writeFile(t, cp, "#!/bin/sh\necho \"cp: error writing '$7/x': No space left on device\" >&2\nexit 1\n", 0o755)
		was := cpProgram
		cpProgram = cp
		t.Cleanup(func() { cpProgram = was })
		err := h.upgrade(Request{Automatic: true})
		if err == nil || !strings.Contains(err.Error(), "rolled-back") || !strings.Contains(err.Error(), "No space left on device") {
			t.Fatalf("got %v", err)
		}
		if cerr := copyTree(t.Context(), h.dataRoot, filepath.Join(t.TempDir(), "copy")); !errors.Is(cerr, syscall.ENOSPC) {
			t.Errorf("a copy out of room: %v", cerr)
		}
		st := h.state()
		if st.HasFailed("v1.1.0") || st.Attempt.Result != ResultRolledBack || h.docker.running["server"] != h.deploy("v1.0.0") {
			t.Errorf("attempt %+v, failed %v, running %v", st.Attempt, st.Failed, h.docker.running)
		}
		if left, _ := filepath.Glob(filepath.Join(h.u.Config.BackupDir, "*")); len(left) != 0 {
			t.Errorf("left %v", left)
		}
		// Room again: the next automatic attempt takes it.
		cpProgram = was
		h.now = h.now.Add(time.Hour)
		if err := h.upgrade(Request{Automatic: true}); err != nil || h.state().Running != "v1.1.0" {
			t.Errorf("the next attempt: %v, running %s", err, h.state().Running)
		}
	})
}

// A data root inside the directory the deployment was installed from by
// hand (setup.sh --data-root /opt/easyrmm-v1.0.0/data) survives the
// upgrades that leave that deployment behind: of a directory the updater
// did not unpack, only .env goes.
func TestTidyKeepsADataRootInAnOldBundle(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	newRoot := filepath.Join(h.root, "easyrmm-v1.0.0", "data")
	if err := os.Rename(h.dataRoot, newRoot); err != nil {
		t.Fatal(err)
	}
	h.dataRoot, h.docker.dataRoot = newRoot, newRoot
	envPath := filepath.Join(h.deploy("v1.0.0"), ".env")
	env, err := setEnv([]byte(readFile(t, envPath)), "EASYRMM_DATA_ROOT", newRoot)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, envPath, string(env), 0o600)
	for _, v := range []string{"v1.1.0", "v1.2.0", "v1.3.0"} {
		h.offer(v, nil)
		if err := h.upgrade(Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := readFile(t, filepath.Join(newRoot, "server", "data")); got != "the data of v1.0.0" {
		t.Errorf("the data root holds %q", got)
	}
	if _, err := os.Stat(envPath); err == nil {
		t.Error("the old .env is left")
	}
}

// What runs is the highest of what the server says, what the updater
// recorded and what .env names, which a server cannot write; the server's
// word must agree with .env's.
func TestRunningVersionSources(t *testing.T) {
	t.Run("a server that says it is older", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		h.offer("v1.1.0", nil)
		h.offer("v1.2.0", stopAt("v1.1.0"))
		for _, v := range []string{"v1.1.0", "v1.2.0"} {
			if err := h.upgrade(Request{Version: release.MustParseVersion(v)}); err != nil {
				t.Fatal(err)
			}
		}
		h.u.Self = release.MustParseVersion("v1.2.0")
		h.offer("v1.3.0", stopAt("v1.2.0"))
		h.docker.serverSays = "v1.0.0"
		h.now = h.now.Add(time.Hour)
		err := h.upgrade(Request{Automatic: true})
		if err == nil || !strings.Contains(err.Error(), "the server says it runs v1.0.0, and the deployment's .env names v1.2.0: the updater does not act while they disagree") {
			t.Fatalf("got %v", err)
		}
		if st := h.state(); st.Running != "v1.2.0" || st.Attempt.To != "v1.2.0" {
			t.Errorf("running %s, attempt %+v", st.Running, st.Attempt)
		}
	})
	t.Run("upgraded by hand while the server is down", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		h.offer("v1.1.0", nil)
		if err := h.upgrade(Request{}); err != nil {
			t.Fatal(err)
		}
		// Upgraded by hand to v1.3.0 (.env), the updater's record still
		// v1.1.0, the server stopped.
		envPath := filepath.Join(h.deploy("v1.1.0"), ".env")
		writeFile(t, envPath, strings.Replace(readFile(t, envPath), "EASYRMM_VERSION=1.1.0", "EASYRMM_VERSION=1.3.0", 1), 0o600)
		h.docker.running = map[string]string{}
		h.offer("v1.2.0", nil)
		if err := h.upgrade(Request{Automatic: true}); err != nil {
			t.Fatal(err)
		}
		if err := h.upgrade(Request{Version: release.MustParseVersion("v1.2.0")}); err == nil || !strings.Contains(err.Error(), "older than the running v1.3.0") {
			t.Errorf("asked for by name: %v", err)
		}
		if h.docker.called("compose stop") != 1 {
			t.Error("upgraded below the version .env names")
		}
	})
	t.Run("a clone's .env and a server that disagrees with the record", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		envPath := filepath.Join(h.deploy("v1.0.0"), ".env")
		writeFile(t, envPath, strings.Replace(readFile(t, envPath), "EASYRMM_VERSION=1.0.0", "EASYRMM_VERSION=latest", 1), 0o600)
		if err := os.MkdirAll(h.u.StateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := (&State{Running: "v1.1.0"}).save(h.u.StateDir); err != nil {
			t.Fatal(err)
		}
		h.docker.serverSays = "v1.0.0"
		h.offer("v1.0.5", nil)
		if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "the server says it runs v1.0.0, and the updater last brought up v1.1.0") {
			t.Errorf("got %v", err)
		}
	})
}

// .env is read as setup.sh writes it, every line of it; what Compose would
// read otherwise is refused rather than misread.
func TestEnvSyntax(t *testing.T) {
	long := "A=1\nLONG=" + strings.Repeat("x", 70<<10) + "\nEASYRMM_ENCRYPTION_KEY=secret\nEASYRMM_DATA_ROOT=/data\n"
	if err := checkEnv([]byte(long)); err != nil {
		t.Fatal(err)
	}
	if envValue([]byte(long), "EASYRMM_DATA_ROOT") != "/data" {
		t.Error("a value after a long line was not read")
	}
	out, err := setEnv([]byte(long), "EASYRMM_VERSION", "1.2.3")
	if err != nil || !strings.Contains(string(out), "\nEASYRMM_ENCRYPTION_KEY=secret\nEASYRMM_DATA_ROOT=/data\nEASYRMM_VERSION=1.2.3\n") {
		t.Errorf("a line after a long one was dropped: %v", err)
	}
	for env, want := range map[string]string{
		"export EASYRMM_DATA_ROOT=/elsewhere\n":                   "line 1 is not KEY=value",
		"A=1\n  EASYRMM_DATA_ROOT=/elsewhere\n":                   "line 2 is not KEY=value",
		"EASYRMM_DATA_ROOT = /elsewhere\n":                        "line 1 is not KEY=value",
		"EASYRMM_DATA_ROOT=\"/elsewhere\"\n":                      "EASYRMM_DATA_ROOT's value is quoted",
		"EASYRMM_SMTP_FROM='EasyRMM <a@b>'\n":                     "EASYRMM_SMTP_FROM's value is quoted",
		"EASYRMM_DATA_ROOT=/a\nEASYRMM_DATA_ROOT=/b\n":            "sets EASYRMM_DATA_ROOT twice, on lines 1 and 2",
		"EASYRMM_DATA_ROOT=/srv/easyrmm # the data\n":             "is not plain",
		"EASYRMM_DATA_ROOT=${HOME}/easyrmm\n":                     "is not plain",
		"COMPOSE_PROFILES=authentik, patching\n":                  "is not plain",
		"EASYRMM_DATA_ROOT=/srv/easyrmm\r\n":                      "carriage return",
		"# comment\n\n  # indented comment\nEASYRMM_SECRET=a b\n": "",
	} {
		err := checkEnv([]byte(env))
		if (want == "") != (err == nil) || want != "" && !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", env, err, want)
		}
	}
	// The running deployment's is refused before anything is done.
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	envPath := filepath.Join(h.deploy("v1.0.0"), ".env")
	writeFile(t, envPath, "export "+readFile(t, envPath), 0o600)
	h.offer("v1.1.0", nil)
	if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "the deployment's .env line 1 is not KEY=value") {
		t.Errorf("got %v", err)
	}
}

// The data root the updater backs up is the one Compose mounts: when .env
// reads otherwise to Compose, the upgrade is refused before it stops.
func TestComposeDataRoot(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.docker.composeDataRoot = "/srv/elsewhere"
	h.offer("v1.1.0", nil)
	h.refusedBeforeStopping(h.upgrade(Request{}), "the data root it reads is /srv/elsewhere, not "+h.dataRoot)
}

// New versions are unpacked, and their setup.sh run, in the updater's own
// bundle directory, which only root may change, nor any directory above
// it; not beside a deployment installed in a directory others can write.
func TestBundleDirectory(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	h.u.BundleDir = filepath.Join(filepath.Dir(h.root), "bundles", "easyrmm")
	h.offer("v1.1.0", nil)
	for _, c := range []struct {
		dir  string
		mode os.FileMode
		want string
	}{
		{filepath.Dir(h.u.BundleDir), 0o777, "bundles, above " + h.u.BundleDir + ", can be written by others than root (mode 777)"},
		{filepath.Dir(h.u.BundleDir), 0o775, "can be written by others than root (mode 775)"},
		{h.u.BundleDir, 0o757, h.u.BundleDir + " can be written by others than root (mode 757)"},
	} {
		if err := os.MkdirAll(h.u.BundleDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(c.dir, c.mode); err != nil {
			t.Fatal(err)
		}
		h.refusedBeforeStopping(h.upgrade(Request{}), c.want)
		if err := os.Chmod(c.dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A sticky directory above it, as /tmp, is fine.
	if err := os.Chmod(filepath.Dir(h.u.BundleDir), 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := h.upgrade(Request{}); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(h.u.BundleDir, "easyrmm-v1.1.0", "deploy")
	if h.u.Config.Deployment != want || h.docker.running["server"] != want {
		t.Errorf("deployment %s, running %v", h.u.Config.Deployment, h.docker.running)
	}
	if _, err := os.Stat(filepath.Join(h.root, "easyrmm-v1.1.0")); err == nil {
		t.Error("unpacked beside the old deployment")
	}
}
