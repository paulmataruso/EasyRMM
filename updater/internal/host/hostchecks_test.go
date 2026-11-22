package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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

// A data-root entry that is a link, a link at any depth that leads out of
// the data root, or a mount point anywhere in the data root, is refused
// before anything stops: a backup would copy the link, not what it leads
// to, and a restore would put the link back over the failed version's data,
// or fail to move a mount point aside.
func TestDataRootLinksAndMountPoints(t *testing.T) {
	t.Run("a link a service mounts", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		elsewhere := filepath.Join(t.TempDir(), "server")
		if err := os.Rename(filepath.Join(h.dataRoot, "server"), elsewhere); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(h.dataRoot, "server")); err != nil {
			t.Fatal(err)
		}
		h.offer("v1.1.0", nil)
		h.refusedBeforeStopping(h.upgrade(Request{}), "mounts "+filepath.Join(h.dataRoot, "server")+" at /var/lib/easyrmm, which leads, through a link, to "+elsewhere+", outside the data root")
	})
	t.Run("a link at the top", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		inside := filepath.Join(h.dataRoot, "server")
		if err := os.Symlink(inside, filepath.Join(h.dataRoot, "other")); err != nil {
			t.Fatal(err)
		}
		h.offer("v1.1.0", nil)
		h.refusedBeforeStopping(h.upgrade(Request{}), filepath.Join(h.dataRoot, "other")+" is a link (to "+inside+")")
	})
	for name, target := range map[string]func(h *testHost) string{
		"a link deeper out":          func(h *testHost) string { return h.t.TempDir() },
		"a relative link deeper out": func(*testHost) string { return "../../../elsewhere" },
		"a link deeper to nothing":   func(*testHost) string { return "/nonexistent/bigdisk" },
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "v1.0.0", release.ChannelStable)
			to := target(h)
			link := filepath.Join(h.dataRoot, "server", "files", "big")
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(to, link); err != nil {
				t.Fatal(err)
			}
			h.offer("v1.1.0", nil)
			h.refusedBeforeStopping(h.upgrade(Request{}), link+" is a link (to "+to+") that leads out of the data root")
		})
	}
	// A mount whose way, below the data root's top, goes through a link out
	// of it: Docker follows the link.
	t.Run("a mount through a link", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "srv")
		bigdisk := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "meshcentral"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(bigdisk, filepath.Join(root, "meshcentral", "files")); err != nil {
			t.Fatal(err)
		}
		deploy := filepath.Join(t.TempDir(), "easyrmm-v1.0.0", "deploy")
		mounts := []composeMount{{Service: "meshcentral", Type: "bind", Source: filepath.Join(root, "meshcentral", "files"), Target: "/opt/meshcentral/meshcentral-files"}}
		err := checkMounts(mounts, root, deploy)
		if err == nil || !strings.Contains(err.Error(), "which leads, through a link, to "+bigdisk) {
			t.Errorf("got %v", err)
		}
		// One that does not exist yet, below a link out: Docker makes it
		// there.
		mounts[0].Source = filepath.Join(root, "meshcentral", "files", "new", "dir")
		if err := checkMounts(mounts, root, deploy); err == nil || !strings.Contains(err.Error(), "which leads, through a link, to "+filepath.Join(bigdisk, "new", "dir")) {
			t.Errorf("not there yet: %v", err)
		}
		// Through the data root's own link, inside it: taken.
		link := filepath.Join(t.TempDir(), "data")
		if err := os.Symlink(root, link); err != nil {
			t.Fatal(err)
		}
		mounts[0].Source = filepath.Join(link, "meshcentral", "data")
		if err := checkMounts(mounts, root, deploy); err != nil {
			t.Errorf("through the data root's link: %v", err)
		}
		mounts[0].Source = filepath.Join(root, "meshcentral", "data")
		if err := checkMounts(mounts, link, deploy); err != nil {
			t.Errorf("the data root named by its link: %v", err)
		}
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
		// directory may be mount points; links deeper down that lead into
		// the data root are copied as they are.
		if err := os.Symlink("../postgres/18", filepath.Join(h.dataRoot, "server", "relative")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(h.dataRoot, "postgres"), filepath.Join(h.dataRoot, "server", "absolute")); err != nil {
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
// copy of the data root (a restore done again removes the first's before
// it copies), a restore's copy of the deployment's directory, the images
// and the bundle all on one disk need all of it. A file counts as the larger of its
// length and its blocks: a copy may fill a file's holes.
func TestRoomAddsUpPerFilesystem(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	writeFile(t, filepath.Join(h.dataRoot, "postgres", "18", "docker", "base"), strings.Repeat("x", 4<<20), 0o600)
	// 64 MiB long, with no block written.
	sparse, err := os.Create(filepath.Join(h.dataRoot, "server", "sparse"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sparse.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	if err := sparse.Close(); err != nil {
		t.Fatal(err)
	}
	size, err := checkDataRoot(h.dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	if size < 68<<20 {
		t.Errorf("the data root measures %d bytes, less than its files' lengths", size)
	}
	tree, err := deploymentSize(h.deploy("v1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	// Room for each need alone, not for all of them.
	room := 2*size + minImageSpace + 2*bundleSpace
	was := freeSpace
	freeSpace = func(string) (int64, error) { return room, nil }
	t.Cleanup(func() { freeSpace = was })
	h.offer("v1.1.0", nil)
	err = h.upgrade(Request{})
	h.refusedBeforeStopping(err, "the upgrade needs")
	for _, want := range []string{"the backup", "a restore's copy of the data root ", "a restore's copy of the deployment's directory", "the new images", "the bundle's download", "the unpacked bundle"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v lacks %q", err, want)
		}
	}
	// With room for all of it but the restore's copy of the deployment's
	// directory, refused.
	room = 2*size + 2*tree + minImageSpace + 2*bundleSpace - 1
	err = h.upgrade(Request{})
	h.refusedBeforeStopping(err, "the upgrade needs")
	// With room for all of it, taken.
	room++
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
}

// An attempt that runs out of room once the deployment has stopped does
// not count against the version, nor do automatic upgrades try it again
// every hour, each time stopping the deployment: they wait until an
// operator, having made room, asks for it. status and status.json (the
// console's) say how many bytes it needed.
func TestOutOfRoomAfterTheStop(t *testing.T) {
	for name, tc := range map[string]struct {
		run   func(h *testHost) // the attempt that runs out
		short func(h *testHost, st *State) int64
		path  func(h *testHost) string
	}{
		"in the backup": {
			run: func(h *testHost) {
				// It runs out at its first copy.
				cp := filepath.Join(h.t.TempDir(), "cp")
				writeFile(h.t, cp, "#!/bin/sh\necho \"cp: error writing '$6/x': No space left on device\" >&2\nexit 1\n", 0o755)
				was := cpProgram
				cpProgram = cp
				defer func() { cpProgram = was }()
				if err := h.upgrade(Request{Automatic: true}); err == nil || !strings.Contains(err.Error(), "rolled-back") || !strings.Contains(err.Error(), "No space left on device") {
					h.t.Fatalf("got %v", err)
				}
			},
			// What it still had to copy: all of it, less the backup's
			// directory and its data/, which it had made.
			short: func(h *testHost, _ *State) int64 {
				data, err := checkDataRoot(h.dataRoot)
				if err != nil {
					h.t.Fatal(err)
				}
				tree, err := deploymentSize(h.deploy("v1.0.0"))
				if err != nil {
					h.t.Fatal(err)
				}
				made := h.t.TempDir()
				if err := os.Mkdir(filepath.Join(made, "data"), 0o700); err != nil {
					h.t.Fatal(err)
				}
				dirs, err := treeSize(made)
				if err != nil {
					h.t.Fatal(err)
				}
				return data + tree - dirs
			},
			path: func(h *testHost) string { return h.u.Config.BackupDir },
		},
		"in the held start": {
			run: func(h *testHost) {
				h.docker.fail = func(dir string, args []string) error {
					if dir == h.deploy("v1.1.0") && slices.Contains(args, "--wait") {
						// Free space ran out under the new images.
						freeSpace = func(string) (int64, error) { return 1 << 20, nil }
						return errors.New("Error response from daemon: write /var/lib/docker/overlay2/x: no space left on device")
					}
					return nil
				}
				defer func() { h.docker.fail = nil }()
				if err := h.upgrade(Request{Automatic: true}); err == nil || !strings.Contains(err.Error(), "rolled-back") {
					h.t.Fatalf("got %v", err)
				}
			},
			// The most any filesystem lacks of what the room check counts.
			short: func(h *testHost, _ *State) int64 {
				data, err := checkDataRoot(h.dataRoot)
				if err != nil {
					h.t.Fatal(err)
				}
				tree, err := deploymentSize(h.deploy("v1.0.0"))
				if err != nil {
					h.t.Fatal(err)
				}
				// One disk holds everything.
				return 2*data + 2*tree + minImageSpace + 2*bundleSpace - 1<<20
			},
			path: func(h *testHost) string { return h.u.Config.BackupDir },
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "v1.0.0", release.ChannelStable)
			was := freeSpace
			t.Cleanup(func() { freeSpace = was })
			h.offer("v1.1.0", nil)
			tc.run(h)
			freeSpace = was
			st := h.state()
			want := &NeedsRoom{Version: "v1.1.0", Short: tc.short(h, st), Path: tc.path(h)}
			if st.NeedsRoom == nil || *st.NeedsRoom != *want || st.HasFailed("v1.1.0") || st.Attempt.Result != ResultRolledBack || h.docker.running["server"] != h.deploy("v1.0.0") {
				t.Fatalf("needs room %+v, not %+v; failed %v, attempt %+v, running %v", st.NeedsRoom, want, st.Failed, st.Attempt, h.docker.running)
			}
			if left, _ := filepath.Glob(filepath.Join(h.u.Config.BackupDir, "*-v1.0.0")); name == "in the backup" && len(left) != 0 {
				t.Errorf("left %v", left)
			}
			says := fmt.Sprintf("v1.1.0 needs room: %d bytes short on the filesystem of %s", want.Short, want.Path)
			if status := readFile(t, h.statusDir().path(StatusFile)); !strings.Contains(status, fmt.Sprintf(`"short": %d`, want.Short)) {
				t.Errorf("status.json:\n%s", status)
			}
			s, err := h.u.Status(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var out strings.Builder
			s.Write(&out)
			if !strings.Contains(out.String(), says) {
				t.Errorf("status lacks %q:\n%s", says, out.String())
			}
			// Room again: the timer's runs wait for an operator.
			h.now = h.now.Add(time.Hour)
			stops := h.docker.called("compose stop")
			if err := h.upgrade(Request{Automatic: true}); err != nil || h.docker.called("compose stop") != stops || h.docker.running["server"] != h.deploy("v1.0.0") {
				t.Errorf("the next automatic run: %v, running %v", err, h.docker.running)
			}
			// The operator's run takes it.
			if err := h.upgrade(Request{}); err != nil || h.state().Running != "v1.1.0" || h.state().NeedsRoom != nil {
				t.Errorf("the operator's run: %v, state %+v", err, h.state())
			}
		})
	}
	// A copy out of room says so.
	cp := filepath.Join(t.TempDir(), "cp")
	writeFile(t, cp, "#!/bin/sh\necho \"cp: error writing '$7/x': No space left on device\" >&2\nexit 1\n", 0o755)
	was := cpProgram
	cpProgram = cp
	t.Cleanup(func() { cpProgram = was })
	src := t.TempDir()
	if cerr := copyTree(t.Context(), src, filepath.Join(t.TempDir(), "copy")); !errors.Is(cerr, syscall.ENOSPC) {
		t.Errorf("a copy out of room: %v", cerr)
	}
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

// .env is read by Compose's rules, every line of it; what Compose would
// read otherwise is refused rather than misread (TestEnvLikeCompose).
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
		"export EASYRMM_DATA_ROOT=/elsewhere\n":                         "line 1 is not KEY=value",
		"A=1\n  EASYRMM_DATA_ROOT=/elsewhere\n":                         "line 2 is not KEY=value",
		"EASYRMM_DATA_ROOT = /elsewhere\n":                              "line 1 is not KEY=value",
		"EASYRMM_DATA_ROOT=\"/srv/easyrmm\" # the data\n":               "",
		"EASYRMM_SMTP_FROM='EasyRMM <a@b>'\n":                           "",
		"EASYRMM_DATA_ROOT=/a\nEASYRMM_DATA_ROOT=/b\n":                  "sets EASYRMM_DATA_ROOT twice, on lines 1 and 2",
		"EASYRMM_DATA_ROOT=/srv/easyrmm # the data\n":                   "",
		"EASYRMM_DATA_ROOT=/srv/easyrmm#data\n":                         "is not plain",
		"EASYRMM_SMTP_FROM=\"EasyRMM\nEASYRMM_DATA_ROOT=/elsewhere\"\n": "line 1: EASYRMM_SMTP_FROM's quoted value does not end on its line",
		"EASYRMM_DATA_ROOT=${HOME}/easyrmm\n":                           "is not plain",
		"COMPOSE_PROFILES=authentik, patching\n":                        "is not plain",
		"EASYRMM_DATA_ROOT=/srv/easyrmm\r\n":                            "carriage return",
		"# comment\n\n  # indented comment\nEASYRMM_SECRET=a b\n":       "",
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

// setupEnv runs setup.sh's check_env on env, in dir, then its env_value
// for key, as setup.sh reads .env.
func setupEnv(t *testing.T, dir, env, key string) (string, error) {
	t.Helper()
	script := readFile(t, "../../../deploy/scripts/setup.sh")
	part := func(start string) string {
		at := strings.Index(script, "\n"+start)
		if at < 0 {
			t.Fatalf("setup.sh has no %s", start)
		}
		end := strings.Index(script[at+1:], "\n}\n")
		if strings.HasSuffix(start, "=") {
			end = strings.Index(script[at+1:], "\n")
			return script[at+1 : at+1+end+1]
		}
		return script[at+1 : at+1+end+3]
	}
	harness := "set -euo pipefail\ndie() { echo \"error: $*\" >&2; exit 1; }\n" + part("env_read=") + part("check_env() {") + part("env_value() {") +
		"cd \"$1\"\ncheck_env .env\nenv_value \"$2\"\n"
	writeFile(t, filepath.Join(dir, ".env"), env, 0o600)
	cmd := exec.Command("bash", "-c", harness, "setup.sh", dir, key)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s(%w)", out, err)
	}
	return strings.TrimSuffix(string(out), "\n"), nil
}

// composeEnv is what docker compose reads of keys from env, its .env.
func composeEnv(t *testing.T, dir, env string, keys ...string) (map[string]string, error) {
	t.Helper()
	var b strings.Builder
	b.WriteString("services:\n  s:\n    image: busybox\n    environment:\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "      %s: \"${%s-<unset>}\"\n", k, k)
	}
	writeFile(t, filepath.Join(dir, "docker-compose.yml"), b.String(), 0o644)
	writeFile(t, filepath.Join(dir, ".env"), env, 0o600)
	cmd := exec.Command("docker", "compose", "config", "--format", "json")
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var config struct {
		Services map[string]struct {
			Environment map[string]string `json:"environment"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &config); err != nil {
		return nil, err
	}
	got := map[string]string{}
	for k, v := range config.Services["s"].Environment {
		// config writes a $ as $$.
		got[k] = strings.ReplaceAll(v, "$$", "$")
	}
	return got, nil
}

// .env is read by Compose's rules, by the updater and by setup.sh alike:
// what either reads, Compose reads the same, and the lines after it too;
// what either would read otherwise, it refuses. A sender with a name is
// read as written, quoted or not (docs/operations/mail.md).
func TestEnvLikeCompose(t *testing.T) {
	_, noCompose := exec.Command("docker", "compose", "version").Output()
	const from, root, password = "EASYRMM_SMTP_FROM", "EASYRMM_DATA_ROOT", "EASYRMM_SMTP_PASSWORD"
	for _, c := range []struct {
		line, key string
		// want is what Compose reads; goErr and shErr are the updater's
		// and setup.sh's refusals, "" when they read it.
		want, goErr, shErr string
	}{
		{line: `EASYRMM_SMTP_FROM=EasyRMM <rmm@example.com>`, key: from, want: "EasyRMM <rmm@example.com>"},
		{line: `EASYRMM_SMTP_FROM="EasyRMM <rmm@example.com>"`, key: from, want: "EasyRMM <rmm@example.com>"},
		{line: `EASYRMM_SMTP_FROM='EasyRMM <rmm@example.com>'`, key: from, want: "EasyRMM <rmm@example.com>"},
		{line: `EASYRMM_SMTP_FROM="EasyRMM <rmm@example.com>"  # the sender`, key: from, want: "EasyRMM <rmm@example.com>"},
		{line: `EASYRMM_SMTP_FROM=EasyRMM <rmm@example.com> # the sender`, key: from, want: "EasyRMM <rmm@example.com>"},
		{line: `EASYRMM_SMTP_FROM="Ops \"Night\" Desk <rmm@example.com>"`, key: from, want: `Ops "Night" Desk <rmm@example.com>`},
		{line: `EASYRMM_SMTP_PASSWORD='p#ss w$rd'`, key: password, want: "p#ss w$rd"},
		{line: `EASYRMM_SMTP_PASSWORD=p#ss\w0rd`, key: password, want: `p#ss\w0rd`},
		{line: `EASYRMM_SMTP_PASSWORD="a\\b$$c"`, key: password, want: `a\b$c`},
		{line: `EASYRMM_DATA_ROOT=/srv/easyrmm`, key: root, want: "/srv/easyrmm"},
		{line: `EASYRMM_DATA_ROOT="/srv/easyrmm"`, key: root, want: "/srv/easyrmm"},
		{line: `EASYRMM_DATA_ROOT='/srv/easyrmm' # where the data is`, key: root, want: "/srv/easyrmm"},
		{line: "EASYRMM_DATA_ROOT=  /srv/easyrmm \t # where the data is", key: root, want: "/srv/easyrmm"},
		{line: `EASYRMM_DATA_ROOT=/srv/easyrmm#data`, key: root, want: "/srv/easyrmm#data", goErr: "is not plain"},
		{line: `EASYRMM_DATA_ROOT="${HOME}/easyrmm"`, key: root, goErr: "is not plain", shErr: "holds a backslash, a $ or a quote"},
		{line: `EASYRMM_DATA_ROOT="/srv/easy\"rmm"`, key: root, goErr: "is not plain", shErr: "holds a backslash, a $ or a quote"},
		{line: `EASYRMM_DATA_ROOT=/srv/"easyrmm"`, key: root, goErr: "is not plain", shErr: "holds a backslash, a $ or a quote"},
		{line: `export EASYRMM_DATA_ROOT=/srv/easyrmm`, key: root, goErr: "line 1 is not KEY=value", shErr: "line 1 is not KEY=value"},
		{line: `  EASYRMM_DATA_ROOT=/srv/easyrmm`, key: root, goErr: "line 1 is not KEY=value", shErr: "line 1 is not KEY=value"},
		{line: `EASYRMM_DATA_ROOT = /srv/easyrmm`, key: root, goErr: "line 1 is not KEY=value", shErr: "line 1 is not KEY=value"},
		{line: `EASYRMM_SMTP_FROM="EasyRMM <rmm@example.com>`, key: from, goErr: "quoted value does not end on its line", shErr: "quoted value does not end on its line"},
		{line: `EASYRMM_SMTP_FROM="EasyRMM" <rmm@example.com>`, key: from, goErr: "text follows its closing quote", shErr: "text follows its closing quote"},
		{line: `EASYRMM_SMTP_FROM='it''s'`, key: from, goErr: "text follows its closing quote", shErr: "text follows its closing quote"},
		{line: "EASYRMM_SMTP_FROM=\"EasyRMM\nEASYRMM_DATA_ROOT=/elsewhere\"", key: root, goErr: "line 1: EASYRMM_SMTP_FROM's quoted value does not end", shErr: "line 1: EASYRMM_SMTP_FROM's quoted value does not end"},
		{line: "EASYRMM_DATA_ROOT=/srv/easyrmm\r", key: root, goErr: "carriage return", shErr: "control character"},
		{line: "EASYRMM_SMTP_FROM=\u00a0\"EasyRMM", key: from, goErr: "starts with a blank other than", shErr: "starts with a blank other than"},
	} {
		env := c.line + "\nB=after\n"
		err := checkEnv([]byte(env))
		if c.goErr == "" && err != nil || c.goErr != "" && (err == nil || !strings.Contains(err.Error(), c.goErr)) {
			t.Errorf("%q: the updater: %v, want %q", c.line, err, c.goErr)
		}
		if err == nil && (slices.Contains(envKeysRead, c.key) && envValue([]byte(env), c.key) != c.want || envValue([]byte(env), "B") != "after") {
			t.Errorf("%q: the updater reads %q, and B=%q", c.line, envValue([]byte(env), c.key), envValue([]byte(env), "B"))
		}
		got, err := setupEnv(t, t.TempDir(), env, c.key)
		switch {
		// setup.sh reads EASYRMM_DATA_ROOT, not the mail server.
		case c.shErr == "" && (err != nil || c.key == root && got != c.want):
			t.Errorf("%q: setup.sh: %q, %v", c.line, got, err)
		case c.shErr != "" && (err == nil || !strings.Contains(err.Error(), c.shErr)):
			t.Errorf("%q: setup.sh: %q, %v, want %q", c.line, got, err, c.shErr)
		}
		if c.want == "" || noCompose != nil {
			continue
		}
		read, err := composeEnv(t, t.TempDir(), env, c.key, "B")
		if err != nil || read[c.key] != c.want || read["B"] != "after" {
			t.Errorf("%q: Compose reads %q, %v", c.line, read, err)
		}
	}
	if noCompose != nil {
		t.Logf("no docker compose here: %v", noCompose)
	}
	// What setup.sh reads, it checks; and the release's .env.example passes.
	script := readFile(t, "../../../deploy/scripts/setup.sh")
	reads := regexp.MustCompile(`\$\(env_value ([A-Z][A-Z_]+)\)`).FindAllStringSubmatch(script, -1)
	if len(reads) < 15 {
		t.Errorf("setup.sh reads %d settings", len(reads))
	}
	for _, m := range reads {
		if !regexp.MustCompile(`\nenv_read="[^"\n]* ` + m[1] + ` `).MatchString(script) {
			t.Errorf("setup.sh reads %s, which env_read does not list", m[1])
		}
	}
	example := readFile(t, "../../../deploy/.env.example")
	if err := checkEnv([]byte(example)); err != nil {
		t.Errorf(".env.example: %v", err)
	}
	if _, err := setupEnv(t, t.TempDir(), example, "EASYRMM_DATA_ROOT"); err != nil {
		t.Errorf(".env.example, by setup.sh: %v", err)
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
		{filepath.Dir(h.u.BundleDir), 0o777, "bundles, on the way to " + h.u.BundleDir + ", can be written by others than root (mode 777)"},
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

// A link on the way to the bundle directory is taken when it belongs to
// root, and only root can change the way to where it leads, element by
// element, links and all: whoever could would change where the updater
// unpacks.
func TestBundleDirectoryBehindALink(t *testing.T) {
	setUp := func(t *testing.T) (h *testHost, base, real, link string) {
		t.Helper()
		h = newTestHost(t, "v1.0.0", release.ChannelStable)
		base = filepath.Dir(h.root)
		real = filepath.Join(base, "disks", "real")
		if err := os.MkdirAll(real, 0o755); err != nil {
			t.Fatal(err)
		}
		// A link to a link: bundles -> disks/current -> real.
		if err := os.Symlink("real", filepath.Join(base, "disks", "current")); err != nil {
			t.Fatal(err)
		}
		link = filepath.Join(base, "bundles")
		if err := os.Symlink("disks/current", link); err != nil {
			t.Fatal(err)
		}
		h.u.BundleDir = filepath.Join(link, "easyrmm")
		h.offer("v1.1.0", nil)
		return h, base, real, link
	}
	t.Run("root's", func(t *testing.T) {
		h, _, real, _ := setUp(t)
		if err := h.upgrade(Request{}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(real, "easyrmm", "easyrmm-v1.1.0", "deploy", "docker-compose.yml")); err != nil {
			t.Error(err)
		}
	})
	t.Run("where it leads written by others", func(t *testing.T) {
		h, base, _, _ := setUp(t)
		disks := filepath.Join(base, "disks")
		if err := os.Chmod(disks, 0o777); err != nil {
			t.Fatal(err)
		}
		h.refusedBeforeStopping(h.upgrade(Request{}), disks+", on the way to "+h.u.BundleDir+", can be written by others than root (mode 777)")
	})
	t.Run("a loop", func(t *testing.T) {
		h, base, _, _ := setUp(t)
		current := filepath.Join(base, "disks", "current")
		if err := os.Remove(current); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../bundles", current); err != nil {
			t.Fatal(err)
		}
		h.refusedBeforeStopping(h.upgrade(Request{}), "too many levels of symbolic links")
		if err := rootOnlyWay(filepath.Join(base, "bundles"), h.u.BundleDir); err == nil || !strings.Contains(err.Error(), "more than 40 links on the way to "+filepath.Join(base, "bundles")) {
			t.Errorf("followed: %v", err)
		}
	})
	t.Run("someone else's", func(t *testing.T) {
		if os.Getuid() != 0 {
			t.Skip("only root gives a link to someone else")
		}
		h, base, _, _ := setUp(t)
		current := filepath.Join(base, "disks", "current")
		if err := os.Lchown(current, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		h.refusedBeforeStopping(h.upgrade(Request{}), current+", a link (to real) on the way to "+h.u.BundleDir+", does not belong to root")
	})
}

// The mount points looked at are those whose names lie in the data root,
// or in where a link to it leads; a mount point elsewhere is not followed,
// so that a link on it, or a network mount that does not answer, does not
// matter.
func TestDataRootMountPointsByName(t *testing.T) {
	t.Run("the data root through a link", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		// .env names a link to the data root; the host's mount table
		// names the mount point by where it is.
		link := filepath.Join(t.TempDir(), "data")
		if err := os.Symlink(h.dataRoot, link); err != nil {
			t.Fatal(err)
		}
		env := filepath.Join(h.deploy("v1.0.0"), ".env")
		writeFile(t, env, strings.Replace(readFile(t, env), "EASYRMM_DATA_ROOT="+h.dataRoot, "EASYRMM_DATA_ROOT="+link, 1), 0o600)
		point := filepath.Join(h.dataRoot, "postgres")
		h.mounts(point)
		h.offer("v1.1.0", nil)
		h.refusedBeforeStopping(h.upgrade(Request{}), point+" is a mount point in the data root")
	})
	t.Run("a link elsewhere into it", func(t *testing.T) {
		h := newTestHost(t, "v1.0.0", release.ChannelStable)
		// A mount point listed under a name that, through a link, leads
		// into the data root: not followed.
		dir := t.TempDir()
		if err := os.Symlink(filepath.Join(h.dataRoot, "server"), filepath.Join(dir, "elsewhere")); err != nil {
			t.Fatal(err)
		}
		h.mounts(filepath.Join(dir, "elsewhere"))
		h.offer("v1.1.0", nil)
		if err := h.upgrade(Request{}); err != nil {
			t.Fatal(err)
		}
	})
}

// The updater backs up, restores and starts the deployment as its
// docker-compose.yml says, with what that mounts: so it refuses, before
// anything stops, any other file Compose would read, a .env that changes
// which files Compose reads, and a mount of anything a backup does not
// hold, each saying why.
func TestComposeFilesAndMounts(t *testing.T) {
	bind := func(source, target string, ro bool) map[string]any {
		return map[string]any{"type": "bind", "source": source, "target": target, "read_only": ro}
	}
	for name, tc := range map[string]struct {
		change func(h *testHost)
		want   string // "" when it is allowed
	}{
		"an override file": {
			change: func(h *testHost) {
				writeFile(h.t, filepath.Join(h.deploy("v1.0.0"), "docker-compose.override.yml"), "services: {}\n", 0o644)
			},
			want: "docker-compose.override.yml is in " + "%deploy%",
		},
		"compose.yaml beside it": {
			change: func(h *testHost) {
				writeFile(h.t, filepath.Join(h.deploy("v1.0.0"), "compose.yaml"), "services: {}\n", 0o644)
			},
			want: "compose.yaml is in",
		},
		"COMPOSE_FILE in .env": {
			change: func(h *testHost) { h.appendEnv("COMPOSE_FILE=docker-compose.yml:extra.yml\n") },
			want:   ".env line 5 sets COMPOSE_FILE",
		},
		"COMPOSE_PROJECT_NAME in .env": {
			change: func(h *testHost) { h.appendEnv("COMPOSE_PROJECT_NAME=other\n") },
			want:   ".env line 5 sets COMPOSE_PROJECT_NAME",
		},
		"a named volume": {
			change: func(h *testHost) {
				h.docker.mounts = map[string][]map[string]any{"server": {{"type": "volume", "source": "easyrmm_cache", "target": "/cache"}}}
			},
			want: "the service server mounts a volume volume at /cache",
		},
		"a directory outside": {
			change: func(h *testHost) {
				h.docker.mounts = map[string][]map[string]any{"meshcentral": {bind("/var/lib/elsewhere", "/x", false)}}
			},
			want: "the service meshcentral mounts /var/lib/elsewhere at /x, outside the data root",
		},
		"the data root whole": {
			change: func(h *testHost) {
				h.docker.mounts = map[string][]map[string]any{"meshcentral": {bind(h.dataRoot, "/x", false)}}
			},
			want: "mounts " + "%dataRoot%" + " at /x, outside the data root",
		},
		"a failed data root": {
			change: func(h *testHost) {
				h.docker.mounts = map[string][]map[string]any{"meshcentral": {bind(filepath.Join(h.dataRoot, failedPrefix+"x"), "/x", false)}}
			},
			want: "at /x, outside the data root",
		},
		"the status directory writable": {
			change: func(h *testHost) {
				h.docker.mounts = map[string][]map[string]any{workerService: {bind(filepath.Join(h.dataRoot, "updater", "status"), statusMount, false)}}
			},
			want: "the service " + workerService + " mounts",
		},
		"certificates elsewhere writable": {
			change: func(h *testHost) {
				h.docker.mounts = map[string][]map[string]any{"server": {bind("/etc/letsencrypt/live/x", "/etc/easyrmm/acme", false)}}
			},
			want: "the service server mounts /etc/letsencrypt/live/x",
		},
		"allowed": {
			change: func(h *testHost) {
				h.docker.mounts = map[string][]map[string]any{
					// The fake mounts each deployment's own docker/ into
					// PostgreSQL, as docker-compose.yml does.
					"server":      {bind("/etc/letsencrypt/live/x", "/etc/easyrmm/tls", true), bind("/etc/localtime", "/etc/localtime", true)},
					workerService: {bind(filepath.Join(h.dataRoot, "easypatch", "keys"), "/app/keys", true), bind("/var/run/docker.sock", "/var/run/docker.sock", false)},
				}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "v1.0.0", release.ChannelStable)
			h.offer("v1.1.0", nil)
			tc.change(h)
			err := h.upgrade(Request{})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			want := strings.NewReplacer("%deploy%", h.deploy("v1.0.0"), "%dataRoot%", h.dataRoot).Replace(tc.want)
			if strings.HasPrefix(want, ".env") {
				// .env is read before an attempt begins.
				if err == nil || !strings.Contains(err.Error(), "the deployment's "+want) || h.docker.called("compose stop") != 0 || h.state().Attempt != nil {
					t.Fatalf("got %v, want %q", err, want)
				}
				return
			}
			h.refusedBeforeStopping(err, want)
		})
	}
	// A new version whose bundle has a file Compose would read beside its
	// docker-compose.yml is refused once unpacked, before anything stops,
	// and automatic upgrades skip it: its bundle will not change.
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	files := bundleFiles("v1.1.0")
	files["easyrmm-v1.1.0/deploy/compose.override.yaml"] = "services: {}\n"
	h.offerFiles("v1.1.0", files, nil)
	err := h.upgrade(Request{})
	if err == nil || !strings.Contains(err.Error(), "compose.override.yaml is in "+h.deploy("v1.1.0")) {
		t.Fatalf("got %v", err)
	}
	if h.docker.called("compose stop") != 0 || h.docker.running["server"] != h.deploy("v1.0.0") || !h.state().HasFailed("v1.1.0") {
		t.Errorf("running %v, failed %v", h.docker.running, h.state().Failed)
	}
}

// appendEnv adds lines to the running deployment's .env.
func (h *testHost) appendEnv(lines string) {
	h.t.Helper()
	env := filepath.Join(h.deploy("v1.0.0"), ".env")
	writeFile(h.t, env, readFile(h.t, env)+lines, 0o600)
}
