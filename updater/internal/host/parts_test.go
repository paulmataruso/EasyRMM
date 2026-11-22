package host

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "updater.conf")
	writeFile(t, path, "# comment\n\ndeployment = /opt/easyrmm-v1.0.0/deploy\nchannel = edge\nauto_upgrade = true\nauto_upgrade_hours = 22-4\nbackup_dir = /srv/backups\n", 0o600)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Deployment != "/opt/easyrmm-v1.0.0/deploy" || c.Channel != release.ChannelEdge || !c.AutoUpgrade ||
		c.Hours != (Hours{22, 4}) || c.BackupDir != "/srv/backups" || c.Path != path {
		t.Errorf("config %+v", c)
	}
	at := func(h int) time.Time { return time.Date(2026, 1, 1, h, 30, 0, 0, time.UTC) }
	for h, want := range map[int]bool{21: false, 22: true, 23: true, 0: true, 3: true, 4: false, 12: false} {
		if c.Hours.Contains(at(h)) != want {
			t.Errorf("22-4 contains %d:30: %v", h, !want)
		}
	}
	if (Hours{2, 5}).Contains(at(5)) || !(Hours{2, 5}).Contains(at(2)) || !(Hours{0, 24}).Contains(at(23)) {
		t.Error("2-5 or 0-24")
	}
	if got := (Hours{2, 5}).String(); got != "02:00 to 05:00" {
		t.Errorf("String = %q", got)
	}

	writeFile(t, path, "deployment = /d/deploy\n", 0o600)
	c, err = LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Channel != release.ChannelStable || c.AutoUpgrade || c.Hours != (Hours{0, 24}) || c.BackupDir != DefaultBackupDir {
		t.Errorf("defaults %+v", c)
	}

	for name, contents := range map[string]string{
		"no deployment":          "channel = stable\n",
		"not key = value":        "deployment /d\n",
		"an empty key":           "= x\n",
		"a key twice":            "deployment = /d\ndeployment = /e\n",
		"an unknown key":         "deployment = /d\nupdate_url = https://example.com\n",
		"a relative deployment":  "deployment = d/deploy\n",
		"an unclean deployment":  "deployment = /d/../e\n",
		"a deployment w/ spaces": "deployment = /d e\n",
		"another channel":        "deployment = /d\nchannel = nightly\n",
		"auto_upgrade maybe":     "deployment = /d\nauto_upgrade = maybe\n",
		"hours 25":               "deployment = /d\nauto_upgrade_hours = 2-25\n",
		"hours the same":         "deployment = /d\nauto_upgrade_hours = 3-3\n",
		"hours 24-":              "deployment = /d\nauto_upgrade_hours = 24-2\n",
		"hours as words":         "deployment = /d\nauto_upgrade_hours = night\n",
		"backups at the root":    "deployment = /d\nbackup_dir = /\n",
		"relative backups":       "deployment = /d\nbackup_dir = backups\n",
	} {
		writeFile(t, path, contents, 0o600)
		if c, err := LoadConfig(path); err == nil {
			t.Errorf("%s: loaded %+v", name, c)
		}
	}
}

func TestReadOwnFileRefuses(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	writeFile(t, good, "deployment = /d\n", 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	writable := filepath.Join(dir, "writable")
	writeFile(t, writable, "deployment = /d\n", 0o620)
	big := filepath.Join(dir, "big")
	writeFile(t, big, strings.Repeat("#\n", 40<<10), 0o600)
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"a link": link, "a group-writable file": writable, "a large file": big, "a named pipe": fifo, "a directory": dir,
		"a missing file": filepath.Join(dir, "missing"),
	} {
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("%s was read", name)
		}
	}
	old := rootUID
	rootUID = old + 1
	defer func() { rootUID = old }()
	if _, err := LoadConfig(good); err == nil || !strings.Contains(err.Error(), "does not belong to root") {
		t.Errorf("another owner's file: %v", err)
	}
}

func TestSetDeployment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "updater.conf")
	writeFile(t, path, "# keep me\ndeployment = /a/deploy\n  channel = edge\n", 0o600)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetDeployment("/b/deploy"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != "# keep me\ndeployment = /b/deploy\n  channel = edge\n" || c.Deployment != "/b/deploy" || mode(t, path) != 0o600 {
		t.Errorf("rewritten %q", got)
	}
	if err := c.SetDeployment("/b/../c"); err == nil {
		t.Error("an unclean path was written")
	}
}

func TestEnvFile(t *testing.T) {
	env := []byte("A=1\nB=2\nA=3\nCOMPOSE_PROFILES=patching,authentik\n")
	if envValue(env, "A") != "3" || envValue(env, "C") != "" || envValue(env, "B") != "2" {
		t.Error("envValue")
	}
	out, err := setEnv(env, "A", "4")
	if err != nil || string(out) != "A=4\nB=2\nCOMPOSE_PROFILES=patching,authentik\n" {
		t.Errorf("setEnv replaced: %q, %v", out, err)
	}
	if out, err = setEnv(env, "C", "5"); err != nil || !strings.HasSuffix(string(out), "authentik\nC=5\n") {
		t.Errorf("setEnv added: %q, %v", out, err)
	}
	if _, err := setEnv(env, "A", "x\nB=evil"); err == nil {
		t.Error("a value with a line break was set")
	}
	if !hasProfile(env, "authentik") || !hasProfile(env, "patching") || hasProfile(env, "auth") || hasProfile(nil, "authentik") {
		t.Error("hasProfile")
	}
}

func TestCheckPostgresMajor(t *testing.T) {
	root := t.TempDir()
	if err := checkPostgresMajor(root, 18); err == nil {
		t.Error("no postgres directory")
	}
	if err := os.MkdirAll(filepath.Join(root, "postgres", "18", "docker"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkPostgresMajor(root, 18); err == nil || !strings.Contains(err.Error(), "no PostgreSQL data") {
		t.Errorf("no PG_VERSION: %v", err)
	}
	writeFile(t, filepath.Join(root, "postgres", "18", "docker", "PG_VERSION"), "18\n", 0o600)
	if err := checkPostgresMajor(root, 18); err != nil {
		t.Error(err)
	}
	if err := checkPostgresMajor(root, 19); err == nil || !strings.Contains(err.Error(), "by hand") {
		t.Errorf("another major: %v", err)
	}
	// A PG_VERSION that is a link is not followed.
	if err := os.MkdirAll(filepath.Join(root, "postgres", "19", "docker"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(root, "postgres", "19", "docker", "PG_VERSION")); err != nil {
		t.Fatal(err)
	}
	if err := checkPostgresMajor(root, 19); err == nil {
		t.Error("a linked PG_VERSION was read")
	}
}

func TestCheckDaemon(t *testing.T) {
	ctx := context.Background()
	for opts, ok := range map[string]bool{
		`["name=seccomp,profile=builtin","name=cgroupns"]`: true,
		`["name=seccomp,profile=builtin","name=userns"]`:   false,
		`["name=rootless","name=seccomp,profile=builtin"]`: false,
		`not json`: false,
	} {
		f := newFakeDocker(t, t.TempDir())
		f.security = opts
		if err := (Docker{R: f}).CheckDaemon(ctx); (err == nil) != ok {
			t.Errorf("%s: %v", opts, err)
		}
	}
	f := newFakeDocker(t, t.TempDir())
	f.fail = failing(func(_, call string) bool { return strings.HasPrefix(call, "info") })
	if err := (Docker{R: f}).CheckDaemon(ctx); err == nil {
		t.Error("docker info failing")
	}
}

func TestStatusDir(t *testing.T) {
	root := t.TempDir()
	sd := statusDirOf(root)
	if sd.Held() {
		t.Error("held before anything")
	}
	if err := sd.Unhold(); err != nil {
		t.Errorf("unholding without a hold: %v", err)
	}
	// A status directory made with another mode is given 755.
	if err := os.MkdirAll(string(sd), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := sd.Hold(); err != nil {
		t.Fatal(err)
	}
	if !sd.Held() || mode(t, string(sd)) != 0o755 || mode(t, filepath.Dir(string(sd))) != 0o755 || mode(t, sd.path(HoldFile)) != 0o644 {
		t.Errorf("held %v, modes %o %o", sd.Held(), mode(t, string(sd)), mode(t, sd.path(HoldFile)))
	}
	if err := sd.Unhold(); err != nil || sd.Held() {
		t.Errorf("unhold: %v", err)
	}
	// A status directory a container could write is refused.
	other := statusDirOf(t.TempDir())
	if err := os.MkdirAll(string(other), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(string(other), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := other.Hold(); err == nil {
		t.Error("a world-writable status directory was used")
	}
	// Or a link.
	linked := t.TempDir()
	if err := os.MkdirAll(filepath.Join(linked, "updater"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(linked, "updater", "status")); err != nil {
		t.Fatal(err)
	}
	if err := statusDirOf(linked).HoldAgentUpdates(time.Now()); err == nil {
		t.Error("a linked status directory was used")
	}
}

func backupAt(t *testing.T, dir string, at time.Time, complete bool) string {
	t.Helper()
	data := t.TempDir()
	writeFile(t, filepath.Join(data, "f"), "x", 0o600)
	conf := filepath.Join(t.TempDir(), "updater.conf")
	writeFile(t, conf, "deployment = /d\n", 0o600)
	tree := t.TempDir()
	for _, d := range []string{"deploy", "docker"} {
		writeFile(t, filepath.Join(tree, d, "f"), "x", 0o600)
	}
	meta := BackupMeta{Version: "v1.0.0", Deployment: filepath.Join(tree, "deploy"), DataRoot: data, Taken: at}
	b, err := takeBackup(context.Background(), backupDirFor(dir, meta), meta, conf, 0, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		if err := os.Remove(filepath.Join(b.Dir, "backup.json")); err != nil {
			t.Fatal(err)
		}
	}
	return b.Dir
}

func TestRotateBackups(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "backups")
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	var all []string
	for i := range 5 {
		all = append(all, backupAt(t, dir, t0.Add(time.Duration(i)*time.Hour), true))
	}
	incomplete := backupAt(t, dir, t0.Add(10*time.Hour), false)
	kept := backupAt(t, dir, t0.Add(11*time.Hour), false)
	writeFile(t, filepath.Join(dir, "a-file"), "x", 0o600)
	// The oldest is protected, as a rollback may restore it; so is the
	// incomplete backup being written.
	if err := rotateBackups(dir, all[0], kept); err != nil {
		t.Fatal(err)
	}
	var left []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		left = append(left, filepath.Join(dir, e.Name()))
	}
	want := []string{all[0], all[3], all[4], kept, filepath.Join(dir, "a-file")}
	slices.Sort(want)
	if !slices.Equal(left, want) {
		t.Errorf("left %v\nwant %v", left, want)
	}
	if slices.Contains(left, incomplete) {
		t.Error("an incomplete backup was kept")
	}
	if err := rotateBackups(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing directory was rotated")
	}
}

func TestTakeBackupLeavesOutTheUpdatersFiles(t *testing.T) {
	data := t.TempDir()
	writeFile(t, filepath.Join(data, "server", "f"), "x", 0o600)
	writeFile(t, filepath.Join(data, "updater", "status", "hold"), "", 0o644)
	writeFile(t, filepath.Join(data, ".failed-x", "f"), "x", 0o600)
	if err := os.Symlink("/etc", filepath.Join(data, "server", "etc")); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(t.TempDir(), "updater.conf")
	writeFile(t, conf, "deployment = /d\n", 0o600)
	tree := t.TempDir()
	for _, d := range []string{"deploy", "docker"} {
		writeFile(t, filepath.Join(tree, d, "f"), "x", 0o600)
	}
	dir := filepath.Join(t.TempDir(), "backups")
	meta := BackupMeta{Version: "v1.0.0", Deployment: filepath.Join(tree, "deploy"), DataRoot: data, Taken: time.Now()}
	b, err := takeBackup(context.Background(), backupDirFor(dir, meta), meta, conf, 0, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(b.Dir, "data"))
	if len(entries) != 1 || entries[0].Name() != "server" {
		t.Errorf("backed up %v", entries)
	}
	// Links are copied as links, not followed.
	if fi, err := os.Lstat(filepath.Join(b.Dir, "data", "server", "etc")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link: %v", err)
	}
	if err := copyTree(context.Background(), conf, filepath.Join(b.Dir, "updater.conf")); err == nil {
		t.Error("copied over an existing file")
	}
	if err := copyTree(context.Background(), filepath.Join(data, "missing"), filepath.Join(b.Dir, "new")); err == nil {
		t.Error("copied a missing file")
	}
	// Restoring into a data root whose tree lacks docker/ still works.
	if err := os.RemoveAll(filepath.Join(tree, "docker")); err != nil {
		t.Fatal(err)
	}
	if err := b.restoreTree(context.Background(), tree, "stamp"); err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(tree, "docker", "f")) != "x" {
		t.Error("docker/ not restored")
	}
}

func TestUnpackBundle(t *testing.T) {
	files := map[string]string{
		"easyrmm-v1.0.0/deploy/docker-compose.yml": "x",
		"easyrmm-v1.0.0/deploy/scripts/setup.sh":   "#!/bin/sh\n",
	}
	write := func(t *testing.T, extra ...*tar.Header) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "bundle.tar.gz")
		writeFile(t, path, string(tarGz(t, files, extra...)), 0o600)
		return path
	}
	parent := t.TempDir()
	dir, err := unpackBundle(write(t), parent, "easyrmm-v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join(parent, "easyrmm-v1.0.0") || readFile(t, filepath.Join(dir, "deploy", "docker-compose.yml")) != "x" ||
		mode(t, filepath.Join(dir, "deploy", "scripts", "setup.sh")) != 0o755 || mode(t, filepath.Join(dir, "deploy", "docker-compose.yml")) != 0o644 {
		t.Errorf("unpacked into %s", dir)
	}
	if entries, _ := os.ReadDir(parent); len(entries) != 1 {
		t.Errorf("left beside it: %v", entries)
	}

	for name, h := range map[string]*tar.Header{
		"a link":                 {Typeflag: tar.TypeSymlink, Name: "easyrmm-v1.0.0/deploy/.env", Linkname: "/etc/shadow"},
		"a hard link":            {Typeflag: tar.TypeLink, Name: "easyrmm-v1.0.0/deploy/x", Linkname: "easyrmm-v1.0.0/deploy/docker-compose.yml"},
		"a device":               {Typeflag: tar.TypeChar, Name: "easyrmm-v1.0.0/deploy/null", Devmajor: 1, Devminor: 3},
		"a named pipe":           {Typeflag: tar.TypeFifo, Name: "easyrmm-v1.0.0/deploy/fifo"},
		"a path outside":         {Typeflag: tar.TypeReg, Name: "../evil", Size: 1, Mode: 0o644},
		"another top":            {Typeflag: tar.TypeReg, Name: "easyrmm-v9.9.9/x", Size: 1, Mode: 0o644},
		"a path climbing out":    {Typeflag: tar.TypeReg, Name: "easyrmm-v1.0.0/../../evil", Size: 1, Mode: 0o644},
		"an absolute path":       {Typeflag: tar.TypeReg, Name: "/etc/cron.d/evil", Size: 1, Mode: 0o644},
		"a file twice":           {Typeflag: tar.TypeReg, Name: "easyrmm-v1.0.0/deploy/docker-compose.yml", Size: 1, Mode: 0o644},
		"a file over a dir":      {Typeflag: tar.TypeReg, Name: "easyrmm-v1.0.0/deploy", Size: 1, Mode: 0o644},
		"a directory over files": {Typeflag: tar.TypeDir, Name: "easyrmm-v1.0.0/deploy/docker-compose.yml/", Mode: 0o755},
	} {
		p := t.TempDir()
		if dir, err := unpackBundle(write(t, h), p, "easyrmm-v1.0.0"); err == nil {
			t.Errorf("%s: unpacked into %s", name, dir)
		}
		if entries, _ := os.ReadDir(p); len(entries) != 0 {
			t.Errorf("%s: left %v", name, entries)
		}
	}
	// A set-user-ID bit is dropped.
	p := t.TempDir()
	dir, err = unpackBundle(write(t, &tar.Header{Typeflag: tar.TypeReg, Name: "easyrmm-v1.0.0/deploy/x", Size: 1, Mode: 0o6777}), p, "easyrmm-v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "deploy", "x")); err != nil || fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || fi.Mode().Perm() != 0o755 {
		t.Errorf("mode %v, %v", fi.Mode(), err)
	}
	// Not gzip, or not tar.
	notGzip := filepath.Join(t.TempDir(), "b")
	writeFile(t, notGzip, "plain", 0o600)
	if _, err := unpackBundle(notGzip, t.TempDir(), "easyrmm-v1.0.0"); err == nil {
		t.Error("a file that is not gzip was unpacked")
	}
	if _, err := unpackBundle(filepath.Join(t.TempDir(), "missing"), t.TempDir(), "easyrmm-v1.0.0"); err == nil {
		t.Error("a missing bundle was unpacked")
	}
	// A bundle without its top directory.
	files = map[string]string{"other/x": "x"}
	if _, err := unpackBundle(write(t), t.TempDir(), "easyrmm-v1.0.0"); err == nil {
		t.Error("a bundle of another top directory was unpacked")
	}
}

// ExecRunner runs the docker found on the updater's PATH, in a fixed
// environment.
func TestExecRunner(t *testing.T) {
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "docker"), `#!/bin/sh
case "$1" in
ok) echo "in $(pwd) with HOME=$HOME FOO=${FOO:-unset}"; cat ;;
*) echo one >&2; echo two >&2; echo three >&2; exit 3 ;;
esac
`, 0o755)
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	t.Setenv("FOO", "from the shell")
	t.Setenv("HOME", "/home/from-the-shell")
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out, err := ExecRunner{}.Run(context.Background(), dir, []byte("input"), "ok")
	if err != nil || string(out) != "in "+dir+" with HOME="+me.HomeDir+" FOO=unset\ninput" {
		t.Errorf("Run = %q, %v", out, err)
	}
	// HOME is the home of the user the updater runs as: as root, /root;
	// as CI's runner, its own, where docker finds the Compose plugin
	// (with root's, which it cannot read, docker knows no compose).
	was := currentUser
	currentUser = func() (*user.User, error) { return &user.User{Uid: "1001", HomeDir: "/home/runner"}, nil }
	t.Cleanup(func() { currentUser = was })
	out, err = ExecRunner{}.Run(context.Background(), dir, nil, "ok")
	if err != nil || string(out) != "in "+dir+" with HOME=/home/runner FOO=unset\n" {
		t.Errorf("Run as another user = %q, %v", out, err)
	}
	currentUser = func() (*user.User, error) { return nil, errors.New("no such user") }
	if out, err = (ExecRunner{}).Run(context.Background(), dir, nil, "ok"); err != nil || !strings.Contains(string(out), "HOME=/root ") {
		t.Errorf("Run as an unknown user = %q, %v", out, err)
	}
	_, err = ExecRunner{}.Run(context.Background(), dir, nil, "fail", "now")
	if err == nil || !strings.Contains(err.Error(), "docker fail now") || !strings.Contains(err.Error(), "one / two / three") {
		t.Errorf("a failure: %v", err)
	}
	if got := lastLines("a\nb\nc\nd\n", 2); got != "c / d" {
		t.Errorf("lastLines = %q", got)
	}
	writeFile(t, filepath.Join(bin, "systemctl"), "#!/bin/sh\n[ \"$1\" = daemon-reload ] || { echo no >&2; exit 1; }\n", 0o755)
	if err := systemctl(context.Background(), "daemon-reload"); err != nil {
		t.Error(err)
	}
	if err := systemctl(context.Background(), "reboot"); err == nil || !strings.Contains(err.Error(), "no") {
		t.Errorf("systemctl reboot: %v", err)
	}
}

// Containers of the project that compose stop leaves running are stopped
// by their IDs; any still running then is an error.
func TestStopLeftovers(t *testing.T) {
	for name, tc := range map[string]struct {
		ps   []string
		want bool
	}{
		"none left":   {ps: []string{""}, want: true},
		"one stopped": {ps: []string{"abc\n", ""}, want: true},
		"one stays":   {ps: []string{"abc\n", "abc\n"}, want: false},
	} {
		var calls []string
		r := runnerFunc(func(_ context.Context, _ string, _ []byte, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(args, " "))
			if args[0] == "ps" {
				out := tc.ps[0]
				tc.ps = tc.ps[1:]
				return []byte(out), nil
			}
			return nil, nil
		})
		err := Docker{R: r}.Stop(context.Background(), "/d")
		if (err == nil) != tc.want {
			t.Errorf("%s: %v (%v)", name, err, calls)
		}
		if name == "one stopped" && !slices.Contains(calls, "stop abc") {
			t.Errorf("%s: %v", name, calls)
		}
	}
}

type runnerFunc func(ctx context.Context, dir string, stdin []byte, args ...string) ([]byte, error)

func (f runnerFunc) Run(ctx context.Context, dir string, stdin []byte, args ...string) ([]byte, error) {
	return f(ctx, dir, stdin, args...)
}

// An old deployment the updater unpacked goes whole; of any other (a Git
// clone, an operator's bundle directory) only deploy/.env, which holds the
// key; and nothing that holds what the updater keeps.
func TestRemoveDeployment(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	st := &State{Attempt: &Attempt{DataRoot: h.dataRoot}}
	parent := t.TempDir()
	for _, root := range []string{filepath.Join(parent, "EasyRMM"), filepath.Join(parent, "easyrmm-v0.9.0")} {
		writeFile(t, filepath.Join(root, ".git", "HEAD"), "ref: refs/heads/main\n", 0o644)
		writeFile(t, filepath.Join(root, "deploy", ".env"), "EASYRMM_SECRET_KEY=x\n", 0o600)
		writeFile(t, filepath.Join(root, "deploy", "docker-compose.yml"), "x", 0o644)
		if err := h.u.removeDeployment(st, filepath.Join(root, "deploy")); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root, "deploy", ".env")); err == nil {
			t.Errorf("%s: the .env is left", root)
		}
		if _, err := os.Stat(filepath.Join(root, "deploy", "docker-compose.yml")); err != nil {
			t.Errorf("%s was removed", root)
		}
		if err := h.u.removeDeployment(st, filepath.Join(root, "deploy")); err != nil {
			t.Errorf("%s without .env: %v", root, err)
		}
	}
	unpacked := filepath.Join(parent, "easyrmm-v1.0.1")
	writeFile(t, filepath.Join(unpacked, "deploy", ".env"), "x", 0o600)
	writeFile(t, filepath.Join(parent, ".easyrmm-v1.0.1.unpack-123", "x"), "x", 0o600)
	st.Unpacked = []string{unpacked}
	if err := h.u.removeDeployment(st, filepath.Join(unpacked, "deploy")); err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(parent, "*easyrmm-v1.0.1*")); len(left) != 0 || len(st.Unpacked) != 0 {
		t.Errorf("left %v, unpacked %v", left, st.Unpacked)
	}
	// One that holds the data root, the backups, the state or the
	// configuration stays, unpacked by the updater or not.
	for name, keep := range map[string]*string{"data root": &st.Attempt.DataRoot, "backups": &h.u.Config.BackupDir, "state": &h.u.StateDir, "configuration": &h.u.Config.Path} {
		holding := filepath.Join(parent, "easyrmm-v1.0.2")
		writeFile(t, filepath.Join(holding, "deploy", ".env"), "x", 0o600)
		was := *keep
		*keep = filepath.Join(holding, "kept")
		st.Unpacked = []string{holding}
		if err := h.u.removeDeployment(st, filepath.Join(holding, "deploy")); err == nil || !strings.Contains(err.Error(), "which the updater keeps") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(holding, "deploy", ".env")); err != nil {
			t.Errorf("%s: removed", name)
		}
		*keep = was
	}
	// So does an operator's .env that is the configuration.
	h.u.Config.Path = filepath.Join(parent, "easyrmm-v0.9.0", "deploy", ".env")
	writeFile(t, h.u.Config.Path, "x", 0o600)
	if err := h.u.removeDeployment(st, filepath.Dir(h.u.Config.Path)); err == nil {
		t.Error("removed the configuration")
	}
}

// An upgrade never unpacks over a directory the updater did not unpack (a
// Git clone, an operator's own), and replaces one it did.
func TestUpgradeBesideAClone(t *testing.T) {
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	writeFile(t, filepath.Join(h.root, "easyrmm-v1.1.0", ".git", "HEAD"), "x", 0o644)
	h.offer("v1.1.0", nil)
	if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "the updater did not unpack it") {
		t.Errorf("over a clone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "easyrmm-v1.1.0", ".git", "HEAD")); err != nil {
		t.Error("the clone was touched")
	}
	// One an earlier attempt unpacked and left is replaced.
	st := h.state()
	st.Unpacked = append(st.Unpacked, filepath.Join(h.root, "easyrmm-v1.1.0"))
	if err := st.save(h.u.StateDir); err != nil {
		t.Fatal(err)
	}
	if err := h.upgrade(Request{Version: release.MustParseVersion("v1.1.0")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "easyrmm-v1.1.0", ".git")); err == nil {
		t.Error("an earlier attempt's file is left")
	}
}

// deploy/docker-compose.yml, as Compose reads it, passes the updater's
// checks of what a deployment mounts, with Authentik's profile and
// without, its certificates in the data root or elsewhere.
func TestTheDeploymentsMounts(t *testing.T) {
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skipf("no docker compose here: %v", err)
	}
	for name, env := range map[string]string{
		"plain":                  "EASYRMM_TLS_DIR=/srv/test-data/tls\n",
		"with Authentik":         "EASYRMM_TLS_DIR=/srv/test-data/tls\nCOMPOSE_PROFILES=authentik\n",
		"certificates elsewhere": "EASYRMM_TLS_DIR=/etc/ssl/easyrmm\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "easyrmm-v1.0.0")
			deploy := filepath.Join(root, "deploy")
			writeFile(t, filepath.Join(deploy, "docker-compose.yml"), readFile(t, "../../../deploy/docker-compose.yml"), 0o644)
			if err := os.Symlink(filepath.Join(must(filepath.Abs("../../..")), "docker"), filepath.Join(root, "docker")); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(deploy, ".env"), "EASYRMM_DATA_ROOT=/srv/test-data\nPOSTGRES_PASSWORD=x\nEASYRMM_DB_OWNER_PASSWORD=x\nEASYRMM_DB_APP_PASSWORD=x\nEASYRMM_PUBLIC_URL=https://rmm.example.com\nEASYRMM_SECRET_KEY=x\n"+env, 0o600)
			d := Docker{R: ExecRunner{}}
			mounts, err := d.Mounts(t.Context(), deploy)
			if err != nil {
				t.Fatal(err)
			}
			root2, err := dataRootOf(mounts, deploy)
			if err != nil || root2 != "/srv/test-data" {
				t.Fatalf("the data root %s, %v", root2, err)
			}
			if err := checkMounts(mounts, root2, deploy); err != nil {
				t.Error(err)
			}
			if err := checkComposeFiles(deploy); err != nil {
				t.Error(err)
			}
			if len(mounts) < 10 {
				t.Errorf("only %d mounts: %v", len(mounts), mounts)
			}
		})
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
