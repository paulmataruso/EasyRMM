package host

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/updater/internal/fetch"
	"github.com/paulmataruso/easyrmm/updater/internal/release"
	"github.com/paulmataruso/easyrmm/updater/internal/release/releasetest"
)

// TestMain runs the tests with ensureRootPath checking the directories
// they make, and not the TMPDIR they are given.
func TestMain(m *testing.M) {
	checkedBelow = filepath.Clean(os.TempDir())
	os.Exit(m.Run())
}

func init() {
	// The tests' files are the user's who runs them.
	rootUID = uint32(os.Getuid()) //nolint:gosec // a user ID
	minImageSpace = 1 << 20
}

const (
	testCommit    = "7fc6602ea97f32b40fa0bf4496e58694d536be7c"
	serverRepo    = "ghcr.io/paulmataruso/easyrmm-server"
	engineImage   = "ghcr.io/paulmataruso/easypatch-server:1.12.1" + releasetest.Digest
	pgImage       = "postgres:18.6-alpine3.24" + releasetest.Digest
	meshImage     = "ghcr.io/ylianst/meshcentral:1.3.1" + releasetest.Digest
	authentikImg  = "ghcr.io/goauthentik/server:2026.8.5" + releasetest.Digest
	testAuditHead = "5c1e6b0f9a3e4d2c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c"
	// newerAuditHead is the head a newer version's database reaches, at
	// audit ID 57.
	newerAuditHead = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
)

var (
	sigstoreOnce sync.Once
	sigstore     *releasetest.Sigstore
	sigstoreErr  error
)

func testSigstore(t *testing.T) *releasetest.Sigstore {
	t.Helper()
	sigstoreOnce.Do(func() { sigstore, sigstoreErr = releasetest.New() })
	if sigstoreErr != nil {
		t.Fatal(sigstoreErr)
	}
	return sigstore
}

// fakeDocker answers the docker commands the updater runs, as Docker and
// Compose would for a deployment whose docker-compose.yml lists, in this
// test, its services and their images:
//
//	service <name> <restart> <image> [<depends on>...]
//
// An image "SERVER" is ${EASYRMM_IMAGE}:${EASYRMM_VERSION} from .env. A
// service in the authentik profile is named authentik-*.
type fakeDocker struct {
	t       *testing.T
	mu      sync.Mutex
	calls   []string
	running map[string]string // service -> deploy dir it runs from
	// dataRoot is written by a started server: the version that ran.
	dataRoot string
	rootDir  string
	security string
	// fail returns an error for a command (its dir and args), or nil.
	fail func(dir string, args []string) error
	// composeDataRoot, when set, is the data root Compose reads, whatever
	// .env says; serverSays, when set, the version the server reports.
	composeDataRoot string
	serverSays      string
	// psql records what PostgreSQL was sent. The audit chain's head is the
	// database's, in the data root (headFile), so that a restore brings
	// the backup's back; a version above v1.0.0 that starts writes its own.
	psql []string
	vars []map[string]string
	// mounts are volumes added to services' (service -> Compose's JSON).
	mounts map[string][]map[string]any
}

// headFile is where the fake database keeps its audit chain's head.
func headFile(dataRoot string) string {
	return filepath.Join(dataRoot, "postgres", "18", "docker", "audit-head")
}

func newFakeDocker(t *testing.T, dataRoot string) *fakeDocker {
	return &fakeDocker{
		t: t, running: map[string]string{}, dataRoot: dataRoot, rootDir: t.TempDir(),
		security: `["name=seccomp,profile=builtin","name=cgroupns"]`,
	}
}

type fakeService struct {
	name, restart, image string
	deps                 []string
}

func (f *fakeDocker) services(dir string) ([]fakeService, []byte) {
	env, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		f.t.Fatalf("docker compose in %s without .env: %v", dir, err)
	}
	compose, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		f.t.Fatalf("docker compose in %s: %v", dir, err)
	}
	var out []fakeService
	for _, l := range strings.Split(string(compose), "\n") {
		fields := strings.Fields(l)
		if len(fields) < 4 || fields[0] != "service" {
			continue
		}
		s := fakeService{name: fields[1], restart: fields[2], image: fields[3], deps: fields[4:]}
		if strings.HasPrefix(s.name, "authentik-") && !hasProfile(env, "authentik") {
			continue
		}
		if s.image == "SERVER" {
			s.image = envValue(env, "EASYRMM_IMAGE") + ":" + envValue(env, "EASYRMM_VERSION")
		}
		out = append(out, s)
	}
	return out, env
}

func (f *fakeDocker) Run(ctx context.Context, dir string, stdin []byte, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	call := strings.Join(args, " ")
	if dir != "" {
		call = dir + ": " + call
	}
	f.calls = append(f.calls, call)
	if f.fail != nil {
		if err := f.fail(dir, args); err != nil {
			return nil, err
		}
	}
	switch {
	case call == "info --format {{json .SecurityOptions}}":
		return []byte(f.security + "\n"), nil
	case call == "info --format {{.DockerRootDir}}":
		return []byte(f.rootDir + "\n"), nil
	case slices.Equal(args, []string{"compose", "config", "--images"}):
		svcs, _ := f.services(dir)
		var b strings.Builder
		for _, s := range svcs {
			b.WriteString(s.image + "\n")
		}
		return []byte(b.String()), nil
	case slices.Equal(args, []string{"compose", "config", "--format", "json"}):
		svcs, _ := f.services(dir)
		cfg := map[string]any{}
		for _, s := range svcs {
			deps := map[string]any{}
			for _, d := range s.deps {
				deps[d] = map[string]any{"condition": "service_started"}
			}
			svc := map[string]any{"image": s.image, "depends_on": deps}
			if s.restart != "-" {
				svc["restart"] = s.restart
			}
			env, _ := os.ReadFile(filepath.Join(dir, ".env"))
			root := envValue(env, "EASYRMM_DATA_ROOT")
			switch {
			case f.composeDataRoot != "":
				root = f.composeDataRoot
			case root == "":
				root = "/srv/easyrmm"
			}
			// As deploy/docker-compose.yml mounts them: from the data root,
			// the deployment's docker/, and the certificates.
			var volumes []any
			switch s.name {
			case "server":
				volumes = []any{
					map[string]any{"type": "bind", "source": root + "/server", "target": "/var/lib/easyrmm"},
					map[string]any{"type": "bind", "source": root + "/tls", "target": tlsMount, "read_only": true},
					map[string]any{"type": "bind", "source": root + "/updater/status", "target": "/run/easyrmm-updater", "read_only": true},
					map[string]any{"type": "tmpfs", "target": "/tmp"},
				}
			case "postgres":
				volumes = []any{
					map[string]any{"type": "bind", "source": root + "/postgres", "target": "/var/lib/postgresql"},
					map[string]any{"type": "bind", "source": filepath.Join(filepath.Dir(dir), "docker", "postgres", "init"), "target": "/docker-entrypoint-initdb.d", "read_only": true},
				}
			}
			for _, m := range f.mounts[s.name] {
				volumes = append(volumes, m)
			}
			if volumes != nil {
				svc["volumes"] = volumes
			}
			cfg[s.name] = svc
		}
		return json.Marshal(map[string]any{"name": Project, "services": cfg})
	case slices.Equal(args, []string{"compose", "pull", "--quiet"}):
		return nil, nil
	case len(args) == 5 && args[0] == "image" && args[1] == "inspect":
		return []byte("sha256:0\n"), nil
	case slices.Equal(args, []string{"compose", "stop"}):
		clear(f.running)
		return nil, nil
	case slices.Equal(args, []string{"ps", "--filter", "label=com.docker.compose.project=" + Project, "--format", `{{.Label "com.docker.compose.project.working_dir"}}`}):
		var b strings.Builder
		for _, dir := range f.running {
			b.WriteString(dir + "\n")
		}
		return []byte(b.String()), nil
	case len(args) > 1 && args[0] == "ps":
		return nil, nil
	case len(args) > 2 && args[0] == "compose" && args[1] == "up":
		return nil, f.up(dir, args[2:])
	case len(args) > 2 && args[0] == "compose" && args[1] == "wait":
		return nil, nil
	case len(args) > 3 && args[0] == "compose" && args[1] == "exec":
		return f.exec(dir, stdin, args[3:])
	}
	f.t.Errorf("unexpected docker %s", call)
	return nil, fmt.Errorf("unexpected docker %s", call)
}

// up starts the services named after the options, in dir: a server
// writes its version into the data root, as migrations would change it.
func (f *fakeDocker) up(dir string, args []string) error {
	var named []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--wait-timeout":
			i++
		case strings.HasPrefix(a, "--"):
		default:
			named = append(named, a)
		}
	}
	svcs, env := f.services(dir)
	for _, s := range svcs {
		if len(named) > 0 && !slices.Contains(named, s.name) {
			continue
		}
		if other, ok := f.running[s.name]; ok && other != dir {
			return fmt.Errorf("%s runs from %s already", s.name, other)
		}
		f.running[s.name] = dir
		if s.name == "server" {
			version := "v" + strings.SplitN(envValue(env, "EASYRMM_VERSION"), "@", 2)[0]
			if err := os.WriteFile(filepath.Join(f.dataRoot, "server", "ran"), []byte(version), 0o600); err != nil {
				return err
			}
			// A newer version writes audit records of its own.
			if v, err := release.ParseVersion(version); err == nil && v.Compare(release.MustParseVersion("v1.0.0")) > 0 {
				if err := os.WriteFile(headFile(f.dataRoot), []byte("57|"+newerAuditHead), 0o600); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// exec runs a command in the service's container, whichever directory it
// was started from: the project's name is fixed, so Compose finds it from
// any of them.
func (f *fakeDocker) exec(_ string, stdin []byte, args []string) ([]byte, error) {
	user := ""
	if args[0] == "--user" {
		user, args = args[1], args[2:]
	}
	service := args[0]
	runDir, ok := f.running[service]
	if !ok {
		return nil, fmt.Errorf("service %q is not running", service)
	}
	switch {
	case service == "server" && slices.Equal(args[1:], []string{"easyrmm-server", "healthcheck"}):
		return nil, nil
	case service == "server" && slices.Equal(args[1:], []string{"easyrmm-server", "version"}) && f.serverSays != "":
		return []byte(f.serverSays + "\n"), nil
	case service == "server" && slices.Equal(args[1:], []string{"easyrmm-server", "version"}):
		env, _ := os.ReadFile(filepath.Join(runDir, ".env"))
		return []byte("v" + strings.SplitN(envValue(env, "EASYRMM_VERSION"), "@", 2)[0] + "\n"), nil
	case service == "postgres" && user == "postgres" && args[1] == "psql":
		sql := string(stdin)
		f.psql = append(f.psql, sql)
		vars := map[string]string{}
		for i, a := range args {
			if a == "-v" && i+1 < len(args) {
				k, v, _ := strings.Cut(args[i+1], "=")
				vars[k] = v
			}
		}
		f.vars = append(f.vars, vars)
		switch {
		case strings.Contains(sql, "encode(entry_hash"):
			head, err := os.ReadFile(headFile(f.dataRoot))
			if err != nil {
				return nil, err
			}
			return append(head, '\n'), nil
		case strings.Contains(sql, "json_build_object"):
			return []byte(`{"devices": ["desk-1", "desk-2"], "deviceCount": 2, "jobs": 7, "audit": 31}` + "\n"), nil
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected exec %v", args)
}

func (f *fakeDocker) called(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

// testHost is a host with a deployment of version from, and the versions
// to offer, each a bundle with its manifest and attestation.
type testHost struct {
	t        *testing.T
	root     string // the directory bundles are unpacked in
	dataRoot string
	releases string // the directory versions are offered from
	docker   *fakeDocker
	u        *Updater
	now      time.Time
	installs []string
}

// compose is the test's docker-compose.yml: four services that keep
// running, one-shot services, one of them that nothing depends on, and
// Authentik's.
const compose = `service postgres unless-stopped ` + pgImage + `
service server unless-stopped SERVER postgres
service meshcentral unless-stopped ` + meshImage + `
service easypatch-db-init no ` + pgImage + ` postgres
service easypatch-api unless-stopped ` + engineImage + ` easypatch-db-init
service easypatch-worker unless-stopped ` + engineImage + ` easypatch-api
service authentik-server - ` + authentikImg + ` postgres
service authentik-setup no ` + authentikImg + ` authentik-server
`

const fakeSetup = `#!/bin/sh
set -eu
[ "$#" -eq 2 ] && [ "$1" = --upgrade ] && [ "$2" = --no-updater ] || { echo "setup.sh: bad options: $*" >&2; exit 2; }
# As setup.sh: the updater's lock, which the updater hands it.
[ "${EASYRMM_UPDATER_LOCK_FD:-}" = 3 ] && [ "$(basename "$(readlink /proc/self/fd/3)")" = lock ] && flock -n 3 || { echo "setup.sh: the updater's lock is not mine" >&2; exit 3; }
echo "SETUP_RAN=yes" >> .env
echo "setup.sh ran in $(pwd)"
`

// bundleFiles is a bundle's tree for version, under easyrmm-<version>/.
func bundleFiles(version string) map[string]string {
	top := "easyrmm-" + version + "/"
	return map[string]string{
		top + "deploy/docker-compose.yml":                              compose,
		top + "deploy/.env.example":                                    "EASYRMM_VERSION=latest\n",
		top + "deploy/scripts/setup.sh":                                fakeSetup,
		top + "deploy/updater/easyrmm-updater-linux-" + runtime.GOARCH: "updater of " + version,
		top + "deploy/updater/easyrmm-updater.service":                 "service of " + version,
		top + "deploy/updater/easyrmm-updater.timer":                   "timer of " + version,
		top + "docker/postgres/init/01-roles.sh":                       "#!/bin/sh\n",
		top + "docs/operations/upgrading.md":                           "# Upgrading\n",
		top + "deploy/scripts/import-easypatch.sh":                     "#!/bin/sh\n",
		top + "docker/meshcentral/start.sh":                            "#!/bin/sh\n",
		top + "docker/authentik/blueprints/easyrmm.yaml":               "version: 1\n",
		top + "LICENSE.md":                                             "FSL-1.1-ALv2\n",
		top + "docker/postgres/easypatch-db-init.sh":                   "#!/bin/sh\n",
		top + "docker/postgres/authentik-db-init.sh":                   "#!/bin/sh\n",
		top + "docker/authentik/start.sh":                              "#!/bin/sh\n",
		top + "CHANGELOG.md":                                           "# Changelog\n",
		top + "docs/deployment/docker.md":                              "# Docker\n",
		top + "docker/authentik/setup.py":                              "print()\n",
		top + "docs/operations/updater.md":                             "# The updater\n",
		top + "docs/operations/backup-restore.md":                      "# Backups\n",
		top + "LICENSING.md":                                           "x\n",
		top + "docs/deployment/agents.md":                              "# Agents\n",
		top + "docs/operations/import-easypatch.md":                    "# Import\n",
	}
}

// tarGz is a .tar.gz of files (each regular, mode 755 when it is a script)
// and the directories they lie in.
func tarGz(t *testing.T, files map[string]string, extra ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	dirs := map[string]bool{}
	for _, n := range names {
		for d := filepath.Dir(n); d != "."; d = filepath.Dir(d) {
			if !dirs[d] {
				dirs[d] = true
				if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: d + "/", Mode: 0o755}); err != nil {
					t.Fatal(err)
				}
			}
		}
		mode := int64(0o644)
		if strings.HasSuffix(n, ".sh") || strings.Contains(n, "easyrmm-updater-linux-") {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: mode, Size: int64(len(files[n]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, files[n]); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range extra {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte("x"), int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeFile(t *testing.T, path, contents string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// newTestHost is a host running version, installed from its bundle, with
// automatic upgrades on the channel.
func newTestHost(t *testing.T, version string, channel release.Channel) *testHost {
	t.Helper()
	base := t.TempDir()
	// Only its owner writes the directories above the bundle directory,
	// whatever the umask.
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	h := &testHost{
		t: t, root: filepath.Join(base, "opt"), dataRoot: filepath.Join(base, "srv"),
		releases: filepath.Join(base, "releases"), now: time.Date(2026, 11, 21, 3, 0, 0, 0, time.UTC),
	}
	for _, d := range []string{h.root, h.releases, filepath.Join(h.dataRoot, "server"), filepath.Join(h.dataRoot, "postgres", "18", "docker"), filepath.Join(base, "etc")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(h.dataRoot, "postgres", "18", "docker", "PG_VERSION"), "18\n", 0o600)
	writeFile(t, headFile(h.dataRoot), "42|"+testAuditHead, 0o600)
	writeFile(t, filepath.Join(h.dataRoot, "server", "ran"), version, 0o600)
	writeFile(t, filepath.Join(h.dataRoot, "server", "data"), "the data of "+version, 0o600)
	for name, contents := range bundleFiles(version) {
		writeFile(t, filepath.Join(h.root, name), contents, 0o644)
	}
	deploy := filepath.Join(h.root, "easyrmm-"+version, "deploy")
	writeFile(t, filepath.Join(deploy, ".env"), fmt.Sprintf("EASYRMM_DATA_ROOT=%s\nEASYRMM_SECRET_KEY=secret\nEASYRMM_IMAGE=%s\nEASYRMM_VERSION=%s\n",
		h.dataRoot, serverRepo, release.MustParseVersion(version).ImageTag()), 0o600)
	conf := filepath.Join(base, "etc", "updater.conf")
	writeFile(t, conf, fmt.Sprintf("# the updater\ndeployment = %s\nchannel = %s\nauto_upgrade = yes\nauto_upgrade_hours = 2-5\nbackup_dir = %s\n",
		deploy, channel, filepath.Join(base, "backups")), 0o600)
	c, err := LoadConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	h.docker = newFakeDocker(t, h.dataRoot)
	h.u = &Updater{
		Config:   c,
		StateDir: filepath.Join(base, "state"),
		Docker:   Docker{R: h.docker},
		Source:   fetch.Dir(h.releases),
		Verifier: func() (*release.Verifier, error) { return release.NewVerifier(testSigstore(t).TrustedRoot()) },
		Install: Install{Binary: filepath.Join(base, "sbin", "easyrmm-updater"), UnitDir: filepath.Join(base, "systemd"), Systemctl: func(_ context.Context, args ...string) error {
			h.installs = append(h.installs, strings.Join(args, " "))
			return nil
		}},
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:       func() time.Time { return h.now },
		BundleDir: h.root,
	}
	for _, d := range []string{filepath.Dir(h.u.Install.Binary), h.u.Install.UnitDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The deployment runs.
	if err := h.u.Docker.Start(context.Background(), deploy, time.Minute); err != nil {
		t.Fatal(err)
	}
	return h
}

// offer publishes version: its bundle, a manifest naming it, and an
// attestation with the claims claims changes (none: GitHub's own).
func (h *testHost) offer(version string, change func(*releasetest.Manifest, *releasetest.Claims)) {
	h.t.Helper()
	h.offerFiles(version, bundleFiles(version), change)
}

// offerFiles publishes version with a bundle of files.
func (h *testHost) offerFiles(version string, files map[string]string, change func(*releasetest.Manifest, *releasetest.Claims)) {
	h.t.Helper()
	bundle := tarGz(h.t, files)
	sum := sha256.Sum256(bundle)
	m := releasetest.NewManifest(version, testCommit)
	m.BundleSHA256 = hex.EncodeToString(sum[:])
	m.Engine, m.Postgres, m.MeshCentral, m.Authentik = engineImage, pgImage, meshImage, authentikImg
	claims := releasetest.For(release.MustParseVersion(version), testCommit)
	if change != nil {
		change(&m, &claims)
	}
	manifest := m.JSON()
	attestation, err := testSigstore(h.t).Attest(claims, releasetest.File{Name: "easyrmm-" + version + "-manifest.json", Contents: manifest})
	if err != nil {
		h.t.Fatal(err)
	}
	writeFile(h.t, filepath.Join(h.releases, "easyrmm-"+version+"-deploy.tar.gz"), string(bundle), 0o644)
	writeFile(h.t, filepath.Join(h.releases, "easyrmm-"+version+"-manifest.json"), string(manifest), 0o644)
	writeFile(h.t, filepath.Join(h.releases, "easyrmm-"+version+"-manifest.json.sigstore.json"), string(attestation), 0o644)
}

func (h *testHost) deploy(version string) string {
	return filepath.Join(h.root, "easyrmm-"+version, "deploy")
}

func (h *testHost) state() *State {
	h.t.Helper()
	st, err := loadState(h.u.StateDir)
	if err != nil {
		h.t.Fatal(err)
	}
	return st
}

func (h *testHost) statusDir() StatusDir { return statusDirOf(h.dataRoot) }

func (h *testHost) upgrade(req Request) error {
	if req.By == "" {
		req.By = "a test"
	}
	return h.u.Upgrade(context.Background(), req)
}

// failing makes docker fail when match matches a command, with its dir.
func failing(match func(dir, call string) bool) func(string, []string) error {
	return func(dir string, args []string) error {
		if call := strings.Join(args, " "); match(dir, call) {
			return errors.New("docker failed: " + call)
		}
		return nil
	}
}
