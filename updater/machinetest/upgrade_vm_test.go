//go:build vm

package machinetest

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/vmtest"
	"github.com/paulmataruso/easyrmm/updater/internal/host"
	"github.com/paulmataruso/easyrmm/updater/internal/release"
	"github.com/paulmataruso/easyrmm/updater/internal/release/releasetest"
)

const (
	machineImage = "debian-12"
	// The last release's patching engine, by the digest its attested
	// manifest names (edge builds run it too). EASYRMM_UPDATER_TEST_ENGINE
	// names another.
	defaultEngine = "ghcr.io/paulmataruso/easypatch-server:1.12.1@sha256:013f668d5dbec0c9031b496a274905baeb5378afa5a82fa38b0f8063db2e9b57"
	// The registry on the machine that the test pushes its server images
	// into, and that the machine's Docker pulls them from by digest, as it
	// would from ghcr.io.
	registryImage = "registry:3@sha256:82f6ff4a7f982960c8aa51617fea3aabc485df6e55cce80d22deb1de36f1bc3c"
	registry      = "127.0.0.1:5000"
	installDir    = "/opt/easyrmm"
	dataRoot      = "/srv/easyrmm"
	statusDir     = dataRoot + "/updater/status"
	backupDir     = "/var/backups/easyrmm-updater"
	// The fingerprint of Docker's package signing key
	// (https://docs.docker.com/engine/install/debian/).
	dockerKey = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
)

// The versions: A is installed, B is upgraded to and rolled back from, C
// is a release whose server never turns healthy, and E a release that
// installs only over D (its manifest's upgradeFrom), both published once
// C has failed.
const (
	versionA = "v9.0.0"
	versionB = "v9.0.1"
	versionC = "v9.0.2"
	versionD = "v9.1.0"
	versionE = "v9.2.0"
)

// withAuthentik, when EASYRMM_UPDATER_TEST_AUTHENTIK is 1, installs the
// deployment with Authentik (setup.sh --with-authentik): its services must
// run from each version's directory, and its database come back with the
// rest from each restore.
var withAuthentik = os.Getenv("EASYRMM_UPDATER_TEST_AUTHENTIK") == "1"

// TestUpgradeOnAMachine installs a deployment from a bundle with setup.sh
// on a Debian 12 machine with Docker, as an operator does, and drives the
// updater it installed (a test build, which trusts a virtual Sigstore the
// test makes and reads its versions from a directory):
//
//  1. status and check;
//  2. an upgrade from A to B, both bundles built from this checkout by
//     bundle.sh, each manifest attested by the virtual Sigstore;
//  3. a rollback of that confirmed upgrade, losing what was written since;
//  4. an upgrade to C, whose server fails its health check: the updater
//     brings A back from the backup it took;
//  5. D and E published, E naming D as its required upgrade stop: E asked
//     for by name is refused before anything stops, and the timer's
//     service, automatic upgrades on, installs D first and E on its next
//     run.
//
// Each step is checked from the outside: the version the server reports,
// the directory every container runs from, the data, the audit chain, the
// status the server reads and the updater's configuration. Run it with
// `make test-vm-updater`; it needs Docker and Go on the host, and the
// machine needs the internet (Docker's packages and the images the bundle
// names). EASYRMM_UPDATER_TEST_AUTHENTIK=1 installs Authentik too.
func TestUpgradeOnAMachine(t *testing.T) {
	if !slices.Contains(vmtest.Selected(t), machineImage) {
		t.Skipf("the updater's machine test runs on %s", machineImage)
	}
	for _, tool := range []string{"docker", "git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is needed: %v", tool, err)
		}
	}
	ctx := t.Context()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.TrimSpace(string(hostRun(t, root, nil, "git", "rev-parse", "HEAD")))
	engine := cmp.Or(os.Getenv("EASYRMM_UPDATER_TEST_ENGINE"), defaultEngine)
	work := t.TempDir()
	served := filepath.Join(work, "served")
	if err := os.Mkdir(served, 0o755); err != nil {
		t.Fatal(err)
	}
	base := serve(t, served)
	versions := []string{versionA, versionB, versionC, versionD, versionE}

	// The server images and the updater's test builds, while the machine
	// boots.
	builds := make(chan error, 1)
	go func() { builds <- buildAll(ctx, root, work, versions, t.Logf) }()

	vm := vmtest.Boot(t, machineImage, vmtest.Options{Forward: []int{5000}, MemoryMB: 6144, DiskGB: 40})
	m := &machine{t: t, vm: vm, authentik: withAuthentik}
	m.run("Docker", installDocker, time.Hour)
	m.run("the registry", fmt.Sprintf(`set -e
docker run -d --name registry --network host --restart always -e REGISTRY_HTTP_ADDR=0.0.0.0:5000 %s >/dev/null
for i in $(seq 1 90); do curl -fsS http://%s/v2/ >/dev/null 2>&1 && exit 0; sleep 2; done
echo "the registry did not answer" >&2; exit 1`, registryImage, registry), 30*time.Minute)
	if err := <-builds; err != nil {
		t.Fatal(err)
	}

	// Each version's server image into the machine's registry, then its
	// bundle and its attested manifest.
	pushTo := fmt.Sprintf("127.0.0.1:%d", vm.HostPort(5000))
	sigstore, err := releasetest.New()
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := sigstore.TrustedRootJSON()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(served, "trusted-root.json"), trusted)
	for _, v := range versions {
		digest := push(t, localImage(v), pushTo+"/easyrmm-server:"+imageTag(v))
		b := bundle{
			version: v, commit: commit, digest: digest, engine: engine,
			updater: filepath.Join(work, "updater-"+v), broken: v == versionC,
			emulated: vm.Emulated(),
		}
		if v == versionE {
			b.upgradeFrom = versionD
		}
		b.build(t, root, filepath.Join(work, "bundle-"+v), served, sigstore)
	}

	// 1. Installed as an operator would, from A's bundle with setup.sh,
	// which installs the updater; B and C offered to it.
	m.run("installing "+versionA, fmt.Sprintf(`set -e
mkdir -p %[2]s /etc/easyrmm/updater-test /var/lib/easyrmm-updater-test/releases
curl -fsS -o /etc/easyrmm/updater-test/trusted-root.json %[1]strusted-root.json
chmod 0644 /etc/easyrmm/updater-test/trusted-root.json
cd /root
curl -fsS -O %[1]seasyrmm-%[3]s-deploy.tar.gz
tar -xzf easyrmm-%[3]s-deploy.tar.gz -C %[2]s
cd %[2]s/easyrmm-%[3]s/deploy
./scripts/setup.sh --hostname 127.0.0.1 --ip-addresses 127.0.0.1 %[6]s</dev/null
docker compose pull --quiet
docker compose up -d
cd /var/lib/easyrmm-updater-test/releases
for v in %[4]s %[5]s; do
  for f in manifest.json manifest.json.sigstore.json deploy.tar.gz; do curl -fsS -O "%[1]seasyrmm-$v-$f"; done
done`, base, installDir, versionA, versionB, versionC, authentikFlags()), 2*time.Hour)
	m.healthy(versionA, 2*time.Hour)
	m.serves(versionA)
	if out := m.run("the updater's version", "easyrmm-updater version", time.Minute); !strings.HasPrefix(out, versionA+" (TEST BUILD") {
		t.Errorf("the installed updater: %q", out)
	}
	if conf := m.run("its configuration", "cat /etc/easyrmm/updater.conf; stat -c '%U %a' /etc/easyrmm/updater.conf", time.Minute); !strings.Contains(conf, "deployment = "+deployDir(versionA)+"\n") ||
		!strings.Contains(conf, "channel = stable\n") || !strings.Contains(conf, "auto_upgrade = no\n") || !strings.HasSuffix(conf, "root 600\n") {
		t.Errorf("updater.conf:\n%s", conf)
	}
	m.run("its timer", "systemctl is-enabled easyrmm-updater.timer && systemctl is-active easyrmm-updater.timer", time.Minute)
	status := m.run("status", "easyrmm-updater status", 10*time.Minute)
	for _, want := range []string{"TEST BUILD", "(the server says " + versionA + ")", "Channel:     stable; automatic upgrades off", "Held:        false"} {
		if !strings.Contains(status, want) {
			t.Errorf("status lacks %q:\n%s", want, status)
		}
	}
	check := m.run("check", "easyrmm-updater check", 10*time.Minute)
	for _, want := range []string{"Offered:  " + versionB + ", " + versionC, "Newest:   " + versionC + ", verified (commit " + commit + ")"} {
		if !strings.Contains(check, want) {
			t.Errorf("check lacks %q:\n%s", want, check)
		}
	}
	m.appendAudit(versionA, "test.before_upgrade", 2)
	if m.authentik {
		m.psqlDB(versionA, "authentik", "CREATE TABLE machinetest_marker (note text); INSERT INTO machinetest_marker VALUES ('before the upgrade');")
	}

	// 2. Upgrade to B.
	m.updater("upgrading to "+versionB, "easyrmm-updater upgrade "+versionB)
	m.serves(versionB)
	st := m.status()
	if a := st.Attempt; a == nil || a.Action != "upgrade" || a.Result != host.ResultSucceeded || a.From != versionA || a.To != versionB {
		t.Errorf("after the upgrade: %+v", a)
	}
	if st.Running != versionB || st.Previous != versionA || st.Rollback == nil || st.Rollback.To != versionA {
		t.Errorf("status after the upgrade: %+v", st)
	}
	held := m.run("the engine's hold", "cat "+statusDir+"/agent-updates-held-until; stat -c '%U %a' "+statusDir+" "+statusDir+"/agent-updates-held-until; test ! -e "+statusDir+"/hold", time.Minute)
	lines := strings.Split(strings.TrimSpace(held), "\n")
	until, err := time.Parse(time.RFC3339, lines[0])
	if left := time.Until(until); err != nil || left < 23*time.Hour || left > 25*time.Hour || len(lines) != 3 || lines[1] != "root 755" || lines[2] != "root 644" {
		t.Errorf("the hold on the engine's agent updates, and the status directory: %q (%v)", held, err)
	}
	if out := m.run("the updater replaced itself", "easyrmm-updater version", time.Minute); !strings.HasPrefix(out, versionB+" (TEST BUILD") {
		t.Errorf("the updater after the upgrade: %q", out)
	}
	if conf := m.run("the configuration", "cat /etc/easyrmm/updater.conf", time.Minute); !strings.Contains(conf, "deployment = "+deployDir(versionB)+"\n") {
		t.Errorf("updater.conf after the upgrade:\n%s", conf)
	}
	if backups := m.run("the backup", "cd "+backupDir+" && stat -c '%U %a' . && ls && cat */backup.json", time.Minute); !strings.HasPrefix(backups, "root 700\n") ||
		!regexp.MustCompile(`(?m)^[0-9]{8}T[0-9]{6}Z-`+regexp.QuoteMeta(versionA)+`$`).MatchString(backups) || !strings.Contains(backups, `"version": "`+versionA+`"`) {
		t.Errorf("the backup:\n%s", backups)
	}
	if n := m.audit(versionB, "count(*) FILTER (WHERE action = 'test.before_upgrade')"); n != "2" {
		t.Errorf("the records written before the upgrade: %s", n)
	}

	// 3. Written since, then rolled back: lost, and the audit IDs move on.
	m.appendAudit(versionB, "test.after_upgrade", 3)
	if m.authentik {
		m.psqlDB(versionB, "authentik", "INSERT INTO machinetest_marker VALUES ('after the upgrade');")
	}
	discarded, err := strconv.Atoi(m.audit(versionB, "max(id)"))
	if err != nil {
		t.Fatal(err)
	}
	rollback := m.updater("rolling back to "+versionA, "easyrmm-updater rollback --yes")
	if !strings.Contains(rollback, "It loses ") {
		t.Errorf("the rollback did not say what it loses:\n%s", rollback)
	}
	m.serves(versionA)
	st = m.status()
	if a := st.Attempt; a == nil || a.Action != "rollback" || a.Result != host.ResultRolledBack {
		t.Errorf("after the rollback: %+v", a)
	}
	if st.Running != versionA || st.Rollback != nil {
		t.Errorf("status after the rollback: %+v", st)
	}
	m.rolledBack(versionA, versionB, discarded)
	if n := m.audit(versionA, "count(*) FILTER (WHERE action = 'test.after_upgrade')"); n != "0" {
		t.Errorf("records written after the upgrade survived the rollback: %s", n)
	}
	if m.authentik {
		if notes := m.psqlDB(versionA, "authentik", "SELECT string_agg(note, ', ') FROM machinetest_marker;"); notes != "before the upgrade" {
			t.Errorf("Authentik's database after the rollback: %q", notes)
		}
	}
	if out := m.run("the updater kept its version", "easyrmm-updater version", time.Minute); !strings.HasPrefix(out, versionB+" (TEST BUILD") {
		t.Errorf("the updater after the rollback: %q", out)
	}
	if conf := m.run("the configuration", "cat /etc/easyrmm/updater.conf", time.Minute); !strings.Contains(conf, "deployment = "+deployDir(versionA)+"\n") {
		t.Errorf("updater.conf after the rollback:\n%s", conf)
	}
	if status := m.run("status", "easyrmm-updater status", 10*time.Minute); !strings.Contains(status, "Skipped by automatic upgrades (failed or rolled back): "+versionB) {
		t.Errorf("status after the rollback:\n%s", status)
	}

	// 4. C's server never turns healthy: A comes back from the backup.
	discarded, err = strconv.Atoi(m.audit(versionA, "max(id)"))
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit := m.try("upgrading to "+versionC, "easyrmm-updater upgrade "+versionC, 3*time.Hour)
	if exit == 0 {
		t.Fatalf("the upgrade to %s succeeded:\n%s\n%s", versionC, stdout, stderr)
	}
	m.serves(versionA)
	st = m.status()
	if a := st.Attempt; a == nil || a.Result != host.ResultRolledBack || a.To != versionC || !strings.Contains(a.Reason, "unhealthy") {
		t.Errorf("after the failed upgrade: %+v", a)
	}
	if st.Running != versionA {
		t.Errorf("status after the failed upgrade: %+v", st)
	}
	m.rolledBack(versionA, versionC, discarded)
	if out := m.run("what the failure left", fmt.Sprintf(`set -e
test ! -e %[1]s/easyrmm-%[2]s
test ! -e %[3]s/hold
stat -c '%%U %%a %%n' %[4]s/.failed-*-%[2]s`, installDir, versionC, statusDir, dataRoot), time.Minute); !strings.HasPrefix(out, "root 700 "+dataRoot+"/.failed-") {
		t.Errorf("the failed data root: %q", out)
	}
	if n := m.audit(versionA, "count(*) FILTER (WHERE action = 'test.before_upgrade')"); n != "2" {
		t.Errorf("the records written before the upgrades: %s", n)
	}
	if m.authentik {
		if notes := m.psqlDB(versionA, "authentik", "SELECT string_agg(note, ', ') FROM machinetest_marker;"); notes != "before the upgrade" {
			t.Errorf("Authentik's database after the failed upgrade: %q", notes)
		}
	}

	// 5. D and E published; E installs only over D.
	m.run("publishing "+versionD+" and "+versionE, fmt.Sprintf(`set -e
cd /var/lib/easyrmm-updater-test/releases
for v in %[2]s %[3]s; do
  for f in manifest.json manifest.json.sigstore.json deploy.tar.gz; do curl -fsS -O "%[1]seasyrmm-$v-$f"; done
done`, base, versionD, versionE), 10*time.Minute)
	const serverStarted = "docker inspect -f '{{.State.StartedAt}}' easyrmm-server-1"
	started := m.run("the server's start", serverStarted, time.Minute)
	stdout, stderr, exit = m.try("upgrading to "+versionE+" from below its stop", "easyrmm-updater upgrade "+versionE, time.Hour)
	if refusal := versionE + " installs only over " + versionD + " or later, and " + versionA + " runs: install " + versionD + " first (easyrmm-updater upgrade " + versionD + ")"; exit == 0 || !strings.Contains(stderr, refusal) {
		t.Errorf("the upgrade to %s from below its stop, which should say %q: exit %d\n%s\n%s", versionE, refusal, exit, stdout, stderr)
	}
	if again := m.run("the server's start", serverStarted, time.Minute); again != started {
		t.Errorf("the refused upgrade restarted the server: started %s, then %s", started, again)
	}
	m.serves(versionA)
	check = m.run("check", "easyrmm-updater check", 10*time.Minute)
	for _, want := range []string{
		"Newest:   " + versionE + ", verified (commit " + commit + ")",
		"which must first upgrade to " + versionD + ", a required upgrade stop: easyrmm-updater upgrade " + versionD,
	} {
		if !strings.Contains(check, want) {
			t.Errorf("check lacks %q:\n%s", want, check)
		}
	}
	// Automatic upgrades on, at any hour; the timer stopped so that its
	// service runs only when the test starts it, as the timer would.
	m.run("automatic upgrades on", `set -e
systemctl stop easyrmm-updater.timer
sed -i -e 's/^auto_upgrade = .*/auto_upgrade = yes/' -e 's/^auto_upgrade_hours = .*/auto_upgrade_hours = 0-24/' /etc/easyrmm/updater.conf
grep -x 'auto_upgrade = yes' /etc/easyrmm/updater.conf
grep -x 'auto_upgrade_hours = 0-24' /etc/easyrmm/updater.conf`, time.Minute)
	m.updater("the timer's service, installing "+versionD+" first", "systemctl start easyrmm-updater.service")
	m.serves(versionD)
	st = m.status()
	if a := st.Attempt; a == nil || a.Action != "upgrade" || a.By != "automatic" || a.Result != host.ResultSucceeded || a.From != versionA || a.To != versionD {
		t.Errorf("after the first automatic upgrade: %+v", a)
	}
	if journal := m.run("the service's journal", "journalctl -u easyrmm-updater.service --no-pager -o cat", time.Minute); !strings.Contains(journal, "installing the required upgrade stop first") {
		t.Errorf("the journal does not say the stop was installed first:\n%s", journal)
	}
	if out := m.run("the updater replaced itself", "easyrmm-updater version", time.Minute); !strings.HasPrefix(out, versionD+" (TEST BUILD") {
		t.Errorf("the updater after the upgrade to the stop: %q", out)
	}
	m.updater("the timer's service, installing "+versionE, "systemctl start easyrmm-updater.service")
	m.serves(versionE)
	st = m.status()
	if a := st.Attempt; a == nil || a.By != "automatic" || a.Result != host.ResultSucceeded || a.From != versionD || a.To != versionE {
		t.Errorf("after the second automatic upgrade: %+v", a)
	}
	if st.Running != versionE || st.Previous != versionD {
		t.Errorf("status after the upgrades: %+v", st)
	}
	if n := m.audit(versionE, "count(*) FILTER (WHERE action = 'test.before_upgrade')"); n != "2" {
		t.Errorf("the records written before the upgrades, on %s: %s", versionE, n)
	}
	if m.authentik {
		if notes := m.psqlDB(versionE, "authentik", "SELECT string_agg(note, ', ') FROM machinetest_marker;"); notes != "before the upgrade" {
			t.Errorf("Authentik's database on %s: %q", versionE, notes)
		}
	}
}

// authentikFlags are setup.sh's flags for Authentik, when the test
// installs it: a sign-in name no one resolves, which the deployment's own
// services never need to.
func authentikFlags() string {
	if !withAuthentik {
		return ""
	}
	return "--with-authentik --authentik-hostname auth.rmm.test --admin-email admin@rmm.test "
}

// installDocker installs Docker Engine and its Compose plugin from Docker's
// Debian repository, its signing key checked by fingerprint.
const installDocker = `set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
apt-get install -y -q ca-certificates curl gnupg >/dev/null
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
fpr=$(gpg --show-keys --with-colons /etc/apt/keyrings/docker.asc | awk -F: '$1 == "fpr" { print $10; exit }')
[ "$fpr" = "` + dockerKey + `" ] || { echo "Docker's key is $fpr" >&2; exit 1; }
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" >/etc/apt/sources.list.d/docker.list
apt-get update -q >/dev/null
apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
docker version --format 'Docker {{.Server.Version}}'
docker compose version`

func localImage(v string) string { return "easyrmm-updater-machinetest/easyrmm-server:" + imageTag(v) }
func imageTag(v string) string   { return release.MustParseVersion(v).ImageTag() }
func deployDir(v string) string  { return installDir + "/easyrmm-" + v + "/deploy" }

// buildAll builds each version's server image from the checkout, and the
// updater's test build reporting that version.
func buildAll(ctx context.Context, root, work string, versions []string, logf func(string, ...any)) error {
	for _, v := range versions {
		start := time.Now()
		if out, err := command(ctx, root, nil, "docker", "build", "-q", "-f", "docker/server/Dockerfile",
			"--build-arg", "VERSION="+v, "-t", localImage(v), "."); err != nil {
			return fmt.Errorf("building the server image of %s: %w\n%s", v, err, out)
		}
		if out, err := command(ctx, root, []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64"}, "go", "build",
			"-tags", "updatertest", "-trimpath", "-ldflags", "-s -w -X main.Version="+v,
			"-o", filepath.Join(work, "updater-"+v), "./updater/cmd/easyrmm-updater"); err != nil {
			return fmt.Errorf("building the updater's test build of %s: %w\n%s", v, err, out)
		}
		logf("built %s's server image and updater in %s", v, time.Since(start).Round(time.Second))
	}
	return nil
}

// push pushes an image through the machine's forwarded registry port and
// returns its digest.
func push(t *testing.T, local, remote string) string {
	t.Helper()
	hostRun(t, "", nil, "docker", "tag", local, remote)
	t.Cleanup(func() {
		_, _ = command(context.Background(), "", nil, "docker", "image", "rm", remote, local)
	})
	out := hostRun(t, "", nil, "docker", "push", remote)
	d := regexp.MustCompile(`digest: (sha256:[0-9a-f]{64})`).FindSubmatch(out)
	if d == nil {
		t.Fatalf("docker push %s said no digest:\n%s", remote, out)
	}
	return string(d[1])
}

// bundle is one version's release: its bundle from bundle.sh, its
// manifest, and the manifest's attestation.
type bundle struct {
	version, commit, digest, engine string
	// updater is the updater's test build, which replaces bundle.sh's.
	updater string
	// broken gives the server a health check that never passes.
	broken bool
	// upgradeFrom is the manifest's required upgrade stop, if any.
	upgradeFrom string
	// emulated gives every service an hour to become healthy: on an
	// emulated machine, the first starts of PostgreSQL and the engine
	// take longer than the health checks allow (Compose then fails
	// --wait, and up -d for what depends on them).
	emulated bool
}

// build runs bundle.sh, then has the bundle's deployment run the server
// from the machine's registry and the updater's test build, writes its
// manifest and attests it, into served.
func (b bundle) build(t *testing.T, root, out, served string, sigstore *releasetest.Sigstore) {
	t.Helper()
	tag := imageTag(b.version)
	hostRun(t, root, []string{
		"EASYRMM_IMAGE_PIN=ghcr.io/paulmataruso/easyrmm-server:" + tag + "@" + b.digest,
		"EASYPATCH_IMAGE_PIN=" + b.engine,
	}, "scripts/release/bundle.sh", b.version, out)
	name := "easyrmm-" + b.version + "-deploy.tar.gz"
	updater, err := os.ReadFile(b.updater)
	if err != nil {
		t.Fatal(err)
	}
	var compose []byte
	changed := map[string]bool{}
	data := rewriteBundle(t, filepath.Join(out, name), func(path string, data []byte) []byte {
		switch path {
		case "easyrmm-" + b.version + "/deploy/.env.example":
			changed[path] = true
			data = regexp.MustCompile(`(?m)^EASYRMM_IMAGE=.*$`).ReplaceAll(data, []byte("EASYRMM_IMAGE="+registry+"/easyrmm-server"))
			return regexp.MustCompile(`(?m)^EASYRMM_VERSION=.*$`).ReplaceAll(data, []byte("EASYRMM_VERSION="+tag+"@"+b.digest))
		case "easyrmm-" + b.version + "/deploy/updater/easyrmm-updater-linux-amd64":
			changed[path] = true
			return updater
		case "easyrmm-" + b.version + "/deploy/docker-compose.yml":
			changed[path] = true
			if b.emulated {
				data = regexp.MustCompile(`(?m)^( +start_period:) \S+$`).ReplaceAll(data, []byte("$1 60m"))
			}
			switch {
			case b.broken:
				data = bytes.Replace(data, []byte("\n  server:\n"), []byte("\n  server:\n"+brokenHealthCheck), 1)
			case b.emulated:
				data = bytes.Replace(data, []byte("\n  server:\n"), []byte("\n  server:\n"+slowHealthCheck), 1)
			}
			compose = data
		}
		return data
	})
	if len(changed) != 3 || bytes.Contains(compose, []byte(brokenHealthCheck)) != b.broken {
		t.Fatalf("%s: changed %v", name, changed)
	}
	writeFile(t, filepath.Join(served, name), data)

	m := releasetest.NewManifest(b.version, b.commit)
	sum := sha256.Sum256(data)
	m.BundleSHA256 = hex.EncodeToString(sum[:])
	m.Server, m.ServerDigest, m.Engine = registry+"/easyrmm-server", "@"+b.digest, b.engine
	m.Postgres, m.MeshCentral, m.Authentik = "", "", ""
	m.UpgradeFrom = b.upgradeFrom
	for _, img := range composeImages(compose) {
		switch {
		case img == b.engine:
		case strings.HasPrefix(img, "postgres:"):
			m.Postgres = img
		case strings.HasPrefix(img, "ghcr.io/ylianst/meshcentral:"):
			m.MeshCentral = img
		case strings.HasPrefix(img, "ghcr.io/goauthentik/server:"):
			m.Authentik = img
		default:
			t.Fatalf("%s names an image the test does not know: %s", name, img)
		}
	}
	major, _, _ := strings.Cut(strings.TrimPrefix(m.Postgres, "postgres:"), ".")
	if m.PostgresMajor, err = strconv.Atoi(major); err != nil || m.MeshCentral == "" || m.Authentik == "" {
		t.Fatalf("%s: the images %+v", name, m)
	}
	manifest := m.JSON()
	manifestName := "easyrmm-" + b.version + "-manifest.json"
	attestation, err := sigstore.Attest(releasetest.For(release.MustParseVersion(b.version), b.commit),
		releasetest.File{Name: manifestName, Contents: manifest})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(served, manifestName), manifest)
	writeFile(t, filepath.Join(served, manifestName+".sigstore.json"), attestation)
}

// brokenHealthCheck is C's: its server is never healthy, and Compose says
// so within seconds.
const brokenHealthCheck = `    healthcheck:
      test: ["CMD", "false"]
      interval: 5s
      timeout: 3s
      retries: 2
      start_period: 0s
`

// slowHealthCheck is the server image's own health check, given an hour to
// pass on an emulated machine.
const slowHealthCheck = `    healthcheck:
      test: ["CMD", "/usr/local/bin/easyrmm-server", "healthcheck"]
      interval: 30s
      timeout: 6s
      retries: 3
      start_period: 60m
`

// composeImages lists the images a Compose file names literally.
func composeImages(compose []byte) []string {
	var imgs []string
	for _, m := range regexp.MustCompile(`(?m)^ +image: ([^$\s]\S*)$`).FindAllSubmatch(compose, -1) {
		imgs = append(imgs, string(m[1]))
	}
	slices.Sort(imgs)
	return slices.Compact(imgs)
}

// rewriteBundle reads a bundle and returns it with each regular file passed
// through change, every header kept but the size.
func rewriteBundle(t *testing.T, path string, change func(name string, data []byte) []byte) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var data []byte
		if h.Typeflag == tar.TypeReg {
			if data, err = io.ReadAll(tr); err != nil {
				t.Fatal(err)
			}
			data = change(h.Name, data)
			h.Size = int64(len(data))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// machine runs the test's scripts on the virtual machine.
type machine struct {
	t  *testing.T
	vm *vmtest.VM
	// authentik is set when the deployment runs Authentik.
	authentik bool
}

// try runs a script and returns what it printed and its exit code.
func (m *machine) try(what, script string, timeout time.Duration) (string, string, int) {
	m.t.Helper()
	ctx, cancel := context.WithTimeout(m.t.Context(), timeout)
	defer cancel()
	start := time.Now()
	stdout, stderr, exit, err := m.vm.Run(ctx, script)
	if err != nil {
		m.t.Fatalf("%s: %v", what, err)
	}
	m.t.Logf("%s: exit %d after %s", what, exit, time.Since(start).Round(time.Second))
	return string(stdout), string(stderr), exit
}

// run runs a script that must succeed and returns its output.
func (m *machine) run(what, script string, timeout time.Duration) string {
	m.t.Helper()
	stdout, stderr, exit := m.try(what, script, timeout)
	if exit != 0 {
		m.t.Fatalf("%s: exit %d\nstdout:\n%s\nstderr:\n%s", what, exit, stdout, stderr)
	}
	return stdout
}

// updater runs the updater, which must succeed, and says what the
// deployment shows when it does not.
func (m *machine) updater(what, script string) string {
	m.t.Helper()
	stdout, stderr, exit := m.try(what, script, 3*time.Hour)
	if exit != 0 {
		m.t.Errorf("%s: exit %d\nstdout:\n%s\nstderr:\n%s", what, exit, stdout, stderr)
		m.diagnose()
		m.t.FailNow()
	}
	return stdout
}

// healthy waits, as an operator would after docker compose up -d, until
// every container of the deployment of v runs healthy, and says how long
// that took.
func (m *machine) healthy(v string, timeout time.Duration) {
	m.t.Helper()
	_, _, exit := m.try(v+" healthy", fmt.Sprintf(`cd %s
end=$(($(date +%%s) + %d))
while [ "$(date +%%s)" -lt "$end" ]; do
  states=$(docker compose ps --format '{{.Service}} {{.State}} {{.Health}}')
  if ! printf '%%s\n' "$states" | grep -v ' running healthy$' | grep -q .; then exit 0; fi
  sleep 10
done
printf '%%s\n' "$states" >&2
exit 1`, deployDir(v), int(timeout.Seconds())), timeout+5*time.Minute)
	if exit != 0 {
		m.t.Errorf("%s did not turn healthy within %s", v, timeout)
		m.diagnose()
		m.t.FailNow()
	}
}

// diagnose logs the deployment's containers and recent logs, and the
// updater's journal and status.
func (m *machine) diagnose() {
	m.t.Helper()
	stdout, stderr, _ := m.try("diagnostics", `cd "$(sed -n 's/^deployment = //p' /etc/easyrmm/updater.conf)" 2>/dev/null || cd /
docker ps -a --filter label=com.docker.compose.project=easyrmm --format '{{.Names}} {{.Status}} {{.Label "com.docker.compose.project.working_dir"}}'
for c in $(docker ps -a -q --filter label=com.docker.compose.project=easyrmm); do
  echo "--- $(docker inspect --format '{{.Name}}' "$c")"
  docker inspect --format '{{if .State.Health}}{{range .State.Health.Log}}{{.Start}} exit {{.ExitCode}}: {{.Output}}{{end}}{{end}}' "$c" | tail -n 5
  docker logs --tail 30 "$c" 2>&1
done
echo "--- the updater's journal"
journalctl -t easyrmm-updater -u easyrmm-updater --no-pager -n 80
echo "--- status.json"
cat `+statusDir+`/status.json`, 10*time.Minute)
	m.t.Logf("diagnostics:\n%s\n%s", stdout, stderr)
}

// serves checks that every container of the deployment runs from v's
// directory and that its server reports v, ready.
func (m *machine) serves(v string) {
	m.t.Helper()
	out := m.run(v+" serving", fmt.Sprintf(`set -e
cd %s
docker compose exec -T server easyrmm-server healthcheck >/dev/null
docker compose exec -T server easyrmm-server version
docker ps --filter label=com.docker.compose.project=easyrmm --format '{{.Label "com.docker.compose.service"}} {{.Label "com.docker.compose.project.working_dir"}} {{.Status}}' | sort`,
		deployDir(v)), 10*time.Minute)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if lines[0] != v {
		m.t.Errorf("the server reports %q, not %s", lines[0], v)
	}
	services := map[string]bool{}
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		services[f[0]] = true
		if len(f) < 3 || f[1] != deployDir(v) || f[2] != "Up" {
			m.t.Errorf("%s: %s", v, l)
		}
	}
	want := []string{"postgres", "server", "meshcentral", "easypatch-api", "easypatch-worker"}
	if m.authentik {
		want = append(want, "authentik-server", "authentik-worker")
	}
	for _, s := range want {
		if !services[s] {
			m.t.Errorf("%s: %s is not running:\n%s", v, s, out)
		}
	}
}

// status is the status the server reads.
func (m *machine) status() host.Status {
	m.t.Helper()
	var s host.Status
	out := m.run("status.json", "cat "+statusDir+"/status.json", time.Minute)
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		m.t.Fatalf("status.json: %v\n%s", err, out)
	}
	return s
}

// psql runs SQL as PostgreSQL's superuser in EasyRMM's database, in the
// deployment of v.
func (m *machine) psql(v, sql string) string {
	m.t.Helper()
	return m.psqlDB(v, "easyrmm", sql)
}

// psqlDB runs SQL as PostgreSQL's superuser in database db.
func (m *machine) psqlDB(v, db, sql string) string {
	m.t.Helper()
	return strings.TrimSpace(m.run("psql", fmt.Sprintf("cd %s && docker compose exec -T --user postgres postgres psql -X -q -A -t -v ON_ERROR_STOP=1 -p 15432 -d %s <<'SQL'\n%s\nSQL",
		deployDir(v), db, sql), 10*time.Minute))
}

// audit is an aggregate over the audit log.
func (m *machine) audit(v, aggregate string) string {
	return m.psql(v, "SELECT "+aggregate+" FROM audit_log;")
}

// appendAudit appends n records through the database's own function, as
// the server writes them.
func (m *machine) appendAudit(v, action string, n int) {
	m.t.Helper()
	m.psql(v, fmt.Sprintf(`SELECT easyrmm_audit_append(now(), 'system', NULL, 'machine test', NULL, NULL, NULL,
		'%s', '', '', 'success', NULL, '', '{}'::jsonb) FROM generate_series(1, %d);`, action, n))
}

// rolledBack checks the rollback's audit record: after every ID the
// discarded version wrote, naming it, and the chain intact.
func (m *machine) rolledBack(running, discardedVersion string, discardedLastID int) {
	m.t.Helper()
	out := m.psql(running, `SELECT id || '|' || target_id || '|' || details::text FROM audit_log WHERE action = 'updater.rolled_back' ORDER BY id DESC LIMIT 1;
SELECT coalesce(first_bad_id::text, 'intact') FROM easyrmm_audit_verify(0, 1000000);`)
	lines := strings.Split(out, "\n")
	if len(lines) != 2 {
		m.t.Fatalf("the rollback's record: %q", out)
	}
	f := strings.SplitN(lines[0], "|", 3)
	if len(f) != 3 {
		m.t.Fatalf("the rollback's record: %q", lines[0])
	}
	id, _ := strconv.Atoi(f[0])
	var details struct {
		DiscardedLastID *int `json:"discardedLastId"`
	}
	_ = json.Unmarshal([]byte(f[2]), &details)
	if id <= discardedLastID || f[1] != discardedVersion || details.DiscardedLastID == nil || *details.DiscardedLastID < discardedLastID {
		m.t.Errorf("the rollback's record, after ID %d of %s: %s", discardedLastID, discardedVersion, lines[0])
	}
	if lines[1] != "intact" {
		m.t.Errorf("the audit chain breaks at %s", lines[1])
	}
}

// serve serves dir to the machine, which reaches the host's loopback as
// 10.0.2.2 (QEMU's user networking), and returns its address there.
func serve(t *testing.T, dir string) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.FileServer(http.Dir(dir)), ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return fmt.Sprintf("http://10.0.2.2:%d/", ln.Addr().(*net.TCPAddr).Port)
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// command runs a program on the host and returns its output, stdout and
// stderr together.
func command(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	return cmd.CombinedOutput()
}

func hostRun(t *testing.T, dir string, env []string, name string, args ...string) []byte {
	t.Helper()
	out, err := command(t.Context(), dir, env, name, args...)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}
