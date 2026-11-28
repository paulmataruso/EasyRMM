package host

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/updater/internal/release"
)

// composeFile is the deployment's Compose file, from this package's
// directory.
const composeFile = "../../../deploy/docker-compose.yml"

// composeVolumes lists every bind mount's source in a Compose file, each
// once: the entries of each service's volumes list.
func composeVolumes(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entry := regexp.MustCompile(`^      - (\S+)$`)
	var sources []string
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "    volumes:":
			in = true
		case in && strings.HasPrefix(strings.TrimSpace(line), "#"):
		case in && entry.MatchString(line):
			src, _, _ := strings.Cut(entry.FindStringSubmatch(line)[1], ":/")
			sources = append(sources, src)
		default:
			in = false
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(sources)
	return slices.Compact(sources)
}

// Every volume of the deployment is in a backup: the data root's (every
// one that holds state), or the deployment's own docker/ files (the
// tree). The exceptions are the updater's own status, which it writes as
// it goes, and the operator's certificates in manual TLS mode, which
// setup.sh puts in the data root but an operator may point elsewhere,
// mounted read-only and never changed by an upgrade. A volume anywhere
// else would be state the updater neither backs up nor restores.
func TestBackupCoversEveryVolume(t *testing.T) {
	const dataRootVar = "${EASYRMM_DATA_ROOT:-/srv/easyrmm}/"
	const keystoreDirVar = "${EASYRMM_KEYSTORE_DIR:-/var/lib/easyrmm-keystore}"
	var dataRoot []string
	for _, src := range composeVolumes(t, composeFile) {
		switch {
		case strings.HasPrefix(src, dataRootVar):
			dir := strings.TrimPrefix(src, dataRootVar)
			if top, _, _ := strings.Cut(dir, "/"); !skippedEntry(top) {
				dataRoot = append(dataRoot, dir)
			} else if dir != updaterEntry+"/status" {
				t.Errorf("%s mounts %s, which a backup leaves out", composeFile, src)
			}
		case strings.HasPrefix(src, "../docker/"):
		case src == "${EASYRMM_TLS_DIR:-/srv/easyrmm/tls}":
		// The keystore's state and socket folder are kept out of every backup
		// on purpose (ADR-0081): the sealed key must not travel with the
		// database it protects. checkMounts refuses them anywhere a backup
		// copies (TestKeystoreMountsLieApartFromBackups).
		case src == keystoreDirVar, src == keystoreDirVar+"/run":
		// The log store (ADR-0060) lives on EASYRMM_LOGS_ROOT, which
		// defaults to ${EASYRMM_DATA_ROOT}-logs. It is a separate
		// database whose data can be re-collected; the updater's backup
		// covers only the main data root.
		case strings.HasPrefix(src, "${EASYRMM_LOGS_ROOT:-${EASYRMM_DATA_ROOT:-/srv/easyrmm}-logs}/"):
		default:
			t.Errorf("%s mounts %s, which a backup does not hold", composeFile, src)
		}
	}
	if setup := readFile(t, "../../../deploy/scripts/setup.sh"); !strings.Contains(setup, "EASYRMM_TLS_DIR=${data_root}/tls") {
		t.Error("setup.sh no longer puts EASYRMM_TLS_DIR in the data root")
	}
	// What an Authentik deployment keeps: its directories, and its
	// database in the cluster.
	for _, want := range []string{"postgres", "server", "authentik/data", "authentik/secrets", "authentik/invitations", "easypatch/keys", "meshcentral/data"} {
		if !slices.Contains(dataRoot, want) {
			t.Errorf("%s does not mount %s from the data root: the test is out of date", composeFile, want)
		}
	}

	// An Authentik deployment, every volume written, whose upgrade fails
	// at the held start after the backup: each comes back as it was.
	h := newTestHost(t, "v1.0.0", release.ChannelStable)
	envPath := filepath.Join(h.deploy("v1.0.0"), ".env")
	writeFile(t, envPath, readFile(t, envPath)+"COMPOSE_PROFILES=authentik\n", 0o600)
	for _, dir := range dataRoot {
		writeFile(t, filepath.Join(h.dataRoot, dir, "state"), "before the upgrade: "+dir, 0o600)
	}
	writeFile(t, filepath.Join(h.dataRoot, "postgres", "18", "docker", "base", "authentik"), "Authentik's database", 0o600)
	h.offer("v1.1.0", nil)
	h.docker.fail = func(dir string, args []string) error {
		if dir != h.deploy("v1.1.0") || !slices.Contains(args, "--wait") {
			return nil
		}
		for _, d := range dataRoot {
			writeFile(t, filepath.Join(h.dataRoot, d, "state"), "written by v1.1.0", 0o600)
			writeFile(t, filepath.Join(h.dataRoot, d, "new"), "written by v1.1.0", 0o600)
		}
		writeFile(t, filepath.Join(h.dataRoot, "postgres", "18", "docker", "base", "authentik"), "changed by v1.1.0", 0o600)
		return errors.New("container easyrmm-authentik-server-1 is unhealthy")
	}
	if err := h.upgrade(Request{}); err == nil || !strings.Contains(err.Error(), "rolled-back") {
		t.Fatalf("got %v", err)
	}
	for _, dir := range dataRoot {
		if got := readFile(t, filepath.Join(h.dataRoot, dir, "state")); got != "before the upgrade: "+dir {
			t.Errorf("%s holds %q", dir, got)
		}
		if _, err := os.Lstat(filepath.Join(h.dataRoot, dir, "new")); err == nil {
			t.Errorf("%s keeps what the failed version wrote", dir)
		}
	}
	if got := readFile(t, filepath.Join(h.dataRoot, "postgres", "18", "docker", "base", "authentik")); got != "Authentik's database" {
		t.Errorf("the cluster holds %q", got)
	}
	if h.docker.running["authentik-server"] != h.deploy("v1.0.0") {
		t.Errorf("Authentik runs from %q", h.docker.running["authentik-server"])
	}
}

func TestVerifyCopy(t *testing.T) {
	ctx := context.Background()
	src := filepath.Join(t.TempDir(), "src")
	writeFile(t, filepath.Join(src, "a", "b"), "bee", 0o600)
	if err := os.Symlink("a/b", filepath.Join(src, "l")); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		change func(dst string) error
		want   string
	}{
		"cut short":     {func(dst string) error { return os.WriteFile(filepath.Join(dst, "a", "b"), []byte("be"), 0o600) }, "differs at a/b"},
		"missing":       {func(dst string) error { return os.Remove(filepath.Join(dst, "a", "b")) }, "lacks a/b"},
		"one more":      {func(dst string) error { return os.WriteFile(filepath.Join(dst, "c"), nil, 0o600) }, "has c"},
		"another mode":  {func(dst string) error { return os.Chmod(filepath.Join(dst, "a"), 0o700) }, "differs at a"},
		"another link":  {func(dst string) error { return relink(filepath.Join(dst, "l"), "a") }, "-> a, not"},
		"a link for it": {func(dst string) error { return relink(filepath.Join(dst, "a", "b"), "/etc/passwd") }, "differs at a/b"},
	} {
		dst := filepath.Join(t.TempDir(), "copy")
		if err := copyTree(ctx, src, dst); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := tc.change(dst); err != nil {
			t.Fatal(err)
		}
		if err := verifyCopy(src, dst); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := verifyCopy(filepath.Join(src, "missing"), src); err == nil {
		t.Error("a source that is not there")
	}
	if err := verifyCopy(src, filepath.Join(src, "missing")); err == nil {
		t.Error("a copy that is not there")
	}
}

func relink(path, target string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return os.Symlink(target, path)
}
