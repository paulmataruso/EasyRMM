//go:build integration

package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cluster is a PostgreSQL cluster in a throwaway container, its data
// mounted from the host as the deployment's postgres service mounts
// <data root>/postgres, with no network.
type cluster struct {
	t    *testing.T
	name string
}

func newCluster(t *testing.T, dir string) *cluster {
	t.Helper()
	image, err := exec.Command("docker", "inspect", "-f", "{{.Config.Image}}", testDBContainer()).Output()
	if err != nil {
		t.Fatalf("the test database's image (make test-db): %v", err)
	}
	id := make([]byte, 4)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	c := &cluster{t: t, name: "easyrmm-updater-pg-" + hex.EncodeToString(id)}
	args := []string{"run", "-d", "--name", c.name, "--network", "none", "-e", "POSTGRES_PASSWORD=test-only", "-v", dir + ":/var/lib/postgresql"}
	// PostgreSQL never runs as root; run as anyone else, it runs as the
	// user who runs the test, whose files the test can copy.
	if uid := os.Getuid(); uid != 0 {
		args = append(args, "--user", fmt.Sprintf("%d:%d", uid, os.Getgid()))
	}
	c.docker(append(args, strings.TrimSpace(string(image)))...)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", c.name).Run() })
	// The image's first start creates the cluster with a server it then
	// stops: wait for the one that stays.
	c.wait("PostgreSQL init process complete")
	return c
}

func (c *cluster) docker(args ...string) string {
	c.t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		c.t.Fatalf("docker %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// wait waits for PostgreSQL to answer. pg_isready is told the user: run as
// CI's user, which the image does not know, it cannot name one itself.
func (c *cluster) wait(logLine string) {
	c.t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		logs, _ := exec.Command("docker", "logs", c.name).CombinedOutput()
		if (logLine == "" || strings.Contains(string(logs), logLine)) &&
			exec.Command("docker", "exec", c.name, "pg_isready", "-q", "-U", "postgres").Run() == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", c.name).CombinedOutput()
	c.t.Fatalf("PostgreSQL did not start: %s", lastLines(string(logs), 10))
}

func (c *cluster) start() { c.t.Helper(); c.docker("start", c.name); c.wait("") }

// stop shuts PostgreSQL down cleanly, as docker compose stop does.
func (c *cluster) stop() { c.t.Helper(); c.docker("stop", "-t", "60", c.name) }

func (c *cluster) sql(db, sql string) string {
	c.t.Helper()
	return c.docker("exec", c.name, "psql", "-U", "postgres", "-d", db, "-v", "ON_ERROR_STOP=1", "-AtXq", "-c", sql)
}

// An Authentik deployment's state through a backup and a restore, with a
// real PostgreSQL cluster: Authentik's database (its users, their second
// factors, and the key pair that signs EasyRMM's ID tokens) in the same
// cluster as EasyRMM's and the engine's, and its directories in the data
// root. The new version changes all of it; the restore brings back what
// the backup held.
func TestAuthentikRoundTrip(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	dataRoot := filepath.Join(base, "srv")
	deploy := filepath.Join(base, "opt", "easyrmm-v1.0.0", "deploy")
	writeFile(t, filepath.Join(deploy, ".env"), "EASYRMM_DATA_ROOT="+dataRoot+"\nCOMPOSE_PROFILES=authentik\n", 0o600)
	writeFile(t, filepath.Join(deploy, "..", "docker", "authentik", "blueprints", "easyrmm.yaml"), "blueprint", 0o644)
	conf := filepath.Join(base, "etc", "updater.conf")
	writeFile(t, conf, "deployment = "+deploy+"\n", 0o600)
	dirs := map[string]string{
		"authentik/data/media/public/logo.png": "the operator's logo",
		"authentik/secrets/bootstrap-token":    "the bootstrap token",
		"authentik/invitations/admin":          "the first administrator's invitation",
		"server/acme/account.json":             "the ACME account",
	}
	for name, contents := range dirs {
		writeFile(t, filepath.Join(dataRoot, name), contents, 0o600)
	}
	pgDir := filepath.Join(dataRoot, "postgres")
	if err := os.MkdirAll(pgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// As setup.sh makes it: the Alpine image's postgres user's.
	if os.Getuid() == 0 {
		if err := os.Chown(pgDir, 70, 70); err != nil {
			t.Fatal(err)
		}
	}

	pg := newCluster(t, pgDir)
	pg.sql("postgres", "CREATE DATABASE easyrmm")
	pg.sql("postgres", "CREATE DATABASE easypatch")
	pg.sql("postgres", "CREATE ROLE authentik LOGIN")
	pg.sql("postgres", "CREATE DATABASE authentik OWNER authentik")
	pg.sql("authentik", `CREATE TABLE authentik_core_user (username text PRIMARY KEY, totp text);
		CREATE TABLE authentik_crypto_certificatekeypair (name text PRIMARY KEY, key_data text);
		INSERT INTO authentik_core_user VALUES ('akadmin', 'the administrator''s authenticator');
		INSERT INTO authentik_crypto_certificatekeypair VALUES ('easyrmm', 'the key that signs EasyRMM''s ID tokens')`)
	const (
		users = "SELECT string_agg(username || ': ' || totp, ', ' ORDER BY username) FROM authentik_core_user"
		keys  = "SELECT string_agg(name || ': ' || key_data, ', ' ORDER BY name) FROM authentik_crypto_certificatekeypair"
		dbs   = "SELECT string_agg(datname, ' ' ORDER BY datname) FROM pg_database WHERE NOT datistemplate"
	)
	wantUsers, wantKeys, wantDBs := pg.sql("authentik", users), pg.sql("authentik", keys), pg.sql("postgres", dbs)
	if wantDBs != "authentik easypatch easyrmm postgres" {
		t.Fatalf("the cluster holds %s", wantDBs)
	}

	// The upgrade stops the deployment and backs it up.
	pg.stop()
	meta := BackupMeta{Version: "v1.0.0", Deployment: deploy, DataRoot: dataRoot, Taken: time.Now()}
	b, err := takeBackup(ctx, backupDirFor(filepath.Join(base, "backups"), meta), meta, conf, 0, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}

	// The new version starts on the data root and changes Authentik's
	// state: a key rotated, a user added, a directory written.
	pg.start()
	pg.sql("authentik", "UPDATE authentik_crypto_certificatekeypair SET key_data = 'rotated by v1.1.0'")
	pg.sql("authentik", "INSERT INTO authentik_core_user VALUES ('added', 'by v1.1.0')")
	pg.sql("postgres", "CREATE DATABASE made_by_v1_1_0")
	pg.stop()
	writeFile(t, filepath.Join(dataRoot, "authentik", "secrets", "bootstrap-token"), "changed by v1.1.0", 0o600)
	writeFile(t, filepath.Join(dataRoot, "authentik", "data", "media", "added"), "by v1.1.0", 0o600)

	// It fails, and the rollback restores the backup.
	aside, err := b.restoreData(ctx, dataRoot, "20261121T030000Z-v1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	pg.start()
	if got := pg.sql("authentik", users); got != wantUsers {
		t.Errorf("Authentik's users: %s, not %s", got, wantUsers)
	}
	if got := pg.sql("authentik", keys); got != wantKeys {
		t.Errorf("Authentik's key pairs: %s, not %s", got, wantKeys)
	}
	if got := pg.sql("postgres", dbs); got != wantDBs {
		t.Errorf("the restored cluster holds %s, not %s", got, wantDBs)
	}
	for name, contents := range dirs {
		if got := readFile(t, filepath.Join(dataRoot, name)); got != contents {
			t.Errorf("%s holds %q", name, got)
		}
	}
	if _, err := os.Lstat(filepath.Join(dataRoot, "authentik", "data", "media", "added")); err == nil {
		t.Error("the restore kept a file the failed version wrote")
	}
	// What the failed version left is kept aside for diagnosis.
	if got := readFile(t, filepath.Join(aside, "authentik", "secrets", "bootstrap-token")); got != "changed by v1.1.0" {
		t.Errorf("kept aside: %q", got)
	}
	pg.stop()
}
