//go:build integration

package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch/eptest"
	"github.com/paulmataruso/easyrmm/server/internal/remote"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

func TestCleanupAndPurgeAudit(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var uid string
		if err := tx.QueryRow(ctx, `INSERT INTO users (email, display_name) VALUES ('a@b.example', 'A') RETURNING id`).Scan(&uid); err != nil {
			return err
		}
		for i, q := range []string{
			// expired long ago, revoked long ago, still live
			`INSERT INTO sessions (token_hash, user_id, state, idle_expires_at, expires_at) VALUES ($1, $2, 'active', now() - interval '30 days', now() - interval '30 days')`,
			`INSERT INTO sessions (token_hash, user_id, state, idle_expires_at, expires_at, revoked_at) VALUES ($1, $2, 'active', now() + interval '1 hour', now() + interval '1 hour', now() - interval '8 days')`,
			`INSERT INTO sessions (token_hash, user_id, state, idle_expires_at, expires_at) VALUES ($1, $2, 'active', now() + interval '1 hour', now() + interval '1 hour')`,
		} {
			if _, err := tx.Exec(ctx, q, []byte{byte(i), 1, 2, 3}, uid); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ('\x01', $1, now() - interval '2 days'), ('\x02', $1, now() + interval '1 hour')`, uid); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Cleanup(ctx, inst.DB); err != nil {
		t.Fatal(err)
	}
	var sessions, tokens int
	_ = inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		_ = tx.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&sessions)
		return tx.QueryRow(ctx, `SELECT count(*) FROM password_reset_tokens`).Scan(&tokens)
	})
	if sessions != 1 || tokens != 1 {
		t.Fatalf("after cleanup: %d sessions, %d tokens; want 1 and 1", sessions, tokens)
	}

	// Audit retention: entries older than the window are removed.
	super, err := pgx.Connect(ctx, inst.SuperDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(ctx)
	for _, at := range []string{"now() - interval '400 days'", "now()"} {
		if _, err := super.Exec(ctx, `SELECT easyrmm_audit_append(`+at+`, 'system', NULL, 'test', NULL, NULL, NULL, 'test.event', '', '', 'success', NULL, '', '{}')`); err != nil {
			t.Fatal(err)
		}
	}
	n, err := PurgeAudit(ctx, inst.DB, 365*24*time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("purge: %d, %v", n, err)
	}
	if _, err := PurgeAudit(ctx, inst.DB, 24*time.Hour); err == nil {
		t.Fatal("retention under 30 days was accepted")
	}
}

func TestServeHealth(t *testing.T) {
	inst := testdb.New(t)
	addr := reserveAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveHealth(ctx, addr, inst.DB, notHeld(t), discard()) }()
	for p, want := range map[string]string{"/healthz": "ok\n", "/readyz": "ready\n"} {
		resp, body := get(t, &http.Client{}, "http://"+addr+p, addr)
		if resp.StatusCode != http.StatusOK || body != want {
			t.Fatalf("%s: %d %q", p, resp.StatusCode, body)
		}
	}
	// Readiness fails once the database is gone; liveness does not.
	inst.DB.Close()
	if resp, _ := get(t, &http.Client{}, "http://"+addr+"/readyz", addr); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz without database: %d", resp.StatusCode)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serveHealth: %v", err)
	}
	if err := serveHealth(context.Background(), "256.0.0.1:1", nil, notHeld(t), discard()); err == nil {
		t.Fatal("bad listen address accepted")
	}
}

// secretKeys holds one random secret key per test database. Values sealed
// by one Run (the job-signing key, for example) must open in the next Run
// against the same database, as they do in a deployment whose
// EASYRMM_SECRET_KEY does not change.
var secretKeys sync.Map

func runConfig(t *testing.T, inst *testdb.Instance) *config.Config {
	t.Helper()
	fresh := make([]byte, 32)
	_, _ = rand.Read(fresh)
	stored, _ := secretKeys.LoadOrStore(inst.Name, fresh)
	raw := stored.([]byte)
	sep := "?"
	if strings.Contains(inst.SuperDSN, "?") {
		sep = "&"
	}
	pub, _ := url.Parse("https://rmm.test")
	return &config.Config{
		PublicURL: pub, TLSMode: config.TLSOffload,
		ListenOffload: reserveAddr(t), ListenHealth: reserveAddr(t),
		DatabaseURL:          inst.SuperDSN + sep + "role=easyrmm_app",
		DatabaseMigrationURL: inst.SuperDSN + sep + "role=easyrmm_owner",
		DatabaseMaxConns:     4,
		SecretKeys:           []secrets.Key{{ID: "k1", Raw: raw}},
		DataDir:              filepath.Join(t.TempDir(), "data"),
		RequireMFA:           true, SessionIdle: time.Hour, SessionMaxAge: 2 * time.Hour,
		PasswordResetTTL: 30 * time.Minute, AuditRetention: 365 * 24 * time.Hour, JobRetention: 90 * 24 * time.Hour, ArgonMaxParallel: 2,
		Patching: testEngine(t),
	}
}

// unusedAddr returns a loopback address nothing is expected to listen on,
// for a service the test leaves unreachable: its port was free when picked
// and is closed again. Never for a server under test (reserveAddr).
func unusedAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// testEngine is a stand-in for the patching engine every deployment runs
// with EasyRMM.
func testEngine(t *testing.T) config.Patching {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return config.Patching{URL: eptest.NewEngine(t, key).URL(), Key: key}
}

func TestRunEndToEnd(t *testing.T) {
	inst := testdb.New(t)
	cfg := runConfig(t, inst)
	cfg.SMTP = config.SMTPConfig{Host: "127.0.0.1", Port: 25, From: "rmm@rmm.test", TLS: "none"}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, discard()) }()

	resp, body := get(t, &http.Client{}, "http://"+cfg.ListenOffload+"/api/v1/health", "rmm.test")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("health through Run: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, &http.Client{}, "http://"+cfg.ListenHealth+"/readyz", "localhost"); resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz: %d", resp.StatusCode)
	}
	if info, err := os.Stat(filepath.Join(cfg.DataDir, "setup-token")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("setup token: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRunFailures(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()

	cfg := runConfig(t, inst)
	cfg.DatabaseMigrationURL = "postgres://%zz"
	if err := Run(ctx, cfg, discard()); err == nil || !strings.Contains(err.Error(), "EASYRMM_DATABASE_MIGRATION_URL") {
		t.Fatalf("bad migration URL: %v", err)
	}

	cfg = runConfig(t, inst)
	cfg.SMTP = config.SMTPConfig{Host: "mail.example.com", Port: 25, From: "rmm@rmm.test", TLS: "none"}
	if err := Run(ctx, cfg, discard()); err == nil || !strings.Contains(err.Error(), "mailer") {
		t.Fatalf("unencrypted remote SMTP accepted: %v", err)
	}

	cfg = runConfig(t, inst)
	cfg.DatabaseURL = "postgres://%zz"
	if err := Run(ctx, cfg, discard()); err == nil {
		t.Fatal("bad runtime database URL accepted")
	}

	cfg = runConfig(t, inst)
	cfg.WebDir = filepath.Join(t.TempDir(), "no-web")
	if err := Run(ctx, cfg, discard()); err == nil || !strings.Contains(err.Error(), "web interface") {
		t.Fatalf("missing web dir: %v", err)
	}

	cfg = runConfig(t, inst)
	cfg.DataDir = "/proc/easyrmm-cannot-create"
	if err := Run(ctx, cfg, discard()); err == nil {
		t.Fatal("unusable data directory accepted")
	}

	// The health listener failing to bind stops the server with its error.
	cfg = runConfig(t, inst)
	cfg.ListenHealth = "256.0.0.1:1"
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(cctx, cfg, discard()) }()
	resp, _ := get(t, &http.Client{}, "http://"+cfg.ListenOffload+"/api/v1/health", "rmm.test")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: %d", resp.StatusCode)
	}
	cancel()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "health listener") {
		t.Fatalf("health listener failure not reported: %v", err)
	}
}

func TestRunWithRemoteAccess(t *testing.T) {
	inst := testdb.New(t)
	cfg := runConfig(t, inst)
	cfg.MeshPublicURL, _ = url.Parse("https://mesh.rmm.test")
	internal, _ := url.Parse("http://" + unusedAddr(t)) // MeshCentral is not running
	cfg.Mesh = config.MeshConfig{Enabled: true, InternalURL: internal, ConfigDir: t.TempDir(), CertURL: "https://127.0.0.1:443"}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, discard()) }()
	resp, _ := get(t, &http.Client{}, "http://"+cfg.ListenOffload+"/api/v1/health", "rmm.test")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: %d", resp.StatusCode)
	}
	path := filepath.Join(cfg.Mesh.ConfigDir, "config.json")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("MeshCentral config: %v", err)
	}
	raw, _ := os.ReadFile(path) //nolint:gosec // test directory
	type meshConfig struct {
		Settings struct {
			Cert      string   `json:"cert"`
			Port      int      `json:"port"`
			AliasPort int      `json:"aliasPort"`
			Framing   []string `json:"allowedFramingOrigins"`
			Key       string   `json:"loginCookieEncryptionKey"`
		} `json:"settings"`
		Domains map[string]struct {
			AllowedOrigin []string `json:"allowedOrigin"`
		} `json:"domains"`
	}
	var mc meshConfig
	if err := json.Unmarshal(raw, &mc); err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(internal.Port())
	if mc.Settings.Cert != "mesh.rmm.test" || mc.Settings.Port != port || mc.Settings.AliasPort != 443 ||
		len(mc.Settings.Framing) != 1 || mc.Settings.Framing[0] != "https://rmm.test" || len(mc.Settings.Key) != 160 {
		t.Fatalf("MeshCentral settings: %+v", mc.Settings)
	}
	if got := strings.Join(mc.Domains[""].AllowedOrigin, " "); got != "mesh.rmm.test" {
		t.Fatalf("MeshCentral allowedOrigin = %q", got)
	}
	// The MeshCentral hostname reaches the gateway.
	if resp, body := get(t, &http.Client{}, "http://"+cfg.ListenOffload+"/", "mesh.rmm.test"); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "Remote session required") {
		t.Fatalf("mesh host through Run: %d %s", resp.StatusCode, body)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Run did not stop")
	}

	// The same key is used on the next start, so the file does not change.
	before, _ := os.ReadFile(path) //nolint:gosec // test directory
	if err := writeMeshConfig(cfg, mustSecrets(t, inst, cfg), discard()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path) //nolint:gosec // test directory
	if string(before) != string(after) {
		t.Fatal("MeshCentral configuration changed between starts")
	}
	// Origins added since (IP access on two addresses) change the file, so
	// MeshCentral's start script restarts MeshCentral with them.
	cfg.IPAccess, cfg.IPMeshPort = true, 4443
	cfg.IPAddresses = []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	if err := writeMeshConfig(cfg, mustSecrets(t, inst, cfg), discard()); err != nil {
		t.Fatal(err)
	}
	after, _ = os.ReadFile(path) //nolint:gosec // test directory
	mc = meshConfig{}
	if err := json.Unmarshal(after, &mc); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(mc.Domains[""].AllowedOrigin, " "); got != "mesh.rmm.test 192.0.2.10 [2001:db8::10]" {
		t.Fatalf("MeshCentral allowedOrigin with IP access = %q", got)
	}
	// An unwritable directory is reported, not fatal.
	cfg.Mesh.ConfigDir = "/proc/easyrmm-no-such-dir"
	if err := writeMeshConfig(cfg, mustSecrets(t, inst, cfg), discard()); err == nil {
		t.Fatal("writing into an unusable directory succeeded")
	}
}

func mustSecrets(t *testing.T, inst *testdb.Instance, cfg *config.Config) *remote.Secrets {
	t.Helper()
	sealer, err := secrets.NewSealer(cfg.SecretKeys...)
	if err != nil {
		t.Fatal(err)
	}
	s, err := remote.LoadSecrets(context.Background(), inst.DB, sealer)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
