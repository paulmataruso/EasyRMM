//go:build integration

package app

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
	"github.com/paulmataruso/easyrmm/server/internal/updater"
)

// TestRunHeld runs the server held by the updater from its start, then
// releases and holds it again while it runs (ADR-0052). While held, every
// kind of request to its edge gets 503 with Retry-After, and its health
// check passes, as Compose's --wait needs; a stale device raises no offline
// alert.
func TestRunHeld(t *testing.T) {
	inst := testdb.New(t)
	cfg := runConfig(t, inst)
	cfg.MeshPublicURL, _ = url.Parse("https://mesh.rmm.test")
	meshInternal, _ := url.Parse("http://" + freeAddr(t)) // MeshCentral is not running
	cfg.Mesh = config.MeshConfig{Enabled: true, InternalURL: meshInternal, ConfigDir: t.TempDir(), CertURL: "https://127.0.0.1:443"}
	authentik := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "authentik")
	}))
	defer authentik.Close()
	cfg.Authentik = config.Authentik{Hostname: "auth.rmm.test", AdminEmail: "admin@msp.example",
		ClientSecret: strings.Repeat("s", 48), Upstream: authentik.Listener.Addr().String()}
	cfg.Patching.AgentHostnames = []string{"patch.old.test"}
	cfg.UpdaterStatusDir = t.TempDir()
	hold := filepath.Join(cfg.UpdaterStatusDir, updater.HoldFile)
	if err := os.WriteFile(hold, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stale, disk := staleDevice(t, inst)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, discard()) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(60 * time.Second):
			t.Error("Run did not stop")
		}
	}()

	// Every kind of request the edge serves, by name and path.
	requests := []struct{ what, host, path string }{
		{"the console", "rmm.test", "/"},
		{"the console's API", "rmm.test", "/api/v1/health"},
		{"EasyRMM's agents", "rmm.test", agentproto.PathHeartbeat},
		{"the engine's agents", "rmm.test", "/api/v1/agents/heartbeat"},
		{"an imported EasyPatch's name", "patch.old.test", "/api/v1/agents/heartbeat"},
		{"Authentik's name", "auth.rmm.test", "/"},
		{"MeshCentral's name", "mesh.rmm.test", "/"},
		{"a name it does not serve", "other.test", "/"},
	}
	isHeld := func(resp httpResult, body string) bool {
		return resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") == "60" && strings.Contains(body, `"code":"held"`)
	}
	allHeld := func(want bool) []string {
		var wrong []string
		for _, r := range requests {
			resp, body := get(t, &http.Client{}, "http://"+cfg.ListenOffload+r.path, r.host)
			if isHeld(resp, body) != want {
				wrong = append(wrong, r.what+": "+resp.Header.Get("Retry-After")+" "+body)
			}
		}
		return wrong
	}
	waitFor := func(what string, want bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for wrong := allHeld(want); len(wrong) > 0; wrong = allHeld(want) {
			if time.Now().After(deadline) {
				t.Fatalf("%s:\n%s", what, strings.Join(wrong, "\n"))
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	ready := func(want string) {
		t.Helper()
		resp, body := get(t, &http.Client{}, "http://"+cfg.ListenHealth+"/readyz", "localhost")
		if resp.StatusCode != http.StatusOK || body != want {
			t.Fatalf("readyz: %d %q, want %q", resp.StatusCode, body, want)
		}
	}

	// Held from the start: the first answer is already 503.
	if wrong := allHeld(true); len(wrong) > 0 {
		t.Fatalf("held from the start:\n%s", strings.Join(wrong, "\n"))
	}
	ready("ready, held by the updater\n")
	if resp, _ := get(t, &http.Client{}, "http://"+cfg.ListenHealth+"/healthz", "localhost"); resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz while held: %d", resp.StatusCode)
	}
	// The server evaluates its alert policies while held: the full disk
	// raises its alert, the device away for a day none.
	deadline := time.Now().Add(15 * time.Second)
	for alerts(t, inst, disk) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the alert policies were not evaluated")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if n := alerts(t, inst, stale); n != 0 {
		t.Fatalf("%d alerts for the device away for a day, while held", n)
	}

	// The updater removes the file: everything is served again.
	if err := os.Remove(hold); err != nil {
		t.Fatal(err)
	}
	waitFor("after the hold", false)
	ready("ready\n")
	if resp, body := get(t, &http.Client{}, "http://"+cfg.ListenOffload+"/", "auth.rmm.test"); resp.StatusCode != http.StatusOK || body != "authentik" {
		t.Fatalf("Authentik's name after the hold: %d %q", resp.StatusCode, body)
	}

	// It writes the file again while the server runs: held again.
	if err := os.WriteFile(hold, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor("holding a running server", true)
	ready("ready, held by the updater\n")
	if n := alerts(t, inst, stale); n != 0 {
		t.Fatalf("%d alerts for the device away for a day", n)
	}
}

// staleDevice enrolls a device that last checked in a day ago, and one
// whose disk has been full for ten minutes; the deployment's seeded
// policies watch both.
func staleDevice(t *testing.T, inst *testdb.Instance) (stale, disk uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var org, site uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('Acme') RETURNING id`).Scan(&org); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, org).Scan(&site); err != nil {
			return err
		}
		for _, d := range []struct {
			id   *uuid.UUID
			name string
			ago  int
		}{{&stale, "away", 24 * 60}, {&disk, "full", 0}} {
			key := make([]byte, 32)
			_, _ = rand.Read(key)
			if err := tx.QueryRow(ctx, `INSERT INTO devices (organization_id, site_id, name, hostname, platform, agent_public_key, enrolled_at, agent_last_seen_at)
				VALUES ($1, $2, $3, $3, 'linux', $4, now() - interval '2 days', now() - make_interval(mins => $5)) RETURNING id`,
				org, site, d.name, key, d.ago).Scan(d.id); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO device_metric_samples (device_id, at, cpu_percent, memory_percent, swap_percent, disk_percent, load1)
			SELECT $1, now() - make_interval(secs => g * 60 + 20), 5, 20, 0, 97, 0.5 FROM generate_series(0, 9) g`, disk)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return stale, disk
}

func alerts(t *testing.T, inst *testdb.Instance, device uuid.UUID) int {
	t.Helper()
	var n int
	ctx := context.Background()
	if err := inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE device_id = $1`, device).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}
