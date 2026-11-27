//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	agentclient "github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/logblock"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// logStoreURLs makes a log store database owned by easyrmm_logs_owner and
// returns the two connection strings the server is given: the runtime role's
// and the owner's, as login roles with passwords, as a deployment has them.
func logStoreURLs(t *testing.T) (appURL, ownerURL string) {
	t.Helper()
	base := os.Getenv(testdb.EnvVar)
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	for _, stmt := range []string{
		`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'easyrmm_logs_owner') THEN CREATE ROLE easyrmm_logs_owner; END IF; END $$`,
		`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'easyrmm_logs_app') THEN CREATE ROLE easyrmm_logs_app; END IF; END $$`,
		`ALTER ROLE easyrmm_logs_owner LOGIN PASSWORD 'owner-test-only'`,
		`ALTER ROLE easyrmm_logs_app LOGIN PASSWORD 'app-test-only'`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	name := "easyrmm_logs_a_" + hex.EncodeToString(suffix)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name+" OWNER easyrmm_logs_owner"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c, err := pgx.Connect(context.Background(), base); err == nil {
			_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			_ = c.Close(context.Background())
		}
	})
	if _, err := admin.Exec(ctx, "GRANT CONNECT ON DATABASE "+name+" TO easyrmm_logs_app"); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	app, owner := *u, *u
	app.User = url.UserPassword("easyrmm_logs_app", "app-test-only")
	owner.User = url.UserPassword("easyrmm_logs_owner", "owner-test-only")
	return app.String(), owner.String()
}

func block(t *testing.T, seq int64, source string, evs ...logblock.Event) agentproto.CollectedBlock {
	t.Helper()
	b, err := logblock.Seal(source, logblock.ClassFor(source), evs)
	if err != nil {
		t.Fatal(err)
	}
	return agentproto.CollectedBlock{Seq: seq, Source: source, Class: b.Class, Start: b.Start, End: b.End, Count: b.Count, Raw: b.Raw, Codec: b.Codec, Data: b.Data}
}

// TestCollectedLogsAPI sends a collector's blocks through the agent API with
// the agent's own client, reads them through the console API as people with
// and without the right to see command lines, and checks that a deployment
// without a log store degrades to "unavailable" and nothing else.
func TestCollectedLogsAPI(t *testing.T) {
	appURL, ownerURL := logStoreURLs(t)
	h := newHarnessWith(t, false, func(c *config.Config) { c.LogsDatabaseURL, c.LogsDatabaseMigrationURL = appURL, ownerURL })
	admin, _ := setUp(t, h)
	for range 200 { // the schema is migrated in the background
		if h.deps.LogStore.Ready() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !h.deps.LogStore.Ready() {
		t.Fatal("the log store was not migrated")
	}
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Collect", "expiresInDays": 1}, &token)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts("collect-01"))
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	device := "/api/v1/devices/" + enr.DeviceID

	now := time.Now().UTC().Add(-10 * time.Minute)
	ack, err := ac.CollectedLogs(ctx, agentproto.CollectedBatch{Blocks: []agentproto.CollectedBlock{
		block(t, 100, "linux.journal",
			logblock.Event{Time: now, Level: "info", Message: "nginx started"},
			logblock.Event{Time: now.Add(time.Minute), Level: "error", Message: "disk failure on sda"}),
		block(t, 101, "linux.audit", logblock.Event{Time: now.Add(2 * time.Minute), ID: "EXECVE", Message: "EXECVE",
			Sensitive: map[string]string{"cmdline": "mysql -pSecretValue"}}),
	}})
	if err != nil || ack.Seq != 101 || ack.Refused != 0 {
		t.Fatalf("ack %+v %v", ack, err)
	}
	// A repeat after a lost answer is stored once.
	if ack, err = ac.CollectedLogs(ctx, agentproto.CollectedBatch{Blocks: []agentproto.CollectedBlock{
		block(t, 100, "linux.journal", logblock.Event{Time: now, Message: "nginx started"})}}); err != nil || ack.Seq != 101 {
		t.Fatalf("repeat ack %+v %v", ack, err)
	}

	type page struct {
		Items []struct {
			Time      time.Time         `json:"time"`
			Source    string            `json:"source"`
			Level     string            `json:"level"`
			Message   string            `json:"message"`
			Sensitive map[string]string `json:"sensitive"`
		} `json:"items"`
		More            bool     `json:"more"`
		CanSeeSensitive bool     `json:"canSeeSensitive"`
		Sources         []string `json:"sources"`
	}
	var p page
	admin.expect(http.StatusOK, "GET", device+"/collected-logs", nil, &p)
	if len(p.Items) != 3 || p.Items[0].Source != "linux.audit" || p.Items[0].Sensitive["cmdline"] == "" || !p.CanSeeSensitive || len(p.Sources) != 2 {
		t.Fatalf("admin's read: %+v", p)
	}
	admin.expect(http.StatusOK, "GET", device+"/collected-logs?source=linux.journal&q=DISK", nil, &p)
	if len(p.Items) != 1 || p.Items[0].Level != "error" {
		t.Fatalf("filtered: %+v", p.Items)
	}
	var tl struct {
		Buckets []struct {
			Source string `json:"source"`
			Events int64  `json:"events"`
		} `json:"buckets"`
	}
	admin.expect(http.StatusOK, "GET", device+"/collected-logs/timeline", nil, &tl)
	var total int64
	for _, b := range tl.Buckets {
		total += b.Events
	}
	if total != 3 {
		t.Fatalf("timeline holds %d events: %+v", total, tl.Buckets)
	}
	wantStatus(t, admin.do("GET", device+"/collected-logs?since=yesterday", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", device+"/collected-logs?source=Not%20A%20Source", nil), http.StatusUnprocessableEntity, "validation_failed")
	wantStatus(t, admin.do("GET", device+"/collected-logs?since=2026-11-27T10:00:00Z&until=2026-11-27T09:00:00Z", nil), http.StatusUnprocessableEntity, "validation_failed")

	// A technician sees the events, not the command line, and cannot find it.
	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")
	p = page{}
	tech.expect(http.StatusOK, "GET", device+"/collected-logs", nil, &p)
	if len(p.Items) != 3 || p.CanSeeSensitive {
		t.Fatalf("technician's read: %+v", p)
	}
	for _, e := range p.Items {
		if len(e.Sensitive) != 0 {
			t.Fatalf("a command line reached a caller without log.view_sensitive: %+v", e)
		}
	}
	p = page{}
	tech.expect(http.StatusOK, "GET", device+"/collected-logs?q=SecretValue", nil, &p)
	if len(p.Items) != 0 {
		t.Fatalf("a search found a command line for a caller without log.view_sensitive: %+v", p.Items)
	}
	// Read-only has no log.view.
	invite(t, h, admin, "rory@acme.example", []map[string]any{{"role": "read_only", "organizationId": acme}})
	viewer := h.client()
	viewer.signIn("rory@acme.example", "a long and unusual passphrase", "")
	wantStatus(t, viewer.do("GET", device+"/collected-logs", nil), http.StatusForbidden, "")
}

// TestCollectedLogsWithoutAStore: with no log store configured the console
// says logs are unavailable (503) and the agent's route is absent (404), so
// an agent keeps its blocks; nothing else is affected.
func TestCollectedLogsWithoutAStore(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Collect", "expiresInDays": 1}, &token)
	ctx := context.Background()
	ac := h.agentClient()
	key := newKey(t)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts("collect-02"))
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	wantStatus(t, admin.do("GET", "/api/v1/devices/"+enr.DeviceID+"/collected-logs", nil), http.StatusServiceUnavailable, "logs_unavailable")
	_, err = ac.CollectedLogs(ctx, agentproto.CollectedBatch{Blocks: []agentproto.CollectedBlock{block(t, 1, "linux.journal", logblock.Event{Time: time.Now(), Message: "x"})}})
	var ce *agentclient.Error
	if !errors.As(err, &ce) || ce.Status != http.StatusNotFound {
		t.Fatalf("an agent's upload to a server without a store: %v", err)
	}
	// The rest of the device works.
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+enr.DeviceID, nil, nil)
}
