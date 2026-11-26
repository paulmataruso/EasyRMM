//go:build integration

package agentapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/qaticket"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agentlogs"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/hardware"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentapi"
	"github.com/paulmataruso/easyrmm/server/internal/inventory"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
	"github.com/paulmataruso/easyrmm/server/internal/quickassist"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

// TestAgentEndpointRefusals sends the signed endpoints the input they must
// refuse (wrong content type, malformed JSON, trailing data, a body over the
// limit, a run id that is not one, a run of another device, an unknown
// ticket, a volume nobody reported) to the real handlers over the real
// database, and checks the answer's status and code.
func TestAgentEndpointRefusals(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	au := audit.New(inst.DB, time.Now)
	_, jobKey, _ := ed25519.GenerateKey(rand.Reader)
	_, qaKey, _ := ed25519.GenerateKey(rand.Reader)
	_, ksKey, _ := ed25519.GenerateKey(rand.Reader)

	svc := agents.New(inst.DB, au, nil, log)
	jobSvc := jobs.New(inst.DB, au, jobKey, time.Hour, time.Hour, log)
	api, err := agentapi.New(svc, nil, []agentapi.Address{{URL: "https://rmm.example.com"}}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	api.WithJobs(jobSvc).
		WithInventory(inventory.New(inst.DB, time.Hour, log)).
		WithHardware(hardware.New(inst.DB, time.Hour, time.Hour, log)).
		WithAgentLogs(agentlogs.New(inst.DB, au, 1, log)).
		WithEscrow(keystore.New(inst.DB, au, nil, ksKey, log)).
		WithQuickAssist(quickassist.New(inst.DB, au, qaKey, "https://rmm.example.com"))
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	var site uuid.UUID
	if err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var org uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('Refusals') RETURNING id`).Scan(&org); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name) VALUES ($1, 'HQ') RETURNING id`, org).Scan(&site)
	}); err != nil {
		t.Fatal(err)
	}
	tok, err := svc.CreateToken(ctx, access.System("test"), site, agents.TokenInput{Name: "t", ExpiresInDays: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	resp, err := svc.Enroll(ctx, netip.MustParseAddr("192.0.2.10"), agentproto.EnrollRequest{
		Token: tok.Secret, PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		Facts: agentproto.Facts{Hostname: "h", Platform: "linux", Arch: "amd64", AgentVersion: "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dev := resp.DeviceID

	type answer struct {
		code int
		body string
	}
	send := func(path, contentType string, body []byte) answer {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
		auth, _ := agentproto.Sign(key, dev, http.MethodPost, path, body, time.Now())
		req.Header.Set("Authorization", auth)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer func() { _ = r.Body.Close() }()
		b, _ := io.ReadAll(r.Body)
		return answer{r.StatusCode, string(b)}
	}
	const js = "application/json"
	want := func(name string, a answer, code int, in string) {
		t.Helper()
		if a.code != code || !strings.Contains(a.body, in) {
			t.Errorf("%s: got %d %q, want %d containing %q", name, a.code, a.body, code, in)
		}
	}

	// Every JSON endpoint refuses what is not one JSON object.
	jsonRoutes := []string{
		agentproto.PathHeartbeat, agentproto.PathRemoved, agentproto.PathJobsPoll, agentproto.PathAgentLogs,
		agentproto.PathEscrowVolumes, agentproto.PathEscrow,
		qaticket.PathEnd, qaticket.PathMesh, qaticket.PathInstall,
		"/api/agent/v1/jobs/" + uuid.NewString() + "/result",
	}
	for _, p := range jsonRoutes {
		want(p+" content type", send(p, "text/plain", []byte(`{}`)), http.StatusUnsupportedMediaType, "unsupported_media_type")
		want(p+" malformed", send(p, js, []byte(`{"x":`)), http.StatusBadRequest, "not valid JSON")
		want(p+" trailing", send(p, js, []byte(`{} {}`)), http.StatusBadRequest, "single JSON object")
	}
	// The inventory and hardware reports are JSON documents kept as sent.
	for _, p := range []string{agentproto.PathInventory, agentproto.PathHardware} {
		want(p+" content type", send(p, "text/plain", []byte(`{}`)), http.StatusUnsupportedMediaType, "unsupported_media_type")
		a := send(p, js, []byte(`not json`))
		if a.code != http.StatusBadRequest {
			t.Errorf("%s malformed: got %d %q, want 400", p, a.code, a.body)
		}
	}

	// Bodies over each endpoint's limit.
	want("heartbeat oversize", send(agentproto.PathHeartbeat, js, bytes.Repeat([]byte("a"), agentproto.MaxBody+1)), http.StatusRequestEntityTooLarge, "body_too_large")
	want("escrow volumes oversize", send(agentproto.PathEscrowVolumes, js, bytes.Repeat([]byte("a"), agentproto.MaxEscrowVolumesBody+1)), http.StatusRequestEntityTooLarge, "body_too_large")
	want("escrow oversize", send(agentproto.PathEscrow, js, bytes.Repeat([]byte("a"), agentproto.MaxEscrowBody+1)), http.StatusRequestEntityTooLarge, "body_too_large")
	want("logs oversize", send(agentproto.PathAgentLogs, js, bytes.Repeat([]byte("a"), agentproto.MaxLogBody+1)), http.StatusRequestEntityTooLarge, "body_too_large")
	want("inventory oversize", send(agentproto.PathInventory, js, bytes.Repeat([]byte("a"), agentproto.MaxInventoryBody+1)), http.StatusRequestEntityTooLarge, "body_too_large")
	want("hardware oversize", send(agentproto.PathHardware, js, bytes.Repeat([]byte("a"), agentproto.MaxHardwareBody+1)), http.StatusRequestEntityTooLarge, "body_too_large")
	want("result oversize", send("/api/agent/v1/jobs/"+uuid.NewString()+"/result", js, bytes.Repeat([]byte("a"), agentproto.MaxResultBody+1)), http.StatusRequestEntityTooLarge, "body_too_large")

	// Job runs: a name that is no run, and a run this device does not have.
	want("start, not a run id", send("/api/agent/v1/jobs/nope/start", js, nil), http.StatusNotFound, "run_not_found")
	want("start, no such run", send("/api/agent/v1/jobs/"+uuid.NewString()+"/start", js, nil), http.StatusNotFound, "run_not_found")
	want("result, not a run id", send("/api/agent/v1/jobs/nope/result", js, []byte(`{}`)), http.StatusNotFound, "run_not_found")
	want("result, no such run", send("/api/agent/v1/jobs/"+uuid.NewString()+"/result", js, []byte(`{"status":"succeeded"}`)), http.StatusBadRequest, "result_invalid")

	// A heartbeat that carries what the build accepts keeps it on the device.
	a := send(agentproto.PathHeartbeat, js, []byte(`{"facts":{"hostname":"h","platform":"linux","arch":"amd64","agentVersion":"1"},"accepts":["script.run"]}`))
	if a.code != http.StatusOK {
		t.Fatalf("heartbeat with accepts: %d %q", a.code, a.body)
	}
	var kept []string
	if err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT agent_accepts FROM devices WHERE id = $1`, dev).Scan(&kept)
	}); err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || kept[0] != "script.run" {
		t.Errorf("the heartbeat's accepts were not kept: %v", kept)
	}

	// Escrow: a report of no volumes needs nothing, and a record that
	// names nothing is refused, never stored.
	want("escrow volumes, none", send(agentproto.PathEscrowVolumes, js, []byte(`{}`)), http.StatusOK, `"need"`)
	want("escrow upload, empty record", send(agentproto.PathEscrow, js, []byte(`{}`)), http.StatusBadRequest, "escrow_invalid")

	// Quick Assist: a ticket nobody issued, and a device with no session.
	want("qa enroll content type", func() answer {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+qaticket.PathEnroll, strings.NewReader(`{}`))
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Body.Close() }()
		b, _ := io.ReadAll(r.Body)
		return answer{r.StatusCode, string(b)}
	}(), http.StatusUnsupportedMediaType, "unsupported_media_type")
	for name, body := range map[string]string{"malformed": `{"ticket":`, "unknown ticket": `{"ticket":"AAAA","publicKey":"AAAA","code":"1"}`} {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+qaticket.PathEnroll, strings.NewReader(body))
		req.Header.Set("Content-Type", js)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode < 400 || r.StatusCode >= 500 {
			t.Errorf("qa enroll %s: got %d, want a 4xx", name, r.StatusCode)
		}
	}
	for _, p := range []string{qaticket.PathStatus, qaticket.PathConverted} {
		if a := send(p, js, []byte(`{}`)); a.code < 400 {
			t.Errorf("%s for a device with no Quick Assist session: got %d %q, want an error", p, a.code, a.body)
		}
	}
	for _, p := range []string{qaticket.PathEnd, qaticket.PathMesh, qaticket.PathInstall} {
		if a := send(p, js, []byte(`{}`)); a.code < 400 {
			t.Errorf("%s for a device with no Quick Assist session: got %d %q, want an error", p, a.code, a.body)
		}
	}

	// The agent's own removal report: one that is too long to be an id is
	// refused, a good one deletes the device, whose agent is then unknown.
	want("removed, id too long", send(agentproto.PathRemoved, js, []byte(`{"id":"`+strings.Repeat("a", 65)+`","removed":true}`)), http.StatusBadRequest, "report_invalid")
	if a := send(agentproto.PathRemoved, js, []byte(`{"id":"x","removed":true}`)); a.code != http.StatusNoContent {
		t.Fatalf("removed: %d %q", a.code, a.body)
	}
	for _, p := range []string{agentproto.PathHeartbeat, agentproto.PathRemoved} {
		if a := send(p, js, []byte(`{}`)); a.code != http.StatusUnauthorized || !strings.Contains(a.body, "device_unknown") {
			t.Errorf("%s from a removed device: %d %q, want device_unknown", p, a.code, a.body)
		}
	}
	if a := send(agentproto.PathJobsPoll, js, []byte(`{}`)); a.code != http.StatusUnauthorized || !strings.Contains(a.body, "device_unknown") {
		t.Errorf("a poll from a removed device: %d %q, want device_unknown", a.code, a.body)
	}
}
