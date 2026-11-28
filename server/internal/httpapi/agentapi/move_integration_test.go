//go:build integration

package agentapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentapi"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/testdb"
)

type moveRig struct {
	t      *testing.T
	srv    *httptest.Server
	device string
	key    ed25519.PrivateKey
	job    ed25519.PublicKey
	db     *database.DB
}

func newMoveRig(t *testing.T, withKey bool) *moveRig {
	t.Helper()
	inst := testdb.New(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	au := audit.New(inst.DB, time.Now)
	svc := agents.New(inst.DB, au, nil, log)
	rig := &moveRig{t: t, db: inst.DB}
	if withKey {
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		sealer, err := secrets.NewSealer(secrets.Key{ID: "k1", Raw: raw})
		if err != nil {
			t.Fatal(err)
		}
		ring, err := jobkeys.Open(ctx, inst.DB, sealer, log, jobkeys.Options{Version: "test", Audit: au})
		if err != nil {
			t.Fatal(err)
		}
		svc.SetKeys(ring)
		rig.job = ring.Newest().Public
	}
	api, err := agentapi.New(svc, nil, []agentapi.Address{{URL: "https://rmm.example.com"}, {URL: "https://203.0.113.10"}, {URL: "https://alt.example.com:8443"}}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	rig.srv = httptest.NewServer(api.Handler())
	t.Cleanup(rig.srv.Close)

	var site uuid.UUID
	if err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var org uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('Moves') RETURNING id`).Scan(&org); err != nil {
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
	_, rig.key, _ = ed25519.GenerateKey(rand.Reader)
	resp, err := svc.Enroll(ctx, netip.MustParseAddr("192.0.2.10"), agentproto.EnrollRequest{
		Token: tok.Secret, PublicKey: base64.StdEncoding.EncodeToString(rig.key.Public().(ed25519.PublicKey)),
		Facts: agentproto.Facts{Hostname: "pc-1", Platform: "linux", Arch: "amd64", AgentVersion: "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rig.device = resp.DeviceID
	return rig
}

// post sends a signed POST as the device, with Host set to host. It returns
// the status, the body and the nonce the request carried.
func (r *moveRig) post(path, host, contentType string, body any) (int, []byte, string) {
	r.t.Helper()
	b, _ := json.Marshal(body)
	h, err := agentproto.Sign(r.key, r.device, http.MethodPost, path, b, time.Now())
	if err != nil {
		r.t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+path, bytes.NewReader(b))
	req.Host = host
	req.Header.Set("Authorization", h)
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	a, _ := agentproto.Parse(h)
	return resp.StatusCode, out, a.Nonce
}

func (r *moveRig) code(body []byte) string {
	var e struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return e.Error.Code
}

func TestAddressRouteConfirmsOnlyWhatItServesAndWhereTheRequestArrived(t *testing.T) {
	rig := newMoveRig(t, true)
	const appJSON = "application/json"

	// An address served, asked at that address: confirmed, verifiably.
	for _, c := range []struct{ address, host string }{
		{"https://rmm.example.com", "rmm.example.com"},
		{"https://RMM.example.com/", "rmm.example.com:443"},
		{"https://203.0.113.10", "203.0.113.10"},
		{"https://alt.example.com:8443", "alt.example.com:8443"},
	} {
		status, body, nonce := rig.post(agentproto.PathAddress, c.host, appJSON, agentproto.AddressRequest{Address: c.address})
		if status != http.StatusOK {
			t.Fatalf("%s at %s: %d %s", c.address, c.host, status, body)
		}
		var ans agentproto.AddressAnswer
		if err := json.Unmarshal(body, &ans); err != nil {
			t.Fatal(err)
		}
		want, _ := agentproto.MoveTarget(c.address)
		if err := agentproto.VerifyAddress(rig.job, ans, rig.device, nonce, want); err != nil {
			t.Errorf("%s: the confirmation does not verify: %v", c.address, err)
		}
	}

	// Refused: an address not served, a request that did not arrive there, a
	// plain http or malformed address, and other content.
	for name, c := range map[string]struct {
		address, host, ct string
		status            int
		code              string
	}{
		"not served":              {"https://elsewhere.example.com", "elsewhere.example.com", appJSON, http.StatusMisdirectedRequest, "address_not_served"},
		"arrived elsewhere":       {"https://rmm.example.com", "203.0.113.10", appJSON, http.StatusMisdirectedRequest, "address_not_served"},
		"another port":            {"https://rmm.example.com", "rmm.example.com:8443", appJSON, http.StatusMisdirectedRequest, "address_not_served"},
		"served name, wrong port": {"https://alt.example.com", "alt.example.com", appJSON, http.StatusMisdirectedRequest, "address_not_served"},
		"plain http":              {"http://rmm.example.com", "rmm.example.com", appJSON, http.StatusMisdirectedRequest, "address_not_served"},
		"with a path":             {"https://rmm.example.com/x", "rmm.example.com", appJSON, http.StatusMisdirectedRequest, "address_not_served"},
		"empty":                   {"", "rmm.example.com", appJSON, http.StatusMisdirectedRequest, "address_not_served"},
		"not json":                {"https://rmm.example.com", "rmm.example.com", "text/plain", http.StatusUnsupportedMediaType, "unsupported_media_type"},
	} {
		status, body, _ := rig.post(agentproto.PathAddress, c.host, c.ct, agentproto.AddressRequest{Address: c.address})
		if status != c.status || rig.code(body) != c.code {
			t.Errorf("%s: %d %s", name, status, body)
		}
	}

	// Not signed by a device: refused before anything is confirmed.
	req, _ := http.NewRequest(http.MethodPost, rig.srv.URL+agentproto.PathAddress, strings.NewReader(`{"address":"https://rmm.example.com"}`))
	req.Host = "rmm.example.com"
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unsigned: %d", resp.StatusCode)
	}
}

func TestAddressRouteWithoutAKeySignsNothing(t *testing.T) {
	rig := newMoveRig(t, false)
	status, body, _ := rig.post(agentproto.PathAddress, "rmm.example.com", "application/json", agentproto.AddressRequest{Address: "https://rmm.example.com"})
	if status != http.StatusServiceUnavailable || rig.code(body) != "address_unconfirmable" {
		t.Errorf("%d %s", status, body)
	}
}

func TestMoveRouteRecordsReportsAndRefusesBadOnes(t *testing.T) {
	rig := newMoveRig(t, true)
	const appJSON = "application/json"
	ctx := context.Background()
	count := func(q string, args ...any) (n int) {
		t.Helper()
		if err := rig.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error { return tx.QueryRow(ctx, q, args...).Scan(&n) }); err != nil {
			t.Fatal(err)
		}
		return n
	}

	status, body, _ := rig.post(agentproto.PathMove, "rmm.example.com", appJSON, agentproto.MoveReport{Kind: agentproto.MoveSetServer, From: "https://203.0.113.10", To: "https://rmm.example.com", Moved: true})
	if status != http.StatusNoContent {
		t.Fatalf("a report: %d %s", status, body)
	}
	if n := count(`SELECT count(*) FROM audit_log WHERE action = 'device.address_change' AND target_id = $1 AND details->>'to' = 'https://rmm.example.com'`, rig.device); n != 1 {
		t.Errorf("audited %d times", n)
	}
	status, _, _ = rig.post(agentproto.PathMove, "rmm.example.com", appJSON, agentproto.MoveReport{Kind: agentproto.MoveFallback, From: "a", To: "b", Error: "no route"})
	if status != http.StatusNoContent {
		t.Fatalf("a failure: %d", status)
	}
	if n := count(`SELECT count(*) FROM audit_log WHERE action = 'device.address_change_failed' AND target_id = $1 AND details->>'error' = 'no route'`, rig.device); n != 1 {
		t.Errorf("failure audited %d times", n)
	}

	status, body, _ = rig.post(agentproto.PathMove, "rmm.example.com", appJSON, agentproto.MoveReport{Kind: "teleport"})
	if status != http.StatusBadRequest || !strings.Contains(string(body), "move report") {
		t.Errorf("a bad kind: %d %s", status, body)
	}
	status, _, _ = rig.post(agentproto.PathMove, "rmm.example.com", "text/plain", agentproto.MoveReport{Kind: agentproto.MoveInstall})
	if status != http.StatusUnsupportedMediaType {
		t.Errorf("a wrong content type: %d", status)
	}
	if n := count(`SELECT count(*) FROM audit_log WHERE action LIKE 'device.address_change%'`); n != 2 {
		t.Errorf("%d records after the refusals", n)
	}
}
