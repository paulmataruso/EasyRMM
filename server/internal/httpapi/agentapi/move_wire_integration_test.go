//go:build integration

package agentapi_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/agent/client"
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

// TestTheAgentsClientAndTheServerAgreeOverTLS runs the agent's own client
// against the real handler, the real ring and the real database, over TLS at
// the address the server serves agents on: the check, the report and each
// way the check fails.
func TestTheAgentsClientAndTheServerAgreeOverTLS(t *testing.T) {
	inst := testdb.New(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	au := audit.New(inst.DB, time.Now)
	svc := agents.New(inst.DB, au, nil, log)
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

	var handler http.Handler
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	api, err := agentapi.New(svc, nil, []agentapi.Address{{URL: "https://rmm.example.com"}, {URL: srv.URL}}, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	handler = api.Handler()

	var site uuid.UUID
	if err := inst.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var org uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ('Wire') RETURNING id`).Scan(&org); err != nil {
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
		Facts: agentproto.Facts{Hostname: "wire-1", Platform: "linux", Arch: "amd64", AgentVersion: "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	newClient := func(server string, as ed25519.PrivateKey) *client.Client {
		c, err := client.New(client.Options{Server: server, Transport: srv.Client().Transport, NoRedirect: true})
		if err != nil {
			t.Fatal(err)
		}
		c.SetIdentity(resp.DeviceID, as)
		return c
	}
	trusted := agentproto.Keys{ring.Newest().Public}

	// The server's own address, as the TLS server is reached: confirmed.
	c := newClient(srv.URL, key)
	if err := c.ConfirmAddress(ctx, trusted); err != nil {
		t.Fatalf("the check at an address the server serves: %v", err)
	}
	// An agent that does not trust the server's key does not take its word.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := c.ConfirmAddress(ctx, agentproto.Keys{otherPub}); !errors.Is(err, agentproto.ErrAddressSignature) {
		t.Errorf("an untrusted key: %v", err)
	}
	// A request signed by another key is refused before anything is signed.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	if err := newClient(srv.URL, stranger).ConfirmAddress(ctx, trusted); err == nil {
		t.Error("a request signed by another key was confirmed")
	}
	// An address the server does not serve is not confirmed, though the
	// request arrived: the same handler on another port.
	other := httptest.NewTLSServer(handler)
	t.Cleanup(other.Close)
	if err := newClient(other.URL, key).ConfirmAddress(ctx, trusted); err == nil {
		t.Error("an address the server does not serve was confirmed")
	}

	// The report is taken and audited.
	if err := c.Moved(ctx, agentproto.MoveReport{Kind: agentproto.MoveSetServer, From: "https://rmm.example.com", To: srv.URL, Moved: true}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := inst.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'device.address_change' AND target_id = $1`, resp.DeviceID).Scan(&n)
	}); err != nil || n != 1 {
		t.Errorf("audited %d times (%v)", n, err)
	}
}
