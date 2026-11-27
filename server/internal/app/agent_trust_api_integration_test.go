//go:build integration

package app_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/agent/trust"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/tlstrust"
)

type trustCA struct {
	ca  *x509.Certificate
	key *ecdsa.PrivateKey
}

func newTrustCA(t *testing.T, name string) trustCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return trustCA{ca: c, key: key}
}

func (c trustCA) leaf(t *testing.T, host string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.ca, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (c trustCA) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.ca.Raw})
}

type trustSource struct{ chains map[string][]tlstrust.Chain }

func (s trustSource) Chains(host string) []tlstrust.Chain { return s.chains[host] }

type noRetrust struct{ calls int }

func (r *noRetrust) Retrust(string, bool) error { r.calls++; return nil }

// TestAgentTrustEndToEnd is ADR-0055 slice 5b1 through the real server: the
// signed trust instruction in the heartbeat answer, the real agent code (state
// folder, verification, widening, replay memory) answering it in its next
// heartbeat, what the console shows and what the audit log keeps.
func TestAgentTrustEndToEnd(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	var token struct {
		Secret string `json:"secret"`
	}
	admin.expect(http.StatusCreated, "POST", "/api/v1/sites/"+hq.ID+"/enrollment-tokens", map[string]any{"name": "Windows", "expiresInDays": 1}, &token)

	ac := h.agentClient()
	key := newKey(t)
	facts := windowsFacts("ws-trust", "1.2.3-test")
	facts.AgentSHA256 = strings.Repeat("a", 64)
	enr, err := ac.Enroll(ctx, token.Secret, key.Public().(ed25519.PublicKey), facts)
	if err != nil {
		t.Fatal(err)
	}
	ac.SetIdentity(enr.DeviceID, key)
	jobKey, err := agentproto.DecodeKey(enr.JobKey)
	if err != nil {
		t.Fatal(err)
	}

	// The server serves rmm.test (the harness's origin) with a certificate
	// from a "public" authority, and falls back to a private one.
	public, private := newTrustCA(t, "Public Root"), newTrustCA(t, "Private Authority")
	h.deps.TLSTrust.SetSource(trustSource{chains: map[string][]tlstrust.Chain{
		"rmm.test": {{Purpose: agentproto.TrustServed, DER: [][]byte{public.leaf(t, "rmm.test")}}, {Purpose: agentproto.TrustFallback, DER: [][]byte{private.leaf(t, "rmm.test")}}},
	}})

	// An agent that does not announce the capability gets nothing.
	plain, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts})
	if err != nil || plain.Trust != nil {
		t.Fatalf("a heartbeat without the capability: %+v %v", plain.Trust, err)
	}

	// The real agent code, with the job key pinned, the "system" trusting
	// only the public authority and a CA file holding the private one.
	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	caPath, err := store.SaveCA(private.pem())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &state.Config{Server: publicOrigin, DeviceID: enr.DeviceID, CAFile: caPath}
	rt := &noRetrust{}
	pool := x509.NewCertPool()
	pool.AddCert(public.ca)
	agent := &trust.Agent{DeviceID: enr.DeviceID, Config: cfg, Keys: func() agentproto.Keys { return agentproto.Keys{jobKey} }, Store: store, Client: rt,
		Verifier: trust.Verifier{SystemRoots: pool}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	beat := func() *agentproto.HeartbeatResponse {
		t.Helper()
		resp, err := ac.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts, Caps: agent.Caps(), Trust: agent.Report()})
		if err != nil {
			t.Fatal(err)
		}
		agent.Answered(ctx, resp.Protocol, resp.Trust)
		return resp
	}

	first := beat() // asked: the first heartbeat that announces the capability
	if first.Trust == nil {
		t.Fatal("no trust instruction for an agent that announced the capability")
	}
	if p, err := agentproto.VerifyTrust(jobKey, *first.Trust, enr.DeviceID, "rmm.test", time.Now()); err != nil || len(p.Chains) != 2 {
		t.Fatalf("instruction: %+v %v", p, err)
	}
	rep := agent.Report()
	if rep == nil || len(rep.Results) != 2 || !rep.Results[0].OK || !rep.Results[1].OK || rep.Refused != "" {
		t.Fatalf("the agent's report: %+v", rep)
	}
	second := beat() // carries the report; the answer asks nothing more
	if second.Trust != nil {
		t.Fatalf("an answered question is asked again: %+v", second.Trust)
	}
	if agent.Report() != nil {
		t.Error("the agent keeps a report the server took")
	}

	var view tlstrust.View
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+enr.DeviceID+"/tls-trust", nil, &view)
	if !view.Capable || len(view.Checks) != 2 || view.Unprotected || view.Trusts != "ca-file" || view.Origin != "rmm.test" {
		t.Fatalf("console view: %+v", view)
	}
	for _, c := range view.Checks {
		if c.State != "passed" {
			t.Errorf("check %+v", c)
		}
	}
	var n int
	if err := h.db.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'device.tls_trust' AND actor_type = 'agent'`).Scan(&n)
	}); err != nil || n != 1 {
		t.Fatalf("audit rows = %d (%v)", n, err)
	}

	// A move's question: the target verifies, so the agent widens, once.
	target := public.leaf(t, "rmm.test")
	if err := h.deps.TLSTrust.Ask(ctx, []uuid.UUID{uuid.MustParse(enr.DeviceID)}, tlstrust.Target{
		Origin: "rmm.test", Chains: []tlstrust.Chain{{Purpose: agentproto.TrustTarget, DER: [][]byte{target}}}}, false); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(caPath)
	beat()
	if rep := agent.Report(); rep == nil || !rep.Widened || rep.Trusts != "system+ca-file" {
		t.Fatalf("report after the move's question: %+v", rep)
	}
	if !cfg.TrustSystem {
		t.Error("the agent's trust was not widened")
	}
	if after, _ := os.ReadFile(caPath); string(after) != string(before) {
		t.Error("the CA file changed with nothing to add")
	}
	if b, err := os.ReadFile(filepath.Join(store.Dir(), "agent.json")); err != nil || !strings.Contains(string(b), `"trustSystem": true`) {
		t.Errorf("the widening was not saved in agent.json: %s (%v)", b, err)
	}
	beat()
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+enr.DeviceID+"/tls-trust", nil, &view)
	if !view.Widened || view.Trusts != "system+ca-file" {
		t.Errorf("console view after the move's question: %+v", view)
	}

	// An agent that cannot verify the target (the system does not hold its
	// authority) leaves its trust where it is, and the console says why.
	other := newTrustCA(t, "Unknown Root")
	if err := h.deps.TLSTrust.Ask(ctx, []uuid.UUID{uuid.MustParse(enr.DeviceID)}, tlstrust.Target{
		Origin: "rmm.test", Chains: []tlstrust.Chain{{Purpose: agentproto.TrustTarget, DER: [][]byte{other.leaf(t, "rmm.test")}}}}, true); err != nil {
		t.Fatal(err)
	}
	calls := rt.calls
	beat()
	beat()
	admin.expect(http.StatusOK, "GET", "/api/v1/devices/"+enr.DeviceID+"/tls-trust", nil, &view)
	failed := false
	for _, c := range view.Checks {
		if c.Purpose == agentproto.TrustTarget && c.State == "failed" && c.Error != "" {
			failed = true
		}
	}
	if !failed || rt.calls != calls {
		t.Errorf("a target that does not verify: checks %+v, retrust calls %d -> %d", view.Checks, calls, rt.calls)
	}

	// A forged instruction (another key) is refused by the agent, and an
	// instruction for this device from this server but for another origin is
	// not obeyed either.
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	forged, err := agentproto.SignTrust(otherKey, agentproto.TrustPayload{V: 1, ID: "forged", DeviceID: enr.DeviceID, Origin: "rmm.test",
		Chains:   []agentproto.TrustChain{{ID: "c", Purpose: agentproto.TrustTarget, Chain: agentproto.EncodeTrustChain([][]byte{other.leaf(t, "rmm.test")})}},
		IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	agent.Answered(ctx, 3, &forged)
	if rep := agent.Report(); rep != nil && rep.ID == "forged" {
		t.Errorf("a forged instruction was answered: %+v", rep)
	}
	if rt.calls != calls {
		t.Error("a forged instruction widened the trust")
	}
}
