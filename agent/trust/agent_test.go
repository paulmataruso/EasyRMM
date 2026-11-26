package trust

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

const (
	testDevice = "dev-1"
	testHost   = "rmm.example.com"
)

var t0 = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

// pki is a certificate authority and what it signs.
type pki struct {
	ca  *x509.Certificate
	key *ecdsa.PrivateKey
}

func newCA(t *testing.T, name string) pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour * 365),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return pki{ca: c, key: key}
}

// leaf issues a server certificate for host, valid at t0.
func (p pki) leaf(t *testing.T, host string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func (p pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	return pool
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func chainOf(id, purpose string, cs ...*x509.Certificate) agentproto.TrustChain {
	der := make([][]byte, len(cs))
	for i, c := range cs {
		der[i] = c.Raw
	}
	return agentproto.TrustChain{ID: id, Purpose: purpose, Chain: agentproto.EncodeTrustChain(der)}
}

type retrust struct {
	calls []string
}

func (r *retrust) Retrust(caFile string, sys bool) error {
	r.calls = append(r.calls, caFile+"|"+map[bool]string{true: "system", false: "file"}[sys])
	return nil
}

// fixture is an agent with a real state folder, the server's job key pinned,
// and a "system" that trusts only public.
type fixture struct {
	t       *testing.T
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	store   state.Store
	cfg     *state.Config
	agent   *Agent
	client  *retrust
	public  pki // a CA the system trusts
	private pki // the server's own authority
	now     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	store, _, err := state.Open(host.Paths{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, pub: pub, priv: priv, store: store, client: &retrust{}, public: newCA(t, "Public Root"), private: newCA(t, "Private Authority"), now: t0}
	f.cfg = &state.Config{Server: "https://" + testHost, DeviceID: testDevice}
	f.agent = f.build()
	return f
}

// build makes an agent over the fixture's state: a restart makes another over
// the same folder.
func (f *fixture) build() *Agent {
	return &Agent{
		DeviceID: testDevice, Config: f.cfg, Key: func() ed25519.PublicKey { return f.pub }, Store: f.store, Client: f.client,
		Verifier: Verifier{SystemRoots: f.public.pool(), Now: func() time.Time { return f.now }},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return f.now },
	}
}

// withCAFile makes the agent trust only the private authority, as an install
// with --ca-file does.
func (f *fixture) withCAFile() {
	f.t.Helper()
	path, err := f.store.SaveCA(pemOf(f.private.ca))
	if err != nil {
		f.t.Fatal(err)
	}
	f.cfg.CAFile = path
}

func (f *fixture) payload(id string, chains ...agentproto.TrustChain) agentproto.TrustPayload {
	return agentproto.TrustPayload{
		V: agentproto.TrustPayloadVersion, ID: id, DeviceID: testDevice, Origin: testHost, Chains: chains,
		IssuedAt: f.now, ExpiresAt: f.now.Add(agentproto.TrustValid),
	}
}

func (f *fixture) sign(p agentproto.TrustPayload) *agentproto.SignedTrust {
	f.t.Helper()
	s, err := agentproto.SignTrust(f.priv, p)
	if err != nil {
		f.t.Fatal(err)
	}
	return &s
}

func (f *fixture) answer(s *agentproto.SignedTrust) *agentproto.TrustReport {
	f.agent.Answered(context.Background(), 3, s)
	return f.agent.Report()
}

func (f *fixture) caFileBytes() []byte {
	f.t.Helper()
	if f.cfg.CAFile == "" {
		return nil
	}
	b, err := os.ReadFile(f.cfg.CAFile)
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func (f *fixture) unchanged(wantCA []byte, wantSystem bool) {
	f.t.Helper()
	if f.cfg.TrustSystem != wantSystem || !bytes.Equal(f.caFileBytes(), wantCA) || len(f.client.calls) != 0 {
		f.t.Errorf("trust changed: system=%v calls=%v", f.cfg.TrustSystem, f.client.calls)
	}
	saved, _, err := f.store.Load()
	if err == nil && saved.TrustSystem != wantSystem {
		f.t.Error("the saved configuration changed")
	}
}

func TestVerifiedTargetWidensTrust(t *testing.T) {
	f := newFixture(t)
	f.withCAFile()
	before := f.caFileBytes()
	leaf := f.public.leaf(t, testHost)
	p := f.payload("m1", chainOf("t", agentproto.TrustTarget, leaf))
	rep := f.answer(f.sign(p))
	if rep == nil || rep.Refused != "" || len(rep.Results) != 1 || !rep.Results[0].OK || !rep.Widened || rep.Trusts != "system+ca-file" {
		t.Fatalf("report = %+v", rep)
	}
	if !f.cfg.TrustSystem || !bytes.Equal(f.caFileBytes(), before) {
		t.Errorf("config = %+v", f.cfg)
	}
	if len(f.client.calls) != 1 || !strings.HasSuffix(f.client.calls[0], "|system") {
		t.Errorf("the running client was not told: %v", f.client.calls)
	}
}

func TestWideningSurvivesInTheSavedConfiguration(t *testing.T) {
	f := newFixture(t)
	f.withCAFile()
	if err := f.store.SaveConfig(f.cfg); err != nil {
		t.Fatal(err)
	}
	f.answer(f.sign(f.payload("m1", chainOf("t", agentproto.TrustTarget, f.public.leaf(t, testHost)))))
	b, err := os.ReadFile(filepath.Join(f.store.Dir(), "agent.json"))
	if err != nil || !strings.Contains(string(b), `"trustSystem": true`) {
		t.Errorf("agent.json = %s (%v)", b, err)
	}
}

func TestTargetThatDoesNotVerifyLeavesTrustUnchanged(t *testing.T) {
	f := newFixture(t)
	f.withCAFile()
	before := f.caFileBytes()
	other := newCA(t, "Unknown Root")
	rep := f.answer(f.sign(f.payload("m1", chainOf("t", agentproto.TrustTarget, other.leaf(t, testHost)))))
	if rep == nil || rep.Refused != "" || len(rep.Results) != 1 || rep.Results[0].OK || rep.Results[0].Error == "" || rep.Widened {
		t.Fatalf("report = %+v", rep)
	}
	f.unchanged(before, false)
}

func TestOneFailedTargetOfTwoWidensNothing(t *testing.T) {
	f := newFixture(t)
	f.withCAFile()
	before := f.caFileBytes()
	other := newCA(t, "Unknown Root")
	rep := f.answer(f.sign(f.payload("m1",
		chainOf("a", agentproto.TrustTarget, f.public.leaf(t, testHost)),
		chainOf("b", agentproto.TrustTarget, other.leaf(t, testHost)))))
	if rep == nil || rep.Widened || !rep.Results[0].OK || rep.Results[1].OK {
		t.Fatalf("report = %+v", rep)
	}
	f.unchanged(before, false)
}

func TestFallbackAndServedChainsNeverWiden(t *testing.T) {
	f := newFixture(t)
	f.withCAFile()
	before := f.caFileBytes()
	rep := f.answer(f.sign(f.payload("m1",
		chainOf("a", agentproto.TrustServed, f.public.leaf(t, testHost)),
		chainOf("b", agentproto.TrustFallback, f.private.leaf(t, testHost)))))
	if rep == nil || rep.Widened || len(rep.Results) != 2 || !rep.Results[0].OK || !rep.Results[1].OK {
		t.Fatalf("report = %+v", rep)
	}
	f.unchanged(before, false)
}

func TestChainForAnotherNameFails(t *testing.T) {
	f := newFixture(t)
	rep := f.answer(f.sign(f.payload("m1", chainOf("t", agentproto.TrustTarget, f.public.leaf(t, "other.example.com")))))
	if rep == nil || rep.Results[0].OK || !strings.Contains(rep.Results[0].Error, "valid for") {
		t.Fatalf("report = %+v", rep)
	}
}

func TestAddedAuthorityAnchorsTheMoveAndIsKept(t *testing.T) {
	f := newFixture(t) // no CA file: an agent that trusted the system alone
	p := f.payload("m1", chainOf("fb", agentproto.TrustFallback, f.private.leaf(t, testHost)), chainOf("t", agentproto.TrustTarget, f.public.leaf(t, testHost)))
	p.AddCerts = []string{base64.StdEncoding.EncodeToString(f.private.ca.Raw)}
	rep := f.answer(f.sign(p))
	if rep == nil || rep.Refused != "" || !rep.Widened || !rep.Results[0].OK || !rep.Results[1].OK {
		t.Fatalf("report = %+v", rep)
	}
	if !f.cfg.TrustSystem || f.cfg.CAFile == "" || !bytes.Contains(f.caFileBytes(), pemOf(f.private.ca)) {
		t.Errorf("the authority was not kept: %+v", f.cfg)
	}
}

func TestInstructionWithoutTargetAddsNothingEvenWithCerts(t *testing.T) {
	f := newFixture(t)
	p := f.payload("m1", chainOf("fb", agentproto.TrustFallback, f.private.leaf(t, testHost)))
	p.AddCerts = []string{base64.StdEncoding.EncodeToString(f.private.ca.Raw)}
	rep := f.answer(f.sign(p))
	if rep == nil || rep.Widened || !rep.Results[0].OK {
		t.Fatalf("report = %+v", rep)
	}
	f.unchanged(nil, false)
}

func TestACertificateToAddThatIsNotAnAuthorityIsRefused(t *testing.T) {
	f := newFixture(t)
	leaf := f.public.leaf(t, testHost)
	p := f.payload("m1", chainOf("t", agentproto.TrustTarget, leaf))
	p.AddCerts = []string{base64.StdEncoding.EncodeToString(leaf.Raw)}
	rep := f.answer(f.sign(p))
	if rep == nil || rep.Refused == "" || len(rep.Results) != 0 || rep.Widened {
		t.Fatalf("report = %+v", rep)
	}
	f.unchanged(nil, false)
}

func TestEasyPatchChainsAreCheckedAgainstTheSystemAlone(t *testing.T) {
	f := newFixture(t)
	f.withCAFile() // trusts the private authority, which the EasyPatch check must not use
	p := f.payload("m1")
	p.EasyPatchHost = "patch.example.com"
	p.EasyPatchChains = []agentproto.TrustChain{
		chainOf("ok", agentproto.TrustServed, f.public.leaf(t, "patch.example.com")),
		chainOf("private", agentproto.TrustFallback, f.private.leaf(t, "patch.example.com")),
	}
	before := f.caFileBytes()
	rep := f.answer(f.sign(p))
	if rep == nil || len(rep.Results) != 2 {
		t.Fatalf("report = %+v", rep)
	}
	if !rep.Results[0].OK || rep.Results[0].Scope != agentproto.TrustScopeEasyPatch {
		t.Errorf("the public chain = %+v", rep.Results[0])
	}
	if rep.Results[1].OK {
		t.Error("an EasyPatch chain verified through the agent's CA file")
	}
	f.unchanged(before, false)
}

// The refusals. None widens anything, and an unverified instruction is not
// echoed to the server.
func TestRefusals(t *testing.T) {
	f := newFixture(t)
	f.withCAFile()
	before := f.caFileBytes()
	leaf := f.public.leaf(t, testHost)
	good := f.payload("m1", chainOf("t", agentproto.TrustTarget, leaf))

	_, attackerKey, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := agentproto.SignTrust(attackerKey, good)

	// A signature made for another instruction, over the same bytes.
	raw, _ := json.Marshal(good)
	otherContext := func(ctx string) *agentproto.SignedTrust {
		return &agentproto.SignedTrust{
			Payload:   base64.StdEncoding.EncodeToString(raw),
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, append([]byte(ctx), raw...))),
		}
	}
	// A signature over the payload with an unknown field.
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["widenEverything"] = true
	extra, _ := json.Marshal(m)
	unknown := &agentproto.SignedTrust{
		Payload:   base64.StdEncoding.EncodeToString(extra),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, append([]byte("EASYRMM-TRUST-SIG-V1\n"), extra...))),
	}
	mod := func(edit func(*agentproto.TrustPayload)) *agentproto.SignedTrust {
		p := good
		edit(&p)
		raw, _ := json.Marshal(p) // signed by hand: SignTrust itself refuses a bad payload
		return &agentproto.SignedTrust{
			Payload:   base64.StdEncoding.EncodeToString(raw),
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, append([]byte("EASYRMM-TRUST-SIG-V1\n"), raw...))),
		}
	}
	cases := []struct {
		name      string
		in        *agentproto.SignedTrust
		echoed    bool // the report names the instruction
		wantInRep string
	}{
		{"wrong key", &forged, false, ""},
		{"an update's signature context", otherContext("EASYRMM-UPDATE-SIG-V1\n"), false, ""},
		{"an uninstall's signature context", otherContext("EASYRMM-UNINSTALL-SIG-V1\n"), false, ""},
		{"an escrow key's signature context", otherContext("easyrmm-escrow-key-v1\n"), false, ""},
		{"no context", otherContext(""), false, ""},
		{"garbage payload", &agentproto.SignedTrust{Payload: "!!", Signature: "!!"}, false, ""},
		{"unknown field", unknown, false, "malformed"},
		{"another device", mod(func(p *agentproto.TrustPayload) { p.DeviceID = "dev-2" }), true, "another device"},
		{"another origin", mod(func(p *agentproto.TrustPayload) { p.Origin = "evil.example.com" }), true, "another origin"},
		{"expired", mod(func(p *agentproto.TrustPayload) {
			p.IssuedAt, p.ExpiresAt = f.now.Add(-11*time.Minute), f.now.Add(-time.Minute)
		}), true, "expired"},
		{"issued in the future", mod(func(p *agentproto.TrustPayload) {
			p.IssuedAt, p.ExpiresAt = f.now.Add(time.Hour), f.now.Add(time.Hour+time.Minute)
		}), true, "future"},
		{"valid for a day", mod(func(p *agentproto.TrustPayload) { p.ExpiresAt = p.IssuedAt.Add(24 * time.Hour) }), true, "malformed"},
		{"a wrong version", mod(func(p *agentproto.TrustPayload) { p.V = 2 }), true, "malformed"},
		{"an IP address as origin", mod(func(p *agentproto.TrustPayload) { p.Origin = "203.0.113.5" }), true, "malformed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f.agent.Answered(context.Background(), 3, nil)
			rep := f.answer(c.in)
			if c.echoed {
				if rep == nil || rep.ID != "m1" || !strings.Contains(rep.Refused, c.wantInRep) || len(rep.Results) != 0 || rep.Widened {
					t.Fatalf("report = %+v", rep)
				}
			} else if rep != nil && rep.ID != "" && rep.Refused == "" {
				t.Fatalf("an unverified instruction got a report: %+v", rep)
			} else if rep != nil && rep.ID != "" {
				t.Fatalf("an unverified instruction was echoed: %+v", rep)
			}
			f.unchanged(before, false)
		})
	}
}

func TestNoPinnedKeyRefusesEverything(t *testing.T) {
	f := newFixture(t)
	f.agent.Key = func() ed25519.PublicKey { return nil }
	rep := f.answer(f.sign(f.payload("m1", chainOf("t", agentproto.TrustTarget, f.public.leaf(t, testHost)))))
	if rep != nil {
		t.Fatalf("report = %+v", rep)
	}
	f.unchanged(nil, false)
}

func TestAServerBelowLevelTwoIsNotObeyed(t *testing.T) {
	f := newFixture(t)
	f.agent.Answered(context.Background(), 1, f.sign(f.payload("m1", chainOf("t", agentproto.TrustTarget, f.public.leaf(t, testHost)))))
	if f.agent.Report() != nil {
		t.Error("a level 1 answer's instruction was handled")
	}
	f.unchanged(nil, false)
}

func TestReplay(t *testing.T) {
	f := newFixture(t)
	f.withCAFile()
	leaf := f.public.leaf(t, testHost)
	first := f.sign(f.payload("m1", chainOf("t", agentproto.TrustTarget, leaf)))
	if rep := f.answer(first); rep == nil || !rep.Widened {
		t.Fatalf("first = %+v", rep)
	}
	calls := len(f.client.calls)

	// The same instruction again (its report has not arrived): reported
	// again, widened once.
	f.agent.Answered(context.Background(), 3, nil)
	if rep := f.answer(first); rep == nil || rep.ID != "m1" || !rep.Widened || len(rep.Results) != 1 {
		t.Fatalf("resend = %+v", rep)
	}
	if len(f.client.calls) != calls {
		t.Error("the instruction was carried out twice")
	}

	// After a restart the agent still knows it.
	f.agent = f.build()
	if rep := f.answer(first); rep == nil || rep.ID != "m1" || len(f.client.calls) != calls {
		t.Fatalf("after a restart: %+v, calls %v", rep, f.client.calls)
	}

	// A new one, then the old copy replayed under a new ID is not possible
	// (the signature covers the ID); the older one with the same ID is
	// known; an older issue time under a new ID is refused.
	f.now = f.now.Add(time.Minute)
	newer := f.sign(f.payload("m2", chainOf("t", agentproto.TrustServed, leaf)))
	if rep := f.answer(newer); rep == nil || rep.Refused != "" {
		t.Fatalf("newer = %+v", rep)
	}
	older := f.payload("m3", chainOf("t", agentproto.TrustTarget, leaf))
	older.IssuedAt, older.ExpiresAt = f.now.Add(-30*time.Second), f.now.Add(5*time.Minute)
	rep := f.answer(f.sign(older))
	if rep == nil || rep.ID != "m3" || !strings.Contains(rep.Refused, "already handled") {
		t.Fatalf("older = %+v", rep)
	}
}

func TestADowngradeToAnOlderInstructionAfterAFailureIsRefused(t *testing.T) {
	// The server says "fallback only" after a widening; an attacker replays
	// the widening instruction under the same ID once it expired.
	f := newFixture(t)
	f.withCAFile()
	leaf := f.public.leaf(t, testHost)
	first := f.sign(f.payload("m1", chainOf("t", agentproto.TrustTarget, leaf)))
	f.answer(first)
	f.now = f.now.Add(agentproto.TrustValid + time.Second)
	f.agent.Answered(context.Background(), 3, nil)
	rep := f.answer(first)
	if rep == nil || !strings.Contains(rep.Refused, "expired") {
		t.Fatalf("replay after expiry = %+v", rep)
	}
}

func TestAnAnswerWithoutInstructionDropsTheReport(t *testing.T) {
	f := newFixture(t)
	f.answer(f.sign(f.payload("m1", chainOf("t", agentproto.TrustServed, f.public.leaf(t, testHost)))))
	if f.agent.Report() == nil {
		t.Fatal("no report")
	}
	f.agent.Answered(context.Background(), 3, nil)
	if f.agent.Report() != nil {
		t.Error("the report stays after the server stopped asking")
	}
}

func TestCapsAnnounceTrust(t *testing.T) {
	f := newFixture(t)
	if c := f.agent.Caps(); len(c) != 1 || c[0] != agentproto.CapTrust {
		t.Errorf("caps = %v", c)
	}
}

func TestTrustsNames(t *testing.T) {
	f := newFixture(t)
	if f.agent.trusts() != "system" {
		t.Error(f.agent.trusts())
	}
	f.withCAFile()
	if f.agent.trusts() != "ca-file" {
		t.Error(f.agent.trusts())
	}
	f.cfg.TrustSystem = true
	if f.agent.trusts() != "system+ca-file" {
		t.Error(f.agent.trusts())
	}
}

func TestWidenWithNothingToWidenIsANoOp(t *testing.T) {
	f := newFixture(t) // system alone, no certificate to add
	rep := f.answer(f.sign(f.payload("m1", chainOf("t", agentproto.TrustTarget, f.public.leaf(t, testHost)))))
	if rep == nil || rep.Refused != "" || rep.Widened || rep.Trusts != "system" {
		t.Fatalf("report = %+v", rep)
	}
	f.unchanged(nil, false)
}

func TestReasonIsBounded(t *testing.T) {
	long := strings.Repeat("x ", 1000)
	if got := reason(os.ErrInvalid); got == "" {
		t.Error("empty")
	}
	if got := reason(errString(long)); len(got) > agentproto.MaxTrustError {
		t.Errorf("len = %d", len(got))
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestVerifyNeedsAChainAndRoots(t *testing.T) {
	v := Verifier{}
	if v.Verify(nil, testHost, true, nil) == nil {
		t.Error("an empty chain passed")
	}
	f := newFixture(t)
	if f.agent.Verifier.Verify([]*x509.Certificate{f.public.leaf(t, testHost)}, testHost, false, nil) == nil {
		t.Error("verified against no roots")
	}
}

func TestCorruptTrustLogIsEmpty(t *testing.T) {
	f := newFixture(t)
	_ = os.MkdirAll(f.store.Dir(), 0o700)
	if err := os.WriteFile(filepath.Join(f.store.Dir(), "trust.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l := f.store.LoadTrustLog(); len(l.Handled) != 0 || !l.Issued.IsZero() {
		t.Errorf("log = %+v", l)
	}
}
