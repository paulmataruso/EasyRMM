package agentproto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func goodTrust(t *testing.T, now time.Time) TrustPayload {
	t.Helper()
	return TrustPayload{
		V: TrustPayloadVersion, ID: "id-1", DeviceID: "dev-1", Origin: "rmm.example.com",
		Chains:   []TrustChain{{ID: "c1", Purpose: TrustTarget, Chain: []string{testCert(t)}}},
		IssuedAt: now, ExpiresAt: now.Add(TrustValid),
	}
}

func TestTrustRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	p := goodTrust(t, now)
	p.EasyPatchHost = "patch.example.com"
	p.EasyPatchChains = []TrustChain{{ID: "e1", Purpose: TrustServed, Chain: []string{testCert(t)}}}
	p.AddCerts = []string{testCert(t)}
	s, err := SignTrust(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyTrust(pub, s, "dev-1", "RMM.example.com", now)
	if err != nil || got.ID != "id-1" || len(got.Chains) != 1 || got.EasyPatchHost != "patch.example.com" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestTrustSignatureHasAContextOfItsOwn(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	p := goodTrust(t, now)
	raw, _ := json.Marshal(p)
	for _, ctx := range []string{updateSigContext, uninstallSigContext, jobSigContext, easyPatchSigContext, repairSigContext, escrowKeySigContext, sigContext, ""} {
		s := SignedTrust{Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(ctx), raw...)))}
		if _, err := VerifyTrust(pub, s, "dev-1", "rmm.example.com", now); !errors.Is(err, ErrTrustSignature) {
			t.Errorf("a signature under context %q: %v", ctx, err)
		}
	}
	// And the other way round: a trust signature is no update, uninstall or escrow key.
	ts, _ := SignTrust(priv, p)
	if _, err := VerifyUninstall(pub, SignedUninstall(ts), "dev-1", now); err == nil {
		t.Error("a trust instruction verified as an uninstall")
	}
	if _, err := VerifyUpdate(pub, SignedUpdate(ts), "dev-1", now); err == nil {
		t.Error("a trust instruction verified as an update")
	}
	if _, _, err := VerifyEscrowKey(pub, SignedEscrowKey(ts), "dev-1", now); err == nil {
		t.Error("a trust instruction verified as an escrow key")
	}
}

func TestVerifyTrustRefusals(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	sign := func(p TrustPayload) SignedTrust {
		raw, _ := json.Marshal(p)
		return SignedTrust{Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(trustSigContext), raw...)))}
	}
	cases := []struct {
		name string
		edit func(*TrustPayload)
		want error
	}{
		{"device", func(p *TrustPayload) { p.DeviceID = "dev-2" }, ErrTrustDevice},
		{"origin", func(p *TrustPayload) { p.Origin = "evil.example.com" }, ErrTrustOrigin},
		{"expired", func(p *TrustPayload) { p.IssuedAt, p.ExpiresAt = now.Add(-11*time.Minute), now.Add(-time.Minute) }, ErrTrustExpired},
		{"future", func(p *TrustPayload) { p.IssuedAt, p.ExpiresAt = now.Add(time.Hour), now.Add(time.Hour+time.Minute) }, ErrTrustFuture},
		{"too long", func(p *TrustPayload) { p.ExpiresAt = p.IssuedAt.Add(TrustValid + time.Second) }, ErrTrustMalformed},
		{"no expiry", func(p *TrustPayload) { p.ExpiresAt = time.Time{} }, ErrTrustMalformed},
		{"version", func(p *TrustPayload) { p.V = 9 }, ErrTrustMalformed},
		{"id", func(p *TrustPayload) { p.ID = "" }, ErrTrustMalformed},
		{"long id", func(p *TrustPayload) { p.ID = strings.Repeat("a", 65) }, ErrTrustMalformed},
		{"IP origin", func(p *TrustPayload) { p.Origin = "203.0.113.5" }, ErrTrustMalformed},
		{"port in origin", func(p *TrustPayload) { p.Origin = "rmm.example.com:443" }, ErrTrustMalformed},
		{"patch chains without host", func(p *TrustPayload) {
			p.EasyPatchChains = []TrustChain{{ID: "e", Purpose: TrustServed, Chain: p.Chains[0].Chain}}
		}, ErrTrustMalformed},
		{"purpose", func(p *TrustPayload) { p.Chains[0].Purpose = "everything" }, ErrTrustMalformed},
		{"duplicate chain id", func(p *TrustPayload) { p.Chains = append(p.Chains, p.Chains[0]) }, ErrTrustMalformed},
		{"empty chain", func(p *TrustPayload) { p.Chains[0].Chain = nil }, ErrTrustMalformed},
		{"not a certificate", func(p *TrustPayload) { p.Chains[0].Chain = []string{"AAAA"} }, ErrTrustMalformed},
		{"not base64", func(p *TrustPayload) { p.AddCerts = []string{"%%%"} }, ErrTrustMalformed},
		{"too many to add", func(p *TrustPayload) { p.AddCerts = make([]string, MaxTrustAddCerts+1) }, ErrTrustMalformed},
		{"too many chains", func(p *TrustPayload) {
			for i := range MaxTrustChains {
				p.Chains = append(p.Chains, TrustChain{ID: "x" + string(rune('a'+i)), Purpose: TrustServed, Chain: p.Chains[0].Chain})
			}
		}, ErrTrustMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := goodTrust(t, now)
			c.edit(&p)
			if _, err := VerifyTrust(pub, sign(p), "dev-1", "rmm.example.com", now); !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
	// SignTrust refuses what the agent would refuse.
	bad := goodTrust(t, now)
	bad.Origin = "203.0.113.5"
	if _, err := SignTrust(priv, bad); !errors.Is(err, ErrTrustMalformed) {
		t.Errorf("SignTrust signed a bad payload: %v", err)
	}
}

func TestVerifyTrustMalformedAndKeyless(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	s, _ := SignTrust(priv, goodTrust(t, now))
	if _, err := VerifyTrust(Keys(nil), s, "dev-1", "rmm.example.com", now); !errors.Is(err, ErrTrustSignature) {
		t.Errorf("no key: %v", err)
	}
	if _, err := VerifyTrust(pub[:5], s, "dev-1", "rmm.example.com", now); !errors.Is(err, ErrTrustSignature) {
		t.Errorf("short key: %v", err)
	}
	if _, err := VerifyTrust(pub, SignedTrust{Payload: "%%", Signature: s.Signature}, "dev-1", "rmm.example.com", now); !errors.Is(err, ErrTrustMalformed) {
		t.Errorf("payload not base64: %v", err)
	}
	// Trailing data after the JSON object, signed.
	raw, _ := base64.StdEncoding.DecodeString(s.Payload)
	trailing := append(raw, []byte(` {"x":1}`)...)
	ts := SignedTrust{Payload: base64.StdEncoding.EncodeToString(trailing), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(trustSigContext), trailing...)))}
	if _, err := VerifyTrust(pub, ts, "dev-1", "rmm.example.com", now); !errors.Is(err, ErrTrustMalformed) {
		t.Errorf("trailing data: %v", err)
	}
}

func TestDecodeTrustCertBoundsAndDigest(t *testing.T) {
	if _, err := DecodeTrustCert(strings.Repeat("A", base64.StdEncoding.EncodedLen(MaxTrustCertBytes)+4)); err == nil {
		t.Error("an oversized certificate was read")
	}
	a, b := []byte{1, 2}, []byte{3}
	if TrustChainDigest([][]byte{a, b}) == TrustChainDigest([][]byte{b, a}) || TrustChainDigest([][]byte{a}) == "" {
		t.Error("the digest ignores order")
	}
	if got := EncodeTrustChain([][]byte{a}); len(got) != 1 || got[0] != base64.StdEncoding.EncodeToString(a) {
		t.Errorf("encoded %v", got)
	}
}
