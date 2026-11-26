package agentproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func escrowPayload(now time.Time) EscrowKeyPayload {
	return EscrowKeyPayload{
		V: EscrowKeyPayloadVersion, DeviceID: "dev", OrgID: "org", KeyID: "key", KeyVersion: 2,
		PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), IssuedAt: now, ExpiresAt: now.Add(EscrowKeyValid),
	}
}

func TestEscrowKeyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	s, err := SignEscrowKey(priv, escrowPayload(now))
	if err != nil {
		t.Fatal(err)
	}
	p, key, err := VerifyEscrowKey(pub, s, "dev", now)
	if err != nil || p.KeyVersion != 2 || len(key) != 32 {
		t.Fatalf("verify: %+v %v", p, err)
	}
	for name, c := range map[string]struct {
		key ed25519.PublicKey
		dev string
		at  time.Time
		err error
	}{
		"device":  {pub, "other", now, ErrEscrowKeyDevice},
		"expired": {pub, "dev", now.Add(EscrowKeyValid), ErrEscrowKeyExpired},
		"key":     {otherKey(), "dev", now, ErrEscrowKeySignature},
	} {
		if _, _, err := VerifyEscrowKey(c.key, s, c.dev, c.at); !errors.Is(err, c.err) {
			t.Errorf("%s: %v, want %v", name, err, c.err)
		}
	}
}

func otherKey() ed25519.PublicKey { p, _, _ := ed25519.GenerateKey(nil); return p }

// The signature context keeps an instruction signed for another purpose from
// being taken as an escrow key.
func TestEscrowKeyRefusesOtherContext(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	u, _ := SignUninstall(priv, UninstallPayload{V: 1, ID: "x", DeviceID: "dev", IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if _, _, err := VerifyEscrowKey(pub, SignedEscrowKey(u), "dev", now); !errors.Is(err, ErrEscrowKeySignature) {
		t.Fatalf("an uninstall signature verified as an escrow key: %v", err)
	}
}

func TestEscrowRecordAndReportChecks(t *testing.T) {
	ok := EscrowRecord{VolumeID: `\\?\Volume{1}\`, ProtectorID: "{ABC-1}", Kind: EscrowBitLocker, KeyID: "k",
		Enc: base64.StdEncoding.EncodeToString(make([]byte, 32)), Ciphertext: base64.StdEncoding.EncodeToString(make([]byte, 70)),
		Fingerprint: strings.Repeat("a", 32)}
	if err := ok.Check(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*EscrowRecord){
		"kind":    func(r *EscrowRecord) { r.Kind = "luks" },
		"volume":  func(r *EscrowRecord) { r.VolumeID = "a|b" },
		"enc":     func(r *EscrowRecord) { r.Enc = "AAAA" },
		"fp":      func(r *EscrowRecord) { r.Fingerprint = "ab" },
		"toolong": func(r *EscrowRecord) { r.Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, 600)) },
	} {
		r := ok
		mut(&r)
		if r.Check() == nil {
			t.Errorf("%s passed", name)
		}
	}
	if (EscrowVolumesReport{Volumes: make([]EscrowVolume, MaxEscrowVolumes+1)}).Check() == nil {
		t.Error("too many volumes passed")
	}
	if (EscrowVolumesReport{Volumes: []EscrowVolume{{ID: "v|x"}}}).Check() == nil {
		t.Error("a bad volume id passed")
	}
}

func TestVerifyEscrowKeyRefusesMalformedInstructions(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	sign := func(payload string) SignedEscrowKey {
		sig := ed25519.Sign(priv, append([]byte(escrowKeySigContext), payload...))
		return SignedEscrowKey{Payload: base64.StdEncoding.EncodeToString([]byte(payload)), Signature: base64.StdEncoding.EncodeToString(sig)}
	}
	good := escrowPayload(now)
	for name, s := range map[string]SignedEscrowKey{
		"payload not base64":   {Payload: "***", Signature: "AAAA"},
		"signature not base64": {Payload: "e30=", Signature: "***"},
		"not JSON":             sign("{"),
		"unknown field":        sign(`{"v":1,"extra":1}`),
		"wrong version":        sign(`{"v":9}`),
	} {
		if _, _, err := VerifyEscrowKey(pub, s, "dev", now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, mut := range map[string]func(*EscrowKeyPayload){
		"key version 0":      func(p *EscrowKeyPayload) { p.KeyVersion = 0 },
		"short public key":   func(p *EscrowKeyPayload) { p.PublicKey = base64.StdEncoding.EncodeToString([]byte("short")) },
		"public key garbage": func(p *EscrowKeyPayload) { p.PublicKey = "***" },
		"bad key id":         func(p *EscrowKeyPayload) { p.KeyID = "a|b" },
		"no expiry":          func(p *EscrowKeyPayload) { p.ExpiresAt = time.Time{} },
	} {
		p := good
		mut(&p)
		s, _ := SignEscrowKey(priv, p)
		if _, _, err := VerifyEscrowKey(pub, s, "dev", now); !errors.Is(err, ErrEscrowKeyMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if (EscrowVolumesReport{Volumes: []EscrowVolume{{ID: "v", Protectors: []EscrowProtector{{ID: "a|b"}}}}}).Check() == nil {
		t.Error("a bad protector id passed")
	}
	if (EscrowVolumesReport{Volumes: []EscrowVolume{{ID: "v", Mount: strings.Repeat("x", 17)}}}).Check() == nil {
		t.Error("a long mount passed")
	}
	rec := EscrowRecord{VolumeID: "v", ProtectorID: "p", Kind: EscrowBitLocker, KeyID: "k", Enc: base64.StdEncoding.EncodeToString(make([]byte, 32)), Ciphertext: "***", Fingerprint: strings.Repeat("a", 32)}
	if rec.Check() == nil {
		t.Error("a ciphertext that is not base64 passed")
	}
}
