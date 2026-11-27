package agentproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testUninstall(now time.Time) UninstallPayload {
	return UninstallPayload{
		V: UninstallPayloadVersion, ID: "5c0d6a3e-8f2b-4d1a-9b7c-2e4f6a8b0c1d", DeviceID: "dev-1",
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}
}

func signRaw(t *testing.T, priv ed25519.PrivateKey, payload string) SignedUninstall {
	t.Helper()
	sig := ed25519.Sign(priv, append([]byte(uninstallSigContext), payload...))
	return SignedUninstall{Payload: base64.StdEncoding.EncodeToString([]byte(payload)), Signature: base64.StdEncoding.EncodeToString(sig)}
}

func TestUninstallSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	s, err := SignUninstall(priv, testUninstall(now))
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyUninstall(pub, s, "dev-1", now)
	if want := testUninstall(now); err != nil || p.ID != want.ID || p.DeviceID != "dev-1" || !p.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("verify: %+v %v", p, err)
	}
	if _, err := VerifyUninstall(otherPub, s, "dev-1", now); !errors.Is(err, ErrUninstallSignature) {
		t.Errorf("another key: %v", err)
	}
	if _, err := VerifyUninstall(Keys(nil), s, "dev-1", now); !errors.Is(err, ErrUninstallSignature) {
		t.Errorf("no key: %v", err)
	}
	if _, err := VerifyUninstall(pub, s, "dev-2", now); !errors.Is(err, ErrUninstallDevice) {
		t.Errorf("another device: %v", err)
	}
	if _, err := VerifyUninstall(pub, s, "dev-1", now.Add(10*time.Minute)); !errors.Is(err, ErrUninstallExpired) {
		t.Errorf("expired: %v", err)
	}
	// Neither an update's nor a job's signature makes an uninstall: the
	// contexts differ.
	b, _ := json.Marshal(testUninstall(now))
	up, err := SignUpdate(priv, testUpdate(now))
	if err != nil {
		t.Fatal(err)
	}
	job, err := SignJob(priv, JobPayload{})
	if err != nil {
		t.Fatal(err)
	}
	for name, sig := range map[string]string{"update": up.Signature, "job": job.Signature} {
		cross := SignedUninstall{Payload: base64.StdEncoding.EncodeToString(b), Signature: sig}
		if _, err := VerifyUninstall(pub, cross, "dev-1", now); !errors.Is(err, ErrUninstallSignature) {
			t.Errorf("%s signature accepted: %v", name, err)
		}
	}
	// An uninstall signature does not make an update either.
	if _, err := VerifyUpdate(pub, SignedUpdate(s), "dev-1", now); err == nil {
		t.Error("an uninstall instruction verified as an update")
	}
	// A changed payload no longer verifies.
	tampered := testUninstall(now)
	tampered.DeviceID = "dev-2"
	tb, _ := json.Marshal(tampered)
	if _, err := VerifyUninstall(pub, SignedUninstall{Payload: base64.StdEncoding.EncodeToString(tb), Signature: s.Signature}, "dev-2", now); !errors.Is(err, ErrUninstallSignature) {
		t.Errorf("tampered: %v", err)
	}
}

func TestUninstallMalformed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	good, _ := json.Marshal(testUninstall(now))
	cases := map[string]string{
		"not JSON":      "not json",
		"unknown field": strings.Replace(string(good), `"v":1`, `"v":1,"extra":true`, 1),
		"version":       strings.Replace(string(good), `"v":1`, `"v":2`, 1),
		"no id":         strings.Replace(string(good), testUninstall(now).ID, "", 1),
		"long id":       strings.Replace(string(good), testUninstall(now).ID, strings.Repeat("a", 65), 1),
	}
	for name, payload := range cases {
		if _, err := VerifyUninstall(pub, signRaw(t, priv, payload), "dev-1", now); !errors.Is(err, ErrUninstallMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	noExpiry := testUninstall(now)
	noExpiry.ExpiresAt = time.Time{}
	b, _ := json.Marshal(noExpiry)
	if _, err := VerifyUninstall(pub, signRaw(t, priv, string(b)), "dev-1", now); !errors.Is(err, ErrUninstallMalformed) {
		t.Errorf("no expiry: %v", err)
	}
	if _, err := VerifyUninstall(pub, SignedUninstall{Payload: "%%%", Signature: "AA=="}, "dev-1", now); !errors.Is(err, ErrUninstallMalformed) {
		t.Errorf("payload not base64: %v", err)
	}
	s, _ := SignUninstall(priv, testUninstall(now))
	if _, err := VerifyUninstall(pub, SignedUninstall{Payload: s.Payload, Signature: "%%%"}, "dev-1", now); !errors.Is(err, ErrUninstallSignature) {
		t.Errorf("signature not base64: %v", err)
	}
}
