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

func testUpdate(now time.Time) UpdatePayload {
	return UpdatePayload{
		V: UpdatePayloadVersion, ID: "0b7e3c1e-2a51-4c4e-9a8e-3f1f6c1d2e3f", DeviceID: "dev-1",
		File: "easyrmm-agent-linux-amd64", Size: 1234, SHA256: strings.Repeat("ab", 32), Version: "v1.2.0-3-gabcdef0",
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}
}

func TestUpdateSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	s, err := SignUpdate(priv, testUpdate(now))
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyUpdate(pub, s, "dev-1", now)
	want := testUpdate(now)
	if err != nil || p.ID != want.ID || p.File != want.File || p.Size != want.Size || p.SHA256 != want.SHA256 ||
		p.Version != want.Version || !p.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("verify: %+v %v", p, err)
	}
	if _, err := VerifyUpdate(otherPub, s, "dev-1", now); !errors.Is(err, ErrUpdateSignature) {
		t.Errorf("another key: %v", err)
	}
	if _, err := VerifyUpdate(pub, s, "dev-2", now); !errors.Is(err, ErrUpdateDevice) {
		t.Errorf("another device: %v", err)
	}
	if _, err := VerifyUpdate(pub, s, "dev-1", now.Add(10*time.Minute)); !errors.Is(err, ErrUpdateExpired) {
		t.Errorf("expired: %v", err)
	}
	// A job signature does not make an update: the contexts differ.
	b, _ := json.Marshal(testUpdate(now))
	job, err := SignJob(priv, JobPayload{})
	if err != nil {
		t.Fatal(err)
	}
	cross := SignedUpdate{Payload: base64.StdEncoding.EncodeToString(b), Signature: job.Signature}
	if _, err := VerifyUpdate(pub, cross, "dev-1", now); !errors.Is(err, ErrUpdateSignature) {
		t.Errorf("job signature accepted: %v", err)
	}
	// A changed payload no longer verifies.
	tampered := testUpdate(now)
	tampered.SHA256 = strings.Repeat("cd", 32)
	tb, _ := json.Marshal(tampered)
	if _, err := VerifyUpdate(pub, SignedUpdate{Payload: base64.StdEncoding.EncodeToString(tb), Signature: s.Signature}, "dev-1", now); !errors.Is(err, ErrUpdateSignature) {
		t.Errorf("tampered: %v", err)
	}
	if _, err := VerifyUpdate(pub, SignedUpdate{Payload: "%%%", Signature: s.Signature}, "dev-1", now); !errors.Is(err, ErrUpdateMalformed) {
		t.Errorf("bad base64: %v", err)
	}
}

func TestUpdateMalformed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	for name, mutate := range map[string]func(*UpdatePayload){
		"version":     func(p *UpdatePayload) { p.V = 2 },
		"no id":       func(p *UpdatePayload) { p.ID = "" },
		"long id":     func(p *UpdatePayload) { p.ID = strings.Repeat("x", 65) },
		"bad file":    func(p *UpdatePayload) { p.File = "../easyrmm-agent-linux-amd64" },
		"exe linux":   func(p *UpdatePayload) { p.File = "easyrmm-agent-linux-amd64.exe" },
		"no exe":      func(p *UpdatePayload) { p.File = "easyrmm-agent-windows-amd64" },
		"empty":       func(p *UpdatePayload) { p.Size = 0 },
		"huge":        func(p *UpdatePayload) { p.Size = MaxAgentBuild + 1 },
		"short sha":   func(p *UpdatePayload) { p.SHA256 = "abcd" },
		"upper sha":   func(p *UpdatePayload) { p.SHA256 = strings.Repeat("AB", 32) },
		"bad version": func(p *UpdatePayload) { p.Version = "v1 (evil)" },
	} {
		t.Run(name, func(t *testing.T) {
			p := testUpdate(now)
			mutate(&p)
			s, err := SignUpdate(priv, p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyUpdate(pub, s, "dev-1", now); !errors.Is(err, ErrUpdateMalformed) {
				t.Errorf("got %v", err)
			}
		})
	}
	// Unknown fields are refused.
	b := []byte(`{"v":1,"id":"x","deviceId":"dev-1","file":"easyrmm-agent-linux-amd64","size":1,"sha256":"` +
		strings.Repeat("ab", 32) + `","version":"","issuedAt":"2026-01-01T00:00:00Z","expiresAt":"2999-01-01T00:00:00Z","run":"rm -rf /"}`)
	sig := ed25519.Sign(priv, append([]byte(updateSigContext), b...))
	s := SignedUpdate{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}
	if _, err := VerifyUpdate(pub, s, "dev-1", now); !errors.Is(err, ErrUpdateMalformed) {
		t.Errorf("unknown field: %v", err)
	}
	// An empty version is allowed: the server may not know it.
	p := testUpdate(now)
	p.Version = ""
	s, _ = SignUpdate(priv, p)
	if _, err := VerifyUpdate(pub, s, "dev-1", now); err != nil {
		t.Errorf("no version: %v", err)
	}
}

func TestBuildFile(t *testing.T) {
	for name, want := range map[string]string{
		"easyrmm-agent-linux-amd64":       "linux/amd64",
		"easyrmm-agent-linux-arm":         "linux/arm",
		"easyrmm-agent-windows-arm64.exe": "windows/arm64",
		"easyrmm-agent-windows-arm64":     "",
		"easyrmm-agent-linux-386.exe":     "",
		"easyrmm-agent-darwin-arm64":      "",
		"SHA256SUMS":                      "",
	} {
		goos, goarch, ok := BuildFile(name)
		if got := goos + "/" + goarch; ok != (want != "") || ok && got != want {
			t.Errorf("%s: %s %v", name, got, ok)
		}
	}
	for v, ok := range map[string]bool{"dev": true, "v1.2.3": true, "0d6ce73-dirty": true, "1.0+build.5": true,
		"": false, "-v1": false, "v 1": false, strings.Repeat("1", 65): false} {
		if ValidVersion(v) != ok {
			t.Errorf("ValidVersion(%q) != %v", v, ok)
		}
	}
}
