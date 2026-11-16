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
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func testEasyPatchInstall(now time.Time) EasyPatchInstallPayload {
	return EasyPatchInstallPayload{
		V: EasyPatchInstallVersion, ID: "5b0e1d3a-77a9-4a8e-9f4e-0d5c6b7a8e9f", DeviceID: "dev-1",
		ServerURL: "https://patch.example.com",
		Packages: []EasyPatchPackage{
			{FileName: "EasyPatchAgent-1.9.0-x64.deb", URL: "https://patch.example.com/downloads/agent/EasyPatchAgent-1.9.0-x64.deb",
				Format: EasyPatchDeb, Arch: "x64", Version: "1.9.0", Size: 4321, SHA256: strings.Repeat("ab", 32)},
			{FileName: "EasyPatchAgent-1.9.0-x64.rpm", URL: "https://patch.example.com/downloads/agent/EasyPatchAgent-1.9.0-x64.rpm",
				Format: EasyPatchRPM, Arch: "x64", Version: "1.9.0", Size: 4322, SHA256: strings.Repeat("cd", 32)},
		},
		Token: "ept_" + strings.Repeat("Z", 40), IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute),
	}
}

func TestEasyPatchInstallSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	s, err := SignEasyPatchInstall(priv, testEasyPatchInstall(now))
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyEasyPatchInstall(pub, s, "dev-1", now)
	if err != nil || p.ID != testEasyPatchInstall(now).ID || len(p.Packages) != 2 || p.Token != testEasyPatchInstall(now).Token {
		t.Fatalf("verify: %+v %v", p, err)
	}
	if _, err := VerifyEasyPatchInstall(otherPub, s, "dev-1", now); !errors.Is(err, ErrEasyPatchSignature) {
		t.Errorf("another key: %v", err)
	}
	if _, err := VerifyEasyPatchInstall(pub, s, "dev-2", now); !errors.Is(err, ErrEasyPatchDevice) {
		t.Errorf("another device: %v", err)
	}
	if _, err := VerifyEasyPatchInstall(pub, s, "dev-1", now.Add(15*time.Minute)); !errors.Is(err, ErrEasyPatchExpired) {
		t.Errorf("expired: %v", err)
	}
	if _, err := VerifyEasyPatchInstall(pub, SignedEasyPatchInstall{Payload: "%%", Signature: s.Signature}, "dev-1", now); !errors.Is(err, ErrEasyPatchMalformed) {
		t.Errorf("bad base64: %v", err)
	}

	// An update's signature does not make an install: the contexts differ.
	b, _ := json.Marshal(testEasyPatchInstall(now))
	upd, err := SignUpdate(priv, testUpdate(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEasyPatchInstall(pub, SignedEasyPatchInstall{Payload: base64.StdEncoding.EncodeToString(b), Signature: upd.Signature},
		"dev-1", now); !errors.Is(err, ErrEasyPatchSignature) {
		t.Errorf("update signature accepted: %v", err)
	}
	// Nor the other way round.
	if _, err := VerifyUpdate(pub, SignedUpdate(s), "dev-1", now); !errors.Is(err, ErrUpdateSignature) {
		t.Errorf("install accepted as an update: %v", err)
	}
	// Unknown fields are refused.
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	raw["force"] = true
	extra, _ := json.Marshal(raw)
	sig := ed25519.Sign(priv, append([]byte(easyPatchSigContext), extra...))
	if _, err := VerifyEasyPatchInstall(pub, SignedEasyPatchInstall{Payload: base64.StdEncoding.EncodeToString(extra),
		Signature: base64.StdEncoding.EncodeToString(sig)}, "dev-1", now); !errors.Is(err, ErrEasyPatchMalformed) {
		t.Errorf("unknown field: %v", err)
	}
}

func TestEasyPatchInstallChecks(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	ca := testCA(t)
	ok := func(p EasyPatchInstallPayload) error {
		s, err := SignEasyPatchInstall(priv, p)
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyEasyPatchInstall(pub, s, "dev-1", now)
		return err
	}
	withCA := testEasyPatchInstall(now)
	withCA.CACert = ca
	if err := ok(withCA); err != nil {
		t.Fatalf("with a CA: %v", err)
	}
	cases := map[string]func(*EasyPatchInstallPayload){
		"version":       func(p *EasyPatchInstallPayload) { p.V = 2 },
		"no id":         func(p *EasyPatchInstallPayload) { p.ID = "" },
		"long id":       func(p *EasyPatchInstallPayload) { p.ID = strings.Repeat("a", 65) },
		"http server":   func(p *EasyPatchInstallPayload) { p.ServerURL = "http://patch.example.com" },
		"server creds":  func(p *EasyPatchInstallPayload) { p.ServerURL = "https://u:p@patch.example.com" },
		"server query":  func(p *EasyPatchInstallPayload) { p.ServerURL = "https://patch.example.com/?x=1" },
		"short token":   func(p *EasyPatchInstallPayload) { p.Token = "ept_" },
		"token space":   func(p *EasyPatchInstallPayload) { p.Token = "ept_ab cdefghij" },
		"token newline": func(p *EasyPatchInstallPayload) { p.Token = "ept_abcdefgh\n--force" },
		"bad CA": func(p *EasyPatchInstallPayload) {
			p.CACert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		},
		"two CAs":         func(p *EasyPatchInstallPayload) { p.CACert = ca + ca },
		"no packages":     func(p *EasyPatchInstallPayload) { p.Packages = nil },
		"many packages":   func(p *EasyPatchInstallPayload) { p.Packages = append(p.Packages, make([]EasyPatchPackage, 7)...) },
		"format mismatch": func(p *EasyPatchInstallPayload) { p.Packages[0].Format = EasyPatchRPM },
		"exe":             func(p *EasyPatchInstallPayload) { p.Packages[0].FileName = "setup.exe" },
		"path in name":    func(p *EasyPatchInstallPayload) { p.Packages[0].FileName = "../EasyPatchAgent-1.9.0-x64.deb" },
		"arch":            func(p *EasyPatchInstallPayload) { p.Packages[0].Arch = "x86" },
		"size":            func(p *EasyPatchInstallPayload) { p.Packages[0].Size = 0 },
		"huge":            func(p *EasyPatchInstallPayload) { p.Packages[0].Size = MaxEasyPatchPackage + 1 },
		"sha":             func(p *EasyPatchInstallPayload) { p.Packages[0].SHA256 = strings.Repeat("AB", 32) },
		"version str":     func(p *EasyPatchInstallPayload) { p.Packages[0].Version = "1.9 beta" },
		"http package": func(p *EasyPatchInstallPayload) {
			p.Packages[0].URL = "http://patch.example.com/downloads/agent/EasyPatchAgent-1.9.0-x64.deb"
		},
		"other file": func(p *EasyPatchInstallPayload) {
			p.Packages[0].URL = "https://patch.example.com/downloads/agent/EasyPatchAgent-1.8.0-x64.deb"
		},
	}
	for name, change := range cases {
		p := testEasyPatchInstall(now)
		change(&p)
		if err := ok(p); !errors.Is(err, ErrEasyPatchMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestEasyPatchArch(t *testing.T) {
	for goarch, want := range map[string]string{"amd64": "x64", "arm64": "arm64", "386": "", "arm": ""} {
		if got := EasyPatchArch(goarch); got != want {
			t.Errorf("%s: %q", goarch, got)
		}
	}
}
