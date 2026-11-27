package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/agent/trust"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func enrolled(t *testing.T, h *harness, jobKey string, gen int64) *state.Config {
	t.Helper()
	linuxOnly(t)
	if err := h.e.openStore(); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	cfg := &state.Config{Server: "https://rmm.example.com", DeviceID: "dev-1", EnrolledAt: time.Now().UTC(), MeshAgentMode: "child"}
	cfg.PinFirstKey(jobKey, gen)
	if err := h.e.store.Save(cfg, key); err != nil {
		t.Fatal(err)
	}
	h.e.store = state.Store{}
	return cfg
}

func TestTrustKeyReplacesTheKeysAndRefusesALowerGeneration(t *testing.T) {
	h := newHarness(t)
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	enrolled(t, h, agentproto.EncodeKey(pubA), 5)

	arg := func(gen int64, p ed25519.PublicKey) string { return fmt.Sprintf("%d:%s", gen, agentproto.EncodeKey(p)) }
	if err := h.run("trust-key", arg(3, pubB)); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("a lower generation: %v", err)
	}
	cfg, _, _ := h.e.store.Load()
	if len(cfg.JobKeys) != 1 || cfg.JobKeys[0].Generation != 5 {
		t.Fatalf("a refused command changed the keys: %+v", cfg.JobKeys)
	}
	// The flag may follow the key, as the console prints it.
	if err := h.run("trust-key", arg(3, pubB), "--force"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.out.String(), "now trusts only") {
		t.Errorf("output %q", h.out)
	}
	cfg, _, _ = h.e.store.Load()
	if len(cfg.JobKeys) != 1 || cfg.JobKey != agentproto.EncodeKey(pubB) || cfg.JobKeys[0].Generation != 3 || len(cfg.DroppedJobKeys) != 1 {
		t.Fatalf("after --force: %+v", cfg)
	}
	// The service was restarted (systemd is faked): nothing to restart here
	// since none was installed, which the output says.
	if !strings.Contains(h.out.String(), "Restart the agent") && !strings.Contains(h.out.String(), "restarted") {
		t.Errorf("no word on the service: %q", h.out)
	}
	// Run again by a policy: same key, same generation, no error.
	if err := h.run("trust-key", arg(3, pubB)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{}, {"nope"}, {"0:" + agentproto.EncodeKey(pubB)}, {"x:" + agentproto.EncodeKey(pubB)}, {"1:short"}, {arg(1, pubB), arg(2, pubB)}} {
		if err := h.run(append([]string{"trust-key"}, bad...)...); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	h.e.isRoot = func() bool { return false }
	if err := h.run("trust-key", arg(9, pubB)); err == nil || !strings.Contains(err.Error(), "as root") {
		t.Errorf("without root: %v", err)
	}
}

func TestStatusListsTheKeysAndTheLatestInstructions(t *testing.T) {
	h := newHarness(t)
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	cfg := enrolled(t, h, agentproto.EncodeKey(pubA), 0)
	if err := h.e.openStore(); err != nil {
		t.Fatal(err)
	}
	cfg.JobKeys = append(cfg.JobKeys, state.JobKey{Key: agentproto.EncodeKey(pubB), Generation: 7})
	cfg.DroppedJobKeys = []state.JobKey{{Key: agentproto.EncodeKey(pubA)}}
	cfg.KeyTransitionUntil = time.Now().Add(5 * time.Minute)
	if err := h.e.store.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	il := &trust.InstructionLog{Store: h.e.store}
	il.Record(agentproto.InstructionJob, "run-9", agentproto.Fingerprint(pubB))
	if err := h.run("status"); err != nil {
		t.Fatal(err)
	}
	out := h.out.String()
	for _, want := range []string{"Job key:    " + agentproto.FormatFingerprint(agentproto.Fingerprint(pubA)) + " generation unknown",
		"generation 7", "Dropped:", "Key change: in transition", "Accepted:   job run-9"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
}

func TestCAFingerprints(t *testing.T) {
	if got := caFingerprints(""); got != nil {
		t.Errorf("no CA file: %v", got)
	}
	if got := caFingerprints(filepath.Join(t.TempDir(), "none.pem")); got != nil {
		t.Errorf("a missing file: %v", got)
	}
	mk := func(name string) []byte {
		key, _, _ := ed25519.GenerateKey(rand.Reader)
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key, priv)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	body := append(append(mk("a"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})...), mk("b")...)
	body = append(body, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	got := caFingerprints(path)
	if len(got) != 2 || len(got[0]) != 64 || got[0] == got[1] {
		t.Fatalf("fingerprints %v", got)
	}
}
