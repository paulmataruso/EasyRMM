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

func paramsPayload() JobPayload {
	at := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	return JobPayload{
		RunID: "6f1c9a3e-1111-4c1e-9a6b-000000000001", JobID: "6f1c9a3e-2222-4c1e-9a6b-000000000002",
		DeviceID: "dev-1", Shell: ShellPowerShell, Script: "$p = [Console]::In.ReadToEnd() | ConvertFrom-Json\n",
		Args: []string{}, TimeoutSeconds: 60, IssuedAt: at, ExpiresAt: at.Add(time.Hour),
		Params: json.RawMessage(`{"name": "alice", "enabled": true, "n": 12}`),
	}
}

func goldenKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("easyrmm-golden-job-key-012345678"))
}

// Golden vectors: a change to the canonical form, the hashes or the signed
// bytes breaks every deployed agent, so it must break these first.
const goldenParamsHash, goldenSignature = "2cee512d5ab96612e51505813e8bc313383f54f1ea7c6662cf4da2ce642680e4", "Z4s+P5QwUyLyxplyREvKfFHZ8OUsnbUe4OhpzFu5c9Tk494ibU8pNA3I3L3muKqVDb7DNcBL6Q2hoxhB+TdUAA=="

func TestParamsGoldenVectors(t *testing.T) {
	c, err := CanonicalParams([]byte(`{"name": "alice", "n": 12, "enabled": true}`))
	if err != nil || string(c) != `{"enabled":true,"n":12,"name":"alice"}` {
		t.Fatalf("canonical = %s, %v", c, err)
	}
	h, _ := HashParams(c)
	if h != goldenParamsHash {
		t.Fatalf("params hash = %s", h)
	}
	if got := HashScript("abc"); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("script hash = %s", got)
	}
	sj, err := SignJob(goldenKey(), paramsPayload())
	if err != nil {
		t.Fatal(err)
	}
	if sj.Signature != goldenSignature {
		t.Fatalf("signature = %s", sj.Signature)
	}
	b, _ := base64.StdEncoding.DecodeString(sj.Payload)
	if !strings.Contains(string(b), `"v":2`) || !strings.Contains(string(b), `"paramsSha256":"`+goldenParamsHash+`"`) {
		t.Fatalf("payload = %s", b)
	}
}

func TestParamsJobVerifies(t *testing.T) {
	key := goldenKey()
	sj, err := SignJob(key, paramsPayload())
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyJob(key.Public().(ed25519.PublicKey), sj, "dev-1", paramsPayload().IssuedAt)
	if err != nil || p.V != JobPayloadVersionParams || string(p.Params) != `{"enabled":true,"n":12,"name":"alice"}` {
		t.Fatalf("verify = %+v, %v", p, err)
	}
}

// resign re-signs an edited payload, as an attacker holding the key would,
// so that only the hash check can refuse it.
func resign(t *testing.T, edit func(*JobPayload)) (SignedJob, ed25519.PublicKey) {
	t.Helper()
	key := goldenKey()
	sj, _ := SignJob(key, paramsPayload())
	p, _, _ := DecodeJob(sj)
	edit(&p)
	b, _ := json.Marshal(p)
	sig := ed25519.Sign(key, append([]byte(jobSigContextParams), b...))
	return SignedJob{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)},
		key.Public().(ed25519.PublicKey)
}

func TestParamsTamperingIsRefused(t *testing.T) {
	now := paramsPayload().IssuedAt
	cases := map[string]struct {
		edit func(*JobPayload)
		want error
	}{
		"params changed, hash kept": {func(p *JobPayload) { p.Params = json.RawMessage(`{"enabled":true,"n":13,"name":"alice"}`) }, ErrJobHash},
		"params hash changed":       {func(p *JobPayload) { p.ParamsSHA256 = strings.Repeat("0", 64) }, ErrJobHash},
		"script changed":            {func(p *JobPayload) { p.Script += "Remove-Item *\n" }, ErrJobHash},
		"script hash missing":       {func(p *JobPayload) { p.ScriptSHA256 = "" }, ErrJobHash},
		"params not canonical":      {func(p *JobPayload) { p.Params = json.RawMessage(`{"name":"alice","b":1}`) }, ErrJobParams},
		"params not an object":      {func(p *JobPayload) { p.Params = json.RawMessage(`["a"]`) }, ErrJobParams},
		"params removed":            {func(p *JobPayload) { p.Params = nil }, ErrJobMalformed},
	}
	for name, c := range cases {
		sj, pub := resign(t, c.edit)
		if _, err := VerifyJob(pub, sj, "dev-1", now); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	// Editing the signed bytes without the key fails the signature.
	sj, _ := SignJob(goldenKey(), paramsPayload())
	b, _ := base64.StdEncoding.DecodeString(sj.Payload)
	sj.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(b), "alice", "mallory", 1)))
	if _, err := VerifyJob(goldenKey().Public().(ed25519.PublicKey), sj, "dev-1", now); !errors.Is(err, ErrJobSignature) {
		t.Errorf("edited payload: %v", err)
	}
	// A version 1 payload carries none of it.
	sj, pub := resign(t, func(p *JobPayload) { p.V = JobPayloadVersion })
	if _, err := VerifyJob(pub, sj, "dev-1", now); err == nil {
		t.Error("a v1 payload with params verified")
	}
}

func TestParamsBounds(t *testing.T) {
	if _, err := CanonicalParams([]byte(`{"a":"` + strings.Repeat("x", MaxParamsBytes) + `"}`)); !errors.Is(err, ErrJobParams) {
		t.Errorf("oversize: %v", err)
	}
	for _, bad := range []string{``, `null`, `1`, `"s"`, `[]`, `{} {}`, `{`} {
		if _, err := CanonicalParams([]byte(bad)); !errors.Is(err, ErrJobParams) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := SignJob(goldenKey(), func() JobPayload { p := paramsPayload(); p.Params = json.RawMessage(`[]`); return p }()); err == nil {
		t.Error("signed a non-object")
	}
}

// An agent from before params decodes strictly and refuses the new fields.
func TestOlderAgentRefusesParamsJob(t *testing.T) {
	sj, _ := SignJob(goldenKey(), paramsPayload())
	b, _ := base64.StdEncoding.DecodeString(sj.Payload)
	var old struct {
		V      int    `json:"v"`
		RunID  string `json:"runId"`
		Script string `json:"script"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&old); err == nil {
		t.Fatal("a build without params accepted the payload")
	}
}
