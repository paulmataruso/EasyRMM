package agentproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func testPayload(now time.Time) JobPayload {
	return JobPayload{
		V: JobPayloadVersion, RunID: "6f1c9a3e-1111-4c1e-9a6b-000000000001", JobID: "6f1c9a3e-2222-4c1e-9a6b-000000000002",
		DeviceID: "dev-1", Shell: ShellBash, Script: "echo hi\n", Args: []string{"a", "b c"}, TimeoutSeconds: 60,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func TestSignedJobsVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	sj, err := SignJob(priv, testPayload(now))
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyJob(pub, sj, "dev-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Script != "echo hi\n" || len(p.Args) != 2 || p.Args[1] != "b c" || !p.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Errorf("payload changed in transit: %+v", p)
	}

	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyJob(other, sj, "dev-1", now); !errors.Is(err, ErrJobSignature) {
		t.Errorf("another key: %v", err)
	}
	if _, err := VerifyJob(pub, sj, "dev-2", now); !errors.Is(err, ErrJobDevice) {
		t.Errorf("another device: %v", err)
	}
	if _, err := VerifyJob(pub, sj, "dev-1", now.Add(time.Hour)); !errors.Is(err, ErrJobExpired) {
		t.Errorf("expired: %v", err)
	}

	// Any change to the payload breaks the signature, and the payload is
	// still readable so the agent can report the refusal.
	raw, _ := base64.StdEncoding.DecodeString(sj.Payload)
	tampered := sj
	tampered.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), "echo hi", "rm -rf", 1)))
	p, err = VerifyJob(pub, tampered, "dev-1", now)
	if !errors.Is(err, ErrJobSignature) || p.RunID != "6f1c9a3e-1111-4c1e-9a6b-000000000001" {
		t.Errorf("tampered payload: %v, %+v", err, p)
	}
	// A signature over the same bytes without the context string fails.
	bare := sj
	bare.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))
	if _, err := VerifyJob(pub, bare, "dev-1", now); !errors.Is(err, ErrJobSignature) {
		t.Errorf("signature without context: %v", err)
	}
}

func TestMalformedJobsAreRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	for name, mutate := range map[string]func(*JobPayload){
		"version":  func(p *JobPayload) { p.V = 2 },
		"shell":    func(p *JobPayload) { p.Shell = "zsh" },
		"empty":    func(p *JobPayload) { p.Script = "" },
		"timeout":  func(p *JobPayload) { p.TimeoutSeconds = 0 },
		"too long": func(p *JobPayload) { p.TimeoutSeconds = 4*3600 + 1 },
		"no run":   func(p *JobPayload) { p.RunID = "" },
		// The fallback is pwsh's alone.
		"fallback": func(p *JobPayload) { p.Shell, p.PwshFallback = ShellPowerShell, true },
	} {
		p := testPayload(now)
		mutate(&p)
		sj, _ := SignJob(priv, p)
		if _, err := VerifyJob(pub, sj, "dev-1", now); !errors.Is(err, ErrJobMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, sj := range map[string]SignedJob{
		"not base64":    {Payload: "%%%", Signature: ""},
		"not json":      {Payload: base64.StdEncoding.EncodeToString([]byte("nope")), Signature: ""},
		"unknown field": {Payload: base64.StdEncoding.EncodeToString([]byte(`{"v":1,"extra":true}`)), Signature: ""},
	} {
		if _, err := VerifyJob(pub, sj, "dev-1", now); !errors.Is(err, ErrJobMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// releaseBeforePayload is JobPayload as 1.0.0-rc.4 declares it, the
// release before ADR-0064: its agents decode a job into it, refusing
// unknown fields.
type releaseBeforePayload struct {
	V              int       `json:"v"`
	RunID          string    `json:"runId"`
	JobID          string    `json:"jobId"`
	DeviceID       string    `json:"deviceId"`
	Shell          string    `json:"shell"`
	Script         string    `json:"script"`
	Args           []string  `json:"args"`
	TimeoutSeconds int       `json:"timeoutSeconds"`
	IssuedAt       time.Time `json:"issuedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// TestPwshJobs: a pwsh job with its fallback verifies now, while the field
// would be refused by the release before's strict decoder, which is why
// the server sends it only to agents that accept job.pwsh. Every other job
// encodes exactly as before.
func TestPwshJobs(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	p := testPayload(now)
	p.Shell, p.PwshFallback = ShellPwsh, true
	sj, err := SignJob(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyJob(pub, sj, "dev-1", now); err != nil || got.Shell != ShellPwsh || !got.PwshFallback {
		t.Fatalf("a pwsh job: %+v %v", got, err)
	}
	raw, _ := base64.StdEncoding.DecodeString(sj.Payload)
	if err := strictDecode(raw, &releaseBeforePayload{}); err == nil {
		t.Error("the release before would take pwshFallback")
	}
	for _, shell := range []string{ShellPowerShell, ShellCmd, ShellBash} {
		p := testPayload(now)
		p.Shell = shell
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("pwshFallback")) || strictDecode(b, &releaseBeforePayload{}) != nil {
			t.Errorf("a %s job changed for the release before: %s", shell, b)
		}
	}
}

// TestNewRequestFields: accepts is absent when nil and present when empty;
// interpreter and powerShell are absent when not set, so a body without
// them is what the release before sent.
func TestNewRequestFields(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
	}{
		{PollRequest{}, `{}`},
		{PollRequest{Accepts: []string{}}, `{"accepts":[]}`},
		{PollRequest{Accepts: []string{CapJobPwsh}}, `{"accepts":["job.pwsh"]}`},
	} {
		if b, err := json.Marshal(c.v); err != nil || string(b) != c.want {
			t.Errorf("%#v = %s %v, want %s", c.v, b, err, c.want)
		}
	}
	b, _ := json.Marshal(ResultRequest{Status: RunSucceeded})
	if bytes.Contains(b, []byte("interpreter")) {
		t.Errorf("a result without an interpreter: %s", b)
	}
	b, _ = json.Marshal(ResultRequest{Status: RunSucceeded, Interpreter: &Interpreter{Path: `C:\Windows\System32\cmd.exe`}})
	if !bytes.Contains(b, []byte(`"interpreter":{"path":"C:\\Windows\\System32\\cmd.exe"}`)) {
		t.Errorf("a result with a path only: %s", b)
	}
	b, _ = json.Marshal(Inventory{})
	if bytes.Contains(b, []byte("powerShell")) {
		t.Errorf("an inventory without PowerShell: %s", b)
	}
}

func TestJobKeysAndShells(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	got, err := DecodeKey(EncodeKey(pub))
	if err != nil || !got.Equal(pub) {
		t.Fatalf("round trip: %v", err)
	}
	for _, bad := range []string{"", "abc", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if _, err := DecodeKey(bad); err == nil {
			t.Errorf("DecodeKey(%q) accepted", bad)
		}
	}
	for _, s := range Shells {
		if !ValidShell(s) || len(ShellPlatforms(s)) == 0 {
			t.Errorf("shell %s", s)
		}
	}
	if ShellPlatforms(ShellPowerShell)[0] != "windows" || ShellPlatforms(ShellPwsh)[0] != "windows" || ShellPlatforms(ShellCmd)[0] != "windows" ||
		ShellPlatforms(ShellBash)[0] != "linux" {
		t.Error("shell platforms")
	}
	if ValidShell("zsh") || ShellPlatforms("pwsh7") != nil {
		t.Error("an unknown shell is accepted")
	}
	for _, s := range Shells {
		want := []string{}
		if s == ShellPwsh {
			want = []string{CapJobPwsh}
		}
		if got := ShellRequires(s); !slices.Equal(got, want) || got == nil {
			t.Errorf("ShellRequires(%s) = %#v", s, got)
		}
	}
	if PathJobStart("r1") != "/api/agent/v1/jobs/r1/start" || PathJobResult("r1") != "/api/agent/v1/jobs/r1/result" {
		t.Error("job paths")
	}
}
