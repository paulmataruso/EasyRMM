package agentproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// previousPayload is JobPayload as the release before F2 decodes it:
// strictly, with no field for an input, an executor, a builtin or a lane.
type previousPayload struct {
	V              int             `json:"v"`
	RunID          string          `json:"runId"`
	JobID          string          `json:"jobId"`
	DeviceID       string          `json:"deviceId"`
	Shell          string          `json:"shell"`
	Script         string          `json:"script"`
	Args           []string        `json:"args"`
	TimeoutSeconds int             `json:"timeoutSeconds"`
	IssuedAt       time.Time       `json:"issuedAt"`
	ExpiresAt      time.Time       `json:"expiresAt"`
	PwshFallback   bool            `json:"pwshFallback,omitempty"`
	Params         json.RawMessage `json:"params,omitempty"`
	ScriptSHA256   string          `json:"scriptSha256,omitempty"`
	ParamsSHA256   string          `json:"paramsSha256,omitempty"`
}

func structured(input string) JobPayload {
	return JobPayload{RunID: "r1", JobID: "j1", DeviceID: "d1", Executor: ExecutorBuiltin, Builtin: BuiltinRegistry, Lane: LaneQuick,
		Input: []byte(input), TimeoutSeconds: 60, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC()}
}

func TestStructuredJobSignsAndVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	in := `{"v":1,"op":"list","hive":"HKLM","view":"64","path":[],"rules":1}`
	sj, err := SignJob(priv, structured(in))
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyJob(pub, sj, "d1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.V != JobPayloadVersionStructured || string(p.Input) != in || p.Builtin != "registry" || p.Lane != "quick" {
		t.Errorf("%+v", p)
	}
	// The input is covered by the signature.
	raw, _ := base64.StdEncoding.DecodeString(sj.Payload)
	forged := bytes.Replace(raw, []byte(base64.StdEncoding.EncodeToString([]byte(in))), []byte(base64.StdEncoding.EncodeToString([]byte(strings.Replace(in, "list", "lisp", 1)))), 1)
	if bytes.Equal(raw, forged) {
		t.Fatal("the input was not found in the payload")
	}
	sj.Payload = base64.StdEncoding.EncodeToString(forged)
	if _, err := VerifyJob(pub, sj, "d1", time.Now()); !errors.Is(err, ErrJobSignature) {
		t.Errorf("a changed input: %v", err)
	}
}

func TestStructuredJobIsRefusedByThePreviousRelease(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sj, _ := SignJob(priv, structured(`{"v":1}`))
	raw, _ := base64.StdEncoding.DecodeString(sj.Payload)
	var old previousPayload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&old); err == nil {
		t.Error("the release before decodes a structured payload; it must refuse the new fields")
	}
	// The release now decodes what the release before wrote, unchanged.
	prev, _ := json.Marshal(previousPayload{V: 1, RunID: "r", JobID: "j", DeviceID: "d", Shell: "sh", Script: "true", Args: []string{}, TimeoutSeconds: 5})
	if _, _, err := DecodeJob(SignedJob{Payload: base64.StdEncoding.EncodeToString(prev)}); err != nil {
		t.Errorf("a payload of the release before: %v", err)
	}
}

func TestStructuredPayloadChecks(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	check := func(name string, mod func(*JobPayload), want error) {
		t.Helper()
		p := structured(`{"v":1}`)
		mod(&p)
		sj, err := SignJob(priv, p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyJob(pub, sj, "d1", time.Now()); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	check("a script in a builtin job", func(p *JobPayload) { p.Script = "x" }, ErrJobMalformed)
	check("a shell in a builtin job", func(p *JobPayload) { p.Shell = "sh" }, ErrJobMalformed)
	check("no builtin", func(p *JobPayload) { p.Builtin = "" }, ErrJobMalformed)
	check("another executor", func(p *JobPayload) { p.Executor = "script" }, ErrJobMalformed)
	check("no input", func(p *JobPayload) { p.Input = nil }, ErrJobInput)
	check("an input over 1 MiB", func(p *JobPayload) { p.Input = bytes.Repeat([]byte("x"), MaxInputBytes+1) }, ErrJobInput)
	check("a quick run over 60 seconds", func(p *JobPayload) { p.TimeoutSeconds = 61 }, ErrJobMalformed)
	check("another device", func(p *JobPayload) { p.DeviceID = "d2" }, ErrJobDevice)
	check("expired", func(p *JobPayload) { p.ExpiresAt = time.Now().Add(-time.Minute) }, ErrJobExpired)
	check("a lane that is not quick", func(p *JobPayload) { p.Lane = "slow" }, ErrJobMalformed)
	// A script job may not carry the new fields.
	sj, _ := SignJob(priv, JobPayload{V: 1, RunID: "r", JobID: "j", DeviceID: "d1", Shell: "sh", Script: "true", TimeoutSeconds: 5,
		Input: []byte("x"), ExpiresAt: time.Now().Add(time.Hour)})
	if _, err := VerifyJob(pub, sj, "d1", time.Now()); !errors.Is(err, ErrJobMalformed) {
		t.Errorf("a script job with an input: %v", err)
	}
	if got := CapBuiltin("registry", 1); got != "builtin.registry.v1" {
		t.Error(got)
	}
	if MaxResultBody != 8<<20 || MaxAnswerBytes != 6<<20 || MaxSignedJob != 2<<20 {
		t.Error("the bounds are the ADR's")
	}
}
