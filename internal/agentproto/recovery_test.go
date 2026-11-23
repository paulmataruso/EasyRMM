package agentproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestRepairInstructionRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	good := RepairPayload{V: RepairPayloadVersion, ID: "r.0", DeviceID: "dev-1", Target: TargetMeshAgent, Step: StepRestart,
		IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	sign := func(p RepairPayload) SignedRepair {
		t.Helper()
		s, err := SignRepair(priv, p)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if p, err := VerifyRepair(pub, sign(good), "dev-1", now); err != nil || p.Target != TargetMeshAgent || p.Step != StepRestart || p.ID != "r.0" {
		t.Fatalf("good: %+v %v", p, err)
	}

	bad := func(mut func(*RepairPayload)) RepairPayload { p := good; mut(&p); return p }
	cases := map[string]struct {
		in   SignedRepair
		dev  string
		now  time.Time
		want error
	}{
		"another device": {sign(good), "dev-2", now, ErrRepairDevice},
		"expired":        {sign(good), "dev-1", now.Add(time.Minute), ErrRepairExpired},
		"version":        {sign(bad(func(p *RepairPayload) { p.V = 2 })), "dev-1", now, ErrRepairMalformed},
		"no id":          {sign(bad(func(p *RepairPayload) { p.ID = "" })), "dev-1", now, ErrRepairMalformed},
		"long id":        {sign(bad(func(p *RepairPayload) { p.ID = string(make([]byte, 65)) })), "dev-1", now, ErrRepairMalformed},
		"target":         {sign(bad(func(p *RepairPayload) { p.Target = "rm -rf /" })), "dev-1", now, ErrRepairMalformed},
		"step":           {sign(bad(func(p *RepairPayload) { p.Step = "format" })), "dev-1", now, ErrRepairMalformed},
		"no expiry":      {sign(bad(func(p *RepairPayload) { p.ExpiresAt = time.Time{} })), "dev-1", now, ErrRepairMalformed},
		"not base64":     {SignedRepair{Payload: "%%%", Signature: "AA=="}, "dev-1", now, ErrRepairMalformed},
		"bad signature":  {SignedRepair{Payload: sign(good).Payload, Signature: "AA=="}, "dev-1", now, ErrRepairSignature},
	}
	for name, c := range cases {
		if _, err := VerifyRepair(pub, c.in, c.dev, c.now); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}

	// Another key, a short key, and another kind of instruction signed with
	// the same key.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyRepair(other, sign(good), "dev-1", now); !errors.Is(err, ErrRepairSignature) {
		t.Errorf("another key: %v", err)
	}
	if _, err := VerifyRepair(pub[:5], sign(good), "dev-1", now); !errors.Is(err, ErrRepairSignature) {
		t.Errorf("short key: %v", err)
	}
	u, _ := SignUninstall(priv, UninstallPayload{V: 1, ID: "x", DeviceID: "dev-1", ExpiresAt: now.Add(time.Minute)})
	if _, err := VerifyRepair(pub, SignedRepair(u), "dev-1", now); !errors.Is(err, ErrRepairSignature) {
		t.Errorf("an uninstall instruction taken for a repair: %v", err)
	}
	// A field the agent does not know is refused, not ignored.
	raw, _ := json.Marshal(map[string]any{"v": 1, "id": "r", "deviceId": "dev-1", "target": "meshagent", "step": "restart",
		"issuedAt": now, "expiresAt": now.Add(time.Minute), "command": "reboot"})
	sig := ed25519.Sign(priv, append([]byte(repairSigContext), raw...))
	extra := SignedRepair{Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(sig)}
	if _, err := VerifyRepair(pub, extra, "dev-1", now); !errors.Is(err, ErrRepairMalformed) {
		t.Errorf("an unknown field: %v", err)
	}
}

func TestValidTargetsAndSteps(t *testing.T) {
	for _, s := range []string{TargetEasyRMMAgent, TargetMeshAgent, TargetEasyPatchAgent} {
		if !ValidTarget(s) {
			t.Errorf("%s refused", s)
		}
	}
	for _, s := range []string{StepRestart, StepRepair} {
		if !ValidStep(s) {
			t.Errorf("%s refused", s)
		}
	}
	if ValidTarget("") || ValidTarget("meshagent ") || ValidStep("") || ValidStep("Restart") {
		t.Error("an unknown name accepted")
	}
}

func TestMeshServerHost(t *testing.T) {
	for in, want := range map[string]string{
		"MeshID=0x1\nMeshServer=wss://Mesh.Example.test:443/agent.ashx\nServerID=ab\n": "mesh.example.test:443",
		"meshserver = wss://mesh.example.test/agent.ashx\r\n":                          "mesh.example.test",
		"MeshServer=wss://[2001:db8::1]:4443/agent.ashx":                               "[2001:db8::1]:4443",
		"MeshID=0x1\n":               "",
		"MeshServer=\n":              "",
		"MeshServer=not a url %zz\n": "",
		"MeshServer=/agent.ashx\n":   "",
		"# MeshServer=wss://commented.example.test/agent.ashx\nMeshID=1":                 "",
		"MeshID=0x1\nMeshServer=wss://first.example.test/a\nMeshServer=wss://second/a\n": "first.example.test",
		"": "",
	} {
		if got := MeshServerHost([]byte(in)); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
