package agentproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNativeIsNotAShellAPersonMayGiveAScript(t *testing.T) {
	if ValidShell(ShellNative) {
		t.Fatal("a person may give a script the native shell")
	}
	for _, s := range Shells {
		if s == ShellNative {
			t.Fatal("native is in the list the console offers")
		}
	}
	if got := ShellPlatforms(ShellNative); len(got) != 1 || got[0] != "windows" {
		t.Fatalf("platforms %v", got)
	}
	if got := ShellRequires(ShellNative); len(got) != 1 || got[0] != CapJobNative {
		t.Fatalf("requires %v", got)
	}
}

func nativePayload() JobPayload {
	params := []byte(`{"computer":"HQ-PC","volume":"C:"}`)
	ph, _ := HashParams(params)
	now := time.Now().UTC()
	return JobPayload{
		V: JobPayloadVersionParams, RunID: "r", JobID: "j", DeviceID: "d", Shell: ShellNative, Script: NativeBitLockerEnable,
		Args: []string{}, TimeoutSeconds: 60, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		Params: params, ScriptSHA256: HashScript(NativeBitLockerEnable), ParamsSHA256: ph,
	}
}

func TestANativeJobVerifiesOnlyAsAParamsJob(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := nativePayload()
	signed, err := SignJob(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyJob(pub, signed, "d", time.Now()); err != nil || got.Shell != ShellNative {
		t.Fatalf("a native job: %+v %v", got, err)
	}
	// Without params (version 1) it is malformed: a handler needs its parameters.
	old := p
	old.V, old.Params, old.ScriptSHA256, old.ParamsSHA256 = JobPayloadVersion, nil, "", ""
	signed, err = SignJob(priv, old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJob(pub, signed, "d", time.Now()); err == nil {
		t.Fatal("a native job without params verified")
	}
	// A script that is not a shell is still refused.
	bad := p
	bad.Shell = "ruby"
	signed, _ = SignJob(priv, bad)
	if _, err := VerifyJob(pub, signed, "d", time.Now()); err == nil {
		t.Fatal("an unknown shell verified")
	}
}

func TestNativeResultIsTheWinmodLine(t *testing.T) {
	line := NativeResult(1, BitLockerEnableResult{Volume: "C:", Escrow: "verified", Encryption: "started", Mode: "used_space"}, "", "")
	body, ok := strings.CutPrefix(line, NativeResultPrefix)
	if !ok || !strings.HasSuffix(line, "\n") {
		t.Fatalf("line %q", line)
	}
	var env struct {
		OK      bool
		Version int
		Data    BitLockerEnableResult
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil || !env.OK || env.Version != 1 || env.Data.Volume != "C:" {
		t.Fatalf("%+v %v", env, err)
	}
	long := NativeResult(1, nil, "boom_code", strings.Repeat("x", 900))
	var f struct {
		OK    bool
		Error struct{ Code, Message string }
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(long, NativeResultPrefix)), &f); err != nil || f.OK || f.Error.Code != "boom_code" || len(f.Error.Message) > 400 {
		t.Fatalf("%+v %v", f, err)
	}
}

func TestEscrowNeedCheck(t *testing.T) {
	ok := []EscrowNeed{
		{VolumeID: "v1"}, {VolumeID: "v1", ProtectorID: "{P}", Replace: []string{"{A}"}},
		{VolumeID: "v1", Rotating: "{P}"}, {VolumeID: "v1", Remove: []string{"{A}"}, Successor: "{B}"},
	}
	for _, n := range ok {
		if err := n.Check(); err != nil {
			t.Errorf("%+v: %v", n, err)
		}
	}
	bad := []EscrowNeed{
		{VolumeID: ""}, {VolumeID: "v1", ProtectorID: "a b;c"}, {VolumeID: "v1", Rotating: "$(x)"}, {VolumeID: "v1", Successor: "`x`"},
		{VolumeID: "v1", Remove: []string{"{A}"}}, {VolumeID: "v1", Remove: []string{"bad;id"}, Successor: "{B}"},
		{VolumeID: "v1", Replace: []string{"bad;id"}}, {VolumeID: "v1", Replace: make([]string, MaxEscrowProtectors+1)},
	}
	for _, n := range bad {
		if err := n.Check(); err == nil {
			t.Errorf("%+v was accepted", n)
		}
	}
}
