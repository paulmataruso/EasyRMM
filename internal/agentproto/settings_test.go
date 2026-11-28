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

func testSettings(version int64) SettingsPayload {
	return SettingsPayload{
		V: SettingsPayloadVersion, DeviceID: "dev-1", Version: version, IssuedAt: time.Unix(1_800_000_000, 0).UTC(),
		Settings: map[string]json.RawMessage{"agent.heartbeat_seconds": json.RawMessage("120")},
	}
}

// signRaw signs any payload bytes under the settings context, to build
// documents that SignSettings would not make.
func signRawSettings(priv ed25519.PrivateKey, b []byte) SignedSettings {
	sig := ed25519.Sign(priv, append([]byte(settingsSigContext), b...))
	return SignedSettings{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}
}

func TestSettingsSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	s, err := SignSettings(priv, testSettings(7))
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifySettings(pub, s, "dev-1")
	if err != nil || p.Version != 7 || string(p.Settings["agent.heartbeat_seconds"]) != "120" {
		t.Fatalf("verify: %+v %v", p, err)
	}
	// A set of keys verifies by any of them.
	if _, err := VerifySettings(Keys{otherPub, pub}, s, "dev-1"); err != nil {
		t.Errorf("key set: %v", err)
	}
	if _, err := VerifySettings(otherPub, s, "dev-1"); !errors.Is(err, ErrSettingsSignature) {
		t.Errorf("another key: %v", err)
	}
	if _, err := VerifySettings(Keys{}, s, "dev-1"); !errors.Is(err, ErrSettingsSignature) {
		t.Errorf("no key: %v", err)
	}
	if _, err := VerifySettings(pub, s, "dev-2"); !errors.Is(err, ErrSettingsDevice) {
		t.Errorf("another device: %v", err)
	}
	// There is no expiry: a document years old verifies.
	old := testSettings(7)
	old.IssuedAt = time.Unix(1_000_000_000, 0).UTC()
	so, _ := SignSettings(priv, old)
	if _, err := VerifySettings(pub, so, "dev-1"); err != nil {
		t.Errorf("an old document: %v", err)
	}
	// A job signature does not make a document: the contexts differ.
	b, _ := json.Marshal(testSettings(7))
	job, err := SignJob(priv, JobPayload{})
	if err != nil {
		t.Fatal(err)
	}
	cross := SignedSettings{Payload: base64.StdEncoding.EncodeToString(b), Signature: job.Signature}
	if _, err := VerifySettings(pub, cross, "dev-1"); !errors.Is(err, ErrSettingsSignature) {
		t.Errorf("job signature accepted: %v", err)
	}
	// A changed payload no longer verifies.
	tampered := testSettings(7)
	tampered.Settings["agent.heartbeat_seconds"] = json.RawMessage("30")
	tb, _ := json.Marshal(tampered)
	if _, err := VerifySettings(pub, SignedSettings{Payload: base64.StdEncoding.EncodeToString(tb), Signature: s.Signature}, "dev-1"); !errors.Is(err, ErrSettingsSignature) {
		t.Errorf("tampered: %v", err)
	}
	if _, err := VerifySettings(pub, SignedSettings{Payload: "%%%", Signature: s.Signature}, "dev-1"); !errors.Is(err, ErrSettingsMalformed) {
		t.Errorf("bad base64: %v", err)
	}
	if _, err := VerifySettings(pub, SignedSettings{Payload: s.Payload, Signature: "%%%"}, "dev-1"); !errors.Is(err, ErrSettingsSignature) {
		t.Errorf("bad signature encoding: %v", err)
	}
}

func TestSettingsRefusals(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	good, _ := json.Marshal(testSettings(1))
	for name, tc := range map[string]struct {
		payload string
		want    error
	}{
		"version zero":     {strings.Replace(string(good), `"version":1`, `"version":0`, 1), ErrSettingsVersion},
		"version negative": {strings.Replace(string(good), `"version":1`, `"version":-5`, 1), ErrSettingsVersion},
		"version too high": {strings.Replace(string(good), `"version":1`, `"version":9007199254740992`, 1), ErrSettingsVersion},
		"unknown envelope": {strings.Replace(string(good), `"v":1`, `"v":1,"extra":true`, 1), ErrSettingsMalformed},
		"wrong v":          {strings.Replace(string(good), `"v":1`, `"v":2`, 1), ErrSettingsMalformed},
		"no settings":      {`{"v":1,"deviceId":"dev-1","version":1,"issuedAt":"2027-01-01T00:00:00Z"}`, ErrSettingsMalformed},
		"no issue time":    {`{"v":1,"deviceId":"dev-1","version":1,"settings":{}}`, ErrSettingsMalformed},
		"not json":         {`nonsense`, ErrSettingsMalformed},
	} {
		if _, err := VerifySettings(pub, signRawSettings(priv, []byte(tc.payload)), "dev-1"); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// The highest version, 2^53 - 1, is allowed.
	top := testSettings(MaxSettingsVersion)
	s, _ := SignSettings(priv, top)
	if p, err := VerifySettings(pub, s, "dev-1"); err != nil || p.Version != MaxSettingsVersion {
		t.Errorf("the highest version: %+v %v", p, err)
	}
	// Too big, signed or not.
	big := testSettings(1)
	big.Settings["agent.x"] = json.RawMessage(`"` + strings.Repeat("a", MaxSettingsDocument) + `"`)
	if _, err := SignSettings(priv, big); !errors.Is(err, ErrSettingsTooBig) {
		t.Errorf("signing too big: %v", err)
	}
	if _, err := VerifySettings(pub, SignedSettings{Payload: strings.Repeat("A", base64.StdEncoding.EncodedLen(MaxSettingsDocument)+4)}, "dev-1"); !errors.Is(err, ErrSettingsTooBig) {
		t.Errorf("verifying too big: %v", err)
	}
}

func TestSettingsHashIgnoresVersionAndTime(t *testing.T) {
	a, b := testSettings(1), testSettings(99)
	b.IssuedAt = b.IssuedAt.Add(time.Hour)
	if SettingsHash(a.Settings) != SettingsHash(b.Settings) {
		t.Error("the hash covers more than the settings")
	}
	c := testSettings(1)
	c.Settings["agent.heartbeat_seconds"] = json.RawMessage("121")
	if SettingsHash(a.Settings) == SettingsHash(c.Settings) {
		t.Error("a different value gives the same hash")
	}
	// Key order does not matter.
	x := map[string]json.RawMessage{"a.b": json.RawMessage("1"), "c.d": json.RawMessage("2")}
	y := map[string]json.RawMessage{"c.d": json.RawMessage("2"), "a.b": json.RawMessage("1")}
	if SettingsHash(x) != SettingsHash(y) {
		t.Error("the hash depends on the order")
	}
}

func TestSettingsReportsAreBounded(t *testing.T) {
	var nilCaps *SettingsCapabilities
	if nilCaps.Takes(CapSettings) {
		t.Error("a missing report takes settings")
	}
	c := &SettingsCapabilities{Accepts: []string{CapSettings}, Settings: map[string]int{"agent.heartbeat_seconds": 1}}
	if !c.Takes(CapSettings) || c.Takes("channel.v1") || c.Check() != nil {
		t.Errorf("a valid report: %v", c.Check())
	}
	for name, bad := range map[string]*SettingsCapabilities{
		"empty key":    {Settings: map[string]int{"": 1}},
		"long key":     {Settings: map[string]int{strings.Repeat("k", MaxSettingsKey+1): 1}},
		"negative":     {Settings: map[string]int{"a.b": -1}},
		"huge version": {Settings: map[string]int{"a.b": 1 << 30}},
		"empty accept": {Accepts: []string{""}},
		"long accept":  {Accepts: []string{strings.Repeat("a", MaxSettingsKey+1)}},
	} {
		if bad.Check() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	many := &SettingsCapabilities{Settings: map[string]int{}}
	for i := 0; i <= MaxCapabilityKeys; i++ {
		many.Settings[strings.Repeat("k", 1)+string(rune('a'+i%26))+strings.Repeat("z", i/26)] = 1
	}
	if many.Check() == nil {
		t.Error("too many keys accepted")
	}
	if (&SettingsReport{Version: 3, Problems: map[string]string{"a.b": ProblemInvalid}}).Check() != nil {
		t.Error("a valid report refused")
	}
	if (&SettingsReport{Problems: map[string]string{"a.b": strings.Repeat("x", MaxSettingsReason+1)}}).Check() == nil {
		t.Error("a long problem accepted")
	}
	if (&SettingsReport{Problems: map[string]string{"": "x"}}).Check() == nil {
		t.Error("an empty problem key accepted")
	}
	tooMany := &SettingsReport{Problems: map[string]string{}}
	for i := 0; i <= MaxSettingProblems; i++ {
		tooMany.Problems[strings.Repeat("p", i+1)] = "x"
	}
	if tooMany.Check() == nil {
		t.Error("too many problems accepted")
	}
}
