package agentproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func newKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

type stmtFixture struct {
	oldPub, newPub   ed25519.PublicKey
	oldPriv, newPriv ed25519.PrivateKey
	install          string
	now              time.Time
}

func newStmtFixture(t *testing.T) stmtFixture {
	t.Helper()
	f := stmtFixture{now: time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)}
	f.oldPub, f.oldPriv = newKeyPair(t)
	f.newPub, f.newPriv = newKeyPair(t)
	devPub, _ := newKeyPair(t)
	f.install = InstallID(devPub)
	return f
}

func (f stmtFixture) payload() KeyStatement {
	return KeyStatement{
		V: KeyStatementVersion, ID: "s-1", DeviceID: "dev-1", Install: f.install,
		Key: EncodeKey(f.newPub), Generation: 2, IssuedAt: f.now, ExpiresAt: f.now.Add(KeyStatementValid),
	}
}

func TestHandoverVerifiesWithATrustedKey(t *testing.T) {
	f := newStmtFixture(t)
	s, err := SignHandover(f.oldPriv, f.payload())
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyHandover(Keys{f.oldPub}, s, "dev-1", f.install, f.now)
	if err != nil || p.Generation != 2 || p.Key != EncodeKey(f.newPub) {
		t.Fatalf("%+v %v", p, err)
	}
	// Any key of the set may have signed it; a single key is a set of one.
	if _, err := VerifyHandover(Keys{f.newPub, f.oldPub}, s, "dev-1", f.install, f.now); err != nil {
		t.Errorf("a set of two: %v", err)
	}
	if _, err := VerifyHandover(f.oldPub, s, "dev-1", f.install, f.now); err != nil {
		t.Errorf("one key: %v", err)
	}
}

func TestHandoverRefusals(t *testing.T) {
	f := newStmtFixture(t)
	signed := func(p KeyStatement) SignedKeyStatement {
		s, err := SignHandover(f.oldPriv, p)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	raw := func(payload []byte, key ed25519.PrivateKey) SignedKeyStatement {
		sig := ed25519.Sign(key, append([]byte(handoverSigContext), payload...))
		return SignedKeyStatement{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(sig)}
	}
	good := f.payload()
	goodJSON, _ := json.Marshal(good)
	other := f.payload()
	other.DeviceID = "dev-2"
	otherInstall := f.payload()
	otherInstall.Install = strings.Repeat("0", 64)
	expired := f.payload()
	expired.IssuedAt, expired.ExpiresAt = f.now.Add(-time.Hour), f.now.Add(-50*time.Minute)
	future := f.payload()
	future.IssuedAt, future.ExpiresAt = f.now.Add(MaxSkew+time.Minute), f.now.Add(MaxSkew+5*time.Minute)
	long := f.payload()
	long.ExpiresAt = f.now.Add(2 * KeyStatementValid)
	noGen := f.payload()
	noGen.Generation = 0
	badKey := f.payload()
	badKey.Key = "not a key"

	tests := map[string]struct {
		s    SignedKeyStatement
		keys Keys
		want error
	}{
		"a signer the agent does not trust": {raw(goodJSON, f.newPriv), Keys{f.oldPub}, ErrKeyStatementSignature},
		"no keys trusted":                   {signed(good), nil, ErrKeyStatementSignature},
		"another device":                    {signed(other), Keys{f.oldPub}, ErrKeyStatementDevice},
		"another install":                   {signed(otherInstall), Keys{f.oldPub}, ErrKeyStatementInstall},
		"expired":                           {signed(expired), Keys{f.oldPub}, ErrKeyStatementExpired},
		"issued in the future":              {signed(future), Keys{f.oldPub}, ErrKeyStatementFuture},
		"valid too long":                    {raw(stmtJSON(long), f.oldPriv), Keys{f.oldPub}, ErrKeyStatementMalformed},
		"no generation":                     {raw(stmtJSON(noGen), f.oldPriv), Keys{f.oldPub}, ErrKeyStatementMalformed},
		"a key that is not one":             {raw(stmtJSON(badKey), f.oldPriv), Keys{f.oldPub}, ErrKeyStatementMalformed},
		"an unknown field":                  {raw([]byte(strings.Replace(string(goodJSON), `"v":1`, `"v":1,"extra":true`, 1)), f.oldPriv), Keys{f.oldPub}, ErrKeyStatementMalformed},
		"two documents":                     {raw(append(append([]byte{}, goodJSON...), goodJSON...), f.oldPriv), Keys{f.oldPub}, ErrKeyStatementMalformed},
		"not base64":                        {SignedKeyStatement{Payload: "!!", Signature: "x"}, Keys{f.oldPub}, ErrKeyStatementMalformed},
		"oversize":                          {raw([]byte(`{"id":"`+strings.Repeat("a", MaxKeyStatementPayload)+`"}`), f.oldPriv), Keys{f.oldPub}, ErrKeyStatementMalformed},
		"a signature that is not base64":    {SignedKeyStatement{Payload: signed(good).Payload, Signature: "!!"}, Keys{f.oldPub}, ErrKeyStatementSignature},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyHandover(tc.keys, tc.s, "dev-1", f.install, f.now); !errors.Is(err, tc.want) {
				t.Errorf("error %v, want %v", err, tc.want)
			}
		})
	}
	// The statement does not verify as a cut-over: another context.
	if _, err := VerifyCutover(Keys{f.oldPub, f.newPub}, signed(good), "dev-1", f.install, f.now); !errors.Is(err, ErrKeyStatementSignature) {
		t.Errorf("a hand-over read as a cut-over: %v", err)
	}
}

func stmtJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestCutoverIsSignedByTheKeyThatStays(t *testing.T) {
	f := newStmtFixture(t)
	p := f.payload()
	s, err := SignCutover(f.newPriv, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCutover(Keys{f.oldPub, f.newPub}, s, "dev-1", f.install, f.now); err != nil {
		t.Fatal(err)
	}
	// Signed by the old key but naming the new one: refused at signing and at verifying.
	if _, err := SignCutover(f.oldPriv, p); !errors.Is(err, ErrKeyStatementMalformed) {
		t.Errorf("a cut-over signed with another key than it names: %v", err)
	}
	forged := SignedKeyStatement{Payload: s.Payload, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(f.oldPriv, append([]byte(cutoverSigContext), stmtJSON(p)...)))}
	if _, err := VerifyCutover(Keys{f.oldPub, f.newPub}, forged, "dev-1", f.install, f.now); !errors.Is(err, ErrKeyStatementSignature) {
		t.Errorf("a cut-over by the key that goes: %v", err)
	}
	// Naming a key the agent does not trust.
	if _, err := VerifyCutover(Keys{f.oldPub}, s, "dev-1", f.install, f.now); !errors.Is(err, ErrKeyStatementSignature) {
		t.Errorf("a cut-over to an untrusted key: %v", err)
	}
	// Another device, another install, a hand-over's signature.
	if _, err := VerifyCutover(Keys{f.newPub}, s, "dev-2", f.install, f.now); !errors.Is(err, ErrKeyStatementDevice) {
		t.Errorf("another device: %v", err)
	}
	if _, err := VerifyCutover(Keys{f.newPub}, s, "dev-1", strings.Repeat("1", 64), f.now); !errors.Is(err, ErrKeyStatementInstall) {
		t.Errorf("another install: %v", err)
	}
	if _, err := VerifyCutover(Keys{f.newPub}, s, "dev-1", f.install, f.now.Add(KeyStatementValid)); !errors.Is(err, ErrKeyStatementExpired) {
		t.Errorf("expired: %v", err)
	}
	handover, _ := SignHandover(f.newPriv, p)
	if _, err := VerifyCutover(Keys{f.newPub}, handover, "dev-1", f.install, f.now); !errors.Is(err, ErrKeyStatementSignature) {
		t.Errorf("a hand-over read as a cut-over: %v", err)
	}
	if _, err := VerifyCutover(Keys{f.newPub}, SignedKeyStatement{Payload: strings.Repeat("A", MaxKeyStatementPayload+4)}, "dev-1", f.install, f.now); !errors.Is(err, ErrKeyStatementMalformed) {
		t.Errorf("oversize: %v", err)
	}
}

func TestEveryVerifierAcceptsEitherOfTwoKeys(t *testing.T) {
	a, aPriv := newKeyPair(t)
	b, bPriv := newKeyPair(t)
	other, _ := newKeyPair(t)
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	for name, priv := range map[string]ed25519.PrivateKey{"first": aPriv, "second": bPriv} {
		u, err := SignUninstall(priv, UninstallPayload{V: UninstallPayloadVersion, ID: "u", DeviceID: "dev-1", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyUninstall(Keys{a, b}, u, "dev-1", now); err != nil {
			t.Errorf("%s key: %v", name, err)
		}
		if _, err := VerifyUninstall(Keys{other}, u, "dev-1", now); !errors.Is(err, ErrUninstallSignature) {
			t.Errorf("%s key, an unrelated set: %v", name, err)
		}
		sum := [32]byte{1}
		sig := SignDownload(priv, Auth{Device: "dev-1", Nonce: "n"}, "/t", sum)
		if err := VerifyDownload(Keys{a, b}, sig, "dev-1", "/t", "n", sum); err != nil {
			t.Errorf("%s key download: %v", name, err)
		}
		if err := VerifyDownload(Keys{other, a}, sig, "dev-1", "/t", "n", sum); (name == "second") != (err != nil) {
			t.Errorf("%s key download against {other, first}: %v", name, err)
		}
	}
}

func TestFingerprintAndInstall(t *testing.T) {
	pub, _ := newKeyPair(t)
	fp := Fingerprint(pub)
	if len(fp) != 32 || fp != strings.ToLower(fp) {
		t.Fatalf("fingerprint %q", fp)
	}
	if g := FormatFingerprint(fp); len(g) != 32+7 || strings.Count(g, " ") != 7 {
		t.Errorf("grouped %q", g)
	}
	if len(InstallID(pub)) != 64 || InstallID(pub) == fp {
		t.Error("install id")
	}
	if (LoggedInstruction{Seq: 1, Kind: "job", ID: "r", Signer: fp, At: time.Now()}).Valid() != true ||
		(LoggedInstruction{Seq: 0, Kind: "job", ID: "r", Signer: fp, At: time.Now()}).Valid() ||
		(LoggedInstruction{Seq: 1, Kind: "job", ID: "r", Signer: "short", At: time.Now()}).Valid() {
		t.Error("log entry validity")
	}
}
