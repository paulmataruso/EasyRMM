package escrowcrypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const secret = "123456-234567-345678-456789-567890-678901-789012-890123"

var ctx = Context{Org: "org1", Device: "dev1", Volume: "vol1", Protector: "prot1", OrgKey: "key1"}

func fixedPriv() []byte {
	p := make([]byte, 32)
	for i := range p {
		p[i] = byte(i + 1)
	}
	return p
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Known answers, pinned so that a change of suite or of the info format
// cannot pass unnoticed: they were produced once and must keep opening.
func TestKnownAnswers(t *testing.T) {
	pub, err := PublicFrom(fixedPriv())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pub); got != "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c" {
		t.Fatalf("public key = %s", got)
	}
	enc := unhex(t, "10d5dc1ac1c15ba18e106e0bb5a11f49896a6c4628f5095802551335b74cec0e")
	ct := unhex(t, "87a7937d6ffb6825b17f635732086f17d6646a76c641ec02ad37b64542575ac0a8ef179156c30a7678fe379172ea290d2ca13088e03d331f234ecee83bc983111eefc5ee5ee7ed")
	pt, err := Open(fixedPriv(), ctx, enc, ct)
	if err != nil || string(pt) != secret {
		t.Fatalf("known record: %q, %v", pt, err)
	}
	fp := Fingerprint("prot1", []byte(secret))
	if got := hex.EncodeToString(fp[:]); got != "4a22c16c2f5621a7023d7a1b9d712ffd" {
		t.Fatalf("fingerprint = %s", got)
	}
	if got := string(ctx.Info()); got != "easyrmm-escrow-v1|org1|dev1|vol1|prot1|key1" {
		t.Fatalf("info = %s", got)
	}
}

func TestRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := Seal(pub, ctx, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != EncSize || bytes.Contains(ct, []byte(secret)) {
		t.Fatal("bad record")
	}
	pt, err := Open(priv, ctx, enc, ct)
	if err != nil || string(pt) != secret {
		t.Fatalf("open: %q, %v", pt, err)
	}
	// Two seals of one secret differ.
	enc2, ct2, _ := Seal(pub, ctx, []byte(secret))
	if bytes.Equal(enc, enc2) || bytes.Equal(ct, ct2) {
		t.Fatal("a seal repeated")
	}
}

// A record copied to another device, volume, protector, organization or key
// does not open, and neither does a damaged one or one under another key.
func TestWrongContextFails(t *testing.T) {
	priv, pub, _ := GenerateKey()
	enc, ct, _ := Seal(pub, ctx, []byte(secret))
	for name, c := range map[string]Context{
		"org":       {"orgX", "dev1", "vol1", "prot1", "key1"},
		"device":    {"org1", "devX", "vol1", "prot1", "key1"},
		"volume":    {"org1", "dev1", "volX", "prot1", "key1"},
		"protector": {"org1", "dev1", "vol1", "protX", "key1"},
		"key":       {"org1", "dev1", "vol1", "prot1", "keyX"},
	} {
		if _, err := Open(priv, c, enc, ct); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v, want ErrDecrypt", name, err)
		}
	}
	bad := bytes.Clone(ct)
	bad[0] ^= 1
	if _, err := Open(priv, ctx, enc, bad); !errors.Is(err, ErrDecrypt) {
		t.Errorf("tampered: %v", err)
	}
	other, _, _ := GenerateKey()
	if _, err := Open(other, ctx, enc, ct); !errors.Is(err, ErrDecrypt) {
		t.Errorf("other key: %v", err)
	}
	if _, err := Open(priv, ctx, enc[:5], ct); !errors.Is(err, ErrDecrypt) {
		t.Errorf("short enc: %v", err)
	}
}

func TestContextAndSecretValidation(t *testing.T) {
	_, pub, _ := GenerateKey()
	if _, _, err := Seal(pub, Context{Org: "a|b", Device: "d", Volume: "v", Protector: "p", OrgKey: "k"}, []byte("x")); err == nil {
		t.Error("a separator in a field was sealed")
	}
	if _, _, err := Seal(pub, ctx, nil); err == nil {
		t.Error("an empty secret was sealed")
	}
	if _, _, err := Seal([]byte{1, 2}, ctx, []byte("x")); !errors.Is(err, ErrKey) {
		t.Errorf("short public key: %v", err)
	}
	if _, err := NormalizeBitLocker(" " + secret + "\n"); err != nil {
		t.Errorf("normalize: %v", err)
	}
	for _, bad := range []string{"", "123456", secret + "-111111", "12345a-234567-345678-456789-567890-678901-789012-890123"} {
		if _, err := NormalizeBitLocker(bad); err == nil {
			t.Errorf("%q passed", bad)
		}
	}
}

func TestFingerprintBindsProtector(t *testing.T) {
	a, b := Fingerprint("p1", []byte(secret)), Fingerprint("p2", []byte(secret))
	if a == b {
		t.Fatal("the protector is not in the fingerprint")
	}
}

func TestKeyDerivationAndRawSeal(t *testing.T) {
	ikm := bytes.Repeat([]byte{7}, 32)
	priv, pub, err := DeriveKey(ikm)
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, _ := DeriveKey(ikm)
	if !bytes.Equal(priv, priv2) || !bytes.Equal(pub, pub2) {
		t.Fatal("the same input material made different keys")
	}
	if p, err := PublicFrom(priv); err != nil || !bytes.Equal(p, pub) {
		t.Fatalf("PublicFrom: %v", err)
	}
	if _, _, err := DeriveKey([]byte("short")); !errors.Is(err, ErrKey) {
		t.Errorf("short input material: %v", err)
	}
	if _, err := PublicFrom([]byte{1}); !errors.Is(err, ErrKey) {
		t.Errorf("short private key: %v", err)
	}
	info := []byte("test|info")
	enc, ct, err := SealRaw(pub, info, []byte("a kek"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := OpenRaw(priv, info, enc, ct); err != nil || string(pt) != "a kek" {
		t.Fatalf("raw round trip: %q %v", pt, err)
	}
	if _, err := OpenRaw(priv, []byte("other"), enc, ct); !errors.Is(err, ErrDecrypt) {
		t.Errorf("another info: %v", err)
	}
	if _, err := OpenRaw([]byte{1}, info, enc, ct); !errors.Is(err, ErrKey) {
		t.Errorf("a short private key: %v", err)
	}
	if _, err := OpenRaw(priv, info, enc, make([]byte, maxRaw+17)); !errors.Is(err, ErrDecrypt) {
		t.Errorf("an oversized ciphertext: %v", err)
	}
	for _, bad := range [][]byte{nil, make([]byte, maxRaw+1)} {
		if _, _, err := SealRaw(pub, info, bad); !errors.Is(err, ErrSecret) {
			t.Errorf("%d bytes: %v", len(bad), err)
		}
	}
	if _, _, err := SealRaw([]byte{1}, info, []byte("x")); !errors.Is(err, ErrKey) {
		t.Errorf("a short public key: %v", err)
	}
	if _, err := Open(priv, Context{Org: "a|b"}, enc, ct); !errors.Is(err, ErrDecrypt) {
		t.Errorf("an invalid context: %v", err)
	}
	if _, err := Open(priv, ctx, enc, make([]byte, MaxSecret+17)); !errors.Is(err, ErrDecrypt) {
		t.Errorf("an oversized record: %v", err)
	}
	if _, _, err := Seal(pub, ctx, make([]byte, MaxSecret+1)); !errors.Is(err, ErrSecret) {
		t.Errorf("an oversized secret: %v", err)
	}
	if b, err := NormalizeBitLockerBytes([]byte(" " + secret + "\n")); err != nil || string(b) != secret {
		t.Errorf("NormalizeBitLockerBytes: %q %v", b, err)
	}
	if _, err := NormalizeBitLockerBytes([]byte("no")); err == nil {
		t.Error("a bad password passed")
	}
	x := []byte{1, 2, 3}
	Zero(x)
	if !bytes.Equal(x, []byte{0, 0, 0}) {
		t.Error("Zero left bytes")
	}
}

func TestLUKSPassphrase(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		p, err := NewLUKSPassphrase()
		if err != nil || len(p) != LUKSPassphraseLen {
			t.Fatalf("passphrase: %v len %d", err, len(p))
		}
		norm, err := NormalizeLUKSBytes(p)
		if err != nil || string(norm) != string(p) {
			t.Fatalf("a passphrase it made does not normalize: %v", err)
		}
		if seen[string(p)] {
			t.Fatal("a passphrase repeated")
		}
		seen[string(p)] = true
	}
	for _, bad := range []string{"", "short", strings.Repeat("a", 41), strings.Repeat("A", 40), strings.Repeat("1", 40), strings.Repeat("a", 39) + "-"} {
		if _, err := NormalizeLUKSBytes([]byte(bad)); err == nil {
			t.Errorf("%q normalized", bad)
		}
	}
	if _, err := NormalizeBytes("luks", []byte(strings.Repeat("a", 40))); err != nil {
		t.Error(err)
	}
	if _, err := NormalizeBytes("bitlocker", []byte(strings.Repeat("a", 40))); err == nil {
		t.Error("a LUKS passphrase passed as BitLocker")
	}
	if _, err := NormalizeBytes("other", []byte("x")); err == nil {
		t.Error("an unknown kind normalized")
	}
}
