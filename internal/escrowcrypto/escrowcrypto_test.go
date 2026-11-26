package escrowcrypto

import (
	"bytes"
	"encoding/hex"
	"errors"
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
