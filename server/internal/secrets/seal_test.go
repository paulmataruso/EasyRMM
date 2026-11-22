package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func newKey(t *testing.T, id string) Key {
	t.Helper()
	raw := make([]byte, KeySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return Key{ID: id, Raw: raw}
}

func TestSealOpenRoundTrip(t *testing.T) {
	s, err := NewSealer(newKey(t, "k1"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal([]byte("JBSWY3DPEHPK3PXP"), []byte("user-totp:42"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "v1.k1.") {
		t.Fatalf("unexpected prefix: %s", sealed)
	}
	if strings.Contains(sealed, "JBSWY3DPEHPK3PXP") {
		t.Fatal("sealed value leaks plaintext")
	}
	got, err := s.Open(sealed, []byte("user-totp:42"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	s, _ := NewSealer(newKey(t, "k1"))
	a, _ := s.Seal([]byte("same"), nil)
	b, _ := s.Seal([]byte("same"), nil)
	if a == b {
		t.Fatal("two seals of the same plaintext must differ")
	}
}

func TestOpenRejectsWrongAssociatedData(t *testing.T) {
	s, _ := NewSealer(newKey(t, "k1"))
	sealed, _ := s.Seal([]byte("secret"), []byte("user-totp:1"))
	if _, err := s.Open(sealed, []byte("user-totp:2")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt for moved ciphertext, got %v", err)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	s, _ := NewSealer(newKey(t, "k1"))
	sealed, _ := s.Seal([]byte("secret"), nil)
	parts := strings.SplitN(sealed, ".", 3)
	raw, _ := base64.RawURLEncoding.DecodeString(parts[2])
	raw[len(raw)-1] ^= 0x01
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := s.Open(tampered, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestOpenRejectsMalformed(t *testing.T) {
	s, _ := NewSealer(newKey(t, "k1"))
	for _, in := range []string{"", "plain", "v2.k1.AAAA", "v1.k1.!!!", "v1.k1.AAAA"} {
		if _, err := s.Open(in, nil); !errors.Is(err, ErrMalformed) {
			t.Errorf("Open(%q): want ErrMalformed, got %v", in, err)
		}
	}
	if _, err := s.Open("v1.zz.AAAA", nil); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("want ErrUnknownKey, got %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	oldKey, newK := newKey(t, "old"), newKey(t, "new")
	before, _ := NewSealer(oldKey)
	sealed, _ := before.Seal([]byte("rotate me"), nil)

	after, err := NewSealer(newK, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if !after.NeedsReseal(sealed) {
		t.Fatal("value sealed with the old key should need resealing")
	}
	got, err := after.Open(sealed, nil)
	if err != nil || !bytes.Equal(got, []byte("rotate me")) {
		t.Fatalf("old value must stay readable: %v", err)
	}
	resealed, _ := after.Seal(got, nil)
	if after.NeedsReseal(resealed) {
		t.Fatal("freshly sealed value should not need resealing")
	}
}

func TestNewSealerValidation(t *testing.T) {
	if _, err := NewSealer(); err == nil {
		t.Error("empty key ring accepted")
	}
	if _, err := NewSealer(Key{ID: "k1", Raw: make([]byte, 16)}); err == nil {
		t.Error("short key accepted")
	}
	if _, err := NewSealer(Key{ID: "Bad.ID", Raw: make([]byte, KeySize)}); err == nil {
		t.Error("invalid key id accepted")
	}
	k := newKey(t, "k1")
	if _, err := NewSealer(k, k); err == nil {
		t.Error("duplicate key id accepted")
	}
}

func TestParseKey(t *testing.T) {
	raw := make([]byte, KeySize)
	for i := range raw {
		raw[i] = byte(i)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
		k, err := ParseKey("k1", enc.EncodeToString(raw)+"\n")
		if err != nil || !bytes.Equal(k.Raw, raw) {
			t.Fatalf("ParseKey failed: %v", err)
		}
	}
	if _, err := ParseKey("k1", base64.StdEncoding.EncodeToString(raw[:20])); err == nil {
		t.Error("short key accepted")
	}
	if _, err := ParseKey("k1", "not base64 at all ***"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestDeriveKeys(t *testing.T) {
	k1 := Key{ID: "k1", Raw: bytes.Repeat([]byte{1}, KeySize)}
	k2 := Key{ID: "k2", Raw: bytes.Repeat([]byte{2}, KeySize)}
	a, _ := NewSealer(k1, k2)
	again, _ := NewSealer(k1)
	rotated, _ := NewSealer(k2, k1)
	keys := func(s *Sealer, info string) []Key {
		t.Helper()
		ks, err := s.DeriveKeys(info)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range ks {
			if len(k.Raw) != KeySize {
				t.Fatalf("%x", k.Raw)
			}
		}
		return ks
	}
	x := keys(a, "easyrmm one use v1")
	if len(x) != 2 || x[0].ID != "k1" || x[1].ID != "k2" {
		t.Fatalf("keys %v", x)
	}
	r := keys(rotated, "easyrmm one use v1")
	switch {
	case !bytes.Equal(x[0].Raw, keys(again, "easyrmm one use v1")[0].Raw):
		t.Fatal("the same key and info derive another key")
	case bytes.Equal(x[0].Raw, keys(a, "easyrmm another use v1")[0].Raw):
		t.Fatal("another use derives the same key")
	case bytes.Equal(x[0].Raw, x[1].Raw):
		t.Fatal("two keys derive the same key")
	case r[0].ID != "k2" || !bytes.Equal(r[0].Raw, x[1].Raw) || !bytes.Equal(r[1].Raw, x[0].Raw):
		// After a rotation, the key derived from the old primary is still
		// there, under its ID.
		t.Fatal("a rotation changes what a key derives")
	case bytes.Equal(x[0].Raw, k1.Raw):
		t.Fatal("the derived key is the key")
	}
}
