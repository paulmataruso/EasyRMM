package keystored

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func fixedKEK() []byte {
	k := make([]byte, KEKSize)
	for i := range k {
		k[i] = byte(0xA0 + i)
	}
	return k
}

// Known answers: pinned values that a change of algorithm, label or
// parameter would break.
func TestKnownAnswers(t *testing.T) {
	if got := hex.EncodeToString(checkValue(fixedKEK())); got != knownKCV {
		t.Errorf("key check value = %s, want %s", got, knownKCV)
	}
	// Argon2id with the pinned parameters (64 MiB, 3 passes, 4 lanes).
	got := hex.EncodeToString(derive([]byte("correct horse battery"), []byte("0123456789abcdef")))
	if got != knownArgon {
		t.Errorf("argon2id = %s, want %s", got, knownArgon)
	}
	if got := string(wrapAAD("org", "key", "escrow")); got != "keystore-wrap-v1|org|key|escrow" {
		t.Errorf("aad = %s", got)
	}
	// A stored value from this format must keep opening.
	v, sealed, err := parseWrapped(knownWrapped)
	if err != nil || v != 3 {
		t.Fatalf("parse: %d %v", v, err)
	}
	pt, err := unwrap(fixedKEK(), sealed, wrapAAD("org", "key", "escrow"))
	if err != nil || string(pt) != "the wrapped secret" {
		t.Fatalf("known wrapped value: %q %v", pt, err)
	}
}

func TestWrapRoundTripAndWrongAAD(t *testing.T) {
	kek := fixedKEK()
	w, err := wrap(kek, 2, wrapAAD("o", "k", "escrow"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(w, "ks1.2.") {
		t.Fatalf("format: %s", w)
	}
	v, sealed, _ := parseWrapped(w)
	if v != 2 {
		t.Fatal("version lost")
	}
	if pt, err := unwrap(kek, sealed, wrapAAD("o", "k", "escrow")); err != nil || string(pt) != "secret" {
		t.Fatalf("round trip: %q %v", pt, err)
	}
	for name, aad := range map[string][]byte{
		"org":     wrapAAD("x", "k", "escrow"),
		"key":     wrapAAD("o", "x", "escrow"),
		"purpose": wrapAAD("o", "k", "service"),
	} {
		if _, err := unwrap(kek, sealed, aad); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: %v, want ErrDecrypt", name, err)
		}
	}
	other := bytes.Clone(kek)
	other[0] ^= 1
	if _, err := unwrap(other, sealed, wrapAAD("o", "k", "escrow")); !errors.Is(err, ErrDecrypt) {
		t.Errorf("other key: %v", err)
	}
	bad := bytes.Clone(sealed)
	bad[len(bad)-1] ^= 1
	if _, err := unwrap(kek, bad, wrapAAD("o", "k", "escrow")); !errors.Is(err, ErrDecrypt) {
		t.Errorf("tampered: %v", err)
	}
	for _, s := range []string{"", "v1.k1.AAAA", "ks1.0.AAAA", "ks1.x.AAAA", "ks1.1", "ks1.1.***"} {
		if _, _, err := parseWrapped(s); !errors.Is(err, ErrFormat) {
			t.Errorf("%q parsed", s)
		}
	}
}

func TestRecoveryCode(t *testing.T) {
	code, err := NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 32+7 || strings.Count(string(code), "-") != 7 {
		t.Fatalf("shape: %s", code)
	}
	raw, err := normalizeCode(code)
	if err != nil || len(raw) != RecoveryCodeBytes {
		t.Fatalf("normalize: %v", err)
	}
	// Lower case, spaces and look-alikes read the same.
	loose := strings.NewReplacer("-", " ", "0", "o", "1", "l").Replace(strings.ToLower(string(code)))
	raw2, err := normalizeCode([]byte(loose))
	if err != nil || !bytes.Equal(raw, raw2) {
		t.Fatalf("loose: %v", err)
	}
	for _, bad := range []string{"", "ABCD", strings.Repeat("U", 32), string(code) + "A"} {
		if _, err := normalizeCode([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	other, _ := NewRecoveryCode()
	if bytes.Equal(code, other) {
		t.Fatal("two codes equal")
	}
}

func TestSecretMemory(t *testing.T) {
	s, err := NewSecret([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Skipf("locked memory is not available here: %v", err)
	}
	if string(s.Bytes()) != "0123456789abcdef0123456789abcdef" {
		t.Fatal("contents lost")
	}
	s.Destroy()
	if s.Bytes() != nil {
		t.Fatal("not destroyed")
	}
	s.Destroy() // twice is fine
}
