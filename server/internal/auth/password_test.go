package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fastParams keep unit tests quick while exercising the same code paths.
var fastParams = Argon2Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}

func TestHashAndVerify(t *testing.T) {
	h := NewHasher(fastParams, 2)
	ctx := context.Background()
	enc, err := h.Hash(ctx, "a long passphrase here")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("unexpected encoding %s", enc)
	}
	ok, rehash, err := h.Verify(ctx, "a long passphrase here", enc)
	if err != nil || !ok || rehash {
		t.Fatalf("verify correct password: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	ok, _, err = h.Verify(ctx, "a long passphrase herE", enc)
	if err != nil || ok {
		t.Fatalf("wrong password accepted: ok=%v err=%v", ok, err)
	}
}

func TestHashesAreSalted(t *testing.T) {
	h := NewHasher(fastParams, 1)
	a, _ := h.Hash(context.Background(), "same password value")
	b, _ := h.Hash(context.Background(), "same password value")
	if a == b {
		t.Fatal("hashes of the same password must differ")
	}
}

func TestVerifyFlagsWeakParameters(t *testing.T) {
	weak := NewHasher(fastParams, 1)
	enc, _ := weak.Hash(context.Background(), "upgrade my hash please")
	strong := NewHasher(Argon2Params{MemoryKiB: 16 * 1024, Iterations: 2, Parallelism: 1, SaltLen: 16, KeyLen: 32}, 1)
	ok, rehash, err := strong.Verify(context.Background(), "upgrade my hash please", enc)
	if err != nil || !ok || !rehash {
		t.Fatalf("want ok and rehash, got ok=%v rehash=%v err=%v", ok, rehash, err)
	}
}

func TestVerifyRejectsMalformedAndHostileHashes(t *testing.T) {
	h := NewHasher(fastParams, 1)
	cases := []string{
		"",
		"plaintext",
		"$2a$10$abcdefghijklmnopqrstuv", // bcrypt
		"$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", // wrong variant
		"$argon2id$v=16$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", // memory bomb
		"$argon2id$v=19$m=8192,t=999,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",   // cpu bomb
		"$argon2id$v=19$m=8192,t=1,p=1,x=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=8192,t=1,p=1$***$aGFzaGhhc2hoYXNoaGFzaA",
	}
	for _, c := range cases {
		if ok, _, err := h.Verify(context.Background(), "whatever", c); err == nil || ok {
			t.Errorf("Verify(%q) = ok %v, err %v; want error", c, ok, err)
		}
	}
}

func TestHasherHonoursContextWhenSaturated(t *testing.T) {
	h := NewHasher(fastParams, 1)
	h.sem <- struct{}{} // occupy the only slot
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Hash(ctx, "a long passphrase here"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	<-h.sem
}

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		pw      string
		context []string
		wantErr bool
	}{
		{"short", nil, true},
		{strings.Repeat("x", MaxPasswordLength+1), nil, true},
		{"Password1234", nil, true}, // block list, case-insensitive
		{"aaaaabbbbbbb", nil, true}, // too few distinct characters
		{"jane.doe-is-great", []string{"Jane.Doe"}, true},
		{"orbit-violet-canyon-42", []string{"jane@example.com"}, false},
		{"Ünïcödé pässphrase", nil, false},
	}
	for _, c := range cases {
		err := ValidatePassword(c.pw, c.context...)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidatePassword(%q) err=%v, wantErr=%v", c.pw, err, c.wantErr)
		}
	}
}
