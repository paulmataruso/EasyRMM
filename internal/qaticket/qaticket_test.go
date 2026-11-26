package qaticket

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func file(t *testing.T, key ed25519.PrivateKey, tk Ticket) []byte {
	t.Helper()
	tr, err := Sign(key, tk)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte("MZ fake exe bytes"), tr...)
}

func TestRoundTripAndRefusals(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_000_000, 0)
	tk := Ticket{Link: "l1", Server: "https://rmm.example", Expiry: now.Add(Lifetime).Unix()}
	f := file(t, key, tk)
	parse := func(b []byte, p ed25519.PublicKey, at time.Time) (Ticket, error) {
		return Parse(bytes.NewReader(b), int64(len(b)), p, at)
	}
	got, err := parse(f, pub, now)
	if err != nil || got.Link != tk.Link || got.Server != tk.Server || got.Expiry != tk.Expiry {
		t.Fatalf("good ticket: %v %v", got, err)
	}
	// The runner has no key of its own: it checks against the ticket's.
	if _, err := parse(f, nil, now); err != nil {
		t.Fatalf("self-checked: %v", err)
	}
	if _, err := parse(f, nil, now.Add(Lifetime)); !errors.Is(err, ErrExpired) {
		t.Fatalf("self-checked expiry: %v", err)
	}
	cases := map[string]struct {
		b    []byte
		pub  ed25519.PublicKey
		at   time.Time
		want error
	}{
		"expired":      {f, pub, now.Add(Lifetime), ErrExpired},
		"other key":    {f, otherPub, now, ErrBad},
		"no trailer":   {[]byte("just an exe"), pub, now, ErrNoTrailer},
		"empty":        {nil, pub, now, ErrNoTrailer},
		"truncated":    {f[:len(f)-3], pub, now, ErrNoTrailer},
		"short key":    {f, pub[:5], now, ErrBad},
		"oversize len": {append(bytes.Repeat([]byte{1}, 10), append([]byte{0x7f, 0xff, 0xff, 0xff}, []byte(magic)...)...), pub, now, ErrBad},
	}
	for name, c := range cases {
		if _, err := parse(c.b, c.pub, c.at); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	// A forged field: change the server in the signed body.
	forged := bytes.Replace(f, []byte("rmm.example"), []byte("evl.example"), 1)
	if _, err := parse(forged, pub, now); !errors.Is(err, ErrBad) {
		t.Errorf("forged server: %v", err)
	}
}
