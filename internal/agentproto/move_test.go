package agentproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestAddressConfirmationBindsDeviceNonceAndAddress(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	a := Auth{Device: "dev-1", Nonce: "nonce-1"}
	ans := SignAddress(priv, a, "https://rmm.example.com")

	if err := VerifyAddress(pub, ans, "dev-1", "nonce-1", "https://rmm.example.com"); err != nil {
		t.Fatalf("a good confirmation: %v", err)
	}
	if err := VerifyAddress(Keys{other, pub}, ans, "dev-1", "nonce-1", "https://rmm.example.com"); err != nil {
		t.Fatalf("a key in a set: %v", err)
	}
	for name, c := range map[string]struct {
		key           Keys
		ans           AddressAnswer
		device, nonce string
		address       string
		want          error
	}{
		"another device":  {Keys{pub}, ans, "dev-2", "nonce-1", "https://rmm.example.com", ErrAddressSignature},
		"another nonce":   {Keys{pub}, ans, "dev-1", "nonce-2", "https://rmm.example.com", ErrAddressSignature},
		"another address": {Keys{pub}, ans, "dev-1", "nonce-1", "https://other.example.com", ErrAddressMismatch},
		"untrusted key":   {Keys{other}, ans, "dev-1", "nonce-1", "https://rmm.example.com", ErrAddressSignature},
		"no keys":         {nil, ans, "dev-1", "nonce-1", "https://rmm.example.com", ErrAddressSignature},
		"unsigned":        {Keys{pub}, AddressAnswer{Address: "https://rmm.example.com"}, "dev-1", "nonce-1", "https://rmm.example.com", ErrAddressUnsigned},
		"not base64":      {Keys{pub}, AddressAnswer{Address: "https://rmm.example.com", Signature: "!!"}, "dev-1", "nonce-1", "https://rmm.example.com", ErrAddressSignature},
	} {
		if err := VerifyAddress(c.key, c.ans, c.device, c.nonce, c.address); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	// A signature over the address does not pass as a download's or another
	// instruction's, whose contexts differ.
	if err := VerifyAddress(pub, AddressAnswer{Address: "x", Signature: SignAddress(priv, a, "y").Signature}, "dev-1", "nonce-1", "x"); err == nil {
		t.Error("a signature for one address verified for another")
	}
}

func TestMoveTargetIsAnHTTPSOriginOnly(t *testing.T) {
	for in, want := range map[string]string{
		"https://rmm.example.com":      "https://rmm.example.com",
		" https://RMM.example.com/ ":   "https://rmm.example.com",
		"https://192.0.2.10":           "https://192.0.2.10",
		"https://rmm.example.com:8443": "https://rmm.example.com:8443",
		"https://[2001:db8::1]":        "https://[2001:db8::1]",
	} {
		got, err := MoveTarget(in)
		if err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "rmm.example.com", "http://rmm.example.com", "http://127.0.0.1", "http://localhost",
		"https://", "https://u:p@rmm.example.com", "https://rmm.example.com/path", "https://rmm.example.com?x=1",
		"https://rmm.example.com#f", "ftp://rmm.example.com", "https:rmm.example.com", "%zz",
	} {
		if got, err := MoveTarget(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestValidMoveKind(t *testing.T) {
	for _, k := range []string{MoveSetServer, MoveInstall, MoveFallback} {
		if !ValidMoveKind(k) {
			t.Errorf("%q refused", k)
		}
	}
	for _, k := range []string{"", "move", "SET-SERVER"} {
		if ValidMoveKind(k) {
			t.Errorf("%q accepted", k)
		}
	}
}
