// Package webauthntest is a software security key for tests (ADR-0032). It
// answers WebAuthn options the way a browser and authenticator would:
// credentials in the JSON form of PublicKeyCredential.toJSON(), "none"
// attestation, ES256 keys. Fields can be changed between calls to play a
// misbehaving client: another origin, a counter that goes backwards, no user
// verification.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// Authenticator is one software security key holding one credential.
type Authenticator struct {
	// RPID and Origin are what the browser would use for the page.
	RPID   string
	Origin string
	// UV: the authenticator verifies the user (PIN or biometric).
	UV bool
	// Synced keys are backup eligible (and backed up).
	Synced bool
	// Discoverable credentials return their user handle when used.
	Discoverable bool
	// Counter is the signature counter; it goes up by one per use unless
	// Stuck.
	Counter uint32
	Stuck   bool
	// Type overrides the client data type, to play a confused client.
	Type string

	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
}

// New makes a key for a page at origin, whose relying party is rpID.
func New(t testing.TB, rpID, origin string) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &Authenticator{RPID: rpID, Origin: origin, UV: true, Discoverable: true, key: key, credID: id}
}

// CredentialID is the credential's id.
func (a *Authenticator) CredentialID() []byte { return a.credID }

var b64 = base64.RawURLEncoding

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		UserVerification string `json:"userVerification"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

// Create answers navigator.credentials.create() for options (the server's
// JSON) and returns the new credential. It refuses, as a browser would, when
// the credential is excluded.
func (a *Authenticator) Create(t testing.TB, options []byte) []byte {
	t.Helper()
	var o creationOptions
	if err := json.Unmarshal(options, &o); err != nil {
		t.Fatalf("webauthntest: creation options: %v", err)
	}
	for _, ex := range o.PublicKey.ExcludeCredentials {
		if ex.ID == b64.EncodeToString(a.credID) {
			t.Fatal("webauthntest: the credential is excluded (already registered)")
		}
	}
	handle, err := b64.DecodeString(o.PublicKey.User.ID)
	if err != nil {
		t.Fatalf("webauthntest: user id: %v", err)
	}
	a.userHandle = handle
	client := a.clientData("webauthn.create", o.PublicKey.Challenge)

	ek, err := a.key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	point := ek.Bytes() // 0x04 || x || y
	x, y := point[1:33], point[33:65]
	cose := cborMap([]kv{{intKey(1), cborInt(2)}, {intKey(3), cborInt(-7)}, {intKey(-1), cborInt(1)}, {intKey(-2), cborBytes(x)}, {intKey(-3), cborBytes(y)}})

	auth := a.authData(0x40) // attested credential data
	auth = append(auth, make([]byte, 16)...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(a.credID))) //nolint:gosec // 32 bytes
	auth = append(auth, a.credID...)
	auth = append(auth, cose...)
	att := cborMap([]kv{{textKey("fmt"), cborText("none")}, {textKey("attStmt"), cborMap(nil)}, {textKey("authData"), cborBytes(auth)}})

	return mustJSON(t, map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"authenticatorAttachment": "cross-platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(client), "attestationObject": b64.EncodeToString(att), "transports": []string{"usb"}},
	})
}

// Get answers navigator.credentials.get() for options. Like a browser, it
// fails when its credential is not among those allowed.
func (a *Authenticator) Get(t testing.TB, options []byte) []byte {
	t.Helper()
	var o requestOptions
	if err := json.Unmarshal(options, &o); err != nil {
		t.Fatalf("webauthntest: request options: %v", err)
	}
	if len(o.PublicKey.AllowCredentials) > 0 {
		allowed := false
		for _, c := range o.PublicKey.AllowCredentials {
			allowed = allowed || c.ID == b64.EncodeToString(a.credID)
		}
		if !allowed {
			t.Fatal("webauthntest: this credential is not allowed")
		}
	}
	client := a.clientData("webauthn.get", o.PublicKey.Challenge)
	auth := a.authData(0)
	sum := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, auth...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	response := map[string]any{"clientDataJSON": b64.EncodeToString(client), "authenticatorData": b64.EncodeToString(auth), "signature": b64.EncodeToString(sig)}
	if a.Discoverable && a.userHandle != nil {
		response["userHandle"] = b64.EncodeToString(a.userHandle)
	}
	return mustJSON(t, map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"authenticatorAttachment": "cross-platform", "clientExtensionResults": map[string]any{}, "response": response,
	})
}

// SetUserHandle sets the user handle a discoverable credential returns,
// to play a credential claiming to be someone else's.
func (a *Authenticator) SetUserHandle(h []byte) { a.userHandle = h }

func (a *Authenticator) clientData(kind, challenge string) []byte {
	if a.Type != "" {
		kind = a.Type
	}
	b, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

func (a *Authenticator) authData(extra byte) []byte {
	rp := sha256.Sum256([]byte(a.RPID))
	flags := byte(0x01) | extra // user present
	if a.UV {
		flags |= 0x04
	}
	if a.Synced {
		flags |= 0x08 | 0x10
	}
	if !a.Stuck {
		a.Counter++
	}
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	return binary.BigEndian.AppendUint32(out, a.Counter)
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A little CBOR (RFC 8949): only what attestation objects and COSE keys
// need.

type kv struct{ k, v []byte }

func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	default:
		// Lengths here are a few hundred bytes at most.
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n)) //nolint:gosec // see above
	}
}

func cborInt(n int64) []byte {
	if n >= 0 {
		return head(0, uint64(n))
	}
	return head(1, uint64(-1-n))
}

func cborBytes(b []byte) []byte { return append(head(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(head(3, uint64(len(s))), s...) }
func intKey(n int64) []byte     { return cborInt(n) }
func textKey(s string) []byte   { return cborText(s) }

func cborMap(entries []kv) []byte {
	out := head(5, uint64(len(entries)))
	for _, e := range entries {
		out = append(out, e.k...)
		out = append(out, e.v...)
	}
	return out
}
