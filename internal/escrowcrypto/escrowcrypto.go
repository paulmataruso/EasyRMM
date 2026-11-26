// Package escrowcrypto is the cryptography of a recovery-key escrow record
// (ADR-0081): HPKE (RFC 9180) base mode with DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256 and AES-256-GCM, from the standard library's crypto/hpke. The
// agent seals with it, and the keystore opens with it; the server does
// neither.
//
// A record's HPKE "info" names the organization, device, volume, protector
// and organization key, so a record copied to another device, volume,
// protector or organization fails to open. The wire names (easyrmm-escrow-v1,
// easyrmm-fp-v1) carry the version, so a later suite is a new name.
package escrowcrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"regexp"
	"strings"
)

// Sizes of what the suite produces.
const (
	// EncSize is the length of the HPKE encapsulated key (X25519).
	EncSize = 32
	// FingerprintSize is the length of a fingerprint in bytes.
	FingerprintSize = 16
	// MaxSecret bounds a secret this package seals: a BitLocker password is
	// 55 characters; a LUKS passphrase is 40.
	MaxSecret = 256
)

// Domain separation labels.
const (
	infoLabel        = "easyrmm-escrow-v1"
	fingerprintLabel = "easyrmm-fp-v1"
)

// Errors.
var (
	// ErrDecrypt is every failure to open a record: a wrong key, a wrong
	// context and a damaged record look the same.
	ErrDecrypt = errors.New("escrowcrypto: the record does not open")
	// ErrKey is a key of the wrong shape.
	ErrKey = errors.New("escrowcrypto: the key is not a valid X25519 HPKE key")
	// ErrSecret is a secret that is empty, too long or malformed.
	ErrSecret = errors.New("escrowcrypto: the secret is not valid")
)

// Context names what a record belongs to; every field is bound into the
// record's HPKE info.
type Context struct {
	Org, Device, Volume, Protector, OrgKey string
}

// Info is the HPKE info of a record: easyrmm-escrow-v1|org|device|volume|
// protector|org key id. A field that holds the separator is refused by
// Valid, so two contexts never share an info string.
func (c Context) Info() []byte {
	return []byte(strings.Join([]string{infoLabel, c.Org, c.Device, c.Volume, c.Protector, c.OrgKey}, "|"))
}

// Valid reports whether every field is set and free of the separator.
func (c Context) Valid() bool {
	for _, f := range []string{c.Org, c.Device, c.Volume, c.Protector, c.OrgKey} {
		if f == "" || len(f) > 128 || strings.ContainsAny(f, "|\x00\r\n") {
			return false
		}
	}
	return true
}

var bitlockerPassword = regexp.MustCompile(`^[0-9]{6}(-[0-9]{6}){7}$`)

// NormalizeBitLocker returns a BitLocker numerical password without the
// spaces around it, or ErrSecret when it is not eight groups of six digits.
func NormalizeBitLocker(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !bitlockerPassword.MatchString(s) {
		return "", ErrSecret
	}
	return s, nil
}

// NormalizeBitLockerBytes is NormalizeBitLocker for a secret held in a byte
// slice that the caller zeroes: it returns a subslice of b, copying nothing.
func NormalizeBitLockerBytes(b []byte) ([]byte, error) {
	b = bytes.TrimSpace(b)
	if !bitlockerPassword.Match(b) {
		return nil, ErrSecret
	}
	return b, nil
}

// Kinds of secret this package normalizes.
const (
	KindBitLocker = "bitlocker"
	KindLUKS      = "luks"
)

// LUKSAlphabet is the 32-letter alphabet of an escrowed LUKS passphrase (RFC
// 4648 base32, lowercase): five bits a letter.
const LUKSAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// LUKSPassphraseLen is the length of an escrowed LUKS passphrase: forty letters
// of five bits, 200 bits in all.
const LUKSPassphraseLen = 40

// NewLUKSPassphrase makes a passphrase from the system's random source. The
// caller zeroes it.
func NewLUKSPassphrase() ([]byte, error) {
	buf := make([]byte, LUKSPassphraseLen)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	for i, b := range buf {
		buf[i] = LUKSAlphabet[b&31] // 256 is a multiple of 32: no bias
	}
	return buf, nil
}

// NormalizeLUKSBytes checks that b is a passphrase this package makes and
// returns it, copying nothing: the key of a LUKS slot is the passphrase as it is.
func NormalizeLUKSBytes(b []byte) ([]byte, error) {
	b = bytes.TrimSpace(b)
	if len(b) != LUKSPassphraseLen {
		return nil, ErrSecret
	}
	for _, c := range b {
		if strings.IndexByte(LUKSAlphabet, c) < 0 {
			return nil, ErrSecret
		}
	}
	return b, nil
}

// NormalizeBytes normalizes a secret of a kind, in place.
func NormalizeBytes(kind string, b []byte) ([]byte, error) {
	switch kind {
	case KindBitLocker:
		return NormalizeBitLockerBytes(b)
	case KindLUKS:
		return NormalizeLUKSBytes(b)
	}
	return nil, ErrSecret
}

// Fingerprint is the first 16 bytes of SHA-256 over
// easyrmm-fp-v1|protector id|normalized secret. A BitLocker numerical
// password carries 128 bits of entropy and a LUKS passphrase made here 200, so
// this reveals nothing usable.
func Fingerprint(protector string, secret []byte) [FingerprintSize]byte {
	h := sha256.New()
	h.Write([]byte(fingerprintLabel + "|" + protector + "|"))
	h.Write(secret)
	var out [FingerprintSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

func suite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.AES256GCM()
}

// GenerateKey makes an HPKE key pair: the private half as serialized by
// RFC 9180 and the public half. The caller owns, and zeroes, the private
// bytes.
func GenerateKey() (priv, pub []byte, err error) {
	kem, _, _ := suite()
	k, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	if priv, err = k.Bytes(); err != nil {
		return nil, nil, err
	}
	return priv, k.PublicKey().Bytes(), nil
}

// PublicFrom returns the public half of a serialized private key.
func PublicFrom(priv []byte) ([]byte, error) {
	kem, _, _ := suite()
	k, err := kem.NewPrivateKey(priv)
	if err != nil {
		return nil, ErrKey
	}
	return k.PublicKey().Bytes(), nil
}

// DeriveKey makes an HPKE key pair from 32 bytes or more of input key
// material (RFC 9180 DeriveKeyPair), such as the Argon2id output of the
// keystore's recovery code. The caller zeroes ikm and the private bytes.
func DeriveKey(ikm []byte) (priv, pub []byte, err error) {
	if len(ikm) < 32 {
		return nil, nil, ErrKey
	}
	kem, _, _ := suite()
	k, err := kem.DeriveKeyPair(ikm)
	if err != nil {
		return nil, nil, ErrKey
	}
	if priv, err = k.Bytes(); err != nil {
		return nil, nil, err
	}
	return priv, k.PublicKey().Bytes(), nil
}

// maxRaw bounds what SealRaw seals: a key, not a document.
const maxRaw = 1024

// SealRaw encrypts a small value to the public key under any info, such as a
// KEK to the recovery key. It returns the encapsulated key and ciphertext.
func SealRaw(pub, info, plaintext []byte) (enc, ct []byte, err error) {
	if len(plaintext) == 0 || len(plaintext) > maxRaw {
		return nil, nil, ErrSecret
	}
	kem, kdf, aead := suite()
	pk, err := kem.NewPublicKey(pub)
	if err != nil {
		return nil, nil, ErrKey
	}
	out, err := hpke.Seal(pk, kdf, aead, info, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return out[:EncSize], out[EncSize:], nil
}

// OpenRaw is SealRaw's opposite. The caller zeroes the plaintext.
func OpenRaw(priv, info, enc, ct []byte) ([]byte, error) {
	if len(enc) != EncSize || len(ct) == 0 || len(ct) > maxRaw+16 {
		return nil, ErrDecrypt
	}
	kem, kdf, aead := suite()
	k, err := kem.NewPrivateKey(priv)
	if err != nil {
		return nil, ErrKey
	}
	buf := make([]byte, 0, len(enc)+len(ct))
	buf = append(append(buf, enc...), ct...)
	pt, err := hpke.Open(k, kdf, aead, info, buf)
	clear(buf)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Seal encrypts secret to the public key under the context's info and
// returns the encapsulated key and the ciphertext.
func Seal(pub []byte, c Context, secret []byte) (enc, ct []byte, err error) {
	if !c.Valid() || len(secret) == 0 || len(secret) > MaxSecret {
		return nil, nil, ErrSecret
	}
	return SealRaw(pub, c.Info(), secret)
}

// Open decrypts a record with the serialized private key. The caller zeroes
// the returned plaintext.
func Open(priv []byte, c Context, enc, ct []byte) ([]byte, error) {
	if !c.Valid() || len(ct) > MaxSecret+16 {
		return nil, ErrDecrypt
	}
	return OpenRaw(priv, c.Info(), enc, ct)
}

// Zero overwrites b.
func Zero(b []byte) { clear(b) }
