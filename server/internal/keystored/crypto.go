package keystored

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// KEKSize is the key-encryption key's length: AES-256.
const KEKSize = 32

// Argon2id parameters (ADR-0081, section 2 and 4): 64 MiB, 3 passes, 4 lanes.
const (
	argonMemory  = 64 * 1024
	argonPasses  = 3
	argonLanes   = 4
	argonKeySize = 32
	saltSize     = 16
)

// Errors of the wrap format.
var (
	// ErrDecrypt is every failure to unwrap: a wrong key, a wrong context
	// and a damaged value look the same.
	ErrDecrypt = errors.New("keystore: the wrapped value does not open")
	// ErrFormat is a wrapped value of no known format.
	ErrFormat = errors.New("keystore: the wrapped value is not in a known format")
)

// derive stretches a passphrase or recovery code with Argon2id.
func derive(secret, salt []byte) []byte {
	return argon2.IDKey(secret, salt, argonPasses, argonMemory, argonLanes, argonKeySize)
}

// checkValue is the KEK's key check value: HKDF-SHA-256 of a fixed label
// under the KEK, 16 bytes. It lets a wrong or missing version be recognized
// without trying to unwrap.
func checkValue(kek []byte) []byte {
	cv, err := hkdf.Key(sha256.New, kek, nil, "easyrmm-kek-check-v1", 16)
	if err != nil {
		// Only a too-long output asks for an error; 16 bytes never does.
		panic(err)
	}
	return cv
}

// wrapAAD is the associated data that binds a wrapped key to its owner:
// keystore-wrap-v1|<org>|<key id>|<purpose>.
func wrapAAD(org, keyID, purpose string) []byte {
	return []byte("keystore-wrap-v1|" + org + "|" + keyID + "|" + purpose)
}

const wrapPrefix = "ks1."

// wrap seals plaintext under a KEK version: AES-256-GCM, wire format
// ks1.<kek version>.<base64url(nonce || ciphertext || tag)>.
func wrap(kek []byte, version int, aad, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	out := make([]byte, gcm.NonceSize(), gcm.NonceSize()+len(plaintext)+gcm.Overhead())
	if _, err := rand.Read(out); err != nil {
		return "", err
	}
	out = gcm.Seal(out, out[:gcm.NonceSize()], plaintext, aad)
	return wrapPrefix + strconv.Itoa(version) + "." + base64.RawURLEncoding.EncodeToString(out), nil
}

// parseWrapped splits a wrapped value into its KEK version and sealed bytes.
func parseWrapped(s string) (version int, sealed []byte, err error) {
	rest, ok := strings.CutPrefix(s, wrapPrefix)
	if !ok {
		return 0, nil, ErrFormat
	}
	v, b, ok := strings.Cut(rest, ".")
	if !ok {
		return 0, nil, ErrFormat
	}
	version, err = strconv.Atoi(v)
	if err != nil || version < 1 {
		return 0, nil, ErrFormat
	}
	sealed, err = base64.RawURLEncoding.DecodeString(b)
	if err != nil {
		return 0, nil, ErrFormat
	}
	return version, sealed, nil
}

// unwrap opens sealed bytes under a KEK. The caller zeroes the result.
func unwrap(kek []byte, sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrDecrypt
	}
	pt, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// codeEncoding is Crockford's base32 alphabet, without padding.
var codeEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// RecoveryCodeBytes is the recovery code's entropy: 160 bits.
const RecoveryCodeBytes = 20

// NewRecoveryCode makes a recovery code: 160 random bits as Crockford base32
// in eight groups of four characters. The keystore shows it once and never
// stores it.
func NewRecoveryCode() ([]byte, error) {
	raw := make([]byte, RecoveryCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	enc := []byte(codeEncoding.EncodeToString(raw))
	clear(raw)
	out := make([]byte, 0, len(enc)+len(enc)/4)
	for i, c := range enc {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, c)
	}
	clear(enc)
	return out, nil
}

// normalizeCode turns a typed recovery code into its 20 bytes: letters in
// either case, dashes and spaces ignored, and Crockford's look-alikes (I and
// L for 1, O for 0) accepted. The caller zeroes the result.
func normalizeCode(code []byte) ([]byte, error) {
	clean := make([]byte, 0, len(code))
	for _, c := range code {
		switch {
		case c == '-' || c == ' ' || c == '\n' || c == '\r' || c == '\t':
			continue
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		switch c {
		case 'I', 'L':
			c = '1'
		case 'O':
			c = '0'
		}
		clean = append(clean, c)
	}
	if len(clean) != RecoveryCodeBytes*8/5 {
		clear(clean)
		return nil, errors.New("keystore: that is not a recovery code")
	}
	raw := make([]byte, codeEncoding.DecodedLen(len(clean)))
	n, err := codeEncoding.Decode(raw, clean)
	clear(clean)
	if err != nil || n != RecoveryCodeBytes {
		clear(raw)
		return nil, errors.New("keystore: that is not a recovery code")
	}
	return raw, nil
}

func versionFile(version int) string { return fmt.Sprintf("kek-v%d", version) }
