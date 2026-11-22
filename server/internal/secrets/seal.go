// Package secrets seals small secrets (TOTP seeds, integration credentials,
// MeshCentral login-token keys) before they are written to the database.
//
// Sealing uses AES-256-GCM from the Go standard library. Every sealed value
// carries the identifier of the key that produced it, so the master key can
// be rotated: new values are sealed with the primary key while values sealed
// with older keys remain readable until they are re-sealed.
//
// Wire format: "v1.<keyID>.<base64url(nonce || ciphertext || tag)>"
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// KeySize is the required master key length in bytes (AES-256).
const KeySize = 32

const formatVersion = "v1"

var keyIDPattern = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// ErrUnknownKey is returned when a sealed value references a key that is not
// present in the key ring.
var ErrUnknownKey = errors.New("secrets: sealed with an unknown key")

// ErrMalformed is returned for values that are not in the sealed wire format.
var ErrMalformed = errors.New("secrets: malformed sealed value")

// ErrDecrypt is returned when authentication of the ciphertext fails, which
// means the value was tampered with, moved to another context, or the key is
// wrong.
var ErrDecrypt = errors.New("secrets: unable to decrypt sealed value")

// Key is a named AES-256 key.
type Key struct {
	ID  string
	Raw []byte
}

// Sealer seals and opens values with a key ring.
type Sealer struct {
	primary string
	// derive is the primary key, which DeriveKey derives keys from.
	derive []byte
	aeads  map[string]cipher.AEAD
}

// NewSealer builds a Sealer. The first key is the primary key used for new
// values; any further keys are accepted for opening only.
func NewSealer(keys ...Key) (*Sealer, error) {
	if len(keys) == 0 {
		return nil, errors.New("secrets: at least one key is required")
	}
	s := &Sealer{primary: keys[0].ID, derive: slices.Clone(keys[0].Raw), aeads: make(map[string]cipher.AEAD, len(keys))}
	for _, k := range keys {
		if !keyIDPattern.MatchString(k.ID) {
			return nil, fmt.Errorf("secrets: invalid key id %q (want 1-16 lowercase letters or digits)", k.ID)
		}
		if len(k.Raw) != KeySize {
			return nil, fmt.Errorf("secrets: key %q must be %d bytes, got %d", k.ID, KeySize, len(k.Raw))
		}
		if _, dup := s.aeads[k.ID]; dup {
			return nil, fmt.Errorf("secrets: duplicate key id %q", k.ID)
		}
		block, err := aes.NewCipher(k.Raw)
		if err != nil {
			return nil, fmt.Errorf("secrets: key %q: %w", k.ID, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("secrets: key %q: %w", k.ID, err)
		}
		s.aeads[k.ID] = aead
	}
	return s, nil
}

// Seal encrypts plaintext. The associated data binds the ciphertext to its
// context (for example "user-totp:<user id>") so that a sealed value copied
// into another row fails to open.
func (s *Sealer) Seal(plaintext, associatedData []byte) (string, error) {
	aead := s.aeads[s.primary]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secrets: reading nonce: %w", err)
	}
	out := aead.Seal(nonce, nonce, plaintext, associatedData)
	return formatVersion + "." + s.primary + "." + base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts a value produced by Seal with the same associated data.
func (s *Sealer) Open(sealed string, associatedData []byte) ([]byte, error) {
	parts := strings.SplitN(sealed, ".", 3)
	if len(parts) != 3 || parts[0] != formatVersion {
		return nil, ErrMalformed
	}
	aead, ok := s.aeads[parts[1]]
	if !ok {
		return nil, ErrUnknownKey
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrMalformed
	}
	nonce, ciphertext := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// DeriveKey derives a 32-byte key for one use, named by info, from the
// primary key with HKDF-SHA-256, so that the key itself is never used for
// anything but sealing. Each use has its own info, and so its own key.
func (s *Sealer) DeriveKey(info string) ([]byte, error) {
	return hkdf.Key(sha256.New, s.derive, nil, info, KeySize)
}

// NeedsReseal reports whether a sealed value was produced by a key other than
// the current primary key.
func (s *Sealer) NeedsReseal(sealed string) bool {
	parts := strings.SplitN(sealed, ".", 3)
	return len(parts) != 3 || parts[1] != s.primary
}

// ParseKey decodes a base64 (standard or URL alphabet, padded or not) master
// key and checks its length.
func ParseKey(id, encoded string) (Key, error) {
	encoded = strings.TrimSpace(encoded)
	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		raw, err = enc.DecodeString(encoded)
		if err == nil {
			break
		}
	}
	if err != nil {
		return Key{}, fmt.Errorf("secrets: key %q is not valid base64", id)
	}
	if len(raw) != KeySize {
		return Key{}, fmt.Errorf("secrets: key %q must decode to %d bytes, got %d", id, KeySize, len(raw))
	}
	return Key{ID: id, Raw: raw}, nil
}
