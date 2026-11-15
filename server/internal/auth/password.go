package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the Argon2id cost parameters. They are stored alongside
// every hash so they can be raised later without invalidating old hashes.
type Argon2Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultArgon2Params exceed the OWASP Password Storage Cheat Sheet minimum
// for Argon2id (19 MiB, t=2, p=1).
var DefaultArgon2Params = Argon2Params{
	MemoryKiB:   64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLen:     16,
	KeyLen:      32,
}

// Password policy bounds. A long maximum allows passphrases while keeping
// hashing cost bounded.
const (
	MinPasswordLength = 12
	MaxPasswordLength = 256
)

var (
	ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	ErrPasswordTooLong  = fmt.Errorf("password must be at most %d characters", MaxPasswordLength)
	ErrPasswordCommon   = errors.New("password is too common or too simple")
	errMalformedHash    = errors.New("auth: malformed password hash")
)

// Hasher hashes and verifies passwords. A semaphore bounds the number of
// concurrent Argon2 computations so a burst of logins cannot exhaust memory.
type Hasher struct {
	params Argon2Params
	sem    chan struct{}
}

// NewHasher returns a Hasher allowing at most maxConcurrent simultaneous
// hash computations.
func NewHasher(params Argon2Params, maxConcurrent int) *Hasher {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &Hasher{params: params, sem: make(chan struct{}, maxConcurrent)}
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// ValidatePassword enforces the password policy. It follows NIST SP 800-63B:
// length over composition rules, and a block list of trivially guessable
// values.
func ValidatePassword(password string, context ...string) error {
	n := utf8.RuneCountInString(password)
	if n < MinPasswordLength {
		return ErrPasswordTooShort
	}
	if n > MaxPasswordLength {
		return ErrPasswordTooLong
	}
	lower := strings.ToLower(password)
	if _, bad := commonPasswords[lower]; bad {
		return ErrPasswordCommon
	}
	distinct := map[rune]struct{}{}
	for _, r := range password {
		distinct[r] = struct{}{}
	}
	if len(distinct) < 5 {
		return ErrPasswordCommon
	}
	for _, c := range context {
		c = strings.ToLower(strings.TrimSpace(c))
		if len(c) >= 4 && strings.Contains(lower, c) {
			return errors.New("password must not contain your name or email address")
		}
	}
	return nil
}

// Hash returns an encoded Argon2id hash in the PHC string format.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	salt := make([]byte, h.params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: reading salt: %w", err)
	}
	p := h.params
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify checks a password against an encoded hash in constant time. The
// second return value reports whether the hash used weaker parameters than
// the current configuration and should be replaced.
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (ok bool, needsRehash bool, err error) {
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.release()
	keyLen := uint32(len(want)) //nolint:gosec // decodeHash bounds the key to 16..64 bytes
	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.MemoryKiB, p.Parallelism, keyLen)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	needsRehash = p.MemoryKiB < h.params.MemoryKiB || p.Iterations < h.params.Iterations ||
		p.Parallelism != h.params.Parallelism || keyLen != h.params.KeyLen
	return true, needsRehash, nil
}

// DummyVerify spends the same work as a real verification. It is used when a
// login names an account that does not exist so response timing does not
// reveal which accounts exist.
func (h *Hasher) DummyVerify(ctx context.Context, password string) {
	if err := h.acquire(ctx); err != nil {
		return
	}
	defer h.release()
	p := h.params
	_ = argon2.IDKey([]byte(password), make([]byte, p.SaltLen), p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLen)
}

func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	var p Argon2Params
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, found := strings.Cut(kv, "=")
		if !found {
			return Argon2Params{}, nil, nil, errMalformedHash
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return Argon2Params{}, nil, nil, errMalformedHash
		}
		switch k {
		case "m":
			p.MemoryKiB = uint32(n)
		case "t":
			p.Iterations = uint32(n)
		case "p":
			if n > 255 {
				return Argon2Params{}, nil, nil, errMalformedHash
			}
			p.Parallelism = uint8(n)
		default:
			return Argon2Params{}, nil, nil, errMalformedHash
		}
	}
	// Refuse absurd parameters so a corrupted row cannot be used to exhaust
	// server memory or CPU.
	if p.MemoryKiB < 8*1024 || p.MemoryKiB > 1024*1024 || p.Iterations < 1 || p.Iterations > 20 || p.Parallelism < 1 || p.Parallelism > 16 {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return Argon2Params{}, nil, nil, errMalformedHash
	}
	return p, salt, key, nil
}

// commonPasswords is a small block list of passwords that satisfy the length
// rule but are trivially guessable. It is intentionally short; length and
// rate limiting carry most of the weight.
var commonPasswords = map[string]struct{}{
	"password1234": {}, "password12345": {}, "password123456": {}, "123456789012": {},
	"qwertyuiop12": {}, "qwerty123456": {}, "letmein12345": {}, "administrator": {},
	"administrator1": {}, "changeme1234": {}, "welcome12345": {}, "iloveyou1234": {},
	"passw0rd1234": {}, "p@ssw0rd1234": {}, "1q2w3e4r5t6y": {}, "abcdefghijkl": {},
	"easyrmm12345": {}, "easyrmmadmin": {}, "aaaaaaaaaaaa": {}, "111111111111": {},
	"correcthorsebatterystaple": {}, "qwertyuiopasdf": {}, "zaq12wsxcde3": {},
}
