package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP parameters follow RFC 6238 defaults, which every common authenticator
// app supports.
const (
	totpPeriod     = 30
	totpDigits     = otp.DigitsSix
	totpSecretSize = 20 // 160 bits, as recommended by RFC 4226
	// totpSkew accepts one step either side of now to tolerate clock drift.
	totpSkew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random base32 TOTP secret.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, totpSecretSize)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: generating totp secret: %w", err)
	}
	return b32.EncodeToString(raw), nil
}

// TOTPURI builds the otpauth:// URI that authenticator apps scan.
func TOTPURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// VerifyTOTP checks a code and returns the time step it matched. Callers
// must reject steps at or before the last accepted step so that a code
// cannot be replayed within its validity window.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (step int64, ok bool) {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	if len(code) != totpDigits.Length() {
		return 0, false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	current := now.Unix() / totpPeriod
	opts := totp.ValidateOpts{Period: totpPeriod, Digits: totpDigits, Algorithm: otp.AlgorithmSHA1}
	matched := int64(-1)
	// Check every candidate step without returning early, so timing does not
	// reveal which step matched.
	for s := current - totpSkew; s <= current+totpSkew; s++ {
		want, err := totp.GenerateCodeCustom(secret, time.Unix(s*totpPeriod, 0), opts)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && matched < 0 {
			matched = s
		}
	}
	if matched < 0 || matched <= lastStep {
		return 0, false
	}
	return matched, true
}

// Recovery codes are single-use fallbacks for a lost authenticator. They
// carry 60 bits of entropy each, so a fast hash is sufficient.
const recoveryCodeCount = 10

// Crockford base32 alphabet: no i, l, o or u, so codes are easy to read aloud.
var recoveryAlphabet = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// NewRecoveryCodes returns fresh human-friendly codes like "k7dq-3mzx-p2hw".
func NewRecoveryCodes() ([]string, error) {
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		raw := make([]byte, 8)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("auth: generating recovery codes: %w", err)
		}
		s := recoveryAlphabet.EncodeToString(raw)[:12]
		codes[i] = s[0:4] + "-" + s[4:8] + "-" + s[8:12]
	}
	return codes, nil
}

// HashRecoveryCode normalises and hashes a recovery code.
func HashRecoveryCode(code string) []byte {
	norm := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte("easyrmm-recovery-code:" + norm))
	return sum[:]
}

// LooksLikeRecoveryCode distinguishes recovery codes from TOTP codes in a
// single MFA input field.
func LooksLikeRecoveryCode(code string) bool {
	norm := strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code))
	return len(norm) == 12
}
