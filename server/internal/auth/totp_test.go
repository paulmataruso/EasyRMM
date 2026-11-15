package auth

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTOTPRFC6238Vector(t *testing.T) {
	// RFC 6238 Appendix B, SHA-1 seed "12345678901234567890", T=59s -> 94287082 (8 digits).
	// With 6 digits the expected value is the low six digits: 287082.
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	step, ok := VerifyTOTP(secret, "287082", time.Unix(59, 0), -1)
	if !ok || step != 1 {
		t.Fatalf("RFC vector rejected: ok=%v step=%d", ok, step)
	}
}

func TestTOTPAcceptsSkewAndRejectsReplay(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	cur := now.Unix() / 30

	step, ok := VerifyTOTP(secret, codeAt(t, secret, now), now, 0)
	if !ok || step != cur {
		t.Fatalf("current code rejected")
	}
	if _, ok := VerifyTOTP(secret, codeAt(t, secret, now), now, step); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := VerifyTOTP(secret, codeAt(t, secret, now.Add(-30*time.Second)), now, 0); !ok {
		t.Fatal("previous-step code rejected")
	}
	if _, ok := VerifyTOTP(secret, codeAt(t, secret, now.Add(30*time.Second)), now, 0); !ok {
		t.Fatal("next-step code rejected")
	}
	if _, ok := VerifyTOTP(secret, codeAt(t, secret, now.Add(-90*time.Second)), now, 0); ok {
		t.Fatal("stale code accepted")
	}
	// An older code is refused once a newer one was used.
	if _, ok := VerifyTOTP(secret, codeAt(t, secret, now.Add(-30*time.Second)), now, cur); ok {
		t.Fatal("older code accepted after newer one")
	}
}

func TestTOTPRejectsMalformedInput(t *testing.T) {
	secret, _ := NewTOTPSecret()
	for _, c := range []string{"", "12345", "1234567", "12a456", "１２３４５６"} {
		if _, ok := VerifyTOTP(secret, c, time.Now(), 0); ok {
			t.Errorf("accepted %q", c)
		}
	}
	// Spaces typed by users are tolerated.
	now := time.Now()
	c := codeAt(t, secret, now)
	if _, ok := VerifyTOTP(secret, c[:3]+" "+c[3:], now, 0); !ok {
		t.Error("code with space rejected")
	}
}

func TestTOTPURI(t *testing.T) {
	u, err := url.Parse(TOTPURI("EasyRMM", "jane@example.com", "ABCDEF"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Query().Get("secret") != "ABCDEF" || u.Query().Get("issuer") != "EasyRMM" {
		t.Fatalf("bad uri %s", u)
	}
	if !strings.Contains(u.Path, "jane@example.com") {
		t.Fatalf("account missing from %s", u.Path)
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("got %d codes", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 14 || c[4] != '-' || c[9] != '-' || !LooksLikeRecoveryCode(c) {
			t.Fatalf("bad code format %q", c)
		}
		if seen[c] {
			t.Fatal("duplicate recovery code")
		}
		seen[c] = true
	}
	if !bytes.Equal(HashRecoveryCode(codes[0]), HashRecoveryCode(" "+strings.ToUpper(strings.ReplaceAll(codes[0], "-", ""))+" ")) {
		t.Fatal("normalisation differs")
	}
	if LooksLikeRecoveryCode("123456") {
		t.Fatal("totp code treated as recovery code")
	}
}
