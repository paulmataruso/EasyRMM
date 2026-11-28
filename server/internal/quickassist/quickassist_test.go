package quickassist

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
)

func TestTokensAreDistinctAndHashedOneWay(t *testing.T) {
	a, err := newToken(PrefixOneTime)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newToken(PrefixOneTime)
	if a == b || !strings.HasPrefix(a, "qal_") || len(a) != 4+43 {
		t.Fatalf("tokens %q %q", a, b)
	}
	if p, _ := newToken(PrefixPermanent); !strings.HasPrefix(p, "qap_") {
		t.Fatalf("permanent prefix %q", p)
	}
	if string(hashToken(a)) == a || len(hashToken(a)) != 32 || !compare(hashToken(a), hashToken(a)) || compare(hashToken(a), hashToken(b)) {
		t.Fatal("hash")
	}
}

func TestCodeHashIsBoundToTheSession(t *testing.T) {
	s1, s2 := uuid.New(), uuid.New()
	if !compare(codeHash(s1, "123456"), codeHash(s1, "123456")) {
		t.Fatal("same session and code differ")
	}
	if compare(codeHash(s1, "123456"), codeHash(s2, "123456")) || compare(codeHash(s1, "123456"), codeHash(s1, "123457")) {
		t.Fatal("hash is not bound to the session and the code")
	}
	if codePattern.MatchString("12345") || codePattern.MatchString("1234567") || codePattern.MatchString("12345a") || !codePattern.MatchString("000000") {
		t.Fatal("code pattern")
	}
}

func TestNewCodeIsSixDigits(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c := NewCode()
		if !codePattern.MatchString(c) {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
	}
	if len(seen) < 150 {
		t.Fatalf("only %d distinct codes in 200", len(seen))
	}
	if pad6(7) != "000007" || pad6(123456) != "123456" {
		t.Fatal("pad6")
	}
}

func TestCleanDropsControlCharactersAndCutsOnRuneBoundaries(t *testing.T) {
	if got := clean("a\x00b\nc\x7f", 10); got != "abc" {
		t.Fatalf("clean: %q", got)
	}
	if got := clean("ééé", 3); got != "é" {
		t.Fatalf("cut inside a rune: %q", got)
	}
}

func TestHolderRule(t *testing.T) {
	x := &Session{Organization: uuid.New()}
	if holder(access.Caller{}, x) {
		t.Fatal("no principal holds a session")
	}
	if !holder(access.System("test"), x) {
		t.Fatal("the system may take over")
	}
}

func TestDefaultSettingsAreInsideTheirBounds(t *testing.T) {
	d := DefaultSettings()
	want := Settings{IdleMinutes: 30, MaxSessionHours: 8, RetentionDays: 30, BucketBurst: 5, BucketRefillMinutes: 3, WaitingCap: 20, PermanentLinkCap: 5}
	if d != want {
		t.Fatalf("defaults %+v", d)
	}
	if d.Idle() != 30*time.Minute || d.MaxSessionLength() != 8*time.Hour {
		t.Fatal("durations")
	}
	for _, sp := range settingSpecs {
		if v := *sp.field(&d); v < sp.min || v > sp.max {
			t.Errorf("%s default %d outside %d-%d", sp.key, v, sp.min, sp.max)
		}
		if sp.message == "" || sp.patch(&SettingsPatch{}) != nil {
			t.Errorf("%s spec", sp.key)
		}
	}
	if len(settingSpecs) != 7 {
		t.Fatalf("specs: %d", len(settingSpecs))
	}
}
