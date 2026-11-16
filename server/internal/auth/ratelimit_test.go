package auth

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestKeyedLimiterBurstAndRefill(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewKeyedLimiter(10*time.Second, 3, 100)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allow("203.0.113.1") {
			t.Fatalf("event %d inside burst denied", i)
		}
	}
	if l.Allow("203.0.113.1") {
		t.Fatal("event beyond burst allowed")
	}
	if !l.Allow("203.0.113.2") {
		t.Fatal("independent key limited")
	}
	now = now.Add(10 * time.Second)
	if !l.Allow("203.0.113.1") {
		t.Fatal("token not refilled")
	}
	if l.Allow("203.0.113.1") {
		t.Fatal("refilled more than one token")
	}
}

func TestKeyedLimiterReady(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewKeyedLimiter(10*time.Second, 2, 100)
	l.now = func() time.Time { return now }
	if !l.Ready("dev") || l.Len() != 0 {
		t.Fatal("an unseen key is not ready, or Ready tracked it")
	}
	for range 2 {
		if !l.Ready("dev") || !l.Allow("dev") {
			t.Fatal("inside the burst")
		}
	}
	if l.Ready("dev") {
		t.Fatal("ready with no tokens left")
	}
	now = now.Add(10 * time.Second)
	// Asked twice: Ready does not spend the refilled token.
	first, second := l.Ready("dev"), l.Ready("dev")
	if !first || !second {
		t.Fatal("Ready spent a token, or none refilled")
	}
	if !l.Allow("dev") || l.Ready("dev") {
		t.Fatal("after the refilled token")
	}
}

func TestKeyedLimiterBoundsMemory(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewKeyedLimiter(time.Second, 1, 50)
	l.now = func() time.Time { return now }
	for i := 0; i < 1000; i++ {
		now = now.Add(time.Millisecond)
		l.Allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	if l.Len() > 50 {
		t.Fatalf("limiter tracks %d keys, cap is 50", l.Len())
	}
}

func TestLimitKey(t *testing.T) {
	for in, want := range map[string]string{
		"198.51.100.7":         "198.51.100.7",
		"::ffff:198.51.100.7":  "198.51.100.7",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
		"fe80::1%eth0":         "fe80::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
	} {
		if got := LimitKey(netip.MustParseAddr(in)); got != want {
			t.Errorf("LimitKey(%s) = %s, want %s", in, got, want)
		}
	}
}
