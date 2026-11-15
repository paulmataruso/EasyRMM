package auth

import (
	"fmt"
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
