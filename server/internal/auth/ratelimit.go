package auth

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// KeyedLimiter is a set of token-bucket limiters keyed by an arbitrary
// string (an IP address, an e-mail address). Idle buckets are evicted so
// memory stays bounded under address-spraying attacks.
type KeyedLimiter struct {
	mu      sync.Mutex
	every   time.Duration
	burst   int
	maxKeys int
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewKeyedLimiter allows burst events immediately and then one event per
// every interval for each key.
func NewKeyedLimiter(every time.Duration, burst, maxKeys int) *KeyedLimiter {
	return &KeyedLimiter{every: every, burst: burst, maxKeys: maxKeys, buckets: map[string]*bucket{}, now: time.Now}
}

// Allow reports whether an event for key may happen now, consuming a token
// if so.
func (k *KeyedLimiter) Allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	b, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) >= k.maxKeys {
			k.evictLocked(now)
		}
		b = &bucket{lim: rate.NewLimiter(rate.Every(k.every), k.burst)}
		k.buckets[key] = b
	}
	b.seen = now
	return b.lim.AllowN(now, 1)
}

// Ready reports whether an event for key would be allowed now, without
// consuming a token: a server can turn away a request it would refuse
// before doing the work of reading it.
func (k *KeyedLimiter) Ready(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.buckets[key]
	return !ok || b.lim.TokensAt(k.now()) >= 1
}

// evictLocked removes buckets that have refilled completely; if that frees
// nothing, it drops the least recently seen half. Dropping a bucket only
// ever makes a key less limited, never more, so this cannot lock anyone out.
func (k *KeyedLimiter) evictLocked(now time.Time) {
	full := k.every * time.Duration(k.burst)
	for key, b := range k.buckets {
		if now.Sub(b.seen) > full {
			delete(k.buckets, key)
		}
	}
	if len(k.buckets) < k.maxKeys {
		return
	}
	var cutoff time.Time
	for _, b := range k.buckets {
		if cutoff.IsZero() || b.seen.Before(cutoff) {
			cutoff = b.seen
		}
	}
	// Move the cutoff to the midpoint between the oldest entry and now.
	cutoff = cutoff.Add(now.Sub(cutoff) / 2)
	for key, b := range k.buckets {
		if !b.seen.After(cutoff) {
			delete(k.buckets, key)
		}
	}
}

// Len returns the number of tracked keys, for tests and metrics.
func (k *KeyedLimiter) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.buckets)
}
