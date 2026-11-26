package agentchannel

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestWakeQueueDedupesAndIsRateLimited(t *testing.T) {
	h := New(Options{Enabled: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	one := uuid.New()
	h.Wake(one, "settings")
	h.Wake(one, "removal") // queued again before it went out: woken once, for the latest reason
	for range 399 {
		h.Wake(uuid.New(), "settings")
	}
	h.wakeMu.Lock()
	if len(h.wakeQ) != 400 || h.wakeSet[one] != "removal" {
		t.Fatalf("queued %d, reason %q", len(h.wakeQ), h.wakeSet[one])
	}
	h.wakeMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.releaseWakes(ctx)
	time.Sleep(500 * time.Millisecond)
	h.wakeMu.Lock()
	sent := 400 - len(h.wakeQ)
	h.wakeMu.Unlock()
	// 100 a second: about 50 in half a second, never the whole queue at once.
	if sent < 10 || sent > 120 {
		t.Fatalf("%d wakes went out in half a second, want about %d", sent, WakesPerSecond/2)
	}
}

func TestWakeDoesNothingWhenOff(t *testing.T) {
	h := New(Options{Enabled: false})
	h.Wake(uuid.New(), "settings")
	if len(h.wakeQ) != 0 {
		t.Fatal("a wake was queued with the channel off")
	}
}
