package runner

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// report is a hardware report of one disk, named n.
func report(n string) agentproto.HardwareReport {
	return agentproto.HardwareReport{Disks: []agentproto.DiskHealth{{Name: n, State: agentproto.FactUnknown, Reason: agentproto.ReasonAsleep}}}
}

func TestHardwareTiming(t *testing.T) {
	r := newRunner(t, &server{}, nil)
	if r.HardwareFirst != 2*time.Minute || r.HardwareEvery != 30*time.Minute || r.HardwareJitter != time.Minute {
		t.Errorf("defaults %v %v %v", r.HardwareFirst, r.HardwareEvery, r.HardwareJitter)
	}
	lo, hi := time.Hour, time.Duration(0)
	for range 1000 {
		w := r.hardwareWait()
		lo, hi = min(lo, w), max(hi, w)
	}
	if lo < 30*time.Minute || hi > 31*time.Minute || hi-lo < 45*time.Second {
		t.Errorf("waits from %v to %v", lo, hi)
	}
}

// TestHardwareLoop: the first reading after HardwareFirst, then one every
// HardwareEvery and its jitter, each sent once.
func TestHardwareLoop(t *testing.T) {
	s := &server{}
	r := newRunner(t, s, nil)
	r.HardwareFirst, r.HardwareEvery, r.HardwareJitter = 40*time.Millisecond, 60*time.Millisecond, 20*time.Millisecond
	var mu sync.Mutex
	var at []time.Time
	r.Hardware = func(context.Context) agentproto.HardwareReport {
		mu.Lock()
		defer mu.Unlock()
		at = append(at, time.Now())
		return report("sda")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	r.hardwareLoop(ctx)
	mu.Lock()
	defer mu.Unlock()
	if len(at) < 2 || at[0].Sub(start) < r.HardwareFirst {
		t.Fatalf("%d readings, the first after %v", len(at), at[0].Sub(start))
	}
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < r.HardwareEvery {
			t.Errorf("reading %d after %v", i, gap)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hardware) != len(at) || s.hardware[0].Disks[0].Name != "sda" {
		t.Errorf("%d readings, %d sent: %+v", len(at), len(s.hardware), s.hardware)
	}
}

// TestHardwareBesideHeartbeats: a reading that does not end holds back no
// heartbeat, and Run waits for it to end with Run's context.
func TestHardwareBesideHeartbeats(t *testing.T) {
	s := &server{status: http.StatusBadGateway, code: "x"}
	r := newRunner(t, s, nil)
	r.MinRetry, r.MaxRetry, r.HardwareFirst = 5*time.Millisecond, 5*time.Millisecond, time.Millisecond
	started := make(chan struct{})
	ended := false
	r.Hardware = func(ctx context.Context) agentproto.HardwareReport {
		close(started)
		<-ctx.Done()
		ended = true
		return report("sda")
	}
	beats := func() int { s.mu.Lock(); defer s.mu.Unlock(); return s.beats }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- r.Run(ctx) }()
	<-started
	from := beats()
	for deadline := time.Now().Add(5 * time.Second); beats() < from+3; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d heartbeats while the reading was out", beats()-from)
		}
	}
	cancel()
	if err := <-done; err != nil || !ended {
		t.Errorf("Run = %v, the reading ended: %v", err, ended)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hwRequests != 0 {
		t.Error("a reading cut short by the agent's stop was sent")
	}
}

// TestHardwareDropped: a report the server does not take is dropped, not
// queued; an older server's 404 is dropped without a warning.
func TestHardwareDropped(t *testing.T) {
	s := &server{}
	r := newRunner(t, s, nil)
	var logs bytes.Buffer
	r.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	n := 0
	r.Hardware = func(context.Context) agentproto.HardwareReport {
		n++
		return report("sd" + string(rune('a'+n)))
	}
	ctx := context.Background()

	s.hwStatus = http.StatusNotFound
	r.sendHardware(ctx)
	if strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "does not take hardware reports") {
		t.Errorf("404: %s", logs.String())
	}
	s.hwStatus = http.StatusInternalServerError
	r.sendHardware(ctx)
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "500") {
		t.Errorf("500: %s", logs.String())
	}
	s.hwStatus = 0
	r.sendHardware(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hwRequests != 3 || len(s.hardware) != 1 || s.hardware[0].Disks[0].Name != "sdd" {
		t.Errorf("%d sent, taken %+v", s.hwRequests, s.hardware)
	}
}
