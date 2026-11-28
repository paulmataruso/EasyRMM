package runner

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestFallbackWaitsAnHourOfFailuresThenTriesAtMostOncePerHour(t *testing.T) {
	s := &server{status: http.StatusBadGateway, code: "bad_gateway"}
	r := newRunner(t, s, nil)
	r.FallbackAfter = 40 * time.Millisecond
	tries := 0
	switchNext := false
	r.Fallback = func(context.Context) bool { tries++; return switchNext }
	ctx := context.Background()

	// Failures shorter than the wait do not try.
	for range 3 {
		if _, err := r.beat(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if tries != 0 {
		t.Fatalf("tried after %d failed heartbeats with no wait", tries)
	}
	time.Sleep(60 * time.Millisecond)
	// After the wait, one try; a failed try is not repeated at once.
	if _, err := r.beat(ctx); err != nil || tries != 1 {
		t.Fatalf("first try: %d %v", tries, err)
	}
	if _, err := r.beat(ctx); err != nil || tries != 1 {
		t.Fatalf("a second try came at once: %d %v", tries, err)
	}
	time.Sleep(60 * time.Millisecond)
	switchNext = true
	if _, err := r.beat(ctx); !errors.Is(err, ErrMoved) || tries != 2 {
		t.Fatalf("after the switch: %d %v", tries, err)
	}
}

func TestASuccessfulHeartbeatEndsTheRunOfFailures(t *testing.T) {
	s := &server{status: http.StatusBadGateway, code: "bad_gateway"}
	r := newRunner(t, s, nil)
	r.FallbackAfter = 40 * time.Millisecond
	tries := 0
	r.Fallback = func(context.Context) bool { tries++; return false }
	ctx := context.Background()

	_, _ = r.beat(ctx)
	time.Sleep(60 * time.Millisecond)
	s.mu.Lock()
	s.status = 0
	s.mu.Unlock()
	if _, err := r.beat(ctx); err != nil {
		t.Fatal(err)
	}
	if !r.down.IsZero() {
		t.Error("a heartbeat that worked left the run of failures open")
	}
	// Failing again starts a new run: no try until it has lasted the wait.
	s.mu.Lock()
	s.status = http.StatusBadGateway
	s.mu.Unlock()
	_, _ = r.beat(ctx)
	_, _ = r.beat(ctx)
	if tries != 0 {
		t.Errorf("tried %d times in a new run of failures", tries)
	}
}

func TestWithoutAFallbackFailuresGoOnAsBefore(t *testing.T) {
	s := &server{status: http.StatusBadGateway, code: "bad_gateway"}
	r := newRunner(t, s, nil)
	r.FallbackAfter = time.Nanosecond
	time.Sleep(time.Millisecond)
	for range 3 {
		if wait, err := r.beat(context.Background()); err != nil || wait <= 0 {
			t.Fatalf("%v %v", wait, err)
		}
	}
	// The default wait is an hour.
	r.FallbackAfter = 0
	r.Fallback = func(context.Context) bool { t.Error("tried within the hour"); return true }
	_, _ = r.beat(context.Background())
}
