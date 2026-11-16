package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// approvalServer answers enrollments with token ert_approve as the server
// does for an approval token: waiting, then whatever decision is set.
type approvalServer struct {
	*httptest.Server
	mu       sync.Mutex
	decision string // "", "approved", "rejected", "error", "gone"
	asks     atomic.Int32
	beats    atomic.Int32
}

func newApprovalServer(t *testing.T) *approvalServer {
	t.Helper()
	s := &approvalServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case agentproto.PathEnroll:
			var in agentproto.EnrollRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			s.asks.Add(1)
			s.mu.Lock()
			decision := s.decision
			s.mu.Unlock()
			switch {
			case in.Token != "ert_approve" || decision == "gone":
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":{"code":"token_invalid","message":"no"}}`)
			case decision == "approved":
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{"deviceId":"dev-77","heartbeatSeconds":60,"jobKey":""}`)
			case decision == "rejected":
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"error":{"code":"enrollment_rejected","message":"rejected"}}`)
			case decision == "error":
				w.WriteHeader(http.StatusBadGateway)
			default:
				w.WriteHeader(http.StatusAccepted)
				_, _ = io.WriteString(w, `{"deviceId":"","pending":{"code":"ABCD-EFGH","retrySeconds":1}}`)
			}
		case agentproto.PathHeartbeat:
			s.beats.Add(1)
			_, _ = io.WriteString(w, `{"heartbeatSeconds":60,"meshAgent":{"available":false}}`)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *approvalServer) decide(d string) {
	s.mu.Lock()
	s.decision = d
	s.mu.Unlock()
}

func fastBackoff(t *testing.T) {
	minB, maxB := approvalBackoffMin, approvalBackoffMax
	approvalBackoffMin, approvalBackoffMax = 10*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { approvalBackoffMin, approvalBackoffMax = minB, maxB })
}

func TestInstallWaitsForApproval(t *testing.T) {
	linuxOnly(t)
	fastBackoff(t)
	srv := newApprovalServer(t)
	h := newHarness(t)

	if err := h.run("install", "--server", srv.URL, "--token", "ert_approve"); err != nil {
		t.Fatalf("install: %v\n%s", err, h.out)
	}
	for _, want := range []string{"Waiting for approval in the EasyRMM console at " + srv.URL + ". Device code: ABCD-EFGH", "finishes enrolling on its own"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("install output lacks %q:\n%s", want, h.out)
		}
	}
	if _, err := os.Stat(filepath.Join(h.e.paths.State(), "agent.json")); !os.IsNotExist(err) {
		t.Error("a waiting device has an enrollment")
	}
	if err := h.run("status"); err != nil || !strings.Contains(h.out.String(), "Waiting:    for approval in the EasyRMM console since") ||
		!strings.Contains(h.out.String(), "Code:       ABCD-EFGH") || !strings.Contains(h.out.String(), "Service:    active") {
		t.Errorf("status while waiting: %q, %v", h.out, err)
	}
	// Running the installer again keeps waiting; another server is refused.
	if err := h.run("install", "--server", srv.URL, "--token", "ert_approve"); err != nil || !strings.Contains(h.out.String(), "Already waiting for approval") {
		t.Errorf("installing again: %q, %v", h.out, err)
	}
	if err := h.run("enroll", "--server", "https://other.example.com"); err == nil || !strings.Contains(err.Error(), "waits for approval from") {
		t.Errorf("another server: %v", err)
	}

	// The service waits through answers that it still waits and through
	// server errors, then enrolls once approved and runs as usual.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.e.dispatch(ctx, []string{"run"}, io.Discard) }()
	waitFor(t, func() bool { return srv.asks.Load() >= 2 })
	srv.decide("error")
	n := srv.asks.Load()
	waitFor(t, func() bool { return srv.asks.Load() >= n+2 })
	srv.decide("approved")
	waitFor(t, func() bool { return srv.beats.Load() > 0 })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	cfg, _, err := h.e.store.Load()
	if err != nil || cfg.DeviceID != "dev-77" || cfg.Server != srv.URL || cfg.MeshAgentMode != "service" {
		t.Fatalf("enrollment after approval: %+v %v", cfg, err)
	}
	if _, err := os.Stat(filepath.Join(h.e.paths.State(), "pending.json")); !os.IsNotExist(err) {
		t.Error("the install token is kept after approval")
	}
	if err := h.run("status"); err != nil || !strings.Contains(h.out.String(), "Device:     dev-77") {
		t.Errorf("status after approval: %q, %v", h.out, err)
	}
}

func TestUninstallWhileWaiting(t *testing.T) {
	linuxOnly(t)
	srv := newApprovalServer(t)
	h := newHarness(t)
	if err := h.run("install", "--server", srv.URL, "--token", "ert_approve"); err != nil {
		t.Fatal(err)
	}
	if err := h.run("uninstall"); err != nil || strings.TrimSpace(h.out.String()) != "EasyRMM agent removed." {
		t.Fatalf("uninstall: %q, %v", h.out, err)
	}
	if _, err := os.Stat(h.e.paths.State()); !os.IsNotExist(err) {
		t.Error("the waiting state is kept after uninstall")
	}
}

func TestRejectedAgentStopsAsking(t *testing.T) {
	linuxOnly(t)
	fastBackoff(t)
	for _, tc := range []struct{ decision, why string }{
		{"rejected", "rejected in the EasyRMM console"},
		{"gone", "no longer valid"},
	} {
		t.Run(tc.decision, func(t *testing.T) {
			srv := newApprovalServer(t)
			h := newHarness(t)
			t.Setenv("EASYRMM_TOKEN", "ert_approve")
			if err := h.run("enroll", "--server", srv.URL); err != nil || !strings.Contains(h.out.String(), `Start the agent with "easyrmm-agent run"`) {
				t.Fatalf("enroll: %q, %v", h.out, err)
			}
			srv.decide(tc.decision)
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			if _, _, err := h.e.awaitApproval(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("a stopped agent returned %v instead of idling", err)
			}
			asked := srv.asks.Load()
			if err := h.run("status"); err != nil || !strings.Contains(h.out.String(), "Stopped:") || !strings.Contains(h.out.String(), tc.why) {
				t.Errorf("status: %q, %v", h.out, err)
			}
			// Installing over it says to uninstall first.
			if err := h.run("install", "--server", srv.URL); err == nil || !strings.Contains(err.Error(), "stopped asking") {
				t.Errorf("installing over a stopped agent: %v", err)
			}
			// Started again, it does not ask again.
			ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel2()
			if _, _, err := h.e.awaitApproval(ctx2); !errors.Is(err, context.DeadlineExceeded) || srv.asks.Load() != asked {
				t.Errorf("restarted: %v, %d asks after %d", err, srv.asks.Load(), asked)
			}
		})
	}
}

func TestStopReasons(t *testing.T) {
	if stopReason(errors.New("dial tcp: refused")) != "" {
		t.Error("a network error stops the agent")
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
