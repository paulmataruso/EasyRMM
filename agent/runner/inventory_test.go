package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func TestBeatSendsMetricsAndSyncsTheInventory(t *testing.T) {
	s := &server{}
	r := newRunner(t, s, nil)
	collected := 0
	kernel := "6.8.0"
	r.Inventory = func(context.Context) agentproto.Inventory {
		collected++
		return agentproto.Inventory{OS: agentproto.OSInfo{Kernel: kernel}, Packages: []agentproto.Package{{Name: "bash", Version: "5.2"}}}
	}
	r.Metrics = func(context.Context) agentproto.Metrics { return agentproto.Metrics{CPUPercent: 12.5, Processes: 99} }
	ctx := context.Background()
	beat := func() {
		t.Helper()
		if wait := r.beat(ctx); wait < 50*time.Second {
			t.Fatalf("beat failed: next in %s", wait)
		}
	}
	uploads := func() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.uploads) }

	// The server holds nothing: the agent uploads what it hashed.
	beat()
	if collected != 1 || uploads() != 1 {
		t.Fatalf("collected %d, uploaded %d", collected, uploads())
	}
	sum := sha256.Sum256(s.uploads[0])
	hash := hex.EncodeToString(sum[:])
	if hash != r.invHash || hash != (&agentproto.Inventory{OS: agentproto.OSInfo{Kernel: kernel}, Packages: []agentproto.Package{{Name: "bash", Version: "5.2"}}}).Hash() {
		t.Error("the upload is not what was hashed")
	}
	if m := s.heartbeats[0].Metrics; m == nil || m.CPUPercent != 12.5 || m.Processes != 99 {
		t.Errorf("heartbeat metrics %+v", m)
	}
	if st, _ := r.Store.LoadStatus(); st.InventoryUploaded.IsZero() || st.InventoryError != "" {
		t.Errorf("status %+v", st)
	}

	// Once the server has it, nothing more is sent and nothing collected
	// until the hour is up.
	s.mu.Lock()
	s.invHash = hash
	s.mu.Unlock()
	beat()
	beat()
	if collected != 1 || uploads() != 1 {
		t.Errorf("collected %d, uploaded %d", collected, uploads())
	}

	// A change found at the next collection is uploaded.
	r.InventoryEvery = time.Nanosecond
	kernel = "6.8.1"
	beat()
	if collected != 2 || uploads() != 2 {
		t.Errorf("after a change: collected %d, uploaded %d", collected, uploads())
	}

	// A refused upload waits before it is tried again.
	r.InventoryEvery = time.Hour
	s.mu.Lock()
	s.invStatus = http.StatusBadRequest
	s.mu.Unlock()
	beat()
	beat()
	if st, _ := r.Store.LoadStatus(); st.InventoryError == "" {
		t.Error("the failure is not in the status")
	}
	if r.invFailed.IsZero() {
		t.Error("no failure recorded")
	}
	s.mu.Lock()
	s.invStatus = 0
	s.mu.Unlock()
	beat()
	if uploads() != 2 {
		t.Errorf("retried before the wait: %d", uploads())
	}
	r.InventoryRetry = time.Nanosecond
	beat()
	if uploads() != 3 || !r.invFailed.IsZero() {
		t.Errorf("not retried after the wait: %d", uploads())
	}
}

func TestBeatWithoutCollectors(t *testing.T) {
	s := &server{}
	r := newRunner(t, s, nil)
	r.beat(context.Background())
	if len(s.heartbeats) != 1 || s.heartbeats[0].Metrics != nil || len(s.uploads) != 0 {
		t.Errorf("heartbeats %+v uploads %d", s.heartbeats, len(s.uploads))
	}
}
