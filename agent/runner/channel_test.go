package runner

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/agent/channel"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type fakeChannel struct {
	mu       sync.Mutex
	wakes    chan channel.Wake
	reported []bool
	report   *agentproto.ChannelReport
}

func (f *fakeChannel) Answered(_ *agentproto.HeartbeatResponse, reported bool) {
	f.mu.Lock()
	f.reported = append(f.reported, reported)
	f.mu.Unlock()
}
func (f *fakeChannel) Report() *agentproto.ChannelReport { return f.report }
func (f *fakeChannel) Wakes() <-chan channel.Wake        { return f.wakes }

// The capability and the connection held are sent only once the server
// answered at level 2 or higher (ADR-0009), and a wake brings the next
// heartbeat forward though the timer is far off.
func TestChannelWakeBringsTheHeartbeatForward(t *testing.T) {
	s := &server{protocol: 2}
	r := newRunner(t, s, nil)
	fc := &fakeChannel{wakes: make(chan channel.Wake, 1), report: &agentproto.ChannelReport{ConnID: "c", Since: 1}}
	r.Channel, r.MinWake = fc, 10*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	beats := func() int { s.mu.Lock(); defer s.mu.Unlock(); return s.beats }
	wait := func(n int) {
		t.Helper()
		for end := time.Now().Add(3 * time.Second); beats() < n; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatalf("only %d heartbeats", beats())
			}
		}
	}
	wait(1)
	time.Sleep(100 * time.Millisecond)
	if beats() != 1 {
		t.Fatalf("a heartbeat without a wake: %d", beats())
	}
	fc.wakes <- channel.Wake{What: agentproto.WakeCheckin}
	wait(2)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if first, second := s.heartbeats[0], s.heartbeats[1]; first.Channel != nil || first.Transport != nil ||
		len(second.Channel) != 1 || second.Transport == nil || second.Transport.ConnID != "c" {
		t.Fatalf("channel fields: first %+v %+v, second %+v %+v", first.Channel, first.Transport, second.Channel, second.Transport)
	}
	if len(fc.reported) < 2 || fc.reported[0] || !fc.reported[1] {
		t.Fatalf("Answered's reported flags: %v", fc.reported)
	}
}
