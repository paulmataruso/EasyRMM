package agentchannel

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// WakesPerSecond is the most check-in wakes the hub sends a second, whatever
// asked for them (ADR-0059, "What a wake makes the agent do"): a change that
// reaches many devices is spread over time instead of making them all check
// in at once.
const WakesPerSecond = 100

// Wake queues a check-in wake for the device: its agent checks in now
// instead of at its next heartbeat. It is for something the heartbeat
// answer carries that just became due, such as a setting. A device queued
// again before its wake went out is woken once. A device without a
// confirmed connection, or outside the dev scope, is not woken at all: its
// heartbeat finds the change. reason is for the agent's log.
func (h *Hub) Wake(device uuid.UUID, reason string) {
	if !h.Enabled() {
		return
	}
	h.wakeMu.Lock()
	if h.wakeSet == nil {
		h.wakeSet = map[uuid.UUID]string{}
	}
	if _, queued := h.wakeSet[device]; !queued {
		h.wakeQ = append(h.wakeQ, device)
	}
	h.wakeSet[device] = reason
	h.wakeMu.Unlock()
}

// nextWake pops the next queued device.
func (h *Hub) nextWake() (uuid.UUID, string, bool) {
	h.wakeMu.Lock()
	defer h.wakeMu.Unlock()
	if len(h.wakeQ) == 0 {
		return uuid.Nil, "", false
	}
	d := h.wakeQ[0]
	h.wakeQ = h.wakeQ[1:]
	reason := h.wakeSet[d]
	delete(h.wakeSet, d)
	return d, reason, true
}

// releaseWakes sends the queued wakes, at most WakesPerSecond a second.
func (h *Hub) releaseWakes(ctx context.Context) {
	t := time.NewTicker(time.Second / WakesPerSecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if d, reason, ok := h.nextWake(); ok {
			h.Push(d, agentproto.ChannelMessage{Type: agentproto.TypeWake, What: agentproto.WakeCheckin, Reason: reason})
		}
	}
}
