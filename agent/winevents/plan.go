package winevents

import (
	"encoding/json"
	"slices"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// A storm is more than this many events with one ID in one query: the first
// stormKeep are sent whole and one summary stands for all of them.
const (
	stormMin  = 20
	stormKeep = 5
)

// aggregate coalesces storms in a run of events (ascending record IDs). No
// event is dropped: each is either in the output whole or counted in a
// summary that is, so the bookmark never passes what was not sent.
func aggregate(events []agentproto.DefenderLogEvent) []agentproto.DefenderLogEvent {
	byID := map[int][]int{}
	for i, e := range events {
		byID[e.EventID] = append(byID[e.EventID], i)
	}
	skip := map[int]bool{}
	summaries := map[int]agentproto.DefenderLogEvent{} // keyed by the index of the last event it stands for
	for _, idx := range byID {
		if len(idx) <= stormMin {
			continue
		}
		last := events[idx[len(idx)-1]]
		s := agentproto.DefenderLogEvent{
			RecordID: last.RecordID, EventID: last.EventID, At: last.At, Count: len(idx) - stormKeep,
			FirstRecord: events[idx[stormKeep]].RecordID, FirstAt: events[idx[stormKeep]].At,
			Severity: last.Severity, Action: last.Action,
		}
		seen := map[string]bool{}
		for _, i := range idx[stormKeep:] {
			skip[i] = true
			if id := events[i].ThreatID; id != "" && !seen[id] && len(s.ThreatIDs) < agentproto.MaxDefenderLogThreats {
				seen[id] = true
				s.ThreatIDs = append(s.ThreatIDs, id)
			}
		}
		summaries[idx[len(idx)-1]] = s
	}
	out := make([]agentproto.DefenderLogEvent, 0, len(events))
	for i, e := range events {
		if s, ok := summaries[i]; ok {
			out = append(out, s)
		}
		if !skip[i] {
			out = append(out, e)
		}
	}
	return out
}

func size(events []agentproto.DefenderLogEvent) int {
	b, _ := json.Marshal(events)
	return len(b)
}

// Plan builds a batch from events in record order: storms are summarized,
// and the batch is cut to the longest run of events whose records fit the
// caps (25 records, 24 KiB), so a backlog drains over several heartbeats.
// Through is the last record the batch covers. A run that needs more than the
// caps for even one event is sent as that event alone.
func Plan(events []agentproto.DefenderLogEvent) (batch []agentproto.DefenderLogEvent, through int64) {
	if len(events) == 0 {
		return nil, 0
	}
	fits := func(k int) bool {
		out := aggregate(events[:k])
		return len(out) <= agentproto.MaxDefenderLogEvents && size(out) <= agentproto.MaxDefenderLogBytes
	}
	k := len(events)
	if !fits(k) {
		k = max(1, sortSearch(len(events), fits))
	}
	out := aggregate(events[:k])
	slices.SortStableFunc(out, func(a, b agentproto.DefenderLogEvent) int {
		switch {
		case a.RecordID < b.RecordID:
			return -1
		case a.RecordID > b.RecordID:
			return 1
		}
		return 0
	})
	return out, events[k-1].RecordID
}

// sortSearch returns the largest k in [0, n] for which fits(k) holds, given
// that it holds for 0 and, once false, stays false.
func sortSearch(n int, fits func(int) bool) int {
	lo, hi := 0, n
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if fits(mid) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}
