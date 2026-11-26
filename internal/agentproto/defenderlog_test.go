package agentproto

import (
	"strings"
	"testing"
	"time"
)

func logEvent(id int, rec int64) DefenderLogEvent {
	return DefenderLogEvent{RecordID: rec, EventID: id, At: time.Now().UTC()}
}

// A batch is bounded: only the event IDs the reader asks for, bounded text, and no more records than a heartbeat may carry.
func TestDefenderLogBatchCheck(t *testing.T) {
	ok := &DefenderLogBatch{Epoch: "e1", Through: 2, Events: []DefenderLogEvent{logEvent(1116, 1), logEvent(5007, 2)}}
	ok.Events[1].Sensitive = map[string]string{"oldValue": "x"}
	if err := ok.Check(); err != nil {
		t.Fatalf("a good batch was refused: %v", err)
	}
	long := strings.Repeat("a", MaxDefenderLogText+1)
	tooMany := &DefenderLogBatch{Epoch: "e"}
	for i := 0; i <= MaxDefenderLogEvents*4; i++ {
		tooMany.Events = append(tooMany.Events, logEvent(1116, int64(i+1)))
	}
	bad := map[string]*DefenderLogBatch{
		"no epoch":           {Events: []DefenderLogEvent{logEvent(1116, 1)}},
		"long epoch":         {Epoch: strings.Repeat("e", 65)},
		"too many records":   tooMany,
		"another event ID":   {Epoch: "e", Events: []DefenderLogEvent{logEvent(4624, 1)}},
		"no record ID":       {Epoch: "e", Events: []DefenderLogEvent{logEvent(1116, 0)}},
		"no time":            {Epoch: "e", Events: []DefenderLogEvent{{RecordID: 1, EventID: 1116}}},
		"a negative count":   {Epoch: "e", Events: []DefenderLogEvent{{RecordID: 1, EventID: 1116, At: time.Now(), Count: -1}}},
		"too many threats":   {Epoch: "e", Events: []DefenderLogEvent{{RecordID: 1, EventID: 1116, At: time.Now(), ThreatIDs: make([]string, MaxDefenderLogThreats+1)}}},
		"long text":          {Epoch: "e", Events: []DefenderLogEvent{{RecordID: 1, EventID: 1116, At: time.Now(), ThreatName: long}}},
		"long sensitive":     {Epoch: "e", Events: []DefenderLogEvent{{RecordID: 1, EventID: 1116, At: time.Now(), Sensitive: map[string]string{"path": strings.Repeat("p", MaxDefenderLogSensitive+1)}}}},
		"long sensitive key": {Epoch: "e", Events: []DefenderLogEvent{{RecordID: 1, EventID: 1116, At: time.Now(), Sensitive: map[string]string{strings.Repeat("k", 41): "x"}}}},
	}
	for name, b := range bad {
		if b.Check() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// The bytes of a batch are bounded too.
	big := &DefenderLogBatch{Epoch: "e"}
	for i := 0; i < MaxDefenderLogEvents*4; i++ {
		e := logEvent(1116, int64(i+1))
		e.Sensitive = map[string]string{"a": strings.Repeat("x", MaxDefenderLogSensitive), "b": strings.Repeat("x", MaxDefenderLogSensitive), "c": strings.Repeat("x", MaxDefenderLogSensitive)}
		big.Events = append(big.Events, e)
	}
	if big.Check() == nil {
		t.Error("a batch of over 48 KiB was accepted")
	}
}
