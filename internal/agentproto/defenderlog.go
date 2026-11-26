package agentproto

import (
	"errors"
	"fmt"
	"time"
)

// The Defender event log, read by the agent and sent in the heartbeat
// (ADR-0074 section 7): a small, bounded batch of compact records, never the
// raw events. What names a path, a user or a changed setting goes in
// Sensitive; the server keeps it apart and shows it only to who may see it.

// Limits of a batch.
const (
	MaxDefenderLogEvents    = 25
	MaxDefenderLogBytes     = 24 << 10
	MaxDefenderLogText      = 200
	MaxDefenderLogSensitive = 300
	MaxDefenderLogThreats   = 20
)

// DefenderLogEventIDs are the Windows Defender Operational event IDs the
// reader asks for (ADR-0074 "Events collected"). Windows filters on them, so
// an event of any other ID is never rendered.
var DefenderLogEventIDs = []int{
	1000, 1001, 1002, 1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 1121,
	2000, 2001, 2002, 2003, 2006, 3002, 3007, 5000, 5001, 5004, 5007, 5008, 5009, 5010, 5011, 5012, 5013, 5100, 5101,
}

// DefenderLogEvent is one event, or (Count above one) the summary of a storm
// of events with the same ID.
type DefenderLogEvent struct {
	RecordID int64     `json:"recordId"`
	EventID  int       `json:"eventId"`
	At       time.Time `json:"at"`
	// Severity is the event's own severity name (Low, Moderate, High,
	// Severe), for detections.
	Severity   string `json:"severity,omitempty"`
	ThreatID   string `json:"threatId,omitempty"`
	ThreatName string `json:"threatName,omitempty"`
	Category   string `json:"category,omitempty"`
	Action     string `json:"action,omitempty"`
	Origin     string `json:"origin,omitempty"`
	Source     string `json:"source,omitempty"`
	ErrorCode  string `json:"errorCode,omitempty"`
	EngineVer  string `json:"engineVersion,omitempty"`
	SigVer     string `json:"signatureVersion,omitempty"`
	// Sensitive holds the path, user name, process name and the old and new
	// value of a configuration change.
	Sensitive map[string]string `json:"sensitive,omitempty"`
	// Summary fields: a storm of Count events from FirstRecord to RecordID,
	// first at FirstAt and last at At, with the distinct threat IDs seen.
	Count       int       `json:"count,omitempty"`
	FirstRecord int64     `json:"firstRecord,omitempty"`
	FirstAt     time.Time `json:"firstAt,omitempty"`
	ThreatIDs   []string  `json:"threatIds,omitempty"`
	Truncated   bool      `json:"truncated,omitempty"`
}

// DefenderLogBatch is what a heartbeat carries of the log: events after the
// last acknowledged record, in record order.
type DefenderLogBatch struct {
	// Epoch names this incarnation of the log: record IDs are unique within
	// it. A cleared log starts a new one.
	Epoch string `json:"epoch"`
	// Gap says records may have been missed (the log was cleared or wrapped
	// past the bookmark).
	Gap bool `json:"gap,omitempty"`
	// Backfill marks the first read of a log, which the server stores but
	// raises alerts from only for recent events.
	Backfill bool `json:"backfill,omitempty"`
	// Through is the highest record ID the batch covers (events and
	// summaries), which the agent's bookmark moves to once it is acknowledged.
	Through int64              `json:"through"`
	Events  []DefenderLogEvent `json:"events"`
}

// DefenderLogAck is the server's acknowledgement: the highest record ID of an
// epoch it stored. The agent resends from there.
type DefenderLogAck struct {
	Epoch    string `json:"epoch"`
	RecordID int64  `json:"recordId"`
}

// Check refuses a batch that is too large, has an event the reader never
// asks for, or holds text beyond its bounds.
func (b *DefenderLogBatch) Check() error {
	if len(b.Epoch) == 0 || len(b.Epoch) > 64 {
		return errors.New("the log epoch is missing or too long")
	}
	if len(b.Events) > MaxDefenderLogEvents*4 {
		return fmt.Errorf("a batch holds at most %d records", MaxDefenderLogEvents*4)
	}
	allowed := map[int]bool{}
	for _, id := range DefenderLogEventIDs {
		allowed[id] = true
	}
	size := 0
	for i, e := range b.Events {
		switch {
		case !allowed[e.EventID]:
			return fmt.Errorf("event %d is not one the reader collects", e.EventID)
		case e.RecordID < 1 || e.At.IsZero():
			return fmt.Errorf("record %d has no ID or time", i)
		case e.Count < 0 || e.Count > 1<<20 || len(e.ThreatIDs) > MaxDefenderLogThreats:
			return fmt.Errorf("record %d has a bad count", i)
		}
		for _, s := range []string{e.Severity, e.ThreatID, e.ThreatName, e.Category, e.Action, e.Origin, e.Source, e.ErrorCode, e.EngineVer, e.SigVer} {
			if len(s) > MaxDefenderLogText {
				return fmt.Errorf("record %d has text over %d bytes", i, MaxDefenderLogText)
			}
			size += len(s)
		}
		for k, v := range e.Sensitive {
			if len(k) > 40 || len(v) > MaxDefenderLogSensitive {
				return fmt.Errorf("record %d has sensitive text over %d bytes", i, MaxDefenderLogSensitive)
			}
			size += len(k) + len(v)
		}
		size += 128 + 40*len(e.ThreatIDs)
	}
	if size > MaxDefenderLogBytes*2 {
		return errors.New("the batch is too large")
	}
	return nil
}
