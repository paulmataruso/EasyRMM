// Package winevents reads the Windows event logs the agent forwards. This
// first user is Microsoft Defender's Operational log (ADR-0074 section 7):
// one query on one channel with a bookmark, compact bounded records, storms
// counted rather than dropped, and the server's acknowledgement before the
// bookmark moves. The log is read through the Source interface; the Windows
// implementation is in source_windows.go and everything else is tested
// everywhere.
package winevents

import (
	"encoding/xml"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

type eventXML struct {
	System struct {
		EventID       int `xml:"EventID"`
		EventRecordID int64
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// recordIDXML reads <EventRecordID> (the struct tag cannot sit on a field
// of the anonymous struct above without changing its zero value).
type recordIDXML struct {
	System struct {
		EventRecordID int64 `xml:"EventRecordID"`
	} `xml:"System"`
}

// Field names Defender writes in an event's data, by lower-case name. The
// names are those of Microsoft's event pages; "to confirm against real
// events" (ADR-0074 R5, R8).
var plainFields = map[string]func(*agentproto.DefenderLogEvent, string){
	"threat id":                     func(e *agentproto.DefenderLogEvent, v string) { e.ThreatID = v },
	"threat name":                   func(e *agentproto.DefenderLogEvent, v string) { e.ThreatName = v },
	"severity name":                 func(e *agentproto.DefenderLogEvent, v string) { e.Severity = v },
	"category name":                 func(e *agentproto.DefenderLogEvent, v string) { e.Category = v },
	"action name":                   func(e *agentproto.DefenderLogEvent, v string) { e.Action = v },
	"origin name":                   func(e *agentproto.DefenderLogEvent, v string) { e.Origin = v },
	"detection origin":              func(e *agentproto.DefenderLogEvent, v string) { e.Origin = v },
	"source name":                   func(e *agentproto.DefenderLogEvent, v string) { e.Source = v },
	"detection source":              func(e *agentproto.DefenderLogEvent, v string) { e.Source = v },
	"error code":                    func(e *agentproto.DefenderLogEvent, v string) { e.ErrorCode = v },
	"engine version":                func(e *agentproto.DefenderLogEvent, v string) { e.EngineVer = v },
	"security intelligence version": func(e *agentproto.DefenderLogEvent, v string) { e.SigVer = v },
	"signature version":             func(e *agentproto.DefenderLogEvent, v string) { e.SigVer = v },
}

// sensitiveFields are what names a path, a user, a process or the setting a
// change touched; they never go in the fields above.
var sensitiveFields = map[string]string{
	"path":           "path",
	"detection user": "user",
	"user":           "user",
	"process name":   "process",
	"old value":      "oldValue",
	"new value":      "newValue",
}

// ErrNotEvent is XML that is not a rendered event.
var ErrNotEvent = errors.New("winevents: not a rendered event")

// clip cuts text to n bytes on a character boundary.
func clip(s string, n int) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s, false
	}
	s = s[:n]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s, true
}

// Parse turns one rendered event (EvtRenderEventXml) into a compact record:
// ID, record ID, time and the fields of the event, each bounded. A record
// stays within the limits of agentproto.Check (about 1 KiB).
func Parse(raw string) (agentproto.DefenderLogEvent, error) {
	var x eventXML
	var rid recordIDXML
	if err := xml.Unmarshal([]byte(raw), &x); err != nil {
		return agentproto.DefenderLogEvent{}, ErrNotEvent
	}
	if err := xml.Unmarshal([]byte(raw), &rid); err != nil || x.System.EventID == 0 || rid.System.EventRecordID == 0 {
		return agentproto.DefenderLogEvent{}, ErrNotEvent
	}
	at, err := time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime)
	if err != nil {
		return agentproto.DefenderLogEvent{}, ErrNotEvent
	}
	e := agentproto.DefenderLogEvent{RecordID: rid.System.EventRecordID, EventID: x.System.EventID, At: at.UTC()}
	for _, d := range x.EventData.Data {
		name := strings.ToLower(strings.TrimSpace(d.Name))
		value := strings.TrimSpace(d.Value)
		if value == "" {
			continue
		}
		if set, ok := plainFields[name]; ok {
			v, cut := clip(value, 120)
			set(&e, v)
			e.Truncated = e.Truncated || cut
		} else if key, ok := sensitiveFields[name]; ok {
			if e.Sensitive == nil {
				e.Sensitive = map[string]string{}
			}
			v, cut := clip(value, agentproto.MaxDefenderLogSensitive)
			e.Sensitive[key] = v
			e.Truncated = e.Truncated || cut
		}
	}
	return e, nil
}

// SeverityRank maps a severity name to the number the alert threshold uses:
// 1 Low, 2 Moderate, 4 High, 5 Severe; 0 for a name it does not know.
func SeverityRank(name string) int {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "low":
		return 1
	case "moderate", "medium":
		return 2
	case "high":
		return 4
	case "severe", "critical":
		return 5
	}
	if n, err := strconv.Atoi(name); err == nil && n >= 0 && n <= 5 {
		return n
	}
	return 0
}
