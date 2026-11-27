package logcollect

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/agent/winevents"
	"github.com/paulmataruso/easyrmm/internal/logblock"
)

// Channel is one Windows event channel the collector reads and the source
// its events are stored under.
type Channel struct {
	Name   string
	Source string
}

// DefaultChannels are the channels of the first collector (ADR-0060).
var DefaultChannels = []Channel{
	{"Security", "windows.security"},
	{"System", "windows.system"},
	{"Application", "windows.application"},
	{"Microsoft-Windows-Windows Defender/Operational", "windows.defender"},
	{"Microsoft-Windows-PowerShell/Operational", "windows.powershell"},
}

// WindowsChannel reads a channel through winevents; the cursor is the highest
// record ID read.
type WindowsChannel struct {
	Channel
	Src winevents.Source
}

// NewWindowsChannel reads c through the platform's reader.
func NewWindowsChannel(c Channel) *WindowsChannel {
	return &WindowsChannel{Channel: c, Src: winevents.NewChannelSource(c.Name)}
}

// Name implements Reader.
func (w *WindowsChannel) Name() string { return "winevent:" + w.Channel.Name }

// Read implements Reader.
func (w *WindowsChannel) Read(ctx context.Context, cursor string, since time.Time, limit int) ([]logblock.Event, string, error) {
	after, _ := strconv.ParseInt(cursor, 10, 64)
	res, err := w.Src.Read(ctx, winevents.Query{After: after, Since: since, Limit: limit})
	if err != nil {
		return nil, cursor, err
	}
	var evs []logblock.Event
	next := after
	for _, x := range res.Events {
		e, rec, err := ParseWindowsEvent(x, w.Source)
		if err != nil {
			continue
		}
		evs = append(evs, e)
		next = max(next, rec)
	}
	if next == after {
		return evs, cursor, nil
	}
	return evs, strconv.FormatInt(next, 10), nil
}

type eventDoc struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID struct {
			Value string `xml:",chardata"`
		} `xml:"EventID"`
		Level       int `xml:"Level"`
		Keywords    string
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		RecordID int64  `xml:"EventRecordID"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner string `xml:",innerxml"`
	} `xml:"UserData"`
}

// sensitiveNames are the data fields whose values are command lines and
// script text; they go to the event's sensitive fields.
var sensitiveNames = map[string]bool{
	"commandline": true, "scriptblocktext": true, "parentcommandline": true, "payload": true,
}

const auditFailure = 0x10000000000000

// ParseWindowsEvent turns an event's XML into an event stored under source,
// and its record ID.
func ParseWindowsEvent(x, source string) (logblock.Event, int64, error) {
	var d eventDoc
	if err := xml.Unmarshal([]byte(x), &d); err != nil {
		return logblock.Event{}, 0, err
	}
	t, err := time.Parse(time.RFC3339Nano, d.System.TimeCreated.SystemTime)
	if err != nil {
		return logblock.Event{}, 0, fmt.Errorf("event time: %w", err)
	}
	id := strings.TrimSpace(d.System.EventID.Value)
	e := logblock.Event{
		Time: t.UTC(), Source: source, ID: id, Level: windowsLevel(d.System.Level, d.System.Keywords),
		Message: strings.TrimSpace(d.System.Provider.Name + " event " + id),
		Fields:  map[string]string{"provider": d.System.Provider.Name, "record": strconv.FormatInt(d.System.RecordID, 10)},
	}
	if d.System.Computer != "" {
		e.Fields["computer"] = d.System.Computer
	}
	for _, v := range d.EventData.Data {
		name := v.Name
		if name == "" || strings.TrimSpace(v.Value) == "" {
			continue
		}
		if sensitiveNames[strings.ToLower(name)] {
			if e.Sensitive == nil {
				e.Sensitive = map[string]string{}
			}
			e.Sensitive[name] = v.Value
			continue
		}
		e.Fields[name] = v.Value
	}
	return e, d.System.RecordID, nil
}

func windowsLevel(level int, keywords string) string {
	switch level {
	case 1, 2:
		return "error"
	case 3:
		return "warn"
	case 5:
		return "debug"
	}
	if k, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(keywords), "0x"), 16, 64); err == nil && k&auditFailure != 0 {
		return "warn" // an audit failure, as in a failed sign-in
	}
	return "info"
}
