package eventrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// IDRange is one event ID or a range of them: To is 0 for a single ID.
type IDRange struct {
	From int `json:"from"`
	To   int `json:"to,omitempty"`
}

// The relative ranges a time filter takes.
var relativeRanges = map[string]time.Duration{
	"1h": time.Hour, "12h": 12 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
}

// TimeFilter is a relative range (Last: 1h, 12h, 24h, 7d or 30d), or a custom
// one in UTC (From and To, RFC 3339, either may be empty).
type TimeFilter struct {
	Last string `json:"last,omitempty"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// Window is the range as times, against now; zero for an open end.
func (t *TimeFilter) Window(now time.Time) (from, to time.Time) {
	if t == nil {
		return
	}
	if d, ok := relativeRanges[t.Last]; ok {
		return now.Add(-d), time.Time{}
	}
	from, _ = time.Parse(time.RFC3339, t.From)
	to, _ = time.Parse(time.RFC3339, t.To)
	return from, to
}

// ChannelCursor is where the next page of one channel starts: after Record.
// Created and Oldest are the log's creation time and oldest record number as
// the first page read them, to notice a log cleared or wrapped since.
type ChannelCursor struct {
	Channel string `json:"channel"`
	Record  int64  `json:"record"`
	Created string `json:"created,omitempty"`
	Oldest  int64  `json:"oldest,omitempty"`
	// Done says the channel ended: no page after this one reads it.
	Done bool `json:"done,omitempty"`
}

// Cursor is where the next page starts, per channel.
type Cursor struct {
	Channels []ChannelCursor `json:"channels"`
}

// For returns the channel's cursor, ignoring case.
func (c *Cursor) For(channel string) *ChannelCursor {
	if c == nil {
		return nil
	}
	for i := range c.Channels {
		if EqualFold(c.Channels[i].Channel, channel) {
			return &c.Channels[i]
		}
	}
	return nil
}

// Input is the input of the event viewer's builtin (version 1). The server
// writes it from typed filters; nobody sends XPath.
type Input struct {
	V     int    `json:"v"`
	Op    string `json:"op"`
	Rules int    `json:"rules"`
	// Sensitive says the person asked for sensitive data and may have it.
	Sensitive bool `json:"sensitive"`
	// Channels: one to ten for a query, one for an event; none otherwise.
	Channels []string `json:"channels,omitempty"`
	// Levels are 1 (critical) to 5 (verbose); Information is 4 and, as Event
	// Viewer counts it, 0.
	Levels     []int     `json:"levels,omitempty"`
	IDs        []IDRange `json:"ids,omitempty"`
	ExcludeIDs []IDRange `json:"excludeIds,omitempty"`
	Providers  []string  `json:"providers,omitempty"`
	Tasks      []int     `json:"tasks,omitempty"`
	// Keywords is a mask, decimal as a string so that no 64-bit value is
	// rounded by a JSON number.
	Keywords string      `json:"keywords,omitempty"`
	Time     *TimeFilter `json:"time,omitempty"`
	Text     string      `json:"text,omitempty"`
	Cursor   *Cursor     `json:"cursor,omitempty"`
	// Record is the event an "event" operation opens; Provider the one a
	// "provider" operation describes.
	Record   int64  `json:"record,omitempty"`
	Provider string `json:"provider,omitempty"`
}

// DecodeInput reads an input strictly: one JSON object, no unknown field,
// nothing after it.
func DecodeInput(b []byte) (Input, error) {
	var in Input
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return in, fmt.Errorf("%w: %w", ErrInput, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return in, fmt.Errorf("%w: more than one document", ErrInput)
	}
	return in, in.Check()
}

// KeywordMask parses the keyword filter.
func (in Input) KeywordMask() (uint64, bool) {
	if in.Keywords == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(in.Keywords, 10, 64)
	return v, err == nil
}

// Check applies the rules every field is held to: the server when a query is
// created, and the agent again against the rules it was built with. A
// Security channel is not an error here; Refusal says whether it is allowed.
func (in Input) Check() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInput, fmt.Sprintf(format, a...))
	}
	if in.V != InputVersion {
		return bad("version %d is not known", in.V)
	}
	switch in.Op {
	case OpChannels, OpQuery, OpEvent, OpProvider:
	default:
		return bad("operation %q is not known", in.Op)
	}
	hasFilters := len(in.Levels)+len(in.IDs)+len(in.ExcludeIDs)+len(in.Providers)+len(in.Tasks) > 0 ||
		in.Keywords != "" || in.Time != nil || in.Text != "" || in.Cursor != nil
	if in.Op != OpQuery && hasFilters {
		return bad("filters are for a query")
	}
	if in.Op != OpEvent && in.Record != 0 {
		return bad("only an event read names a record")
	}
	if in.Op != OpProvider && in.Provider != "" {
		return bad("only a provider read names a provider")
	}
	switch in.Op {
	case OpChannels:
		if len(in.Channels) > 0 || in.Provider != "" {
			return bad("a channel list names no channel")
		}
		return nil
	case OpProvider:
		if len(in.Channels) > 0 {
			return bad("a provider read names no channel")
		}
		if n := utf8.RuneCountInString(in.Provider); n < 1 || n > MaxProviderName || !utf8.ValidString(in.Provider) || strings.ContainsRune(in.Provider, 0) {
			return bad("a provider's name has 1 to %d characters", MaxProviderName)
		}
		return nil
	case OpEvent:
		if len(in.Channels) != 1 || in.Record < 1 {
			return bad("an event read names one channel and a record")
		}
	case OpQuery:
		if len(in.Channels) < 1 || len(in.Channels) > MaxChannelsQueried {
			return bad("a query reads 1 to %d channels", MaxChannelsQueried)
		}
	}
	for _, c := range in.Channels {
		if err := ValidChannel(c); err != nil {
			return err
		}
	}
	if len(DedupeChannels(in.Channels)) != len(in.Channels) {
		return bad("a channel is named twice")
	}
	if in.Op == OpEvent {
		return nil
	}
	for _, l := range in.Levels {
		if l < 0 || l > 5 {
			return bad("a level is 0 to 5")
		}
	}
	if len(in.Levels) > 6 {
		return bad("at most six levels")
	}
	for _, set := range [][]IDRange{in.IDs, in.ExcludeIDs} {
		if len(set) > MaxIDs {
			return bad("at most %d event IDs or ranges to include and %d to exclude", MaxIDs, MaxIDs)
		}
		for _, r := range set {
			if r.From < 0 || r.From > MaxEventID || r.To < 0 || r.To > MaxEventID || r.To != 0 && r.To < r.From {
				return bad("an event ID is 0 to %d and a range runs upward", MaxEventID)
			}
		}
	}
	if len(in.Providers) > MaxProviders {
		return bad("at most %d providers", MaxProviders)
	}
	for _, p := range in.Providers {
		if n := utf8.RuneCountInString(p); n < 1 || n > MaxProviderName || !utf8.ValidString(p) || strings.ContainsRune(p, 0) {
			return bad("a provider's name has 1 to %d characters", MaxProviderName)
		}
		if strings.Contains(p, `'`) && strings.Contains(p, `"`) {
			return bad("a provider's name holds both kinds of quote")
		}
	}
	if len(in.Tasks) > MaxTasks {
		return bad("at most %d task categories", MaxTasks)
	}
	if len(in.Tasks) > 0 && len(in.Providers) != 1 {
		return bad("a task category is chosen with exactly one provider")
	}
	for _, t := range in.Tasks {
		if t < 0 || t > 65535 {
			return bad("a task category is 0 to 65535")
		}
	}
	if in.Keywords != "" {
		if _, ok := in.KeywordMask(); !ok {
			return bad("the keyword mask is not a number")
		}
	}
	if t := in.Time; t != nil {
		if _, rel := relativeRanges[t.Last]; t.Last != "" && !rel {
			return bad("the time range is not known")
		} else if t.Last != "" && (t.From != "" || t.To != "") {
			return bad("a time range is relative or custom, not both")
		}
		var from, to time.Time
		var err error
		if t.From != "" {
			if from, err = time.Parse(time.RFC3339, t.From); err != nil {
				return bad("the start of the time range is not a time")
			}
		}
		if t.To != "" {
			if to, err = time.Parse(time.RFC3339, t.To); err != nil {
				return bad("the end of the time range is not a time")
			}
		}
		if !from.IsZero() && !to.IsZero() && to.Before(from) {
			return bad("the time range ends before it starts")
		}
	}
	if in.Text != "" {
		if n := utf8.RuneCountInString(in.Text); n < 1 || n > MaxText || !utf8.ValidString(in.Text) || strings.ContainsRune(in.Text, 0) {
			return bad("the text has 1 to %d characters", MaxText)
		}
	}
	if in.Cursor != nil {
		if len(in.Cursor.Channels) > MaxChannelsQueried {
			return bad("the cursor names too many channels")
		}
		for _, c := range in.Cursor.Channels {
			if ValidChannel(c.Channel) != nil || c.Record < 0 {
				return bad("the cursor is not valid")
			}
		}
	}
	return nil
}

// Refusal says why the caller may not have what the input asks for, or "".
// The Security log and its archives need sensitive data to be allowed.
func (in Input) Refusal() string {
	if in.Sensitive {
		return ""
	}
	for _, c := range in.Channels {
		if IsSecurity(c) {
			return "the Security log and its archives need permission to see the Security log"
		}
	}
	return ""
}
