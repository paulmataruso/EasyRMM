// Package eventrules is the one set of rules the event viewer's server and
// agent share (ADR-0068): the event model, which channels and fields are
// sensitive, how a channel name is checked, how a query is built from typed
// filters, and the input and result of each version of the builtin. It is
// compiled into both, so that the two checks cannot read an event
// differently. A server and an agent of different releases may carry
// different rules; a result names the Version it used.
package eventrules

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Version is the version of these rules, carried by every result.
const Version = 1

// Versions of the builtin's input and result.
const (
	InputVersion  = 1
	ResultVersion = 1
)

// Operations of the builtin, as of input version 1. Slice 2 adds summary and
// export, with input version 2.
const (
	OpChannels = "channels"
	OpQuery    = "query"
	OpEvent    = "event"
	OpProvider = "provider"
)

// Limits (ADR-0068, Bounds and Filters).
const (
	MaxChannelsQueried = 10
	MaxChannelName     = 255
	MaxIDs             = 32
	MaxProviders       = 16
	MaxTasks           = 16
	MaxProviderName    = 255
	MaxText            = 256
	PageEvents         = 100
	PageBytes          = 1792 * 1024 // 1.75 MiB of event lines
	MaxRead            = 100000      // events read per page
	QuerySeconds       = 45
	InfoSeconds        = 30
	PageLineBytes      = 32 << 10
	EventLineBytes     = 3 << 19 // 1.5 MiB
	MaxValues          = 256
	MaxChannelList     = 5000
	MaxEventID         = 65535
)

// Cuts applied to a line over its budget (ADR-0068, Bounds): the message and
// each value, in a page and for one event.
const (
	PageMessageChars  = 4096
	PageValueChars    = 1024
	EventMessageChars = 256 << 10
	EventValueChars   = 64 << 10
	// CutMarker ends a value or a message that was cut. It is added to the
	// fields and the XML alike, so that the server's comparison holds.
	CutMarker = "…[cut]"
)

// HiddenMarker replaces a value the caller may not see, in the fields and in
// the XML.
const HiddenMarker = "[hidden: needs permission to see command lines and scripts]"

// Errors of the rules.
var (
	ErrChannel = errors.New("eventrules: not a channel name")
	ErrInput   = errors.New("eventrules: the event log input is not valid")
)

// Fold is the form of a channel or provider name that is compared: Unicode
// simple case folding, as the server and the agent both do.
func Fold(s string) string {
	var b strings.Builder
	for _, r := range s {
		// SimpleFold cycles through the orbit; the smallest member is a
		// stable representative.
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < m {
				m = f
			}
		}
		b.WriteRune(m)
	}
	return b.String()
}

// EqualFold reports whether two names are the same ignoring case.
func EqualFold(a, b string) bool { return Fold(a) == Fold(b) }

// ValidChannel checks a channel name against the characters Windows
// refuses; it does not say whether the channel exists.
func ValidChannel(name string) error {
	n := utf8.RuneCountInString(name)
	if n < 1 || n > MaxChannelName || !utf8.ValidString(name) {
		return fmt.Errorf("%w: a name has 1 to %d characters", ErrChannel, MaxChannelName)
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("%w: it starts or ends with a space", ErrChannel)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`<>"|\*?`, r) {
			return fmt.Errorf("%w: it holds a character Windows refuses", ErrChannel)
		}
	}
	return nil
}

// DedupeChannels returns the names with those that are the same ignoring
// case removed, keeping the first spelling and the order.
func DedupeChannels(names []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(names))
	for _, n := range names {
		f := Fold(n)
		if !seen[f] {
			seen[f] = true
			out = append(out, n)
		}
	}
	return out
}

// IsSecurity reports whether a channel is the Security log or one of its
// archives (Archive-Security-*): what needs log.view_sensitive whole.
func IsSecurity(channel string) bool {
	f := Fold(channel)
	return f == Fold("Security") || strings.HasPrefix(f, Fold("Archive-Security-"))
}

// Sensitive field names, matched on a leaf name in any provider (ADR-0068,
// What needs log.view_sensitive; ADR-0060's list, plus the fields added).
var sensitiveEverywhere = map[string]bool{}

func init() {
	for _, n := range []string{
		"CommandLine", "ParentCommandLine", "ScriptBlockText", "TaskContent", "TaskContentNew",
		"ImagePath", "ServiceFileName", "CONSUMER", "PossibleCause", "Query", "Destination",
		// PowerShell module logging, 4103.
		"Payload", "ContextInfo",
	} {
		sensitiveEverywhere[Fold(n)] = true
	}
}

// providerFields are the names common enough elsewhere that they count only
// within their own provider (ADR-0068, Fields added to the list): a
// provider's name is matched by its fold and a substring.
var providerFields = []struct{ provider, field string }{
	{"Shell-Core", "Command"},
	{"Sysmon", "Details"},
	{"Bits-Client", "url"},
}

// classicLogs are logs whose events keep the host's command line in unnamed
// values, so every value of every event in them is sensitive.
var classicLogs = []string{"Windows PowerShell"}

// SensitiveField reports whether the value of the named field is sensitive
// in an event of the channel and provider. An unnamed value has the name "".
func SensitiveField(channel, provider, name string) bool {
	f := Fold(name)
	if f != "" && sensitiveEverywhere[f] {
		return true
	}
	if f != "" {
		fp := Fold(provider)
		for _, p := range providerFields {
			if f == Fold(p.field) && strings.Contains(fp, Fold(p.provider)) {
				return true
			}
		}
	}
	for _, c := range classicLogs {
		if EqualFold(channel, c) {
			return true
		}
	}
	return false
}

// ContainsFold reports whether hay holds needle, ignoring case, as the text
// filter matches: a substring, never a pattern.
func ContainsFold(hay, needle string) bool {
	return strings.Contains(Fold(hay), Fold(needle))
}
