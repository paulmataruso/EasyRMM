package hardware

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/inventory"
)

// maxCount bounds every count: 2⁶².
const maxCount = int64(1) << 62

// factDef is one fact of a disk's reading: its name in the report and the
// console, the physical bounds of its value, and where it is.
type factDef struct {
	name   string
	lo, hi int64
	get    func(*agentproto.DiskHealth) *agentproto.Fact
}

// factDefs are a reading's facts in the order the console lists them.
var factDefs = []factDef{
	{"criticalWarning", 0, 255, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.CriticalWarning }},
	{"smartStatus", 0, 1, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.SMARTStatus }},
	{"thresholds", 0, 0, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.Thresholds }},
	{"temperature", -40, 150, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.Temperature }},
	{"temperatureLimit", -40, 150, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.TemperatureLimit }},
	{"wear", 0, 255, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.Wear }},
	{"availableSpare", 0, 255, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.AvailableSpare }},
	{"availableSpareThreshold", 0, 255, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.AvailableSpareThreshold }},
	{"mediaErrors", 0, maxCount, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.MediaErrors }},
	{"reallocatedSectors", 0, maxCount, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.ReallocatedSectors }},
	{"pendingSectors", 0, maxCount, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.PendingSectors }},
	{"uncorrectableSectors", 0, maxCount, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.UncorrectableSectors }},
	{"driveErrors", 0, maxCount, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.DriveErrors }},
	{"powerOnHours", 0, maxCount, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.PowerOnHours }},
	{"dataWritten", 0, maxCount, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.DataWritten }},
	{"unsafeShutdowns", 0, maxCount, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.UnsafeShutdowns }},
	{"powerMode", 0, 255, func(d *agentproto.DiskHealth) *agentproto.Fact { return &d.PowerMode }},
}

// invalid is what the server makes of a state, reason or value it cannot
// take.
var invalid = agentproto.NotRead(agentproto.FactUnknown, agentproto.ReasonInvalidReport)

// cleanFact keeps a fact with a known state and reason and a value within
// [lo, hi]; anything else becomes unknown (invalid_report). Thresholds
// carries no value.
func cleanFact(f *agentproto.Fact, lo, hi int64) {
	switch f.State {
	case agentproto.FactRead:
		f.Reason = ""
		if lo == 0 && hi == 0 {
			f.Value = nil
			return
		}
		if f.Value == nil || *f.Value < lo || *f.Value > hi {
			*f = invalid
		}
	case agentproto.FactUnknown, agentproto.FactUnsupported, agentproto.FactUnavailable:
		f.Value = nil
		if !agentproto.KnownReason(f.Reason) {
			*f = invalid
		}
	default:
		*f = invalid
	}
}

// routes are the ways a disk may have answered (DiskHealth.Route).
var routes = map[string]bool{"device": true, "adapter": true, "ata": true, "nvme": true, "sg": true}

// maxClockSkew is how far a reading's time may be from the server's before
// the server takes its own: the agent's clock is only shown.
const maxClockSkew = 24 * time.Hour

// clean makes a report's disks safe to store and judge, as cleanInventory
// does for the inventory: names, models and serials cleaned as the
// inventory's are, text cut to size, unknown states and reasons made
// unknown (invalid_report), values held to physical bounds, at most
// MaxListed disks and MaxAttributes attributes each. Disks without a name
// are dropped.
func clean(in []agentproto.DiskHealth, received time.Time) []agentproto.DiskHealth {
	out := make([]agentproto.DiskHealth, 0, min(len(in), agentproto.MaxListed))
	for _, d := range in {
		if len(out) == agentproto.MaxListed {
			break
		}
		d.Name, d.Model, d.Serial = inventory.DiskIdentity(d.Name, d.Model, d.Serial)
		if d.Name == "" {
			continue
		}
		d.Detail = text(d.Detail, agentproto.MaxHardwareDetail)
		if !routes[d.Route] {
			d.Route = ""
		}
		if d.ReadAt.IsZero() || d.ReadAt.Sub(received).Abs() > maxClockSkew {
			d.ReadAt = received
		}
		switch d.State {
		case agentproto.FactRead:
			d.Reason = ""
			if d.Protocol != agentproto.ProtocolNVMe && d.Protocol != agentproto.ProtocolATA {
				d.State, d.Reason = agentproto.FactUnknown, agentproto.ReasonInvalidReport
			}
		case agentproto.FactUnknown, agentproto.FactUnsupported, agentproto.FactUnavailable:
			if !agentproto.KnownReason(d.Reason) {
				d.State, d.Reason = agentproto.FactUnknown, agentproto.ReasonInvalidReport
			}
		default:
			d.State, d.Reason = agentproto.FactUnknown, agentproto.ReasonInvalidReport
		}
		if d.State != agentproto.FactRead {
			// A disk not read has no facts to keep.
			out = append(out, agentproto.DiskHealth{
				Name: d.Name, Model: d.Model, Serial: d.Serial, State: d.State, Reason: d.Reason,
				Detail: d.Detail, Route: d.Route, ReadAt: d.ReadAt,
			})
			continue
		}
		for _, def := range factDefs {
			cleanFact(def.get(&d), def.lo, def.hi)
		}
		d.Attributes = cleanAttributes(d.Attributes)
		out = append(out, d)
	}
	return out
}

// cleanAttributes keeps the first MaxAttributes attributes with an ID,
// each ID once, raw values held to 48 bits.
func cleanAttributes(in []agentproto.Attribute) []agentproto.Attribute {
	out := []agentproto.Attribute{}
	seen := map[uint8]bool{}
	for _, a := range in {
		if len(out) == agentproto.MaxAttributes {
			break
		}
		if a.ID == 0 || seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		a.Raw &= 1<<48 - 1
		out = append(out, a)
	}
	return out
}

// text strips control characters and invalid UTF-8, and cuts to maxRunes.
func text(s string, maxRunes int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxRunes {
		s = strings.TrimSpace(string([]rune(s)[:maxRunes]))
	}
	return s
}
