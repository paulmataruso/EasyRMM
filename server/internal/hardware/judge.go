package hardware

import (
	"fmt"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/inventory"
)

// States of a disk or a fact as the server and the console carry them. A
// judged fact or reading is healthy, warning, failing (the last two are
// unhealthy, with their level), unknown, unsupported or unavailable; a fact
// EasyRMM does not judge, once read, is reported.
const (
	StateHealthy     = "healthy"
	StateWarning     = "warning"
	StateFailing     = "failing"
	StateUnknown     = "unknown"
	StateUnsupported = "unsupported"
	StateUnavailable = "unavailable"
	StateReported    = "reported"
)

// Rules: why a fact or a reading is unhealthy, as the console names them.
const (
	RuleCriticalWarning  = "critical_warning"
	RuleSMARTStatus      = "smart_status"
	RulePreFailAttribute = "prefail_attribute"
	RuleAttribute        = "attribute"
	RuleTemperature      = "temperature"
	RuleWear             = "wear"
	RuleMediaErrors      = "media_errors"
	RuleReallocated      = "reallocated_sectors"
	RulePending          = "pending_sectors"
	RuleUncorrectable    = "uncorrectable_sectors"
)

// WearLimit is the percentage of rated endurance used at which a disk is a
// warning.
const WearLimit = 90

// maxJudgedDetail bounds what a reading's detail says.
const maxJudgedDetail = 500

// failingBits are the NVMe critical warning bits that mean failing: spare
// below its threshold (0), reliability degraded (2), media read-only (3) and
// volatile memory backup failed (4). Every other bit is a warning: the
// temperature (1), the persistent memory region (5), and those the
// specification reserves today (6 and 7), which a newer drive may use.
const failingBits = 1<<0 | 1<<2 | 1<<3 | 1<<4

// criticalWarningBits names each bit of the NVMe critical warning.
var criticalWarningBits = [8]string{
	"available spare below its threshold", "temperature", "reliability degraded", "media read-only",
	"volatile memory backup failed", "persistent memory region read-only or unreliable", "bit 6 (reserved)", "bit 7 (reserved)",
}

// FactView is one fact of a reading as the console shows it: its state,
// why, and its value when it was read.
type FactView struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	Value  *int64 `json:"value"`
}

// AttributeView is one ATA SMART attribute, judged against its threshold
// when the thresholds were read (else reported).
type AttributeView struct {
	agentproto.Attribute
	PreFail bool   `json:"preFail"`
	State   string `json:"state"`
}

// reading is one disk's reading, judged: its state (its level, or the disk
// as a whole when it was not read), why, and what each fact is.
type reading struct {
	state, reason string
	// detail says in words what made the reading warning or failing.
	detail string
	// read: the disk was read, so facts and attributes hold what it said;
	// judged: the drive's verdict was among it.
	read, judged bool
	facts        []FactView
	attributes   []AttributeView
	sample       sample
}

// sample is what a reading adds to the disk's history: each value when it
// was read, else nil.
type sample struct {
	temperature, temperatureLimit, wear              *int64
	reallocated, mediaErrors, pending, uncorrectable *int64
	driveErrors, powerOnHours                        *int64
}

// rank orders levels from worst: a reading's level is its worst judged
// fact's.
var rank = map[string]int{StateFailing: 3, StateWarning: 2, StateUnknown: 1, StateHealthy: 0}

// finding is one judged fact's verdict.
type finding struct {
	level, reason, text string
}

// judgement collects a reading's findings.
type judgement struct {
	findings []finding
}

func (j *judgement) add(level, reason, text string) {
	j.findings = append(j.findings, finding{level, reason, text})
}

// worst returns the reading's level, the first reason found at it, and in
// words every finding at that level when it is warning or failing.
func (j *judgement) worst() (level, reason, detail string) {
	level = StateHealthy
	for _, f := range j.findings {
		if rank[f.level] > rank[level] {
			level, reason = f.level, f.reason
		}
	}
	if level != StateWarning && level != StateFailing {
		return level, reason, ""
	}
	var texts []string
	for _, f := range j.findings {
		if f.level == level {
			texts = append(texts, f.text)
		}
	}
	return level, reason, strings.Join(texts, "; ")
}

// judge applies the server's rules (ADR-0065, "The disk's state: the
// server's rules") to a cleaned reading. A disk whose verdict could not be
// read is unknown (no_verdict), never healthy, whatever else was read; a
// fact the drive does not keep (unsupported, unavailable) is left out of
// the level, and a judged fact that could not be read makes it unknown.
func judge(d *agentproto.DiskHealth) reading {
	if d.State != agentproto.FactRead {
		return reading{state: d.State, reason: d.Reason}
	}
	r := reading{read: true}
	var j judgement
	views := map[string]*FactView{}
	for _, def := range factDefs {
		f := def.get(d)
		v := &FactView{Name: def.name, State: f.State, Reason: f.Reason, Value: f.Value}
		if f.State == agentproto.FactRead {
			v.State = StateReported
		}
		views[def.name] = v
		r.facts = append(r.facts, *v) // replaced below once judged
	}
	// set marks a judged fact's state.
	set := func(name, state, reason string) {
		views[name].State, views[name].Reason = state, reason
	}
	read := func(f agentproto.Fact) (int64, bool) {
		if f.State == agentproto.FactRead && f.Value != nil {
			return *f.Value, true
		}
		return 0, false
	}
	// unreadable makes a judged fact the drive keeps but could not give
	// make the reading unknown.
	unreadable := func(f agentproto.Fact) {
		if f.State == agentproto.FactUnknown {
			j.add(StateUnknown, f.Reason, "")
		}
	}

	// The drive's verdict.
	switch d.Protocol {
	case agentproto.ProtocolNVMe:
		if cw, ok := read(d.CriticalWarning); ok {
			r.judged = true
			switch {
			case cw&failingBits != 0:
				j.add(StateFailing, RuleCriticalWarning, "NVMe critical warning: "+bitNames(cw&failingBits))
				set("criticalWarning", StateFailing, RuleCriticalWarning)
			case cw != 0:
				j.add(StateWarning, RuleCriticalWarning, "NVMe critical warning: "+bitNames(cw))
				set("criticalWarning", StateWarning, RuleCriticalWarning)
			default:
				set("criticalWarning", StateHealthy, "")
			}
		}
	case agentproto.ProtocolATA:
		if st, ok := read(d.SMARTStatus); ok {
			r.judged = true
			if st == agentproto.SMARTThresholdExceeded {
				j.add(StateFailing, RuleSMARTStatus, "SMART status: threshold exceeded")
				set("smartStatus", StateFailing, RuleSMARTStatus)
			} else {
				set("smartStatus", StateHealthy, "")
			}
		} else {
			// A path that does not return the registers reports the status
			// unavailable, and the attributes give the verdict; a status
			// or thresholds that could not be read this time leave the
			// reading unknown.
			unreadable(d.SMARTStatus)
		}
		unreadable(d.Thresholds)
		thresholds := d.Thresholds.State == agentproto.FactRead
		if thresholds && len(d.Attributes) > 0 {
			// The attributes against their thresholds are the verdict where
			// the status could not be read.
			r.judged = true
		}
		var preFail, other []string
		for _, a := range d.Attributes {
			av := AttributeView{Attribute: a, PreFail: a.PreFail(), State: StateReported}
			if thresholds && a.Threshold != nil {
				av.State = StateHealthy
				if t := *a.Threshold; t != 0 && a.Value <= t {
					if a.PreFail() {
						av.State, preFail = StateFailing, append(preFail, fmt.Sprint(a.ID))
					} else {
						av.State, other = StateWarning, append(other, fmt.Sprint(a.ID))
					}
				}
			}
			r.attributes = append(r.attributes, av)
		}
		if len(preFail) > 0 {
			j.add(StateFailing, RulePreFailAttribute, "pre-fail attribute "+strings.Join(preFail, ", ")+" at or below its threshold")
		}
		if len(other) > 0 {
			j.add(StateWarning, RuleAttribute, "attribute "+strings.Join(other, ", ")+" at or below its threshold")
		}
	}
	if !r.judged {
		j.add(StateUnknown, agentproto.ReasonNoVerdict, "")
	}

	// Temperature, against the drive's own limit. Without a limit it is
	// reported, not judged; a limit that could not be read leaves it
	// unknown.
	if t, ok := read(d.Temperature); ok {
		limit, hasLimit := read(d.TemperatureLimit)
		switch {
		case hasLimit && limit > 0 && t >= limit:
			j.add(StateWarning, RuleTemperature, fmt.Sprintf("%d °C, at or over the drive's limit of %d °C", t, limit))
			set("temperature", StateWarning, RuleTemperature)
		case hasLimit && limit > 0:
			set("temperature", StateHealthy, "")
		case d.TemperatureLimit.State == agentproto.FactUnknown:
			j.add(StateUnknown, d.TemperatureLimit.Reason, "")
			set("temperature", StateUnknown, d.TemperatureLimit.Reason)
		}
	} else {
		unreadable(d.Temperature)
	}

	// Counts and wear.
	for _, c := range []struct {
		name, rule string
		f          agentproto.Fact
		over       func(int64) bool
		text       func(int64) string
	}{
		{"wear", RuleWear, d.Wear, func(v int64) bool { return v >= WearLimit },
			func(v int64) string { return fmt.Sprintf("%d%% of rated endurance used", v) }},
		{"mediaErrors", RuleMediaErrors, d.MediaErrors, func(v int64) bool { return v > 0 },
			func(v int64) string { return fmt.Sprintf("NVMe media errors %d", v) }},
		{"reallocatedSectors", RuleReallocated, d.ReallocatedSectors, func(v int64) bool { return v > 0 },
			func(v int64) string { return fmt.Sprintf("reallocated sectors %d", v) }},
		{"pendingSectors", RulePending, d.PendingSectors, func(v int64) bool { return v > 0 },
			func(v int64) string { return fmt.Sprintf("pending sectors %d", v) }},
		{"uncorrectableSectors", RuleUncorrectable, d.UncorrectableSectors, func(v int64) bool { return v > 0 },
			func(v int64) string { return fmt.Sprintf("uncorrectable sectors %d", v) }},
	} {
		v, ok := read(c.f)
		switch {
		case !ok:
			unreadable(c.f)
		case c.over(v):
			j.add(StateWarning, c.rule, c.text(v))
			set(c.name, StateWarning, c.rule)
		default:
			set(c.name, StateHealthy, "")
		}
	}

	r.state, r.reason, r.detail = j.worst()
	if !r.judged {
		// Healthy needs the verdict: without it the reading is unknown,
		// though its facts keep what each says.
		r.state, r.reason, r.detail = StateUnknown, agentproto.ReasonNoVerdict, ""
	}
	if len(r.detail) > 0 {
		// Within what the database keeps (judged_detail).
		r.detail = inventory.Text(strings.ToUpper(r.detail[:1])+r.detail[1:], maxJudgedDetail)
	}
	for i := range r.facts {
		r.facts[i] = *views[r.facts[i].Name]
	}
	r.sample = sample{
		temperature: value(d.Temperature), wear: value(d.Wear),
		reallocated: value(d.ReallocatedSectors), mediaErrors: value(d.MediaErrors),
		pending: value(d.PendingSectors), uncorrectable: value(d.UncorrectableSectors),
		driveErrors: value(d.DriveErrors), powerOnHours: value(d.PowerOnHours),
	}
	if l := value(d.TemperatureLimit); l != nil && *l > 0 {
		r.sample.temperatureLimit = l
	}
	return r
}

// value is a fact's value when it was read.
func value(f agentproto.Fact) *int64 {
	if f.State == agentproto.FactRead {
		return f.Value
	}
	return nil
}

// bitNames names the set bits of an NVMe critical warning.
func bitNames(cw int64) string {
	var names []string
	for i, n := range criticalWarningBits {
		if cw&(1<<i) != 0 {
			names = append(names, n)
		}
	}
	return strings.Join(names, ", ")
}
