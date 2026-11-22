package hardware

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

var (
	read     = agentproto.Read
	notKept  = agentproto.NotRead(agentproto.FactUnsupported, agentproto.ReasonNotKept)
	timedOut = agentproto.NotRead(agentproto.FactUnknown, agentproto.ReasonTimeout)
)

// nvme is a healthy NVMe reading with every fact a drive keeps.
func nvme() agentproto.DiskHealth {
	return agentproto.DiskHealth{
		Name: "nvme0n1", Model: "Example NVMe 1TB", Serial: "S1", State: agentproto.FactRead, Protocol: agentproto.ProtocolNVMe,
		Route: "nvme", CriticalWarning: read(0), SMARTStatus: notKept, Thresholds: notKept,
		Temperature: read(40), TemperatureLimit: read(70), Wear: read(3), AvailableSpare: read(100), AvailableSpareThreshold: read(10),
		MediaErrors: read(0), ReallocatedSectors: notKept, PendingSectors: notKept, UncorrectableSectors: notKept,
		DriveErrors: read(0), PowerOnHours: read(1200), DataWritten: read(5000), UnsafeShutdowns: read(4), PowerMode: notKept,
	}
}

// ata is a healthy ATA reading with two attributes and their thresholds.
func ata() agentproto.DiskHealth {
	t5, t197 := uint8(36), uint8(0)
	return agentproto.DiskHealth{
		Name: "sda", Model: "Example SSD 500GB", Serial: "A1", State: agentproto.FactRead, Protocol: agentproto.ProtocolATA,
		Route: "sg", CriticalWarning: notKept, SMARTStatus: read(agentproto.SMARTPassed), Thresholds: read(0),
		Temperature: read(35), TemperatureLimit: read(60), Wear: read(10), AvailableSpare: notKept, AvailableSpareThreshold: notKept,
		MediaErrors: notKept, ReallocatedSectors: read(0), PendingSectors: read(0), UncorrectableSectors: read(0),
		DriveErrors: read(0), PowerOnHours: read(9000), DataWritten: notKept, UnsafeShutdowns: notKept, PowerMode: read(0xff),
		Attributes: []agentproto.Attribute{
			{ID: 5, Flags: 0x33, Value: 100, Worst: 100, Threshold: &t5, Raw: 0},
			{ID: 197, Flags: 0x32, Value: 100, Worst: 100, Threshold: &t197, Raw: 0},
		},
	}
}

func fact(r reading, name string) FactView {
	for _, f := range r.facts {
		if f.Name == name {
			return f
		}
	}
	return FactView{}
}

func TestJudge(t *testing.T) {
	for _, c := range []struct {
		name          string
		disk          func() agentproto.DiskHealth
		state, reason string
		detail        string
		judged        bool
	}{
		{"healthy NVMe", nvme, StateHealthy, "", "", true},
		{"healthy ATA", ata, StateHealthy, "", "", true},
		{"NVMe spare below threshold", func() agentproto.DiskHealth { d := nvme(); d.CriticalWarning = read(1 << 0); return d },
			StateFailing, RuleCriticalWarning, "NVMe critical warning: available spare below its threshold", true},
		{"NVMe reliability degraded", func() agentproto.DiskHealth { d := nvme(); d.CriticalWarning = read(1 << 2); return d },
			StateFailing, RuleCriticalWarning, "NVMe critical warning: reliability degraded", true},
		{"NVMe read-only", func() agentproto.DiskHealth { d := nvme(); d.CriticalWarning = read(1 << 3); return d },
			StateFailing, RuleCriticalWarning, "NVMe critical warning: media read-only", true},
		{"NVMe backup failed", func() agentproto.DiskHealth { d := nvme(); d.CriticalWarning = read(1 << 4); return d },
			StateFailing, RuleCriticalWarning, "NVMe critical warning: volatile memory backup failed", true},
		{"NVMe temperature bit", func() agentproto.DiskHealth { d := nvme(); d.CriticalWarning = read(1 << 1); return d },
			StateWarning, RuleCriticalWarning, "NVMe critical warning: temperature", true},
		{"NVMe persistent memory bit", func() agentproto.DiskHealth { d := nvme(); d.CriticalWarning = read(1 << 5); return d },
			StateWarning, RuleCriticalWarning, "NVMe critical warning: persistent memory region read-only or unreliable", true},
		{"NVMe reserved bits", func() agentproto.DiskHealth { d := nvme(); d.CriticalWarning = read(1<<6 | 1<<7); return d },
			StateWarning, RuleCriticalWarning, "NVMe critical warning: bit 6 (reserved), bit 7 (reserved)", true},
		{"NVMe failing and warning bits", func() agentproto.DiskHealth { d := nvme(); d.CriticalWarning = read(1<<1 | 1<<3); return d },
			StateFailing, RuleCriticalWarning, "NVMe critical warning: media read-only", true},
		{"NVMe media errors", func() agentproto.DiskHealth { d := nvme(); d.MediaErrors = read(2); return d },
			StateWarning, RuleMediaErrors, "NVMe media errors 2", true},
		{"NVMe worn", func() agentproto.DiskHealth { d := nvme(); d.Wear = read(90); return d },
			StateWarning, RuleWear, "90% of rated endurance used", true},
		{"NVMe nearly worn", func() agentproto.DiskHealth { d := nvme(); d.Wear = read(89); return d }, StateHealthy, "", "", true},
		{"NVMe hot", func() agentproto.DiskHealth { d := nvme(); d.Temperature = read(70); return d },
			StateWarning, RuleTemperature, "70 °C, at or over the drive's limit of 70 °C", true},
		{"NVMe without a limit", func() agentproto.DiskHealth {
			d := nvme()
			d.Temperature, d.TemperatureLimit = read(95), agentproto.NotRead(agentproto.FactUnsupported, agentproto.ReasonNotKept)
			return d
		}, StateHealthy, "", "", true},
		{"NVMe limit zero", func() agentproto.DiskHealth {
			d := nvme()
			d.Temperature, d.TemperatureLimit = read(95), read(0)
			return d
		},
			StateHealthy, "", "", true},
		{"NVMe limit not read", func() agentproto.DiskHealth { d := nvme(); d.TemperatureLimit = timedOut; return d },
			StateUnknown, agentproto.ReasonTimeout, "", true},
		{"NVMe verdict not read", func() agentproto.DiskHealth { d := nvme(); d.CriticalWarning = timedOut; return d },
			StateUnknown, agentproto.ReasonNoVerdict, "", false},
		{"NVMe verdict not read with errors", func() agentproto.DiskHealth {
			d := nvme()
			d.CriticalWarning, d.MediaErrors = timedOut, read(5)
			return d
		}, StateUnknown, agentproto.ReasonNoVerdict, "", false},
		{"NVMe judged fact not read", func() agentproto.DiskHealth { d := nvme(); d.MediaErrors = timedOut; return d },
			StateUnknown, agentproto.ReasonTimeout, "", true},
		{"NVMe judged fact not read, and failing", func() agentproto.DiskHealth {
			d := nvme()
			d.MediaErrors, d.CriticalWarning = timedOut, read(1<<3)
			return d
		}, StateFailing, RuleCriticalWarning, "NVMe critical warning: media read-only", true},
		{"ATA threshold exceeded", func() agentproto.DiskHealth {
			d := ata()
			d.SMARTStatus = read(agentproto.SMARTThresholdExceeded)
			return d
		},
			StateFailing, RuleSMARTStatus, "SMART status: threshold exceeded", true},
		{"ATA pre-fail attribute at threshold", func() agentproto.DiskHealth { d := ata(); d.Attributes[0].Value = 36; return d },
			StateFailing, RulePreFailAttribute, "Pre-fail attribute 5 at or below its threshold", true},
		{"ATA old-age attribute at threshold", func() agentproto.DiskHealth {
			d := ata()
			t := uint8(50)
			d.Attributes[1].Threshold, d.Attributes[1].Value = &t, 40
			return d
		}, StateWarning, RuleAttribute, "Attribute 197 at or below its threshold", true},
		{"ATA threshold zero never trips", func() agentproto.DiskHealth { d := ata(); d.Attributes[1].Value = 0; return d },
			StateHealthy, "", "", true},
		{"ATA without status: the attributes decide", func() agentproto.DiskHealth {
			d := ata()
			d.SMARTStatus = agentproto.NotRead(agentproto.FactUnavailable, agentproto.ReasonNotExposed)
			return d
		}, StateHealthy, "", "", true},
		{"ATA without status: a pre-fail attribute fails", func() agentproto.DiskHealth {
			d := ata()
			d.SMARTStatus = agentproto.NotRead(agentproto.FactUnavailable, agentproto.ReasonNotExposed)
			d.Attributes[0].Value = 1
			return d
		}, StateFailing, RulePreFailAttribute, "Pre-fail attribute 5 at or below its threshold", true},
		{"ATA status timed out", func() agentproto.DiskHealth { d := ata(); d.SMARTStatus = timedOut; return d },
			StateUnknown, agentproto.ReasonTimeout, "", true},
		{"ATA without status or thresholds", func() agentproto.DiskHealth {
			d := ata()
			d.SMARTStatus, d.Thresholds = timedOut, timedOut
			for i := range d.Attributes {
				d.Attributes[i].Threshold = nil
			}
			return d
		}, StateUnknown, agentproto.ReasonNoVerdict, "", false},
		{"ATA reallocated", func() agentproto.DiskHealth { d := ata(); d.ReallocatedSectors = read(3); return d },
			StateWarning, RuleReallocated, "Reallocated sectors 3", true},
		{"ATA pending and uncorrectable", func() agentproto.DiskHealth {
			d := ata()
			d.PendingSectors, d.UncorrectableSectors = read(8), read(1)
			return d
		}, StateWarning, RulePending, "Pending sectors 8; uncorrectable sectors 1", true},
		{"asleep", func() agentproto.DiskHealth {
			return agentproto.DiskHealth{Name: "sdb", State: agentproto.FactUnknown, Reason: agentproto.ReasonAsleep}
		}, agentproto.FactUnknown, agentproto.ReasonAsleep, "", false},
		{"behind a RAID controller", func() agentproto.DiskHealth {
			return agentproto.DiskHealth{Name: "sdc", State: agentproto.FactUnavailable, Reason: agentproto.ReasonRAIDController}
		}, StateUnavailable, agentproto.ReasonRAIDController, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := c.disk()
			r := judge(&d)
			if r.state != c.state || r.reason != c.reason || r.detail != c.detail || r.judged != c.judged {
				t.Errorf("judged %q %q %q judged=%v, want %q %q %q judged=%v", r.state, r.reason, r.detail, r.judged,
					c.state, c.reason, c.detail, c.judged)
			}
		})
	}
}

func TestJudgeFacts(t *testing.T) {
	d := nvme()
	d.Temperature, d.TemperatureLimit, d.MediaErrors = read(75), read(70), timedOut
	r := judge(&d)
	if len(r.facts) != len(factDefs) || r.facts[0].Name != "criticalWarning" {
		t.Fatalf("facts %+v", r.facts)
	}
	for name, want := range map[string]FactView{
		"criticalWarning":    {State: StateHealthy, Value: ptr(0)},
		"smartStatus":        {State: agentproto.FactUnsupported, Reason: agentproto.ReasonNotKept},
		"temperature":        {State: StateWarning, Reason: RuleTemperature, Value: ptr(75)},
		"temperatureLimit":   {State: StateReported, Value: ptr(70)},
		"wear":               {State: StateHealthy, Value: ptr(3)},
		"mediaErrors":        {State: agentproto.FactUnknown, Reason: agentproto.ReasonTimeout},
		"reallocatedSectors": {State: agentproto.FactUnsupported, Reason: agentproto.ReasonNotKept},
		"powerOnHours":       {State: StateReported, Value: ptr(1200)},
	} {
		got := fact(r, name)
		if got.State != want.State || got.Reason != want.Reason || !same(got.Value, want.Value) {
			t.Errorf("%s = %+v, want %+v", name, got, want)
		}
	}
	if r.sample.temperature == nil || *r.sample.temperature != 75 || r.sample.temperatureLimit == nil || r.sample.mediaErrors != nil ||
		r.sample.reallocated != nil || *r.sample.powerOnHours != 1200 {
		t.Errorf("sample %+v", r.sample)
	}

	// A drive limit of zero is no limit: the sample keeps none.
	d = nvme()
	d.TemperatureLimit = read(0)
	if r := judge(&d); r.sample.temperatureLimit != nil || fact(r, "temperature").State != StateReported {
		t.Errorf("limit zero: %+v %+v", r.sample, fact(r, "temperature"))
	}

	// ATA attributes: judged with their thresholds, reported without.
	a := ata()
	a.Attributes[0].Value = 30
	r = judge(&a)
	if len(r.attributes) != 2 || r.attributes[0].State != StateFailing || !r.attributes[0].PreFail ||
		r.attributes[1].State != StateHealthy || r.attributes[1].PreFail {
		t.Errorf("attributes %+v", r.attributes)
	}
	a.Thresholds = timedOut
	if r := judge(&a); r.attributes[0].State != StateReported || r.state != StateUnknown || r.reason != agentproto.ReasonTimeout {
		t.Errorf("attributes without thresholds %+v, %s %s", r.attributes, r.state, r.reason)
	}
}

func ptr(v int64) *int64 { return &v }

func same(a, b *int64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

func TestClean(t *testing.T) {
	now := time.Date(2026, 5, 2, 14, 30, 0, 0, time.UTC)
	long := strings.Repeat("x", 300)
	d := nvme()
	d.Name, d.Model, d.Serial = " nvme0n1\x00 ", "Example\tNVMe", "S1\n"
	d.Detail, d.Route, d.ReadAt = long, "carrier pigeon", now.Add(-48*time.Hour)
	d.Temperature = read(151)
	d.TemperatureLimit = read(-41)
	d.Wear = read(256)
	d.MediaErrors = read(math.MaxInt64)
	d.DriveErrors = agentproto.Fact{State: "broken"}
	d.UnsafeShutdowns = agentproto.Fact{State: agentproto.FactUnknown, Reason: "made_up"}
	d.PowerOnHours = agentproto.Fact{State: agentproto.FactRead}
	// A fact a read disk leaves out arrives with no state: refused too.
	d.DataWritten = agentproto.Fact{}
	d.AvailableSpare = agentproto.Fact{State: agentproto.FactUnsupported, Reason: agentproto.ReasonNotKept, Value: ptr(5)}
	d.Thresholds = read(7)
	d.CriticalWarning = agentproto.Fact{State: agentproto.FactRead, Reason: agentproto.ReasonTimeout, Value: ptr(0)}
	for i := range 40 {
		d.Attributes = append(d.Attributes, agentproto.Attribute{ID: uint8(i % 35), Raw: 1 << 50})
	}
	out := clean([]agentproto.DiskHealth{d}, now)
	if len(out) != 1 {
		t.Fatalf("clean = %+v", out)
	}
	c := out[0]
	if c.Name != "nvme0n1" || c.Model != "ExampleNVMe" || c.Serial != "S1" || len([]rune(c.Detail)) != agentproto.MaxHardwareDetail ||
		c.Route != "" || !c.ReadAt.Equal(now) {
		t.Errorf("identity and text %q %q %q %d %q %v", c.Name, c.Model, c.Serial, len(c.Detail), c.Route, c.ReadAt)
	}
	invalidReport := agentproto.NotRead(agentproto.FactUnknown, agentproto.ReasonInvalidReport)
	for name, got := range map[string]agentproto.Fact{
		"temperature": c.Temperature, "temperatureLimit": c.TemperatureLimit, "wear": c.Wear, "mediaErrors": c.MediaErrors,
		"driveErrors": c.DriveErrors, "unsafeShutdowns": c.UnsafeShutdowns, "powerOnHours": c.PowerOnHours,
		"dataWritten": c.DataWritten,
	} {
		if got.State != invalidReport.State || got.Reason != invalidReport.Reason || got.Value != nil {
			t.Errorf("%s = %+v, want invalid_report", name, got)
		}
	}
	if c.AvailableSpare.Value != nil || c.AvailableSpare.State != agentproto.FactUnsupported {
		t.Errorf("an unsupported fact keeps no value: %+v", c.AvailableSpare)
	}
	if c.Thresholds.State != agentproto.FactRead || c.Thresholds.Value != nil {
		t.Errorf("thresholds carry no value: %+v", c.Thresholds)
	}
	if c.CriticalWarning.Reason != "" || *c.CriticalWarning.Value != 0 {
		t.Errorf("a read fact keeps no reason: %+v", c.CriticalWarning)
	}
	if len(c.Attributes) != agentproto.MaxAttributes || c.Attributes[0].ID != 1 || c.Attributes[0].Raw != 0 {
		t.Errorf("attributes %d %+v", len(c.Attributes), c.Attributes[0])
	}
	seen := map[uint8]bool{}
	for _, a := range c.Attributes {
		if a.ID == 0 || seen[a.ID] {
			t.Errorf("attribute %d kept twice or without an ID", a.ID)
		}
		seen[a.ID] = true
	}

	// The disk as a whole.
	for _, c := range []struct {
		in            agentproto.DiskHealth
		state, reason string
	}{
		{agentproto.DiskHealth{Name: "a", State: agentproto.FactRead, Protocol: "scsi"}, agentproto.FactUnknown, agentproto.ReasonInvalidReport},
		{agentproto.DiskHealth{Name: "b", State: agentproto.FactUnavailable, Reason: "nope"}, agentproto.FactUnknown, agentproto.ReasonInvalidReport},
		{agentproto.DiskHealth{Name: "c", State: "healthy"}, agentproto.FactUnknown, agentproto.ReasonInvalidReport},
		{agentproto.DiskHealth{Name: "d", State: agentproto.FactUnsupported, Reason: agentproto.ReasonVirtualDisk,
			Temperature: read(40), Attributes: []agentproto.Attribute{{ID: 1}}}, agentproto.FactUnsupported, agentproto.ReasonVirtualDisk},
		{agentproto.DiskHealth{Name: "e", State: agentproto.FactRead, Reason: agentproto.ReasonAsleep, Protocol: agentproto.ProtocolATA},
			agentproto.FactRead, ""},
	} {
		out := clean([]agentproto.DiskHealth{c.in}, now)
		if len(out) != 1 || out[0].State != c.state || out[0].Reason != c.reason {
			t.Errorf("%s: %+v", c.in.Name, out)
			continue
		}
		if out[0].State != agentproto.FactRead && (out[0].Temperature.State != "" || out[0].Attributes != nil) {
			t.Errorf("%s: a disk not read keeps facts: %+v", c.in.Name, out[0])
		}
	}

	// Disks without a name are dropped; at most MaxListed are kept.
	many := []agentproto.DiskHealth{{Name: " \x01 "}}
	for range agentproto.MaxListed + 5 {
		many = append(many, agentproto.DiskHealth{Name: "x", State: agentproto.FactUnknown, Reason: agentproto.ReasonAsleep})
	}
	if out := clean(many, now); len(out) != agentproto.MaxListed || out[0].Name != "x" {
		t.Errorf("kept %d disks", len(out))
	}
	// A reading time within a day of the server's is kept.
	d = nvme()
	d.ReadAt = now.Add(-time.Hour)
	if out := clean([]agentproto.DiskHealth{d}, now); !out[0].ReadAt.Equal(now.Add(-time.Hour)) {
		t.Errorf("read at %v", out[0].ReadAt)
	}
}

// FuzzJudge feeds any report through the server's cleaning and rules: they
// never panic, and what they keep is within the states and bounds the
// database takes.
func FuzzJudge(f *testing.F) {
	n, a := nvme(), ata()
	for _, seed := range []any{agentproto.HardwareReport{Disks: []agentproto.DiskHealth{n, a}}, agentproto.HardwareReport{}} {
		b, _ := json.Marshal(seed)
		f.Add(b)
	}
	f.Add([]byte(`{"disks":[{"name":"sda","state":"read","protocol":"ata","temperature":{"state":"read","value":-9223372036854775808},
		"attributes":[{"id":5,"flags":1,"value":0,"threshold":0}]}]}`))
	states := map[string]bool{StateHealthy: true, StateWarning: true, StateFailing: true, StateUnknown: true, StateUnsupported: true,
		StateUnavailable: true}
	rules := map[string]bool{RuleCriticalWarning: true, RuleSMARTStatus: true, RulePreFailAttribute: true, RuleAttribute: true,
		RuleTemperature: true, RuleWear: true, RuleMediaErrors: true, RuleReallocated: true, RulePending: true, RuleUncorrectable: true}
	f.Fuzz(func(t *testing.T, body []byte) {
		var report agentproto.HardwareReport
		if json.Unmarshal(body, &report) != nil {
			return
		}
		now := time.Now()
		for _, d := range clean(report.Disks, now) {
			if d.Name == "" || len([]rune(d.Name)) > 64 || len([]rune(d.Detail)) > agentproto.MaxHardwareDetail || len(d.Attributes) > agentproto.MaxAttributes {
				t.Fatalf("kept %+v", d)
			}
			for _, def := range factDefs {
				f := def.get(&d)
				if f.Value != nil && (*f.Value < def.lo || *f.Value > def.hi) {
					t.Fatalf("%s out of bounds: %d", def.name, *f.Value)
				}
			}
			r := judge(&d)
			if !states[r.state] && r.state != agentproto.FactUnknown {
				t.Fatalf("state %q", r.state)
			}
			if r.reason != "" && !agentproto.KnownReason(r.reason) && !rules[r.reason] {
				t.Fatalf("reason %q", r.reason)
			}
			if len([]rune(r.detail)) > 500 {
				t.Fatalf("detail of %d characters", len([]rune(r.detail)))
			}
			if r.judged != (r.state != StateUnknown || r.reason != agentproto.ReasonNoVerdict) && d.State == agentproto.FactRead {
				t.Fatalf("judged %v with %s %s", r.judged, r.state, r.reason)
			}
		}
	})
}
