package agentproto

import (
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestFacts(t *testing.T) {
	b, _ := json.Marshal(Read(42))
	if string(b) != `{"state":"read","value":42}` {
		t.Errorf("Read: %s", b)
	}
	b, _ = json.Marshal(NotRead(FactUnsupported, ReasonNotKept))
	if string(b) != `{"state":"unsupported","reason":"not_kept"}` {
		t.Errorf("NotRead: %s", b)
	}
	// A zero value is read as 0, not left out.
	b, _ = json.Marshal(Read(0))
	if string(b) != `{"state":"read","value":0}` {
		t.Errorf("Read(0): %s", b)
	}
}

func TestKnownReason(t *testing.T) {
	for _, r := range []string{ReasonContainer, ReasonUSBBridge, ReasonTimedOutRecently, ReasonOtherDisk, ReasonNotKept, ReasonStale, ReasonInvalidReport} {
		if !KnownReason(r) {
			t.Errorf("%s is not known", r)
		}
	}
	for _, r := range []string{"", "healthy", "Timeout", "read"} {
		if KnownReason(r) {
			t.Errorf("%q is known", r)
		}
	}
}

func TestAttributePreFail(t *testing.T) {
	if !(Attribute{Flags: 0x0033}).PreFail() || (Attribute{Flags: 0x0032}).PreFail() {
		t.Error("pre-fail is bit 0 of the flags")
	}
}

// A disk not read is sent without facts, never with facts of no state.
func TestDiskNotReadLeavesFactsOut(t *testing.T) {
	b, err := json.Marshal(DiskHealth{Name: "sda", State: FactUnavailable, Reason: ReasonUSBBridge})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"sda","model":"","serial":"","state":"unavailable","reason":"usb_bridge","readAt":"0001-01-01T00:00:00Z"}`
	if string(b) != want {
		t.Errorf("%s, want %s", b, want)
	}
	b, _ = json.Marshal(DiskHealth{Name: "nvme0n1", State: FactRead, Protocol: ProtocolNVMe, CriticalWarning: Read(0), SMARTStatus: NotRead(FactUnsupported, ReasonNotKept)})
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || string(m["criticalWarning"]) != `{"state":"read","value":0}` ||
		string(m["smartStatus"]) != `{"state":"unsupported","reason":"not_kept"}` || m["temperature"] != nil {
		t.Errorf("read disk %s", b)
	}
}

// The largest report an agent sends, MaxListed disks with every fact at its
// longest and a full attribute table, fits in MaxHardwareBody.
func TestLargestReportFits(t *testing.T) {
	longest := ""
	for r := range reasons {
		if len(r) > len(longest) {
			longest = r
		}
	}
	fact := Read(math.MinInt64)
	if b, n := mustJSON(t, fact), mustJSON(t, NotRead(FactUnavailable, longest)); len(n) > len(b) {
		fact = NotRead(FactUnavailable, longest)
	}
	threshold := uint8(math.MaxUint8)
	d := DiskHealth{
		Name: "PhysicalDrive63", Model: strings.Repeat("M", 40), Serial: strings.Repeat("S", 20), State: FactRead,
		Reason: longest, Detail: strings.Repeat("d", MaxHardwareDetail), Protocol: ProtocolNVMe, Route: "adapter",
		ReadAt: time.Date(2026, 12, 31, 23, 59, 59, 999999999, time.FixedZone("", -11*3600)),
	}
	facts := []*Fact{&d.CriticalWarning, &d.SMARTStatus, &d.Thresholds, &d.Temperature, &d.TemperatureLimit, &d.Wear,
		&d.AvailableSpare, &d.AvailableSpareThreshold, &d.MediaErrors, &d.ReallocatedSectors, &d.PendingSectors,
		&d.UncorrectableSectors, &d.DriveErrors, &d.PowerOnHours, &d.DataWritten, &d.UnsafeShutdowns, &d.PowerMode}
	for _, f := range facts {
		*f = fact
	}
	for range MaxAttributes {
		d.Attributes = append(d.Attributes, Attribute{ID: math.MaxUint8, Flags: math.MaxUint16, Value: math.MaxUint8,
			Worst: math.MaxUint8, Threshold: &threshold, Raw: 1<<48 - 1})
	}
	r := HardwareReport{Disks: slices.Repeat([]DiskHealth{d}, MaxListed)}
	if b := mustJSON(t, r); len(b) > MaxHardwareBody {
		t.Errorf("the largest report is %d bytes, over %d", len(b), MaxHardwareBody)
	} else {
		t.Logf("the largest report: %d bytes of %d", len(b), MaxHardwareBody)
	}
	// Every fact field is in the list above.
	if n := reflect.TypeFor[DiskHealth]().NumField(); n != 9+len(facts)+1 {
		t.Errorf("DiskHealth has %d fields; update the list of facts", n)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A report from a later agent, with a fact this release does not know,
// still decodes.
func TestHardwareReportDecodesUnknownFacts(t *testing.T) {
	var r HardwareReport
	err := json.Unmarshal([]byte(`{"disks":[{"name":"sda","state":"read","protocol":"ata","futureFact":{"state":"read","value":1},
		"smartStatus":{"state":"read","value":0},"attributes":[{"id":5,"flags":51,"value":100,"worst":100,"threshold":10,"raw":0}]}],"batteries":[]}`), &r)
	if err != nil || len(r.Disks) != 1 || r.Disks[0].SMARTStatus.Value == nil || *r.Disks[0].Attributes[0].Threshold != 10 {
		t.Fatalf("%+v %v", r, err)
	}
}
