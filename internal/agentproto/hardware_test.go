package agentproto

import (
	"encoding/json"
	"testing"
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
	for _, r := range []string{ReasonContainer, ReasonUSBBridge, ReasonTimedOutRecently, ReasonNotKept, ReasonStale, ReasonInvalidReport} {
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
