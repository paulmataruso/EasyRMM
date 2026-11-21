package hardware

import (
	"errors"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func nvmeDrive(t *testing.T, log, identify []byte) *fakeNVMe {
	return &fakeNVMe{t: t, answers: map[nvmeCommand]answer{
		nvmeHealthLog:          {data: log},
		nvmeIdentifyController: {data: identify},
	}}
}

// TestReadNVMeWorn: a constructed drive with every counter set, its spare
// below its threshold and wear past 100 %.
func TestReadNVMeWorn(t *testing.T) {
	log := healthLogBytes(0x01, 318, 4, 10, 121, map[int]uint64{
		48: 9_876_543, 128: 41_000, 144: 77, 160: 12, 176: 345,
	})
	h, err := readNVMe(nvmeDrive(t, log, identifyControllerBytes(358)))
	if err != nil {
		t.Fatal(err)
	}
	if h.State != agentproto.FactRead || h.Protocol != agentproto.ProtocolNVMe || h.Attributes != nil {
		t.Errorf("%+v", h)
	}
	wantFacts(t, h, map[string]agentproto.Fact{
		"CriticalWarning": read(1), "Temperature": read(45), "TemperatureLimit": read(85), "Wear": read(121),
		"AvailableSpare": read(4), "AvailableSpareThreshold": read(10), "DataWritten": read(9_876_543),
		"PowerOnHours": read(41_000), "UnsafeShutdowns": read(77), "MediaErrors": read(12), "DriveErrors": read(345),
		"SMARTStatus": notKept, "Thresholds": notKept, "PowerMode": notKept,
		"ReallocatedSectors": notKept, "PendingSectors": notKept, "UncorrectableSectors": notKept,
	})
}

// TestReadNVMeEdges: the reserved warning bits are reported as they are;
// counters past 2^62, or with their upper 64 bits set, are capped; a
// temperature of 0 K is not valid; a WCTEMP of 0 means none.
func TestReadNVMeEdges(t *testing.T) {
	log := healthLogBytes(0xE4, 0, 100, 10, 255, map[int]uint64{48: 1 << 63, 128: 5, 136: 1})
	h, err := readNVMe(nvmeDrive(t, log, identifyControllerBytes(0)))
	if err != nil {
		t.Fatal(err)
	}
	wantFacts(t, h, map[string]agentproto.Fact{
		"CriticalWarning": read(0xE4), "Temperature": notRead(agentproto.FactUnknown, agentproto.ReasonNotValid),
		"TemperatureLimit": notKept, "Wear": read(255), "DataWritten": read(maxCount), "PowerOnHours": read(maxCount),
	})
}

// TestReadNVMeIdentify: Identify Controller only gives the limit, so its
// failures are the limit's, unless they fail the reading.
func TestReadNVMeIdentify(t *testing.T) {
	log := healthLogBytes(0, 323, 100, 10, 0, nil)
	d := nvmeDrive(t, log, nil)
	delete(d.answers, nvmeIdentifyController)
	h, err := readNVMe(d)
	if err != nil || !sameFact(h.TemperatureLimit, notRead(agentproto.FactUnsupported, agentproto.ReasonDeviceRefused)) || !sameFact(h.Temperature, read(50)) {
		t.Errorf("refused: %v, %s", err, factString(h.TemperatureLimit))
	}
	d.answers[nvmeIdentifyController] = answer{data: make([]byte, 4095)}
	if h, err := readNVMe(d); err != nil || !sameFact(h.TemperatureLimit, notRead(agentproto.FactUnknown, agentproto.ReasonBadAnswer)) {
		t.Errorf("truncated: %v, %s", err, factString(h.TemperatureLimit))
	}
	for _, fatal := range []error{timedOut("x"), accessDenied("x"), fail(agentproto.FactUnknown, agentproto.ReasonAgentError, "x")} {
		d.answers[nvmeIdentifyController] = answer{err: fatal}
		if _, err := readNVMe(d); !errors.Is(err, fatal) {
			t.Errorf("%v: %v", fatal, err)
		}
	}
}

func TestReadNVMeHealthLogFails(t *testing.T) {
	d := nvmeDrive(t, make([]byte, 511), identifyControllerBytes(343))
	if _, err := readNVMe(d); !is(err, agentproto.ReasonBadAnswer) {
		t.Errorf("truncated: %v", err)
	}
	d.answers[nvmeHealthLog] = answer{data: make([]byte, 513)}
	if _, err := readNVMe(d); !is(err, agentproto.ReasonBadAnswer) {
		t.Errorf("oversized: %v", err)
	}
	delete(d.answers, nvmeHealthLog)
	if _, err := readNVMe(d); !is(err, agentproto.ReasonDeviceRefused) {
		t.Errorf("refused: %v", err)
	}
	for _, n := range []int{0, 4095, 4097} {
		if _, err := parseIdentifyController(make([]byte, n)); !is(err, agentproto.ReasonBadAnswer) {
			t.Errorf("Identify Controller of %d bytes: %v", n, err)
		}
	}
}
