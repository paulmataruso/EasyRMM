package hardware

import (
	"errors"
	"slices"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func read(v int64) agentproto.Fact { return agentproto.Read(v) }

func notRead(state, reason string) agentproto.Fact { return agentproto.NotRead(state, reason) }

var notKept = notRead(agentproto.FactUnsupported, agentproto.ReasonNotKept)

func sameFact(a, b agentproto.Fact) bool {
	return a.State == b.State && a.Reason == b.Reason && (a.Value == nil) == (b.Value == nil) && (a.Value == nil || *a.Value == *b.Value)
}

// wantFacts checks facts of a reading by name.
func wantFacts(t *testing.T, h agentproto.DiskHealth, want map[string]agentproto.Fact) {
	t.Helper()
	got := map[string]agentproto.Fact{
		"CriticalWarning": h.CriticalWarning, "SMARTStatus": h.SMARTStatus, "Thresholds": h.Thresholds,
		"Temperature": h.Temperature, "TemperatureLimit": h.TemperatureLimit, "Wear": h.Wear,
		"AvailableSpare": h.AvailableSpare, "AvailableSpareThreshold": h.AvailableSpareThreshold,
		"MediaErrors": h.MediaErrors, "ReallocatedSectors": h.ReallocatedSectors, "PendingSectors": h.PendingSectors,
		"UncorrectableSectors": h.UncorrectableSectors, "DriveErrors": h.DriveErrors, "PowerOnHours": h.PowerOnHours,
		"DataWritten": h.DataWritten, "UnsafeShutdowns": h.UnsafeShutdowns, "PowerMode": h.PowerMode,
	}
	for name, w := range want {
		if g, ok := got[name]; !ok || !sameFact(g, w) {
			t.Errorf("%s = %s, want %s", name, factString(g), factString(w))
		}
	}
}

func factString(f agentproto.Fact) string {
	if f.Value != nil {
		return f.State + " " + itoa(*f.Value)
	}
	return f.State + " " + f.Reason
}

func itoa(v int64) string {
	if v < 0 {
		return "-" + itoa(-v)
	}
	if v < 10 {
		return string(rune('0' + v))
	}
	return itoa(v/10) + string(rune('0'+v%10))
}

// failingDrive is a constructed SATA drive past a threshold: reallocated,
// pending and uncorrectable sectors, Device Statistics through the
// general-purpose log with temperature, its limit, wear and a statistic
// supported but not valid now.
var failingAttrs = []attr{
	{id: 1, flags: 0x000F, value: 100, worst: 100, threshold: 6},
	{id: 5, flags: 0x0033, value: 5, worst: 5, raw: 1832, threshold: 10},
	{id: 9, flags: 0x0032, value: 60, worst: 60, raw: 35210},
	{id: 194, flags: 0x0022, value: 36, worst: 50, raw: 0x0014_0028_0024, threshold: 0},
	{id: 197, flags: 0x0012, value: 100, worst: 100, raw: 16},
	{id: 198, flags: 0x0010, value: 100, worst: 100, raw: 3, noThresh: true},
}

func failingDrive(t *testing.T) *fakeATA {
	return &fakeATA{t: t, answers: map[ataCommand]answer{
		ataPowerMode:        {regs: active},
		ataIdentify:         {data: identifyBytes(true, true, false)},
		smartReturnStatus:   {regs: exceeded},
		smartReadData:       {data: smartDataBytes(failingAttrs, true)},
		smartReadThresholds: {data: thresholdBytes(failingAttrs)},
		smartReadLog(logDirectory, 1): {data: directoryBytes(map[uint8]uint16{
			logSummaryErrors: 1, logDeviceStatistics: 8,
		})},
		smartReadLog(logSummaryErrors, 1): {data: errorLogBytes(7)},
		readLogExt(logDirectory, 0): {data: directoryBytes(map[uint8]uint16{
			logDeviceStatistics: 8,
		})},
		readLogExt(logDeviceStatistics, statsList): {data: statsPageBytes(statsList, nil, 0, 1, 3, 4, 5, 7)},
		readLogExt(logDeviceStatistics, statsRotating): {data: statsPageBytes(statsRotating, map[int]uint64{
			statReallocated: statSupported | statValid | 1900,
		})},
		readLogExt(logDeviceStatistics, statsTemperature): {data: statsPageBytes(statsTemperature, map[int]uint64{
			statTemperature:      statSupported | statValid | 41,
			statTemperatureLimit: statSupported | 70, // supported, not valid now
		})},
		readLogExt(logDeviceStatistics, statsSolidState): {data: statsPageBytes(statsSolidState, map[int]uint64{
			statPercentageUsed: statSupported | statValid | 12,
		})},
	}}
}

func TestReadATAFailingDrive(t *testing.T) {
	d := failingDrive(t)
	h, err := readATA(d, false)
	if err != nil {
		t.Fatal(err)
	}
	if h.State != agentproto.FactRead || h.Protocol != agentproto.ProtocolATA {
		t.Errorf("state %s, protocol %s", h.State, h.Protocol)
	}
	wantFacts(t, h, map[string]agentproto.Fact{
		"PowerMode": read(0xFF), "SMARTStatus": read(agentproto.SMARTThresholdExceeded), "Thresholds": read(5),
		// Device Statistics first, then attribute 194's low byte.
		"Temperature": read(41), "TemperatureLimit": notRead(agentproto.FactUnknown, agentproto.ReasonNotValid),
		"Wear": read(12),
		// Attribute 5 first, then Device Statistics' count.
		"ReallocatedSectors": read(1832), "PendingSectors": read(16), "UncorrectableSectors": read(3),
		"PowerOnHours": read(35210), "DriveErrors": read(7),
		"CriticalWarning": notKept, "AvailableSpare": notKept, "AvailableSpareThreshold": notKept,
		"MediaErrors": notKept, "DataWritten": notKept, "UnsafeShutdowns": notKept,
	})
	if len(h.Attributes) != 6 {
		t.Fatalf("attributes %+v", h.Attributes)
	}
	for i, a := range h.Attributes {
		w := failingAttrs[i]
		if a.ID != w.id || a.Flags != w.flags || a.Value != w.value || a.Worst != w.worst || a.Raw != w.raw ||
			(a.Threshold == nil) != w.noThresh || (a.Threshold != nil && *a.Threshold != w.threshold) {
			t.Errorf("attribute %d: %+v", w.id, a)
		}
	}
	if !a5PreFail(h.Attributes) {
		t.Error("attribute 5's pre-fail flag lost")
	}
	// The order of the ADR: CHECK POWER MODE first; only listed pages.
	want := []string{"CHECK POWER MODE", "IDENTIFY DEVICE", "SMART RETURN STATUS", "SMART READ DATA",
		"SMART READ ATTRIBUTE THRESHOLDS", "SMART READ LOG 00h", "READ LOG EXT 00h", "SMART READ LOG 01h",
		"READ LOG EXT 04h page 00h", "READ LOG EXT 04h page 03h", "READ LOG EXT 04h page 05h", "READ LOG EXT 04h page 07h"}
	if !slices.Equal(d.sent, want) {
		t.Errorf("sent %q", d.sent)
	}
}

func a5PreFail(attrs []agentproto.Attribute) bool {
	for _, a := range attrs {
		if a.ID == 5 {
			return a.PreFail()
		}
	}
	return false
}

// TestReadATAThroughSMARTLog: a drive whose general-purpose log directory
// is refused gives Device Statistics through SMART READ LOG, all its pages
// at once; a page listed but beyond the log's length is not read, and
// statistics without their flags are reported so.
func TestReadATAThroughSMARTLog(t *testing.T) {
	d := failingDrive(t)
	delete(d.answers, readLogExt(logDirectory, 0))
	stats := make([]byte, 0, 6*sector)
	stats = append(stats, statsPageBytes(statsList, nil, 0, 3, 5, 7)...)
	stats = append(stats, make([]byte, 2*sector)...)
	stats = append(stats, statsPageBytes(statsRotating, map[int]uint64{statReallocated: 0})...) // not supported
	stats = append(stats, make([]byte, sector)...)
	stats = append(stats, statsPageBytes(statsTemperature, map[int]uint64{
		statTemperature: statSupported | statValid | 0xF6, // -10 °C
	})...)
	d.answers[smartReadLog(logDirectory, 1)] = answer{data: directoryBytes(map[uint8]uint16{logSummaryErrors: 1, logDeviceStatistics: 6})}
	d.answers[smartReadLog(logDeviceStatistics, 6)] = answer{data: stats}
	delete(d.answers, smartReadData)
	h, err := readATA(d, false)
	if err != nil {
		t.Fatal(err)
	}
	wantFacts(t, h, map[string]agentproto.Fact{
		"Temperature": read(-10), "TemperatureLimit": notKept,
		// Page 07h is listed but past the log's 6 pages.
		"Wear": notKept,
		// SMART READ DATA refused: the attributes are the device's
		// refusal, and Device Statistics' count does not keep it.
		"ReallocatedSectors": notRead(agentproto.FactUnsupported, agentproto.ReasonDeviceRefused),
		"PendingSectors":     notRead(agentproto.FactUnsupported, agentproto.ReasonDeviceRefused),
		"DriveErrors":        read(7),
	})
	if h.Attributes != nil {
		t.Errorf("attributes %+v", h.Attributes)
	}
}

func TestReadATAPowerMode(t *testing.T) {
	standby := failingDrive(t)
	standby.answers[ataPowerMode] = answer{regs: registers(0x00, 0, 0)}
	if h, err := readATA(standby, false); !errors.Is(err, errAsleep) || !sameFact(h.PowerMode, read(0)) || len(standby.sent) != 1 {
		t.Errorf("standby: %v, %+v, sent %q", err, h.PowerMode, standby.sent)
	}
	// Woken once a day.
	if h, err := readATA(standby, true); err != nil || !sameFact(h.SMARTStatus, read(1)) {
		t.Errorf("woken: %v, %+v", err, h.SMARTStatus)
	}
	for _, mode := range []uint8{0x01, 0x40} {
		standby.answers[ataPowerMode] = answer{regs: registers(mode, 0, 0)}
		if _, err := readATA(standby, false); !errors.Is(err, errAsleep) {
			t.Errorf("mode %02Xh: %v", mode, err)
		}
	}
	for _, mode := range []uint8{0x41, 0x80, 0x81, 0x82, 0x83, 0xFF} {
		standby.answers[ataPowerMode] = answer{regs: registers(mode, 0, 0)}
		if h, err := readATA(standby, false); err != nil || !sameFact(h.PowerMode, read(int64(mode))) {
			t.Errorf("mode %02Xh: %v", mode, err)
		}
	}

	// A path that returns no registers, and a device that refuses the
	// command: the reading goes on.
	d := failingDrive(t)
	d.answers[ataPowerMode] = answer{}
	if h, err := readATA(d, false); err != nil || !sameFact(h.PowerMode, notRead(agentproto.FactUnknown, agentproto.ReasonBadAnswer)) {
		t.Errorf("no registers: %v, %+v", err, h.PowerMode)
	}
	delete(d.answers, ataPowerMode)
	if h, err := readATA(d, false); err != nil || !sameFact(h.PowerMode, notRead(agentproto.FactUnsupported, agentproto.ReasonDeviceRefused)) {
		t.Errorf("refused: %v, %+v", err, h.PowerMode)
	}
	// Any other error fails the reading before IDENTIFY.
	d.answers[ataPowerMode] = answer{err: ioError("EIO")}
	if _, err := readATA(d, false); !is(err, agentproto.ReasonIOError) {
		t.Errorf("error: %v", err)
	}
}

func TestReadATASMARTState(t *testing.T) {
	for name, tc := range map[string]struct {
		identify []byte
		reason   string
	}{
		"no SMART":           {identifyBytes(false, false, false), agentproto.ReasonNoSMART},
		"SMART off":          {identifyBytes(true, false, false), agentproto.ReasonSMARTOff},
		"words not valid":    {identifyBytes(true, true, true), agentproto.ReasonNoSMART},
		"a packet device":    {append([]byte{0, 0x85}, make([]byte, 510)...), agentproto.ReasonProtocolNotRead},
		"a truncated answer": {make([]byte, 100), agentproto.ReasonBadAnswer},
	} {
		d := failingDrive(t)
		d.answers[ataIdentify] = answer{data: tc.identify}
		if _, err := readATA(d, false); !is(err, tc.reason) {
			t.Errorf("%s: %v", name, err)
		}
	}
	d := failingDrive(t)
	delete(d.answers, ataIdentify)
	if _, err := readATA(d, false); !is(err, agentproto.ReasonDeviceRefused) {
		t.Errorf("IDENTIFY refused: %v", err)
	}
}

// TestReadATAVerdict: without RETURN STATUS's registers the verdict is
// left to the thresholds; a bad checksum or an unknown answer is said so.
func TestReadATAVerdict(t *testing.T) {
	for name, tc := range map[string]struct {
		a    answer
		want agentproto.Fact
	}{
		"no registers": {answer{}, notRead(agentproto.FactUnavailable, agentproto.ReasonStorageDriver)},
		"passing":      {answer{regs: passing}, read(agentproto.SMARTPassed)},
		"neither":      {answer{regs: registers(0, 0x12, 0x34)}, notRead(agentproto.FactUnknown, agentproto.ReasonBadAnswer)},
		"io error":     {answer{err: ioError("x")}, notRead(agentproto.FactUnknown, agentproto.ReasonIOError)},
	} {
		d := failingDrive(t)
		d.answers[smartReturnStatus] = tc.a
		if h, err := readATA(d, false); err != nil || !sameFact(h.SMARTStatus, tc.want) {
			t.Errorf("%s: %v, %s", name, err, factString(h.SMARTStatus))
		}
	}

	d := failingDrive(t)
	bad := smartDataBytes(failingAttrs, true)
	bad[100]++
	d.answers[smartReadData] = answer{data: bad}
	badThresholds := thresholdBytes(failingAttrs)
	badThresholds[2]++
	d.answers[smartReadThresholds] = answer{data: badThresholds}
	h, err := readATA(d, false)
	checksum := notRead(agentproto.FactUnknown, agentproto.ReasonBadChecksum)
	if err != nil {
		t.Fatal(err)
	}
	wantFacts(t, h, map[string]agentproto.Fact{
		"Thresholds": checksum, "PendingSectors": checksum, "PowerOnHours": checksum,
		// Device Statistics still give these.
		"Temperature": read(41), "ReallocatedSectors": read(1900),
	})
}

// TestReadATAErrorLog: the summary error log is read only where a
// directory lists it, or, without one, where the SMART data says the
// drive keeps it.
func TestReadATAErrorLog(t *testing.T) {
	d := failingDrive(t)
	d.answers[smartReadLog(logDirectory, 1)] = answer{data: directoryBytes(map[uint8]uint16{logDeviceStatistics: 8})}
	if h, _ := readATA(d, false); !sameFact(h.DriveErrors, notKept) || slices.Contains(d.sent, "SMART READ LOG 01h") {
		t.Errorf("not listed: %s, sent %q", factString(h.DriveErrors), d.sent)
	}

	d = failingDrive(t)
	delete(d.answers, smartReadLog(logDirectory, 1))
	d.answers[smartReadData] = answer{data: smartDataBytes(failingAttrs, false)}
	if h, _ := readATA(d, false); !sameFact(h.DriveErrors, notKept) || slices.Contains(d.sent, "SMART READ LOG 01h") {
		t.Errorf("no directory, no error logging: %s, sent %q", factString(h.DriveErrors), d.sent)
	}
	d.answers[smartReadData] = answer{err: ioError("x")}
	if h, _ := readATA(d, false); !sameFact(h.DriveErrors, notRead(agentproto.FactUnknown, agentproto.ReasonIOError)) {
		t.Errorf("no directory, no SMART data: %s", factString(h.DriveErrors))
	}
	d.answers[smartReadData] = answer{data: smartDataBytes(failingAttrs, true)}
	if h, _ := readATA(d, false); !sameFact(h.DriveErrors, read(7)) {
		t.Errorf("no directory, error logging: %s", factString(h.DriveErrors))
	}

	bad := errorLogBytes(3)
	bad[0]++
	d.answers[smartReadLog(logSummaryErrors, 1)] = answer{data: bad}
	if h, _ := readATA(d, false); !sameFact(h.DriveErrors, notRead(agentproto.FactUnknown, agentproto.ReasonBadChecksum)) {
		t.Errorf("bad checksum: %s", factString(h.DriveErrors))
	}
	d.answers[smartReadLog(logSummaryErrors, 1)] = answer{err: ioError("x")}
	if h, _ := readATA(d, false); !sameFact(h.DriveErrors, notRead(agentproto.FactUnknown, agentproto.ReasonIOError)) {
		t.Errorf("error: %s", factString(h.DriveErrors))
	}
}

// TestReadATAStatisticsFailures: a page that fails is that page's facts'
// failure; the list failing fails them all.
func TestReadATAStatisticsFailures(t *testing.T) {
	d := failingDrive(t)
	d.answers[readLogExt(logDeviceStatistics, statsTemperature)] = answer{data: statsPageBytes(statsRotating, nil)}
	h, err := readATA(d, false)
	if err != nil {
		t.Fatal(err)
	}
	wantFacts(t, h, map[string]agentproto.Fact{
		"TemperatureLimit": notRead(agentproto.FactUnknown, agentproto.ReasonBadAnswer),
		// Attribute 194's low byte.
		"Temperature": read(0x24), "Wear": read(12),
	})

	delete(d.answers, readLogExt(logDeviceStatistics, statsList))
	h, _ = readATA(d, false)
	refused := notRead(agentproto.FactUnsupported, agentproto.ReasonDeviceRefused)
	wantFacts(t, h, map[string]agentproto.Fact{"TemperatureLimit": refused, "Wear": refused, "Temperature": read(0x24)})

	d = failingDrive(t)
	delete(d.answers, readLogExt(logDirectory, 0))
	d.answers[smartReadLog(logDeviceStatistics, 8)] = answer{data: make([]byte, sector)}
	h, _ = readATA(d, false)
	short := notRead(agentproto.FactUnknown, agentproto.ReasonBadAnswer)
	wantFacts(t, h, map[string]agentproto.Fact{"Wear": short, "TemperatureLimit": short})
	d.answers[smartReadLog(logDeviceStatistics, 8)] = answer{data: make([]byte, 8*sector)}
	h, _ = readATA(d, false)
	wantFacts(t, h, map[string]agentproto.Fact{"Wear": short})
}

// TestReadATAFatal: a timeout or a refused access at any step fails the
// reading.
func TestReadATAFatal(t *testing.T) {
	steps := []ataCommand{ataIdentify, smartReturnStatus, smartReadData, smartReadThresholds, smartReadLog(logDirectory, 1),
		readLogExt(logDirectory, 0), smartReadLog(logSummaryErrors, 1), readLogExt(logDeviceStatistics, statsList),
		readLogExt(logDeviceStatistics, statsSolidState)}
	for _, c := range steps {
		for _, err := range []error{timedOut("x"), accessDenied("x")} {
			d := failingDrive(t)
			d.answers[c] = answer{err: err}
			if _, got := readATA(d, false); !errors.Is(got, err) {
				t.Errorf("%s: %v, want %v", ataNames[c], got, err)
			}
		}
	}
	d := failingDrive(t)
	delete(d.answers, readLogExt(logDirectory, 0))
	d.answers[smartReadLog(logDeviceStatistics, 8)] = answer{err: timedOut("x")}
	if _, err := readATA(d, false); !is(err, agentproto.ReasonTimeout) {
		t.Errorf("SMART READ LOG 04h: %v", err)
	}
}

func TestATAParsersRefuseLengths(t *testing.T) {
	for _, n := range []int{0, 511, 513, 1024} {
		b := make([]byte, n)
		if _, err := parseIdentify(b); !is(err, agentproto.ReasonBadAnswer) {
			t.Errorf("IDENTIFY of %d bytes: %v", n, err)
		}
		if _, err := parseSMARTData(b); !is(err, agentproto.ReasonBadAnswer) {
			t.Errorf("SMART data of %d bytes: %v", n, err)
		}
		if _, err := parseThresholds(b); !is(err, agentproto.ReasonBadAnswer) {
			t.Errorf("thresholds of %d bytes: %v", n, err)
		}
		if _, err := parseLogDirectory("x", b); !is(err, agentproto.ReasonBadAnswer) {
			t.Errorf("directory of %d bytes: %v", n, err)
		}
		if _, err := parseErrorLogCount(b); !is(err, agentproto.ReasonBadAnswer) {
			t.Errorf("error log of %d bytes: %v", n, err)
		}
		if _, err := parseStatsPage(b, 0); !is(err, agentproto.ReasonBadAnswer) {
			t.Errorf("statistics of %d bytes: %v", n, err)
		}
	}
	if _, err := parseStatsPage(make([]byte, sector), 0); !is(err, agentproto.ReasonBadAnswer) {
		t.Errorf("revision 0: %v", err)
	}
	// A repeated attribute ID is read once; its threshold the first.
	attrs := []attr{{id: 5, raw: 1, threshold: 10}, {id: 5, raw: 2, threshold: 20}}
	sd, err := parseSMARTData(smartDataBytes(attrs, false))
	th, err2 := parseThresholds(thresholdBytes(attrs))
	if err != nil || err2 != nil || len(sd.attributes) != 1 || sd.attributes[0].Raw != 1 || th[5] != 10 {
		t.Errorf("%+v %v, %v %v", sd, err, th, err2)
	}
	// The list of pages holds at most what the page has room for.
	list := statsPageBytes(statsList, nil)
	list[8] = 0xFF
	if p, err := parseStatsPage(list, statsList); err != nil || len(p.listed()) > 255 {
		t.Errorf("list %v", err)
	}
	var none directory
	if none.pages(4) != 0 || directory(directoryBytes(map[uint8]uint16{0: 9})).pages(0) != 0 {
		t.Error("pages of no directory, or of the directory itself")
	}
}
