package hardware

import (
	"testing"
)

// The fuzz tests check that no answer makes a parser panic or read past
// its buffer: the answers come from drives, drivers and firmware. Each is
// seeded with the captured answers (captures_test.go) and constructed
// ones.

func FuzzHealthLog(f *testing.F) {
	seed(f, "nvme-health-log")
	f.Add(healthLogBytes(0xFF, 0xFFFF, 255, 255, 255, map[int]uint64{48: ^uint64(0), 56: ^uint64(0)}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if l, err := parseHealthLog(b); err == nil && (l.dataWritten < 0 || l.dataWritten > maxCount || l.mediaErrors > maxCount) {
			t.Errorf("a counter past its cap: %+v", l)
		}
	})
}

func FuzzIdentifyController(f *testing.F) {
	seed(f, "nvme-identify-controller")
	f.Add(identifyControllerBytes(0))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseIdentifyController(b)
	})
}

func FuzzIdentify(f *testing.F) {
	seed(f, "identify-device")
	f.Add(identifyBytes(true, true, false))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseIdentify(b)
	})
}

func FuzzSMARTData(f *testing.F) {
	seed(f, "smart-read-data")
	f.Add(smartDataBytes(failingAttrs, true))
	f.Fuzz(func(t *testing.T, b []byte) {
		if sd, err := parseSMARTData(b); err == nil && len(sd.attributes) > 30 {
			t.Errorf("%d attributes", len(sd.attributes))
		}
	})
}

func FuzzThresholds(f *testing.F) {
	seed(f, "smart-read-attribute-thresholds")
	f.Add(thresholdBytes(failingAttrs))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseThresholds(b)
	})
}

func FuzzLogDirectory(f *testing.F) {
	f.Add(directoryBytes(map[uint8]uint16{1: 1, 4: 8, 0xFF: 0xFFFF}))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := parseLogDirectory("directory", b)
		if err != nil {
			return
		}
		for a := range 256 {
			_ = d.pages(uint8(a)) //nolint:gosec // 0 to 255
		}
	})
}

func FuzzErrorLogCount(f *testing.F) {
	seed(f, "smart-read-log-01h")
	f.Add(errorLogBytes(0xFFFF))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseErrorLogCount(b)
	})
}

func FuzzStatsPage(f *testing.F) {
	f.Add(statsPageBytes(statsList, nil, 0, 1, 3, 4, 5, 7), uint8(statsList))
	f.Add(statsPageBytes(statsTemperature, map[int]uint64{statTemperature: statSupported | statValid | 0x80}), uint8(statsTemperature))
	f.Fuzz(func(t *testing.T, b []byte, page uint8) {
		p, err := parseStatsPage(b, page)
		if err != nil {
			return
		}
		_ = p.listed()
		for off := 8; off+8 <= sector; off += 8 {
			_ = p.stat(off, signedByte)
		}
	})
}

// FuzzSense reads sense data and the SG_IO answers around it.
func FuzzSense(f *testing.F) {
	f.Add(descriptorSense(1, 0, 0x1D, ataRegisters{lbaMid: 0x4F, lbaHigh: 0xC2, status: 0x50}), uint8(2), uint16(0), int32(0))
	f.Add(fixedSense(5, 0x20, 0, nil), uint8(2), uint16(0), int32(0))
	f.Fuzz(func(t *testing.T, b []byte, status uint8, host uint16, resid int32) {
		_, _ = parseSense(b)
		for c := range ataNames {
			_, _, _ = sgOutcome(c, sgAnswer{status: status, hostStatus: host, resid: resid, sense: b}, nil)
		}
	})
}

// FuzzWindowsAnswers reads Windows' answers as returned in the buffers.
func FuzzWindowsAnswers(f *testing.F) {
	f.Add(descriptor(healthLogBytes(0, 323, 100, 10, 0, nil), protocolSpecificSize, 512), uint32(protocolDescriptorSize+512))
	f.Add(ataPassThrough(ataIdentify), uint32(ataPassThroughSize+512))
	f.Fuzz(func(t *testing.T, b []byte, n uint32) {
		_, _ = nvmeAnswer(b, n, 512)
		for c := range ataNames {
			_, _, _ = ataAnswer(c, b, n)
		}
	})
}
