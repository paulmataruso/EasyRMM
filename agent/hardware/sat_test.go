package hardware

import (
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// descriptorSense is constructed descriptor-format sense data as libata
// returns it for a command with CK_COND: RECOVERED ERROR, ATA PASS-THROUGH
// INFORMATION AVAILABLE (00h/1Dh), and the ATA Status Return descriptor.
func descriptorSense(key, asc, ascq uint8, r ataRegisters) []byte {
	return []byte{0x72, key, asc, ascq, 0, 0, 0, 14,
		0x09, 0x0C, 0, r.err, 0, r.count, 0, r.lbaLow, 0, r.lbaMid, 0, r.lbaHigh, r.device, r.status}
}

// fixedSense is the same in fixed format, the registers in its
// information fields.
func fixedSense(key, asc, ascq uint8, r *ataRegisters) []byte {
	b := make([]byte, 18)
	b[0], b[2], b[7], b[12], b[13] = 0x70, key, 10, asc, ascq
	if r != nil {
		b[0] |= 0x80
		b[3], b[4], b[5], b[6], b[9], b[10], b[11] = r.err, r.status, r.device, r.count, r.lbaLow, r.lbaMid, r.lbaHigh
	}
	return b
}

func TestParseSense(t *testing.T) {
	want := ataRegisters{err: 0, count: 0xFF, lbaLow: 1, lbaMid: 0x4F, lbaHigh: 0xC2, device: 0xA0, status: 0x50}
	s, ok := parseSense(descriptorSense(senseRecoveredError, 0, 0x1D, want))
	if !ok || s.key != senseRecoveredError || s.ascq != 0x1D || s.regs == nil || *s.regs != want {
		t.Errorf("descriptor: %+v %v", s, ok)
	}
	s, ok = parseSense(fixedSense(senseRecoveredError, 0, 0x1D, &want))
	if !ok || s.regs == nil || *s.regs != want {
		t.Errorf("fixed: %+v %v", s, ok)
	}
	// Without the valid bit the fixed format's fields hold nothing.
	if s, ok := parseSense(fixedSense(senseIllegalRequest, 0x20, 0, nil)); !ok || s.regs != nil || s.asc != 0x20 {
		t.Errorf("fixed without registers: %+v", s)
	}
	// A descriptor list cut short, another descriptor first, a length
	// past the end.
	d := descriptorSense(senseRecoveredError, 0, 0x1D, want)
	if s, ok := parseSense(d[:15]); !ok || s.regs != nil {
		t.Errorf("cut short: %+v", s)
	}
	other := append([]byte{0x72, 1, 0, 0x1D, 0, 0, 0, 18, 0x00, 0x02, 0, 0}, d[8:]...)
	if s, ok := parseSense(other); !ok || s.regs == nil || *s.regs != want {
		t.Errorf("second descriptor: %+v", s)
	}
	d[7] = 200
	if s, ok := parseSense(d); !ok || s.regs == nil {
		t.Errorf("long additional length: %+v", s)
	}
	for _, b := range [][]byte{nil, {0x72, 1}, make([]byte, 8), fixedSense(0, 0, 0, nil)[:13]} {
		if _, ok := parseSense(b); ok {
			t.Errorf("% X accepted", b)
		}
	}
}

// TestSGOutcome: what an SG_IO answer means, for a read and for a command
// that asks for the registers.
func TestSGOutcome(t *testing.T) {
	data := make([]byte, 512)
	regs := ataRegisters{count: 0xFF, lbaMid: 0x4F, lbaHigh: 0xC2, status: 0x50}
	abort := ataRegisters{err: 0x04, status: 0x51}
	for name, tc := range map[string]struct {
		c      ataCommand
		a      sgAnswer
		reason string
		regs   bool
		data   bool
	}{
		"read":                  {c: smartReadData, a: sgAnswer{}, data: true},
		"short read":            {c: smartReadData, a: sgAnswer{resid: 12}, reason: agentproto.ReasonBadAnswer},
		"host timeout":          {c: smartReadData, a: sgAnswer{hostStatus: 3}, reason: agentproto.ReasonTimeout},
		"driver timeout":        {c: smartReadData, a: sgAnswer{driverStatus: 0x06}, reason: agentproto.ReasonTimeout},
		"host error":            {c: smartReadData, a: sgAnswer{hostStatus: 1}, reason: agentproto.ReasonIOError},
		"busy":                  {c: smartReadData, a: sgAnswer{status: 0x08}, reason: agentproto.ReasonIOError},
		"registers, descriptor": {c: smartReturnStatus, a: sgAnswer{status: 2, sense: descriptorSense(1, 0, 0x1D, regs)}, regs: true},
		"registers, fixed":      {c: ataPowerMode, a: sgAnswer{status: 2, sense: fixedSense(1, 0, 0x1D, &regs)}, regs: true},
		"registers, no sense":   {c: ataPowerMode, a: sgAnswer{status: 2, sense: fixedSense(0, 0, 0, &regs)}, regs: true},
		// A path that ignores CK_COND: no registers.
		"no registers":         {c: smartReturnStatus, a: sgAnswer{}},
		"aborted":              {c: smartReadLog(logDirectory, 1), a: sgAnswer{status: 2, sense: descriptorSense(0x0B, 0, 0, abort)}, reason: agentproto.ReasonDeviceRefused},
		"ATA error":            {c: smartReadData, a: sgAnswer{status: 2, sense: descriptorSense(0x03, 0x11, 0x04, ataRegisters{err: 0x40, status: 0x51})}, reason: agentproto.ReasonIOError},
		"invalid opcode (SAS)": {c: ataIdentify, a: sgAnswer{status: 2, sense: fixedSense(senseIllegalRequest, 0x20, 0, nil)}, reason: agentproto.ReasonProtocolNotRead},
		"invalid field":        {c: ataIdentify, a: sgAnswer{status: 2, sense: fixedSense(senseIllegalRequest, 0x24, 0, nil)}, reason: agentproto.ReasonStorageDriver},
		"no sense data":        {c: ataIdentify, a: sgAnswer{status: 2}, reason: agentproto.ReasonIOError},
		"medium error":         {c: ataIdentify, a: sgAnswer{status: 2, sense: fixedSense(0x03, 0x11, 0, nil)}, reason: agentproto.ReasonIOError},
		// Registers a read did not ask for are not an answer.
		"recovered on a read": {c: smartReadData, a: sgAnswer{status: 2, sense: descriptorSense(1, 0, 0x1D, regs)}, reason: agentproto.ReasonIOError},
	} {
		var buf []byte // the transport's: none for a non-data command
		if tc.c.length > 0 {
			buf = data
		}
		b, r, err := sgOutcome(tc.c, tc.a, buf)
		switch {
		case tc.reason != "" && !is(err, tc.reason):
			t.Errorf("%s: %v, want %s", name, err, tc.reason)
		case tc.reason == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.regs != (r != nil) || (r != nil && *r != regs):
			t.Errorf("%s: registers %+v", name, r)
		case tc.data != (b != nil):
			t.Errorf("%s: data %v", name, b != nil)
		}
	}
}

func TestNVMeStatus(t *testing.T) {
	for status, reason := range map[uint32]string{
		0x001: agentproto.ReasonDeviceRefused, 0x002: agentproto.ReasonDeviceRefused, 0x109: agentproto.ReasonDeviceRefused,
		// The Do Not Retry and More bits do not change the code.
		0x4002: agentproto.ReasonDeviceRefused,
		0x371:  agentproto.ReasonTimeout, 0x004: agentproto.ReasonIOError, 0x281: agentproto.ReasonIOError,
	} {
		if err := nvmeStatus(status); !is(err, reason) {
			t.Errorf("%03Xh: %v, want %s", status, err, reason)
		}
	}
}
