package hardware

import (
	"encoding/binary"
	"sync"
	"testing"
)

// Constructed answers, built here from the specifications' layouts (NVM
// Express Base 2.0c; ACS-4): not captured from any drive. Captured ones
// are in testdata (captures_test.go).

// healthLogBytes is an NVMe health log: critical warning, temperature in
// kelvins, spare, its threshold and percentage used, and the 128-bit
// counters given by their offsets.
func healthLogBytes(warning uint8, kelvin uint16, spare, threshold, used uint8, counters map[int]uint64) []byte {
	b := make([]byte, 512)
	b[0] = warning
	binary.LittleEndian.PutUint16(b[1:], kelvin)
	b[3], b[4], b[5] = spare, threshold, used
	for off, v := range counters {
		binary.LittleEndian.PutUint64(b[off:], v)
	}
	return b
}

// identifyControllerBytes is Identify Controller with a WCTEMP.
func identifyControllerBytes(wctemp uint16) []byte {
	b := make([]byte, 4096)
	copy(b[24:], "Constructed NVMe")
	binary.LittleEndian.PutUint16(b[266:], wctemp)
	return b
}

// identifyBytes is IDENTIFY DEVICE: SMART supported and enabled as given,
// with words 83 and 87 valid unless invalid.
func identifyBytes(smart, smartOn, invalid bool) []byte {
	b := make([]byte, 512)
	put := func(w int, v uint16) { binary.LittleEndian.PutUint16(b[2*w:], v) }
	valid := uint16(0x4000)
	if invalid {
		valid = 0
	}
	put(83, valid)
	put(87, valid)
	if smart {
		put(82, 1)
	}
	if smartOn {
		put(85, 1)
	}
	return b
}

// attr is one entry of the attribute table.
type attr struct {
	id        uint8
	flags     uint16
	value     uint8
	worst     uint8
	raw       uint64
	threshold uint8
	noThresh  bool
}

// sum makes b's last byte its checksum.
func sum(b []byte) []byte {
	var s byte
	for _, c := range b[:len(b)-1] {
		s += c
	}
	b[len(b)-1] = -s
	return b
}

// smartDataBytes is SMART READ DATA with the attributes and the error
// logging bit.
func smartDataBytes(attrs []attr, errorLog bool) []byte {
	b := make([]byte, 512)
	b[0] = 0x10
	for i, a := range attrs {
		e := b[2+12*i:]
		e[0] = a.id
		binary.LittleEndian.PutUint16(e[1:], a.flags)
		e[3], e[4] = a.value, a.worst
		for k := range 6 {
			e[5+k] = byte(a.raw >> (8 * k))
		}
	}
	if errorLog {
		b[370] = 1
	}
	return sum(b)
}

// thresholdBytes is SMART READ ATTRIBUTE THRESHOLDS for the attributes.
func thresholdBytes(attrs []attr) []byte {
	b := make([]byte, 512)
	b[0] = 0x10
	i := 0
	for _, a := range attrs {
		if a.noThresh {
			continue
		}
		b[2+12*i], b[3+12*i] = a.id, a.threshold
		i++
	}
	return sum(b)
}

// directoryBytes is a log directory giving each address its pages.
func directoryBytes(pages map[uint8]uint16) []byte {
	b := make([]byte, 512)
	binary.LittleEndian.PutUint16(b, 1) // the version
	for a, n := range pages {
		binary.LittleEndian.PutUint16(b[2*int(a):], n)
	}
	return b
}

// errorLogBytes is the summary SMART error log with its count.
func errorLogBytes(count uint16) []byte {
	b := make([]byte, 512)
	b[0] = 1
	binary.LittleEndian.PutUint16(b[452:], count)
	return sum(b)
}

// Device Statistics flags: bit 63 supported, bit 62 valid.
const (
	statSupported = 1 << 63
	statValid     = 1 << 62
)

// statsPageBytes is a Device Statistics page: revision 1, its number, and
// statistics by offset; page 00h lists pages instead.
func statsPageBytes(page uint8, stats map[int]uint64, list ...uint8) []byte {
	b := make([]byte, 512)
	binary.LittleEndian.PutUint16(b, 1)
	b[2] = page
	if page == statsList {
		b[8] = byte(len(list))
		copy(b[9:], list)
	}
	for off, v := range stats {
		binary.LittleEndian.PutUint64(b[off:], v)
	}
	return b
}

// answer is what a fake device answers a command.
type answer struct {
	data []byte
	regs *ataRegisters
	err  error
}

// fakeATA is a device at the operating system's boundary: it answers the
// commands it was given and refuses the others as a drive aborts an
// unknown command. Every command it receives must be on the list.
type fakeATA struct {
	t       *testing.T
	answers map[ataCommand]answer
	mu      sync.Mutex
	sent    []string
}

func (d *fakeATA) ata(c ataCommand) ([]byte, *ataRegisters, error) {
	if err := checkATA(c); err != nil {
		d.t.Errorf("the reader sent a command not on the list: %v", err)
		return nil, nil, err
	}
	d.mu.Lock()
	d.sent = append(d.sent, ataNames[c])
	d.mu.Unlock()
	a, ok := d.answers[c]
	if !ok {
		return nil, nil, deviceRefused("aborted %s", ataNames[c])
	}
	return a.data, a.regs, a.err
}

func (d *fakeATA) route() string { return "fake" }
func (d *fakeATA) close()        {}

// fakeNVMe is fakeATA for NVMe.
type fakeNVMe struct {
	t       *testing.T
	answers map[nvmeCommand]answer
}

func (d *fakeNVMe) nvme(c nvmeCommand) ([]byte, error) {
	if err := checkNVMe(c); err != nil {
		d.t.Errorf("the reader sent a command not on the list: %v", err)
		return nil, err
	}
	a, ok := d.answers[c]
	if !ok {
		return nil, deviceRefused("NVMe status 002h")
	}
	return a.data, a.err
}

func (d *fakeNVMe) route() string { return "fake" }
func (d *fakeNVMe) close()        {}

// registers are a non-data command's answer.
func registers(count, mid, high uint8) *ataRegisters {
	return &ataRegisters{count: count, lbaMid: mid, lbaHigh: high, status: 0x50}
}

// passing is RETURN STATUS with no threshold exceeded; exceeded with one.
var (
	passing  = registers(0, 0x4F, 0xC2)
	exceeded = registers(0, 0xF4, 0x2C)
	active   = registers(0xFF, 0, 0)
)
