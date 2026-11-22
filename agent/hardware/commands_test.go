package hardware

import (
	"errors"
	"testing"
)

// ataMutations are every command one field away from c: each bit of each
// register and of the length flipped, every other command code and
// protocol, and each flag negated.
func ataMutations(c ataCommand) map[string]ataCommand {
	out := map[string]ataCommand{}
	add := func(name string, m ataCommand) { out[name] = m }
	for v := range 256 {
		m := c
		m.command = uint8(v) //nolint:gosec // 0 to 255
		if m != c {
			add("command "+hex(v), m)
		}
		m = c
		m.proto = ataProtocol(v) //nolint:gosec // 0 to 255
		if m != c {
			add("protocol "+hex(v), m)
		}
	}
	for b := range 16 {
		m := c
		m.features ^= 1 << b
		add("features bit "+hex(b), m)
		m = c
		m.count ^= 1 << b
		add("count bit "+hex(b), m)
	}
	for b := range 48 {
		m := c
		m.lba ^= 1 << b
		add("lba bit "+hex(b), m)
	}
	for b := range 8 {
		m := c
		m.device ^= 1 << b
		add("device bit "+hex(b), m)
	}
	for b := range 32 {
		m := c
		m.length ^= 1 << b
		add("length bit "+hex(b), m)
	}
	m := c
	m.ext = !m.ext
	add("ext", m)
	m = c
	m.registers = !m.registers
	add("registers", m)
	return out
}

func nvmeMutations(c nvmeCommand) map[string]nvmeCommand {
	out := map[string]nvmeCommand{}
	for v := range 256 {
		m := c
		m.opcode = uint8(v) //nolint:gosec // 0 to 255
		if m != c {
			out["opcode "+hex(v)] = m
		}
	}
	for b := range 32 {
		for name, field := range map[string]func(*nvmeCommand) *uint32{
			"nsid":   func(m *nvmeCommand) *uint32 { return &m.nsid },
			"cdw10":  func(m *nvmeCommand) *uint32 { return &m.cdw10 },
			"cdw11":  func(m *nvmeCommand) *uint32 { return &m.cdw11 },
			"cdw12":  func(m *nvmeCommand) *uint32 { return &m.cdw12 },
			"cdw13":  func(m *nvmeCommand) *uint32 { return &m.cdw13 },
			"cdw14":  func(m *nvmeCommand) *uint32 { return &m.cdw14 },
			"cdw15":  func(m *nvmeCommand) *uint32 { return &m.cdw15 },
			"length": func(m *nvmeCommand) *uint32 { return &m.length },
		} {
			m := c
			*field(&m) ^= 1 << b
			out[name+" bit "+hex(b)] = m
		}
	}
	return out
}

func hex(v int) string {
	return string("0123456789ABCDEF"[v>>4&15]) + string("0123456789ABCDEF"[v&15]) + "h"
}

// TestCommandList changes each fixed field of each allowed command, one at
// a time, and expects the result refused, unless it is itself a command of
// the list (a Device Statistics read of another length or page).
func TestCommandList(t *testing.T) {
	if len(ataNames) != 20 || len(nvmeNames) != 2 {
		t.Fatalf("%d ATA and %d NVMe commands on the list", len(ataNames), len(nvmeNames))
	}
	for c, name := range ataNames {
		if err := checkATA(c); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
		refused := 0
		for what, m := range ataMutations(c) {
			_, listed := ataNames[m]
			if err := checkATA(m); listed != (err == nil) || (err != nil && !errors.Is(err, errNotAllowed)) {
				t.Errorf("%s with its %s changed: listed %v, %v", name, what, listed, err)
			}
			if !listed {
				refused++
			}
		}
		if refused < 400 {
			t.Errorf("%s: only %d changes refused", name, refused)
		}
	}
	for c, name := range nvmeNames {
		if err := checkNVMe(c); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
		for what, m := range nvmeMutations(c) {
			if err := checkNVMe(m); !errors.Is(err, errNotAllowed) {
				t.Errorf("%s with its %s changed: %v", name, what, err)
			}
		}
	}
}

// TestCommandsNotListed sends every opcode, SMART feature, log address and
// Device Statistics page that is not on the list.
func TestCommandsNotListed(t *testing.T) {
	refuse := func(what string, c ataCommand) {
		t.Helper()
		if err := checkATA(c); !errors.Is(err, errNotAllowed) {
			t.Errorf("%s: %v", what, err)
		}
	}
	listedOpcodes := map[uint8]bool{ataReadLogExt: true, ataSMART: true, ataCheckPowerMode: true, ataIdentifyDevice: true}
	for v := range 256 {
		op := uint8(v) //nolint:gosec // 0 to 255
		if !listedOpcodes[op] {
			for _, c := range []ataCommand{ataIdentify, ataPowerMode, smartReadData, readLogExt(logDirectory, 0)} {
				c.command = op
				refuse("opcode "+hex(v), c)
			}
		}
		switch op {
		case smartReadDataFeature, smartReadThresholdsFeature, smartReadLogFeature, smartReturnStatusFeature:
		default:
			// SMART ENABLE (D8h), DISABLE (D9h), EXECUTE OFF-LINE
			// (D4h), WRITE LOG (D6h) among them.
			for _, c := range []ataCommand{smartReadData, smartReturnStatus, smartReadLog(logDirectory, 1)} {
				c.features = uint16(op)
				refuse("SMART feature "+hex(v), c)
			}
		}
		switch op {
		case logDirectory, logSummaryErrors:
		case logDeviceStatistics:
			refuse("SMART READ LOG 04h, 0 sectors", smartReadLog(op, 0))
			refuse("SMART READ LOG 04h, 9 sectors", smartReadLog(op, 9))
		default:
			// The self-test logs (06h, 07h), SCT (E0h, E1h), host
			// logs (80h to 9Fh) and every vendor log among them.
			refuse("SMART READ LOG "+hex(v), smartReadLog(op, 1))
			refuse("READ LOG EXT "+hex(v), readLogExt(op, 0))
		}
		switch op {
		case statsList, statsRotating, statsTemperature, statsSolidState:
		default:
			refuse("Device Statistics page "+hex(v), readLogExt(logDeviceStatistics, op))
		}
		if op != 0 {
			refuse("general-purpose log directory page "+hex(v), readLogExt(logDirectory, op))
		}
		if op != 1 {
			refuse("SMART log directory, "+hex(v)+" sectors", smartReadLog(logDirectory, uint16(op)))
			refuse("summary error log, "+hex(v)+" sectors", smartReadLog(logSummaryErrors, uint16(op)))
		}
		for _, c := range []nvmeCommand{nvmeIdentifyController, nvmeHealthLog} {
			c.opcode = op
			if _, ok := nvmeNames[c]; !ok {
				if err := checkNVMe(c); !errors.Is(err, errNotAllowed) {
					t.Errorf("NVMe opcode %s: %v", hex(v), err)
				}
			}
		}
		// Every other log page and Identify structure.
		if op != 0x02 {
			c := nvmeHealthLog
			c.cdw10 = c.cdw10&^0xFF | uint32(op)
			if err := checkNVMe(c); !errors.Is(err, errNotAllowed) {
				t.Errorf("NVMe log page %s: %v", hex(v), err)
			}
		}
		if op != 0x01 {
			c := nvmeIdentifyController
			c.cdw10 = uint32(op)
			if err := checkNVMe(c); !errors.Is(err, errNotAllowed) {
				t.Errorf("NVMe Identify CNS %s: %v", hex(v), err)
			}
		}
	}
	// Never DMA, never data-out, never a 48-bit form but READ LOG EXT's.
	for _, proto := range []ataProtocol{0, 1, 2, 5, 6, 10, 12, 15} {
		c := smartReadData
		c.proto = proto
		refuse("protocol "+hex(int(proto)), c)
	}
}

// TestCDB16 builds every allowed command as ATA PASS-THROUGH (16): never
// ATA PASS-THROUGH (12), whose operation code A1h is also MMC's BLANK.
func TestCDB16(t *testing.T) {
	for c, name := range ataNames {
		b := cdb16(c)
		if len(b) != 16 || b[0] != 0x85 || b[14] != c.command || b[15] != 0 {
			t.Errorf("%s: % X", name, b)
		}
		if ext := b[1]&1 == 1; ext != (c.command == ataReadLogExt) {
			t.Errorf("%s: extend bit %v", name, ext)
		}
	}
	for name, want := range map[string][]byte{
		// Non-data (3) with CK_COND.
		"CHECK POWER MODE":    {0x85, 0x06, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xE5, 0},
		"SMART RETURN STATUS": {0x85, 0x06, 0x20, 0, 0xDA, 0, 0, 0, 0, 0, 0x4F, 0, 0xC2, 0, 0xB0, 0},
		// PIO data-in (4): T_DIR, BYT_BLOK, T_LENGTH in the count.
		"SMART READ DATA": {0x85, 0x08, 0x0E, 0, 0xD0, 0, 1, 0, 0, 0, 0x4F, 0, 0xC2, 0, 0xB0, 0},
		"IDENTIFY DEVICE": {0x85, 0x08, 0x0E, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xEC, 0},
		// 48-bit: the page in LBA (15:8).
		"READ LOG EXT 04h page 05h":     {0x85, 0x09, 0x0E, 0, 0, 0, 1, 0, 0x04, 0, 0x05, 0, 0, 0, 0x2F, 0},
		"SMART READ LOG 04h, 8 sectors": {0x85, 0x08, 0x0E, 0, 0xD5, 0, 8, 0, 0x04, 0, 0x4F, 0, 0xC2, 0, 0xB0, 0},
	} {
		var c ataCommand
		for cmd, n := range ataNames {
			if n == name {
				c = cmd
			}
		}
		if got := cdb16(c); string(got) != string(want) {
			t.Errorf("%s:\n got % X\nwant % X", name, got, want)
		}
	}
}
