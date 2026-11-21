package hardware

import (
	"encoding/binary"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// The ATA structures, each 512 bytes, are read as the ATA/ATAPI Command
// Set (ACS) lays them out. Raw attribute values are the makers' own; only
// those whose meaning makers share are read (ADR-0065, "What is read").

// sector is the size of every ATA structure the agent reads.
const sector = 512

// ataIdentity is what the agent reads of IDENTIFY DEVICE.
type ataIdentity struct {
	// smart: the SMART feature set is supported (word 82 bit 0, valid when
	// word 83's bits 15:14 are 01); smartOn: it is enabled (word 85 bit 0,
	// valid when word 87's are 01).
	smart, smartOn bool
}

// word reads 16-bit word n of an ATA structure.
func word(b []byte, n int) uint16 { return binary.LittleEndian.Uint16(b[2*n:]) }

// validWord reports whether word n carries information: its bits 15:14 are
// 01.
func validWord(b []byte, n int) bool { return word(b, n)&0xC000 == 0x4000 }

func parseIdentify(b []byte) (ataIdentity, error) {
	if len(b) != sector {
		return ataIdentity{}, badAnswer("IDENTIFY DEVICE: %d bytes, want %d", len(b), sector)
	}
	if word(b, 0)&0x8000 != 0 {
		return ataIdentity{}, notThisProtocol("IDENTIFY DEVICE: a packet (ATAPI) device")
	}
	return ataIdentity{
		smart:   validWord(b, 83) && word(b, 82)&1 != 0,
		smartOn: validWord(b, 87) && word(b, 85)&1 != 0,
	}, nil
}

// checksummed reports whether a SMART structure's bytes sum to 0 modulo
// 256: its last byte is the two's complement of the sum of the others.
func checksummed(b []byte) bool {
	var sum byte
	for _, c := range b {
		sum += c
	}
	return sum == 0
}

// smartData is what the agent reads of SMART READ DATA.
type smartData struct {
	attributes []agentproto.Attribute
	// errorLog: the drive keeps the SMART error log (byte 370 bit 0).
	errorLog bool
}

// attributeTable is the 30 entries of 12 bytes from byte 2 of SMART data
// and of its thresholds.
func attributeTable(b []byte, each func(e []byte)) {
	for i := range agentproto.MaxAttributes {
		if e := b[2+12*i : 14+12*i]; e[0] != 0 {
			each(e)
		}
	}
}

func parseSMARTData(b []byte) (smartData, error) {
	if len(b) != sector {
		return smartData{}, badAnswer("SMART READ DATA: %d bytes, want %d", len(b), sector)
	}
	if !checksummed(b) {
		return smartData{}, badChecksum("SMART READ DATA")
	}
	out := smartData{errorLog: b[370]&1 != 0}
	seen := map[uint8]bool{}
	attributeTable(b, func(e []byte) {
		if seen[e[0]] {
			return
		}
		seen[e[0]] = true
		raw := uint64(e[5]) | uint64(e[6])<<8 | uint64(e[7])<<16 | uint64(e[8])<<24 | uint64(e[9])<<32 | uint64(e[10])<<40
		out.attributes = append(out.attributes, agentproto.Attribute{
			ID: e[0], Flags: binary.LittleEndian.Uint16(e[1:3]), Value: e[3], Worst: e[4], Raw: raw,
		})
	})
	return out, nil
}

// parseThresholds reads SMART READ ATTRIBUTE THRESHOLDS: each attribute's
// threshold by its ID.
func parseThresholds(b []byte) (map[uint8]uint8, error) {
	if len(b) != sector {
		return nil, badAnswer("SMART READ ATTRIBUTE THRESHOLDS: %d bytes, want %d", len(b), sector)
	}
	if !checksummed(b) {
		return nil, badChecksum("SMART READ ATTRIBUTE THRESHOLDS")
	}
	out := map[uint8]uint8{}
	attributeTable(b, func(e []byte) {
		if _, ok := out[e[0]]; !ok {
			out[e[0]] = e[1]
		}
	})
	return out, nil
}

// directory is a log directory (the SMART log directory, log 00h, or
// the general-purpose one, READ LOG EXT 00h): the number of pages each log
// address holds, in word n for address n.
type directory []byte

func parseLogDirectory(what string, b []byte) (directory, error) {
	if len(b) != sector {
		return nil, badAnswer("%s: %d bytes, want %d", what, len(b), sector)
	}
	return directory(b), nil
}

// pages is how many pages the directory gives a log; 0 when the drive does
// not keep it.
func (d directory) pages(address uint8) int {
	if d == nil || address == 0 {
		return 0
	}
	return int(word(d, int(address)))
}

// parseErrorLogCount reads the summary SMART error log (log 01h) for the
// drive's count of errors: the 16-bit value at bytes 452 and 453, after a
// version byte, a pointer byte and five 90-byte entries.
func parseErrorLogCount(b []byte) (int64, error) {
	if len(b) != sector {
		return 0, badAnswer("summary SMART error log: %d bytes, want %d", len(b), sector)
	}
	if !checksummed(b) {
		return 0, badChecksum("summary SMART error log")
	}
	return int64(binary.LittleEndian.Uint16(b[452:454])), nil
}

// statsPage is one page of the Device Statistics log (log 04h).
type statsPage []byte

// parseStatsPage checks a page's header: a revision and the page number
// asked for.
func parseStatsPage(b []byte, page uint8) (statsPage, error) {
	if len(b) != sector {
		return nil, badAnswer("Device Statistics page %02Xh: %d bytes, want %d", page, len(b), sector)
	}
	if word(b, 0) == 0 || b[2] != page {
		return nil, badAnswer("Device Statistics page %02Xh: its header names page %02Xh, revision %d", page, b[2], word(b, 0))
	}
	return statsPage(b), nil
}

// listed returns the pages the list of supported pages (page 00h) names.
func (p statsPage) listed() map[uint8]bool {
	n := min(int(p[8]), sector-9)
	out := make(map[uint8]bool, n)
	for _, page := range p[9 : 9+n] {
		out[page] = true
	}
	return out
}

// Statistics read, by page and offset.
const (
	// statReallocated is page 03h's Number of Reallocated Logical Sectors.
	statReallocated = 0x20
	// statTemperature is page 05h's Current Temperature, signed, in °C.
	statTemperature = 0x08
	// statTemperatureLimit is page 05h's Specified Maximum Operating
	// Temperature.
	statTemperatureLimit = 0x58
	// statPercentageUsed is page 07h's Percentage Used Endurance
	// Indicator.
	statPercentageUsed = 0x08
)

// stat reads the statistic at offset as a fact. Its top byte holds flags:
// bit 63 supported (else the drive does not keep it), bit 62 valid (else
// it holds no value now, never 0). value turns the rest into the fact's
// value.
func (p statsPage) stat(offset int, value func(v uint64) int64) agentproto.Fact {
	v := binary.LittleEndian.Uint64(p[offset:])
	switch {
	case v&(1<<63) == 0:
		return agentproto.NotRead(agentproto.FactUnsupported, agentproto.ReasonNotKept)
	case v&(1<<62) == 0:
		return agentproto.NotRead(agentproto.FactUnknown, agentproto.ReasonNotValid)
	}
	return agentproto.Read(value(v))
}

// signedByte is a temperature statistic: bits 7:0, signed.
func signedByte(v uint64) int64 { return int64(int8(v)) } //nolint:gosec // the low byte, signed by definition

// lowByte is a percentage statistic: bits 7:0.
func lowByte(v uint64) int64 { return int64(v & 0xFF) }

// lowDword is a count statistic: bits 31:0.
func lowDword(v uint64) int64 { return int64(v & 0xFFFFFFFF) }

// standby reports whether CHECK POWER MODE's answer is a standby mode, in
// which the disk is spun down: 00h standby, 01h Standby_y and 40h NV Cache
// power mode with the spindle spun down.
func standby(mode uint8) bool { return mode == 0x00 || mode == 0x01 || mode == 0x40 }

// readATA reads an ATA disk with the commands of the list, in the order the
// ADR gives: CHECK POWER MODE first, so that a sleeping disk is skipped
// unless wake, then IDENTIFY DEVICE, the verdict, the attributes and their
// thresholds, the error log's count and Device Statistics through the log
// directories. A disk without SMART, or with it turned off, fails the
// reading; so does a timeout or a refused access at any step.
func readATA(d ataDevice, wake bool) (agentproto.DiskHealth, error) {
	h := agentproto.DiskHealth{State: agentproto.FactRead, Protocol: agentproto.ProtocolATA}
	notKept := agentproto.NotRead(agentproto.FactUnsupported, agentproto.ReasonNotKept)
	h.CriticalWarning, h.AvailableSpare, h.AvailableSpareThreshold, h.MediaErrors = notKept, notKept, notKept, notKept
	h.DataWritten, h.UnsafeShutdowns = notKept, notKept

	_, regs, err := d.ata(ataPowerMode)
	switch {
	case err == nil && regs == nil:
		h.PowerMode = agentproto.NotRead(agentproto.FactUnknown, agentproto.ReasonBadAnswer)
	case err == nil:
		h.PowerMode = agentproto.Read(int64(regs.count))
		if standby(regs.count) && !wake {
			return h, errAsleep
		}
	case is(err, agentproto.ReasonDeviceRefused):
		h.PowerMode = asFailure(err).fact()
	default:
		return h, err
	}

	data, _, err := d.ata(ataIdentify)
	if err != nil {
		return h, err
	}
	id, err := parseIdentify(data)
	switch {
	case err != nil:
		return h, err
	case !id.smart:
		return h, fail(agentproto.FactUnsupported, agentproto.ReasonNoSMART, "")
	case !id.smartOn:
		return h, fail(agentproto.FactUnavailable, agentproto.ReasonSMARTOff, "")
	}

	_, regs, err = d.ata(smartReturnStatus)
	if fatal(err) {
		return h, err
	}
	h.SMARTStatus = smartStatus(regs, err)

	var sd smartData
	data, _, err = d.ata(smartReadData)
	if fatal(err) {
		return h, err
	}
	if err == nil {
		sd, err = parseSMARTData(data)
	}
	dataErr := err

	data, _, err = d.ata(smartReadThresholds)
	if fatal(err) {
		return h, err
	}
	var thresholds map[uint8]uint8
	if err == nil {
		thresholds, err = parseThresholds(data)
	}
	if err != nil {
		h.Thresholds = asFailure(err).fact()
	} else {
		h.Thresholds = agentproto.Read(int64(len(thresholds)))
	}
	for i := range sd.attributes {
		if t, ok := thresholds[sd.attributes[i].ID]; ok {
			sd.attributes[i].Threshold = &t
		}
	}
	h.Attributes = sd.attributes

	smartDir, err := readDirectory(d, smartReadLog(logDirectory, 1), "SMART log directory")
	if fatal(err) {
		return h, err
	}
	gplDir, err := readDirectory(d, readLogExt(logDirectory, 0), "general-purpose log directory")
	if fatal(err) {
		return h, err
	}

	if h.DriveErrors, err = errorCount(d, smartDir, sd, dataErr); fatal(err) {
		return h, err
	}
	stats, err := deviceStatistics(d, gplDir, smartDir)
	if fatal(err) {
		return h, err
	}

	attr := func(id uint8, value func(raw uint64) int64) agentproto.Fact {
		if dataErr != nil {
			return asFailure(dataErr).fact()
		}
		for _, a := range sd.attributes {
			if a.ID == id {
				return agentproto.Read(value(a.Raw))
			}
		}
		return notKept
	}
	raw := func(r uint64) int64 { return int64(r) } //nolint:gosec // 48 bits
	low := func(r uint64) int64 { return int64(r & 0xFF) }
	h.Temperature = firstRead(stats.fact(statsTemperature, statTemperature, signedByte), attr(194, low), attr(190, low))
	h.TemperatureLimit = stats.fact(statsTemperature, statTemperatureLimit, signedByte)
	h.Wear = stats.fact(statsSolidState, statPercentageUsed, lowByte)
	h.ReallocatedSectors = firstRead(attr(5, raw), stats.fact(statsRotating, statReallocated, lowDword))
	h.PendingSectors = attr(197, raw)
	h.UncorrectableSectors = attr(198, raw)
	h.PowerOnHours = attr(9, raw)
	return h, nil
}

// smartStatus is SMART RETURN STATUS's answer: LBA mid and high 4Fh and
// C2h when no threshold is exceeded, F4h and 2Ch when one is. A path that
// returns no registers leaves the verdict to the thresholds.
func smartStatus(regs *ataRegisters, err error) agentproto.Fact {
	switch {
	case err != nil:
		return asFailure(err).fact()
	case regs == nil:
		return agentproto.NotRead(agentproto.FactUnavailable, agentproto.ReasonStorageDriver)
	case regs.lbaMid == 0x4F && regs.lbaHigh == 0xC2:
		return agentproto.Read(agentproto.SMARTPassed)
	case regs.lbaMid == 0xF4 && regs.lbaHigh == 0x2C:
		return agentproto.Read(agentproto.SMARTThresholdExceeded)
	}
	return agentproto.NotRead(agentproto.FactUnknown, agentproto.ReasonBadAnswer)
}

// firstRead is the first fact that was read; else the first that the drive
// keeps but could not give (unknown or unavailable); else the first.
func firstRead(facts ...agentproto.Fact) agentproto.Fact {
	for _, f := range facts {
		if f.State == agentproto.FactRead {
			return f
		}
	}
	for _, f := range facts {
		if f.State != agentproto.FactUnsupported {
			return f
		}
	}
	return facts[0]
}

// readDirectory reads a log directory; a drive may refuse one, which then
// is nil.
func readDirectory(d ataDevice, c ataCommand, what string) (directory, error) {
	data, _, err := d.ata(c)
	if err != nil {
		return nil, err
	}
	return parseLogDirectory(what, data)
}

// errorCount reads the summary SMART error log's count where the SMART log
// directory lists the log, or, without a directory, where the SMART data
// says the drive keeps one: nothing is tried blind.
func errorCount(d ataDevice, dir directory, sd smartData, dataErr error) (agentproto.Fact, error) {
	switch {
	case dir != nil && dir.pages(logSummaryErrors) == 0,
		dir == nil && dataErr == nil && !sd.errorLog:
		return agentproto.NotRead(agentproto.FactUnsupported, agentproto.ReasonNotKept), nil
	case dir == nil && dataErr != nil:
		return asFailure(dataErr).fact(), nil
	}
	data, _, err := d.ata(smartReadLog(logSummaryErrors, 1))
	if err != nil {
		return asFailure(err).fact(), err
	}
	n, err := parseErrorLogCount(data)
	if err != nil {
		return asFailure(err).fact(), nil
	}
	return agentproto.Read(n), nil
}

// statistics are the Device Statistics pages read, or why each was not.
type statistics struct {
	pages map[uint8]statsPage
	// failed is why the log, or a page of it, could not be read.
	failed map[uint8]error
}

// fact reads one statistic: unsupported (not_kept) when the drive does not
// keep the log or the page.
func (s statistics) fact(page uint8, offset int, value func(uint64) int64) agentproto.Fact {
	if p, ok := s.pages[page]; ok {
		return p.stat(offset, value)
	}
	if err, ok := s.failed[page]; ok {
		return asFailure(err).fact()
	}
	return agentproto.NotRead(agentproto.FactUnsupported, agentproto.ReasonNotKept)
}

// deviceStatistics reads the Device Statistics pages the facts come from,
// only through a directory that lists the log: by READ LOG EXT where the
// general-purpose directory lists it, else by SMART READ LOG where only the
// SMART directory does, all its pages at once (at most 8).
func deviceStatistics(d ataDevice, gplDir, smartDir directory) (statistics, error) {
	s := statistics{pages: map[uint8]statsPage{}, failed: map[uint8]error{}}
	wanted := []uint8{statsRotating, statsTemperature, statsSolidState}
	failAll := func(err error) {
		for _, p := range wanted {
			s.failed[p] = err
		}
	}
	switch {
	case gplDir.pages(logDeviceStatistics) > 0:
		n := gplDir.pages(logDeviceStatistics)
		read := func(page uint8) (statsPage, error) {
			data, _, err := d.ata(readLogExt(logDeviceStatistics, page))
			if err != nil {
				return nil, err
			}
			return parseStatsPage(data, page)
		}
		list, err := read(statsList)
		if err != nil {
			failAll(err)
			return s, err
		}
		listed := list.listed()
		for _, p := range wanted {
			if !listed[p] || int(p) >= n {
				continue
			}
			page, err := read(p)
			if fatal(err) {
				return s, err
			}
			if err != nil {
				s.failed[p] = err
				continue
			}
			s.pages[p] = page
		}
	case smartDir.pages(logDeviceStatistics) > 0:
		n := min(smartDir.pages(logDeviceStatistics), 8)
		data, _, err := d.ata(smartReadLog(logDeviceStatistics, uint16(n))) //nolint:gosec // 1 to 8
		if err == nil && len(data) != n*sector {
			err = badAnswer("SMART READ LOG 04h: %d bytes, want %d", len(data), n*sector)
		}
		if err != nil {
			failAll(err)
			return s, err
		}
		list, err := parseStatsPage(data[:sector], statsList)
		if err != nil {
			failAll(err)
			return s, nil
		}
		listed := list.listed()
		for _, p := range wanted {
			if !listed[p] || int(p) >= n {
				continue
			}
			page, err := parseStatsPage(data[int(p)*sector:(int(p)+1)*sector], p)
			if err != nil {
				s.failed[p] = err
				continue
			}
			s.pages[p] = page
		}
	}
	return s, nil
}
