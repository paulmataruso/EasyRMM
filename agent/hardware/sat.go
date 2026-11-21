package hardware

import "encoding/binary"

// What Linux's SG_IO carries for an ATA command: the SCSI / ATA Translation
// (SAT) of ATA PASS-THROUGH (16), and the answer's sense data. Plain Go,
// tested on every platform; the transport is in linux.go.

// ataPassThrough16 is ATA PASS-THROUGH (16)'s operation code. ATA
// PASS-THROUGH (12), A1h, is never built: A1h is also BLANK, an MMC command
// for optical drives, which Linux relays to them as it is.
const ataPassThrough16 = 0x85

// cdb16 builds the ATA PASS-THROUGH (16) command block of an allowed
// command: protocol PIO data-in (4) for reads, from the device, its length
// in sectors given by the count field; non-data (3) with the
// check-condition bit where the registers are wanted; the extend bit for a
// 48-bit command only.
func cdb16(c ataCommand) []byte {
	b := make([]byte, 16)
	b[0] = ataPassThrough16
	b[1] = byte(c.proto) << 1
	if c.ext {
		b[1] |= 0x01
	}
	if c.proto == ataPIODataIn {
		b[2] = 0x08 | 0x04 | 0x02 // T_DIR from the device, BYT_BLOK, T_LENGTH in the count
	}
	if c.registers {
		b[2] |= 0x20 // CK_COND
	}
	binary.BigEndian.PutUint16(b[3:], c.features)
	binary.BigEndian.PutUint16(b[5:], c.count)
	// Each LBA byte of a 48-bit command beside its 28-bit one: 31:24 and
	// 7:0, 39:32 and 15:8, 47:40 and 23:16.
	var l [8]byte
	binary.LittleEndian.PutUint64(l[:], c.lba)
	b[7], b[8], b[9], b[10], b[11], b[12] = l[3], l[0], l[4], l[1], l[5], l[2]
	b[13], b[14] = c.device, c.command
	return b
}

// Sense keys and additional sense codes the transport tells apart.
const (
	senseNoSense        = 0x00
	senseRecoveredError = 0x01
	senseIllegalRequest = 0x05
	// ascInvalidOpcode: the device does not know ATA PASS-THROUGH (16) at
	// all, as a SAS or other SCSI disk.
	ascInvalidOpcode = 0x20
)

// sense is what an answer's sense data says: its key and additional sense
// code, and the device's registers where the ATA Status Return descriptor
// (descriptor format) or the information fields (fixed format) carry them.
type sense struct {
	key, asc, ascq uint8
	regs           *ataRegisters
}

func parseSense(b []byte) (sense, bool) {
	if len(b) < 8 {
		return sense{}, false
	}
	switch b[0] & 0x7F {
	case 0x72, 0x73: // descriptor format
		s := sense{key: b[1] & 0x0F, asc: b[2], ascq: b[3]}
		end := min(len(b), 8+int(b[7]))
		for off := 8; off+2 <= end; off += 2 + int(b[off+1]) {
			d := b[off:min(end, off+2+int(b[off+1]))]
			if d[0] == 0x09 && len(d) >= 14 { // ATA Status Return
				s.regs = &ataRegisters{err: d[3], count: d[5], lbaLow: d[7], lbaMid: d[9], lbaHigh: d[11], device: d[12], status: d[13]}
			}
		}
		return s, true
	case 0x70, 0x71: // fixed format
		if len(b) < 14 {
			return sense{}, false
		}
		s := sense{key: b[2] & 0x0F, asc: b[12], ascq: b[13]}
		if b[0]&0x80 != 0 { // the information fields are valid
			s.regs = &ataRegisters{err: b[3], status: b[4], device: b[5], count: b[6], lbaLow: b[9], lbaMid: b[10], lbaHigh: b[11]}
		}
		return s, true
	}
	return sense{}, false
}

// SCSI status, host and driver codes of an SG_IO answer.
const (
	scsiGood           = 0x00
	scsiCheckCondition = 0x02
	hostTimeOut        = 0x03
	driverTimeout      = 0x06
)

// sgAnswer is what SG_IO returned for a command.
type sgAnswer struct {
	status       uint8
	hostStatus   uint16
	driverStatus uint16
	resid        int32
	sense        []byte
}

// sgOutcome reads an SG_IO answer: the data read when the command
// succeeded, the registers when it asked for them and the path returned
// them, or why it failed.
func sgOutcome(c ataCommand, a sgAnswer, data []byte) ([]byte, *ataRegisters, error) {
	switch {
	case a.hostStatus == hostTimeOut || a.driverStatus&0x0F == driverTimeout:
		return nil, nil, timedOut("SG_IO: the command timed out")
	case a.hostStatus != 0:
		return nil, nil, ioError("SG_IO: host status %d", a.hostStatus)
	case a.status == scsiGood:
		if c.proto == ataPIODataIn && a.resid != 0 {
			return nil, nil, badAnswer("SG_IO: %d of %d bytes", int(c.length)-int(a.resid), c.length)
		}
		// A path that ignores the check-condition bit returns no
		// registers.
		return data, nil, nil
	case a.status != scsiCheckCondition:
		return nil, nil, ioError("SG_IO: SCSI status %02Xh", a.status)
	}
	s, ok := parseSense(a.sense)
	switch {
	case !ok:
		return nil, nil, ioError("SG_IO: check condition without sense data")
	case s.regs != nil && s.regs.aborted():
		return nil, nil, deviceRefused("the drive aborted the command (error %02Xh, status %02Xh)", s.regs.err, s.regs.status)
	case s.regs != nil && s.regs.status&ataStatusErr != 0:
		return nil, nil, ioError("ATA error %02Xh, status %02Xh", s.regs.err, s.regs.status)
	case s.key == senseIllegalRequest && s.asc == ascInvalidOpcode:
		return nil, nil, notThisProtocol("ATA PASS-THROUGH (16) refused: invalid operation code")
	case s.key == senseIllegalRequest:
		return nil, nil, driverRefused("ATA PASS-THROUGH (16) refused: ASC %02Xh/%02Xh", s.asc, s.ascq)
	case (s.key == senseRecoveredError || s.key == senseNoSense) && s.regs != nil && c.registers && c.proto == ataNonData:
		return nil, s.regs, nil
	}
	return nil, nil, ioError("SG_IO: sense key %Xh, ASC %02Xh/%02Xh", s.key, s.asc, s.ascq)
}

// nvmeStatus reads the status an NVMe admin command completed with, as
// Linux returns it from the ioctl: the status code type in bits 10:8 and
// the status code in 7:0. Invalid Command Opcode, Invalid Field in Command
// and Invalid Log Page are the device refusing; the kernel's own Host
// Aborted Command (371h) is a command it gave up on after its timeout.
func nvmeStatus(status uint32) error {
	switch sc := status & 0x7FF; sc {
	case 0x001, 0x002, 0x109:
		return deviceRefused("NVMe status %03Xh", sc)
	case 0x371:
		return timedOut("NVMe status %03Xh: aborted by the host", sc)
	default:
		return ioError("NVMe status %03Xh", sc)
	}
}
