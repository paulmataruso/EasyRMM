package hardware

import (
	"errors"
	"fmt"
)

// The commands the agent may send to a disk (ADR-0065, "The commands"):
// whole commands with every field fixed, never an opcode alone, since a Get
// Log Page or a SMART READ LOG can change the drive's state through its
// other fields. The reader asks for a command by its name; the name builds
// the command; and each transport checks the command against this list
// before it makes any system call, so that nothing else can reach a disk.

// errNotAllowed is a command that is not on the list. It never reaches the
// operating system.
var errNotAllowed = errors.New("hardware: the command is not on the list of allowed commands")

// nvmeCommand is an NVMe admin command: its opcode, namespace, command dwords
// 10 to 15 and the length of the data it reads.
type nvmeCommand struct {
	opcode uint8
	nsid   uint32
	cdw10  uint32
	cdw11  uint32
	cdw12  uint32
	cdw13  uint32
	cdw14  uint32
	cdw15  uint32
	length uint32
}

// The NVMe commands. Both read; neither changes the drive.
var (
	// nvmeIdentifyController is Identify (06h) with CNS 01h, Identify
	// Controller: NSID 0, CNTID 0, the CNS-specific identifier, CSI and
	// UUID index 0, 4,096 bytes. Model, serial, firmware and the
	// temperature thresholds.
	nvmeIdentifyController = nvmeCommand{opcode: 0x06, cdw10: 0x01, length: 4096}
	// nvmeHealthLog is Get Log Page (02h) for the SMART / Health
	// Information log (LID 02h) of the whole controller (NSID FFFFFFFFh),
	// with LSP 0 and Retain Asynchronous Event set, so that reading it
	// clears no event: 128 dwords (NUMDL 127, NUMDU 0) from offset 0, UUID
	// index and CSI 0.
	nvmeHealthLog = nvmeCommand{opcode: 0x02, nsid: 0xFFFFFFFF, cdw10: 0x02 | 1<<15 | 127<<16, length: 512}
)

// nvmeNames names the allowed NVMe commands, for errors and logs.
var nvmeNames = map[nvmeCommand]string{
	nvmeIdentifyController: "NVMe Identify Controller",
	nvmeHealthLog:          "NVMe health log",
}

// checkNVMe refuses an NVMe command that is not exactly one on the list.
func checkNVMe(c nvmeCommand) error {
	if _, ok := nvmeNames[c]; !ok {
		return fmt.Errorf("%w: NVMe opcode %02Xh", errNotAllowed, c.opcode)
	}
	return nil
}

// ataProtocol is how an ATA command moves data.
type ataProtocol uint8

const (
	// ataNonData moves no data; the device's registers are returned.
	ataNonData ataProtocol = 3
	// ataPIODataIn reads data from the device.
	ataPIODataIn ataProtocol = 4
)

// ataCommand is an ATA command as ATA PASS-THROUGH (16) and Windows'
// ATA_PASS_THROUGH_EX carry it: its registers, protocol and length.
type ataCommand struct {
	command  uint8
	features uint16
	count    uint16
	// lba is the 48-bit LBA field: bits 7:0 LBA low, 15:8 LBA mid, 23:16
	// LBA high, and 47:24 the upper bytes of a 48-bit command.
	lba    uint64
	device uint8
	proto  ataProtocol
	// ext marks a 48-bit command (READ LOG EXT only).
	ext bool
	// registers asks for the device's registers back: the check-condition
	// bit of ATA PASS-THROUGH (16).
	registers bool
	// length is the bytes read: 512 per sector of count.
	length uint32
}

// ATA command codes and SMART subcommands.
const (
	ataReadLogExt     = 0x2F
	ataSMART          = 0xB0
	ataCheckPowerMode = 0xE5
	ataIdentifyDevice = 0xEC

	smartReadDataFeature       = 0xD0
	smartReadThresholdsFeature = 0xD1
	smartReadLogFeature        = 0xD5
	smartReturnStatusFeature   = 0xDA

	// smartLBA is LBA mid 4Fh and LBA high C2h, which every SMART command
	// carries.
	smartLBA = 0x4F<<8 | 0xC2<<16
)

// Log addresses.
const (
	logDirectory        = 0x00
	logSummaryErrors    = 0x01
	logDeviceStatistics = 0x04
)

// The ATA commands. Each only reads.
var (
	// ataIdentify is IDENTIFY DEVICE: whether SMART is supported and
	// enabled, and the drive's identity.
	ataIdentify = ataCommand{command: ataIdentifyDevice, count: 1, proto: ataPIODataIn, length: 512}
	// ataPowerMode is CHECK POWER MODE: a disk in standby is not woken.
	ataPowerMode = ataCommand{command: ataCheckPowerMode, proto: ataNonData, registers: true}
	// smartReadData is SMART READ DATA: the attribute table.
	smartReadData = ataCommand{command: ataSMART, features: smartReadDataFeature, count: 1, lba: smartLBA, proto: ataPIODataIn, length: 512}
	// smartReadThresholds is SMART READ ATTRIBUTE THRESHOLDS.
	smartReadThresholds = ataCommand{command: ataSMART, features: smartReadThresholdsFeature, count: 1, lba: smartLBA, proto: ataPIODataIn, length: 512}
	// smartReturnStatus is SMART RETURN STATUS: the drive's verdict, in
	// LBA mid and high.
	smartReturnStatus = ataCommand{command: ataSMART, features: smartReturnStatusFeature, lba: smartLBA, proto: ataNonData, registers: true}
)

// smartReadLog is SMART READ LOG of a log address: the SMART log
// directory (00h) and the summary error log (01h), one sector each, and
// Device Statistics (04h), as many sectors as the directory says, at most
// 8. Only those are allowed.
func smartReadLog(address uint8, sectors uint16) ataCommand {
	return ataCommand{command: ataSMART, features: smartReadLogFeature, count: sectors, lba: smartLBA | uint64(address),
		proto: ataPIODataIn, length: 512 * uint32(sectors)}
}

// readLogExt is READ LOG EXT of one page of a log: the general-purpose log
// directory (00h, page 0) and the Device Statistics pages the reader uses
// (04h). Only those are allowed.
func readLogExt(address, page uint8) ataCommand {
	return ataCommand{command: ataReadLogExt, count: 1, lba: uint64(address) | uint64(page)<<8, proto: ataPIODataIn, ext: true, length: 512}
}

// Device Statistics pages the reader uses: the list of pages, rotating
// media, temperature and solid state.
const (
	statsList        = 0x00
	statsRotating    = 0x03
	statsTemperature = 0x05
	statsSolidState  = 0x07
)

// ataNames names the allowed ATA commands: the list.
var ataNames = func() map[ataCommand]string {
	m := map[ataCommand]string{
		ataIdentify:                       "IDENTIFY DEVICE",
		ataPowerMode:                      "CHECK POWER MODE",
		smartReadData:                     "SMART READ DATA",
		smartReadThresholds:               "SMART READ ATTRIBUTE THRESHOLDS",
		smartReturnStatus:                 "SMART RETURN STATUS",
		smartReadLog(logDirectory, 1):     "SMART READ LOG 00h",
		smartReadLog(logSummaryErrors, 1): "SMART READ LOG 01h",
		readLogExt(logDirectory, 0):       "READ LOG EXT 00h",
	}
	for n := uint16(1); n <= 8; n++ {
		m[smartReadLog(logDeviceStatistics, n)] = fmt.Sprintf("SMART READ LOG 04h, %d sectors", n)
	}
	for _, p := range []uint8{statsList, statsRotating, statsTemperature, statsSolidState} {
		m[readLogExt(logDeviceStatistics, p)] = fmt.Sprintf("READ LOG EXT 04h page %02Xh", p)
	}
	return m
}()

// checkATA refuses an ATA command that is not exactly one on the list.
func checkATA(c ataCommand) error {
	if _, ok := ataNames[c]; !ok {
		return fmt.Errorf("%w: ATA command %02Xh, features %04Xh", errNotAllowed, c.command, c.features)
	}
	return nil
}
