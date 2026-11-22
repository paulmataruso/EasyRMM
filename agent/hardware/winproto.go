package hardware

import (
	"bytes"
	"encoding/binary"
)

// The buffers of Windows' two IOCTLs, laid out as on 64-bit Windows: the
// Windows agent is built for amd64 and arm64 only. Plain Go, so that every
// platform's tests check their bytes; the transport is in windows.go.

const (
	// STORAGE_PROPERTY_ID: the NVMe protocol-specific property asked of
	// the adapter or of the device.
	propertyAdapterProtocol = 49
	propertyDeviceProtocol  = 50

	protocolTypeNVMe     = 3 // ProtocolTypeNvme
	nvmeDataTypeIdentify = 1 // NVMeDataTypeIdentify
	nvmeDataTypeLogPage  = 2 // NVMeDataTypeLogPage

	// queryHeader is STORAGE_PROPERTY_QUERY up to AdditionalParameters:
	// PropertyId and QueryType.
	queryHeader = 8
	// protocolSpecificSize is STORAGE_PROTOCOL_SPECIFIC_DATA: ten ULONGs.
	protocolSpecificSize = 40
	// protocolDescriptorSize is STORAGE_PROTOCOL_DATA_DESCRIPTOR: Version,
	// Size and a STORAGE_PROTOCOL_SPECIFIC_DATA.
	protocolDescriptorSize = 8 + protocolSpecificSize
)

// nvmeQuery builds IOCTL_STORAGE_QUERY_PROPERTY's buffer, in and out, for
// an allowed NVMe command: STORAGE_PROPERTY_QUERY for property with
// PropertyStandardQuery (0), its STORAGE_PROTOCOL_SPECIFIC_DATA, and room
// for the data after it. Windows builds the command itself from these
// fields: Identify from the CNS and namespace; Get Log Page from the log
// identifier, offset 0 and, in ProtocolDataRequestSubValue4, Retain
// Asynchronous Event (bit 0) and the Log Specific Field (bits 4:1).
func nvmeQuery(property uint32, c nvmeCommand) []byte {
	le := binary.LittleEndian
	b := make([]byte, queryHeader+protocolSpecificSize+int(c.length))
	le.PutUint32(b[0:], property)
	p := b[queryHeader:]
	le.PutUint32(p[0:], protocolTypeNVMe)
	if c.opcode == nvmeIdentifyController.opcode {
		le.PutUint32(p[4:], nvmeDataTypeIdentify)
		le.PutUint32(p[8:], c.cdw10&0xFF) // CNS
		le.PutUint32(p[12:], c.nsid)
	} else {
		le.PutUint32(p[4:], nvmeDataTypeLogPage)
		le.PutUint32(p[8:], c.cdw10&0xFF)                       // log identifier
		le.PutUint32(p[36:], c.cdw10>>15&1|(c.cdw10>>8&0xF)<<1) // RAE, LSP
	}
	// ProtocolDataOffset counts from the STORAGE_PROTOCOL_SPECIFIC_DATA.
	le.PutUint32(p[16:], protocolSpecificSize)
	le.PutUint32(p[20:], c.length)
	return b
}

// nvmeAnswer reads a query's data out of the n bytes returned: a
// STORAGE_PROTOCOL_DATA_DESCRIPTOR, whose STORAGE_PROTOCOL_SPECIFIC_DATA
// says where the data is, from its own start, and how long it is.
func nvmeAnswer(b []byte, n uint32, want uint32) ([]byte, error) {
	le := binary.LittleEndian
	if n < protocolDescriptorSize || int(n) > len(b) {
		return nil, badAnswer("protocol data: %d bytes returned", n)
	}
	if v, s := le.Uint32(b[0:]), le.Uint32(b[4:]); v != protocolDescriptorSize || s != protocolDescriptorSize {
		return nil, badAnswer("protocol data descriptor version %d, size %d", v, s)
	}
	p := b[8:]
	off, length := uint64(le.Uint32(p[16:])), uint64(le.Uint32(p[20:]))
	if length != uint64(want) {
		return nil, badAnswer("protocol data: %d bytes, want %d", length, want)
	}
	if off < protocolSpecificSize || 8+off+length > uint64(n) {
		return nil, badAnswer("protocol data at %d, %d bytes, past the %d returned", off, length, n)
	}
	return bytes.Clone(p[off : off+length]), nil
}

const (
	// ataPassThroughSize is ATA_PASS_THROUGH_EX on 64-bit Windows: Length,
	// AtaFlags, PathId, TargetId, Lun, ReservedAsUchar, DataTransferLength,
	// TimeOutValue, ReservedAsUlong, DataBufferOffset (a ULONG_PTR, at 24),
	// PreviousTaskFile and CurrentTaskFile.
	ataPassThroughSize = 48
	// ataTimeoutSeconds is TimeOutValue, which the port driver applies.
	ataTimeoutSeconds = 60

	ataFlagsDataIn = 0x02 // ATA_FLAGS_DATA_IN
	ataFlags48Bit  = 0x08 // ATA_FLAGS_48BIT_COMMAND
)

// ataPassThrough builds IOCTL_ATA_PASS_THROUGH's buffer, in and out, for an
// allowed command: ATA_PASS_THROUGH_EX and room for the data after it.
// ATA_FLAGS_DATA_IN for reads and no data flag otherwise; 48-bit only for a
// 48-bit command, whose upper bytes go in PreviousTaskFile. Never data-out,
// never DMA. The disk's handle names the device, so PathId, TargetId and
// Lun stay 0.
func ataPassThrough(c ataCommand) []byte {
	le := binary.LittleEndian
	b := make([]byte, ataPassThroughSize+int(c.length))
	le.PutUint16(b[0:], ataPassThroughSize)
	f, n, l := taskFileBytes(c)
	var flags uint16
	if c.proto == ataPIODataIn {
		flags |= ataFlagsDataIn
		le.PutUint64(b[24:], ataPassThroughSize)
	}
	if c.ext {
		flags |= ataFlags48Bit
		prev := b[32:40]
		prev[0], prev[1], prev[2], prev[3], prev[4] = f[1], n[1], l[3], l[4], l[5]
	}
	le.PutUint16(b[2:], flags)
	le.PutUint32(b[8:], c.length)
	le.PutUint32(b[12:], ataTimeoutSeconds)
	cur := taskFile(c)
	copy(b[40:48], cur[:])
	return b
}

// taskFileBytes are a command's features, count and LBA, little-endian.
func taskFileBytes(c ataCommand) (f, n [2]byte, l [8]byte) {
	le := binary.LittleEndian
	le.PutUint16(f[:], c.features)
	le.PutUint16(n[:], c.count)
	le.PutUint64(l[:], c.lba)
	return f, n, l
}

// taskFile is a command's CurrentTaskFile as sent: features, count, LBA
// low, mid and high, device and command, then a reserved byte.
func taskFile(c ataCommand) [8]byte {
	f, n, l := taskFileBytes(c)
	return [8]byte{f[0], n[0], l[0], l[1], l[2], c.device, c.command}
}

// ataAnswer reads a pass-through's answer from the n bytes returned: the
// data read after the structure, or, for a non-data command, the device's
// registers, which the port driver puts in CurrentTaskFile. Registers with
// BSY set, or exactly as they were sent, are not the device's but a driver
// that did not return them: no registers, as on a Linux path without them.
// SMART RETURN STATUS then gives no verdict and CHECK POWER MODE no mode,
// so the disk is neither passed nor taken for asleep.
func ataAnswer(c ataCommand, b []byte, n uint32) ([]byte, *ataRegisters, error) {
	if n < ataPassThroughSize || int(n) > len(b) {
		return nil, nil, badAnswer("ATA pass-through: %d bytes returned", n)
	}
	cur := b[40:48]
	r := &ataRegisters{err: cur[0], count: cur[1], lbaLow: cur[2], lbaMid: cur[3], lbaHigh: cur[4], device: cur[5], status: cur[6]}
	if sent := taskFile(c); r.status&ataStatusBusy != 0 || bytes.Equal(cur[:7], sent[:7]) {
		r = nil
	}
	switch {
	case r != nil && r.aborted():
		return nil, nil, deviceRefused("the drive aborted the command (error %02Xh, status %02Xh)", r.err, r.status)
	case r != nil && r.status&ataStatusErr != 0:
		return nil, nil, ioError("ATA error %02Xh, status %02Xh", r.err, r.status)
	case c.proto == ataPIODataIn:
		if int(n) < ataPassThroughSize+int(c.length) {
			return nil, nil, badAnswer("ATA pass-through: %d of %d bytes", int(n)-ataPassThroughSize, c.length)
		}
		return bytes.Clone(b[ataPassThroughSize : ataPassThroughSize+int(c.length)]), nil, nil
	}
	return nil, r, nil
}
