package hardware

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// The Windows structures as winioctl.h and ntddscsi.h declare them, with
// ULONG_PTR as on 64-bit Windows (amd64 and arm64), so that Go lays them
// out as those do on every platform the tests run on.
type storagePropertyQuery struct {
	PropertyID uint32
	QueryType  uint32
	// AdditionalParameters follow.
}

type storageProtocolSpecificData struct {
	ProtocolType                 uint32
	DataType                     uint32
	ProtocolDataRequestValue     uint32
	ProtocolDataRequestSubValue  uint32
	ProtocolDataOffset           uint32
	ProtocolDataLength           uint32
	FixedProtocolReturnData      uint32
	ProtocolDataRequestSubValue2 uint32
	ProtocolDataRequestSubValue3 uint32
	ProtocolDataRequestSubValue4 uint32
}

type storageProtocolDataDescriptor struct {
	Version              uint32
	Size                 uint32
	ProtocolSpecificData storageProtocolSpecificData
}

type ataPassThroughEx struct {
	Length             uint16
	AtaFlags           uint16
	PathID             uint8
	TargetID           uint8
	Lun                uint8
	ReservedAsUchar    uint8
	DataTransferLength uint32
	TimeOutValue       uint32
	ReservedAsUlong    uint32
	// A ULONG_PTR, 8 bytes aligned to 8 on 64-bit Windows: spelled out so
	// that the layout is the same on a 32-bit test machine.
	_                [4]byte
	DataBufferOffset [8]byte
	PreviousTaskFile [8]uint8
	CurrentTaskFile  [8]uint8
}

// TestWindowsLayouts checks winproto.go's offsets against the declared
// structures: sizes and the offset of every field it writes or reads.
func TestWindowsLayouts(t *testing.T) {
	var q storagePropertyQuery
	var p storageProtocolSpecificData
	var d storageProtocolDataDescriptor
	var a ataPassThroughEx
	for name, got := range map[string][2]uintptr{
		"STORAGE_PROPERTY_QUERY header":    {unsafe.Sizeof(q), queryHeader},
		"STORAGE_PROTOCOL_SPECIFIC_DATA":   {unsafe.Sizeof(p), protocolSpecificSize},
		"STORAGE_PROTOCOL_DATA_DESCRIPTOR": {unsafe.Sizeof(d), protocolDescriptorSize},
		"ATA_PASS_THROUGH_EX":              {unsafe.Sizeof(a), ataPassThroughSize},
		"DataType":                         {unsafe.Offsetof(p.DataType), 4},
		"ProtocolDataRequestValue":         {unsafe.Offsetof(p.ProtocolDataRequestValue), 8},
		"ProtocolDataRequestSubValue":      {unsafe.Offsetof(p.ProtocolDataRequestSubValue), 12},
		"ProtocolDataOffset":               {unsafe.Offsetof(p.ProtocolDataOffset), 16},
		"ProtocolDataLength":               {unsafe.Offsetof(p.ProtocolDataLength), 20},
		"ProtocolDataRequestSubValue4":     {unsafe.Offsetof(p.ProtocolDataRequestSubValue4), 36},
		"ProtocolSpecificData":             {unsafe.Offsetof(d.ProtocolSpecificData), 8},
		"AtaFlags":                         {unsafe.Offsetof(a.AtaFlags), 2},
		"DataTransferLength":               {unsafe.Offsetof(a.DataTransferLength), 8},
		"TimeOutValue":                     {unsafe.Offsetof(a.TimeOutValue), 12},
		"DataBufferOffset":                 {unsafe.Offsetof(a.DataBufferOffset), 24},
		"PreviousTaskFile":                 {unsafe.Offsetof(a.PreviousTaskFile), 32},
		"CurrentTaskFile":                  {unsafe.Offsetof(a.CurrentTaskFile), 40},
	} {
		if got[0] != got[1] {
			t.Errorf("%s: %d, winproto.go uses %d", name, got[0], got[1])
		}
	}
}

func TestNVMeQuery(t *testing.T) {
	le := binary.LittleEndian
	for _, property := range []uint32{propertyDeviceProtocol, propertyAdapterProtocol} {
		b := nvmeQuery(property, nvmeHealthLog)
		p := b[queryHeader:]
		want := []uint32{protocolTypeNVMe, nvmeDataTypeLogPage, 0x02, 0, protocolSpecificSize, 512, 0, 0, 0, 1}
		if len(b) != queryHeader+protocolSpecificSize+512 || le.Uint32(b) != property || le.Uint32(b[4:]) != 0 {
			t.Errorf("health log: % X", b[:queryHeader])
		}
		for i, w := range want {
			if got := le.Uint32(p[4*i:]); got != w {
				t.Errorf("health log, property %d: ULONG %d = %d, want %d", property, i, got, w)
			}
		}
		b = nvmeQuery(property, nvmeIdentifyController)
		p = b[queryHeader:]
		want = []uint32{protocolTypeNVMe, nvmeDataTypeIdentify, 0x01, 0, protocolSpecificSize, 4096, 0, 0, 0, 0}
		if len(b) != queryHeader+protocolSpecificSize+4096 {
			t.Errorf("identify: %d bytes", len(b))
		}
		for i, w := range want {
			if got := le.Uint32(p[4*i:]); got != w {
				t.Errorf("identify, property %d: ULONG %d = %d, want %d", property, i, got, w)
			}
		}
	}
}

// descriptor is a query's answer as Windows returns it in the same buffer.
func descriptor(data []byte, off, length uint32) []byte {
	b := make([]byte, protocolDescriptorSize+len(data))
	binary.LittleEndian.PutUint32(b, protocolDescriptorSize)
	binary.LittleEndian.PutUint32(b[4:], protocolDescriptorSize)
	binary.LittleEndian.PutUint32(b[8+16:], off)
	binary.LittleEndian.PutUint32(b[8+20:], length)
	copy(b[protocolDescriptorSize:], data)
	return b
}

func TestNVMeAnswer(t *testing.T) {
	log := healthLogBytes(0, 323, 100, 10, 0, nil)
	b := descriptor(log, protocolSpecificSize, 512)
	got, err := nvmeAnswer(b, uint32(len(b)), 512)
	if err != nil || string(got) != string(log) {
		t.Fatalf("%v", err)
	}
	b[protocolDescriptorSize] = 0x99 // the answer is a copy
	if got[0] == 0x99 {
		t.Error("the answer shares the buffer")
	}
	for name, tc := range map[string]struct {
		b    []byte
		n    uint32
		want uint32
	}{
		"short":       {b, protocolDescriptorSize - 1, 512},
		"n past":      {b, uint32(len(b)) + 1, 512},
		"other size":  {descriptor(log, protocolSpecificSize, 511), uint32(len(b)), 512},
		"offset low":  {descriptor(log, 8, 512), uint32(len(b)), 512},
		"data past n": {descriptor(log, protocolSpecificSize+1, 512), uint32(len(b)), 512},
		"offset huge": {descriptor(log, 0xFFFFFFFF, 512), uint32(len(b)), 512},
		"version":     {append([]byte{1}, b[1:]...), uint32(len(b)), 512},
	} {
		if _, err := nvmeAnswer(tc.b, tc.n, tc.want); !is(err, agentproto.ReasonBadAnswer) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestATAPassThrough(t *testing.T) {
	le := binary.LittleEndian
	for c, name := range ataNames {
		b := ataPassThrough(c)
		flags := le.Uint16(b[2:])
		if len(b) != ataPassThroughSize+int(c.length) || le.Uint16(b) != ataPassThroughSize || le.Uint32(b[8:]) != c.length ||
			le.Uint32(b[12:]) != 60 || b[46] != c.command || flags&^(ataFlagsDataIn|ataFlags48Bit) != 0 {
			t.Errorf("%s: % X", name, b[:ataPassThroughSize])
		}
		if (flags&ataFlagsDataIn != 0) != (c.length > 0) || (le.Uint64(b[24:]) == ataPassThroughSize) != (c.length > 0) {
			t.Errorf("%s: flags %04X, data at %d", name, flags, le.Uint64(b[24:]))
		}
		if (flags&ataFlags48Bit != 0) != (c.command == ataReadLogExt) {
			t.Errorf("%s: flags %04X", name, flags)
		}
	}
	for name, tc := range map[string]struct {
		c         ataCommand
		prev, cur [8]byte
	}{
		"SMART RETURN STATUS":       {smartReturnStatus, [8]byte{}, [8]byte{0xDA, 0, 0, 0x4F, 0xC2, 0, 0xB0, 0}},
		"SMART READ LOG 04h":        {smartReadLog(logDeviceStatistics, 8), [8]byte{}, [8]byte{0xD5, 8, 0x04, 0x4F, 0xC2, 0, 0xB0, 0}},
		"READ LOG EXT 04h page 07h": {readLogExt(logDeviceStatistics, 7), [8]byte{}, [8]byte{0, 1, 0x04, 0x07, 0, 0, 0x2F, 0}},
	} {
		b := ataPassThrough(tc.c)
		if [8]byte(b[32:40]) != tc.prev || [8]byte(b[40:48]) != tc.cur {
			t.Errorf("%s: previous % X, current % X", name, b[32:40], b[40:48])
		}
	}
}

func TestATAAnswer(t *testing.T) {
	answer := func(c ataCommand, regs [8]byte, data []byte) []byte {
		b := ataPassThrough(c)
		copy(b[40:], regs[:])
		copy(b[ataPassThroughSize:], data)
		return b
	}
	id := identifyBytes(true, true, false)
	b := answer(ataIdentify, [8]byte{0, 1, 0, 0, 0, 0xA0, 0x50}, id)
	if data, r, err := ataAnswer(ataIdentify, b, uint32(len(b))); err != nil || r != nil || string(data) != string(id) {
		t.Errorf("IDENTIFY: %v %+v", err, r)
	}
	if _, _, err := ataAnswer(ataIdentify, b, ataPassThroughSize+100); !is(err, agentproto.ReasonBadAnswer) {
		t.Errorf("short data: %v", err)
	}
	b = answer(smartReturnStatus, [8]byte{0, 0, 0, 0xF4, 0x2C, 0xA0, 0x50}, nil)
	if _, r, err := ataAnswer(smartReturnStatus, b, uint32(len(b))); err != nil || r == nil || r.lbaMid != 0xF4 || r.lbaHigh != 0x2C {
		t.Errorf("RETURN STATUS: %v %+v", err, r)
	}
	b = answer(smartReadData, [8]byte{0x04, 0, 0, 0, 0, 0, 0x51}, nil)
	if _, _, err := ataAnswer(smartReadData, b, uint32(len(b))); !is(err, agentproto.ReasonDeviceRefused) {
		t.Errorf("aborted: %v", err)
	}
	b = answer(smartReadData, [8]byte{0x40, 0, 0, 0, 0, 0, 0x51}, nil)
	if _, _, err := ataAnswer(smartReadData, b, uint32(len(b))); !is(err, agentproto.ReasonIOError) {
		t.Errorf("error: %v", err)
	}
	for _, n := range []uint32{0, ataPassThroughSize - 1, uint32(len(b)) + 1} {
		if _, _, err := ataAnswer(smartReadData, b, n); !is(err, agentproto.ReasonBadAnswer) {
			t.Errorf("%d bytes returned: %v", n, err)
		}
	}
}
