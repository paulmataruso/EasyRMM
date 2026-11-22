package agentproto

import "time"

// Hardware health (ADR-0065). The agent reads each disk's health every 30
// minutes and sends what it read, fact by fact, in a report of its own: not
// in the heartbeat, which stays small, and not in the hashed inventory,
// whose hash would change every half hour. The agent judges nothing; the
// server applies one table of rules to what it reads.
const (
	// PathHardware receives a device's hardware report. A server without
	// it answers 404, and the agent drops that reading.
	PathHardware = "/api/agent/v1/hardware"
	// MaxHardwareBody is the largest hardware report the server reads: at
	// most MaxListed disks of about 3 KiB each, and 267 KiB when every one
	// has every fact and its attribute table at their longest (ADR-0065,
	// Size, as amended).
	MaxHardwareBody = 512 << 10
	// MaxAttributes is the most ATA SMART attributes a disk lists: the
	// attribute table has 30 entries.
	MaxAttributes = 30
	// MaxHardwareDetail bounds a disk's detail, such as a Windows error
	// number.
	MaxHardwareDetail = 200
)

// States of a fact, or of a disk as a whole, as the agent reports them. The
// agent never says healthy or failing: the server judges what was read.
const (
	// FactRead: read, with its value.
	FactRead = "read"
	// FactUnknown: EasyRMM could read it here, and this time it could not
	// tell (a timeout, an I/O error, a bad checksum, a sleeping disk).
	FactUnknown = "unknown"
	// FactUnsupported: the disk, by what it is, has no such data (a virtual
	// disk, an SD card, an attribute the drive does not keep).
	FactUnsupported = "unsupported"
	// FactUnavailable: the data exists, but EasyRMM cannot reach it from
	// where the agent runs (behind a RAID controller, a driver that
	// refuses, a USB bridge, a container).
	FactUnavailable = "unavailable"
)

// Reasons the agent gives for a disk or a fact that was not read, or the
// server for what it shows. Each is a fixed code the console puts in words;
// the server makes any other code unknown (ReasonInvalidReport).
const (
	// The agent runs in a container (unavailable).
	ReasonContainer = "container"
	// A hypervisor's emulated disk (unsupported).
	ReasonVirtualDisk = "virtual_disk"
	// A read failed on a machine the inventory names as virtual
	// (unsupported).
	ReasonVirtualMachine = "virtual_machine"
	// A Storage Spaces virtual disk (unsupported).
	ReasonStorageSpaces = "storage_spaces"
	// An SD or MMC card (unsupported).
	ReasonMemoryCard = "memory_card"
	// A logical volume of a hardware RAID controller (unavailable).
	ReasonRAIDController = "raid_controller"
	// A storage driver on the way refused the query (unavailable).
	ReasonStorageDriver = "storage_driver"
	// The device itself refused the query as not supported (unsupported).
	ReasonDeviceRefused = "device_refused"
	// SAS, FC, iSCSI or another SCSI disk: its own health pages
	// are not read yet (unavailable).
	ReasonProtocolNotRead = "protocol_not_read"
	// A disk behind a USB bridge: not read until a later slice
	// (unavailable).
	ReasonUSBBridge = "usb_bridge"
	// The drive has no SMART feature set (unsupported).
	ReasonNoSMART = "no_smart"
	// SMART is turned off on the drive (unavailable).
	ReasonSMARTOff = "smart_off"
	// The disk is in standby and was not woken (unknown).
	ReasonAsleep = "asleep"
	// The disk did not answer within the kernel's or the port driver's
	// timeout (unknown).
	ReasonTimeout = "timeout"
	// The disk timed out within the last 24 hours and is left alone until
	// then (unknown).
	ReasonTimedOutRecently = "timed_out_recently"
	// The query failed with an I/O error (unknown).
	ReasonIOError = "io_error"
	// The agent may not send the query, as without CAP_SYS_ADMIN
	// (unavailable).
	ReasonAccessDenied = "access_denied"
	// The answer's checksum is wrong (unknown).
	ReasonBadChecksum = "bad_checksum"
	// The answer is too short or malformed (unknown).
	ReasonBadAnswer = "bad_answer"
	// The agent failed reading it: a panic in a parser (unknown).
	ReasonAgentError = "agent_error"
	// The drive does not keep this fact (unsupported).
	ReasonNotKept = "not_kept"
	// The drive keeps this statistic but holds no valid value for it now
	// (unknown).
	ReasonNotValid = "not_valid"
	// The operating system does not expose the fact without a query the
	// inventory does not send (unavailable).
	ReasonNotExposed = "not_exposed"
	// Neither the drive's verdict nor its attributes against their
	// thresholds could be read (unknown).
	ReasonNoVerdict = "no_verdict"
	// Set by the server: a healthy disk not read for over 2 hours
	// (unknown).
	ReasonStale = "stale"
	// Set by the server: the device's latest report does not list the
	// disk (unknown).
	ReasonMissing = "missing"
	// Set by the server: a state or reason it does not know, or a value
	// out of bounds (unknown).
	ReasonInvalidReport = "invalid_report"
)

// reasons are every reason KnownReason accepts.
var reasons = map[string]bool{
	ReasonContainer: true, ReasonVirtualDisk: true, ReasonVirtualMachine: true, ReasonStorageSpaces: true,
	ReasonMemoryCard: true, ReasonRAIDController: true, ReasonStorageDriver: true, ReasonDeviceRefused: true,
	ReasonProtocolNotRead: true, ReasonUSBBridge: true, ReasonNoSMART: true, ReasonSMARTOff: true,
	ReasonAsleep: true, ReasonTimeout: true, ReasonTimedOutRecently: true, ReasonIOError: true,
	ReasonAccessDenied: true, ReasonBadChecksum: true, ReasonBadAnswer: true, ReasonAgentError: true,
	ReasonNotKept: true, ReasonNotValid: true, ReasonNotExposed: true, ReasonNoVerdict: true,
	ReasonStale: true, ReasonMissing: true, ReasonInvalidReport: true,
}

// KnownReason reports whether code is one of the Reason* codes.
func KnownReason(code string) bool { return reasons[code] }

// Fact is one numeric fact with its state. Value is set only when State is
// FactRead; Reason only when it is not.
type Fact struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	Value  *int64 `json:"value,omitempty"`
}

// TextFact is Fact for text, such as a disk's firmware revision.
type TextFact struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	Value  string `json:"value,omitempty"`
}

// Read is a fact read with value v.
func Read(v int64) Fact { return Fact{State: FactRead, Value: &v} }

// NotRead is a fact in state (unknown, unsupported or unavailable) for
// reason.
func NotRead(state, reason string) Fact { return Fact{State: state, Reason: reason} }

// HardwareReport is what the agent read from the device's hardware at one
// reading. Later slices add batteries, sensors and errors beside the disks.
type HardwareReport struct {
	Disks []DiskHealth `json:"disks"`
}

// Disk protocols.
const (
	ProtocolNVMe = "nvme"
	ProtocolATA  = "ata"
)

// SMART status values (DiskHealth.SMARTStatus): what SMART RETURN STATUS
// answered.
const (
	SMARTPassed            = 0 // LBA mid and high 4Fh and C2h
	SMARTThresholdExceeded = 1 // F4h and 2Ch
)

// DiskHealth is one disk's reading. Name, Model and Serial are the
// inventory's for the same disk, so that the server can match the report
// with the inventory. When State is not FactRead the disk as a whole was not
// read, Reason says why, and the facts are left out.
type DiskHealth struct {
	// Name is the inventory's: sda, nvme0n1, PhysicalDrive1.
	Name   string `json:"name"`
	Model  string `json:"model"`
	Serial string `json:"serial"`
	// State is FactRead when the disk was read (its facts then say what
	// was), else why not.
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Detail is a short detail for people, such as a driver's error
	// number; at most MaxHardwareDetail characters.
	Detail string `json:"detail,omitempty"`
	// Protocol is ProtocolNVMe or ProtocolATA once the disk answered.
	Protocol string `json:"protocol,omitempty"`
	// Route is how the disk answered: on Windows "device" or "adapter" (the
	// NVMe protocol-specific property asked of the device or of its
	// adapter) or "ata" (ATA pass-through); on Linux "nvme" (the NVMe
	// admin ioctl) or "sg" (SG_IO with ATA PASS-THROUGH (16)).
	Route string `json:"route,omitempty"`
	// ReadAt is when the agent read the disk, by its own clock.
	ReadAt time.Time `json:"readAt"`

	// CriticalWarning is NVMe's critical warning byte, the drive's verdict.
	CriticalWarning Fact `json:"criticalWarning,omitzero"`
	// SMARTStatus is ATA SMART RETURN STATUS: SMARTPassed or
	// SMARTThresholdExceeded, the drive's verdict.
	SMARTStatus Fact `json:"smartStatus,omitzero"`
	// Thresholds says whether READ ATTRIBUTE THRESHOLDS was read; its
	// values are in Attributes. They give the verdict where SMARTStatus
	// could not be read.
	Thresholds Fact `json:"thresholds,omitzero"`
	// Temperature is the drive's own, in °C.
	Temperature Fact `json:"temperature,omitzero"`
	// TemperatureLimit is the drive's own warning temperature in °C: NVMe
	// WCTEMP, ATA Device Statistics' specified maximum.
	TemperatureLimit Fact `json:"temperatureLimit,omitzero"`
	// Wear is the percentage of rated endurance used, which may exceed 100
	// (NVMe: 255 means above 254).
	Wear Fact `json:"wear,omitzero"`
	// AvailableSpare and AvailableSpareThreshold are NVMe's, in percent.
	AvailableSpare          Fact `json:"availableSpare,omitzero"`
	AvailableSpareThreshold Fact `json:"availableSpareThreshold,omitzero"`
	// MediaErrors is NVMe's count of media and data integrity errors.
	MediaErrors Fact `json:"mediaErrors,omitzero"`
	// ReallocatedSectors is ATA attribute 5, or Device Statistics' count.
	ReallocatedSectors Fact `json:"reallocatedSectors,omitzero"`
	// PendingSectors is ATA attribute 197.
	PendingSectors Fact `json:"pendingSectors,omitzero"`
	// UncorrectableSectors is ATA attribute 198.
	UncorrectableSectors Fact `json:"uncorrectableSectors,omitzero"`
	// DriveErrors is NVMe's number of error information log entries, or
	// the ATA summary SMART error log's count.
	DriveErrors  Fact `json:"driveErrors,omitzero"`
	PowerOnHours Fact `json:"powerOnHours,omitzero"`
	// DataWritten is NVMe's data units written, each 1,000 units of 512
	// bytes.
	DataWritten     Fact `json:"dataWritten,omitzero"`
	UnsafeShutdowns Fact `json:"unsafeShutdowns,omitzero"`
	// PowerMode is ATA CHECK POWER MODE's answer: 00h standby, 80h idle,
	// FFh active or idle.
	PowerMode Fact `json:"powerMode,omitzero"`
	// Attributes is the ATA SMART attribute table, with each attribute's
	// threshold when Thresholds was read.
	Attributes []Attribute `json:"attributes,omitempty"`
}

// Attribute is one entry of the ATA SMART attribute table. The meaning of
// Raw is the drive maker's, but for the few attributes whose meaning makers
// share.
type Attribute struct {
	ID uint8 `json:"id"`
	// Flags: bit 0 means pre-fail.
	Flags uint16 `json:"flags"`
	Value uint8  `json:"value"`
	Worst uint8  `json:"worst"`
	// Threshold is nil when the thresholds were not read.
	Threshold *uint8 `json:"threshold,omitempty"`
	// Raw is the attribute's 48-bit raw value.
	Raw uint64 `json:"raw"`
}

// PreFail reports whether the attribute is a pre-fail one.
func (a Attribute) PreFail() bool { return a.Flags&1 != 0 }
