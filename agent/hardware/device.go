package hardware

import (
	"errors"
	"fmt"
	"time"

	"github.com/paulmataruso/easyrmm/agent/inventory"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// device is one disk, or a Linux NVMe controller, as the operating system
// offers it, opened for one reading: the boundary between the reader and
// the system. Each implementation checks every command against the list
// (checkNVMe, checkATA) before it makes a system call.
type device interface {
	// route names how the disk answered (agentproto.DiskHealth.Route).
	route() string
	close()
}

// nvmeDevice is a device opened for NVMe.
type nvmeDevice interface {
	device
	// nvme sends an NVMe admin command and returns the data it read.
	nvme(c nvmeCommand) ([]byte, error)
}

// ataDevice is a device opened for ATA.
type ataDevice interface {
	device
	// ata sends an ATA command and returns the data it read and, when the
	// command asks for them, the device's registers (nil when the path
	// returned none).
	ata(c ataCommand) ([]byte, *ataRegisters, error)
}

// platform is how this system's disks are told apart and opened.
type platform struct {
	// plan decides from what the inventory lists whether a disk has health
	// to read, and where: a failure, or the target to read. root is where
	// /sys and /dev are on Linux.
	plan func(root string, d inventory.ListedDisk) (*failure, target)
	// openNVMe and openATA open a target's path for one protocol. openATA
	// fails with errAsleep, unless wake, where the system tells a sleeping
	// disk before any command (Windows).
	openNVMe func(path string) (nvmeDevice, error)
	openATA  func(path string, wake bool) (ataDevice, error)
}

// ataRegisters are the device's registers after a command.
type ataRegisters struct {
	err, count, lbaLow, lbaMid, lbaHigh, device, status uint8
}

// ATA status and error bits.
const (
	ataStatusErr = 0x01
	ataErrorAbrt = 0x04
)

// aborted reports whether the device aborted the command: ERR in the
// status with ABRT in the error register.
func (r *ataRegisters) aborted() bool { return r.status&ataStatusErr != 0 && r.err&ataErrorAbrt != 0 }

// protocol is how a disk is read.
type protocol int

const (
	protoNVMe protocol = iota
	protoATA
	// protoEither is tried as NVMe, then as ATA: Windows' RAID bus.
	protoEither
)

// target is what a reading opens: one disk, or on Linux one NVMe
// controller that may serve several of the inventory's disks.
type target struct {
	// key names the target in the reader's memory of timeouts and
	// sleeping disks.
	key string
	// paths are what to open, tried in order until one answers: the
	// controllers of a Linux NVMe namespace; one disk otherwise.
	paths []string
	proto protocol
	// limit is a call's own deadline: the kernel's or the port driver's
	// timeout.
	limit time.Duration
}

// failure is why a disk or a fact was not read: its state and reason, with
// a short detail for people, such as a driver's error number.
type failure struct {
	state, reason, detail string
}

func (f *failure) Error() string {
	if f.detail == "" {
		return f.state + " (" + f.reason + ")"
	}
	return f.state + " (" + f.reason + "): " + f.detail
}

func (f *failure) fact() agentproto.Fact { return agentproto.NotRead(f.state, f.reason) }

func fail(state, reason, format string, args ...any) *failure {
	return &failure{state: state, reason: reason, detail: fmt.Sprintf(format, args...)}
}

// The failures a transport reports.
var (
	errAsleep = &failure{state: agentproto.FactUnknown, reason: agentproto.ReasonAsleep}
)

// deviceRefused is the device's own refusal of a command it does not
// support.
func deviceRefused(format string, args ...any) *failure {
	return fail(agentproto.FactUnsupported, agentproto.ReasonDeviceRefused, format, args...)
}

// driverRefused is a storage driver on the way refusing the query.
func driverRefused(format string, args ...any) *failure {
	return fail(agentproto.FactUnavailable, agentproto.ReasonStorageDriver, format, args...)
}

// notThisProtocol is a SCSI disk refusing ATA PASS-THROUGH: SAS, FC,
// iSCSI or another SCSI disk, whose own health pages are a later
// slice.
func notThisProtocol(format string, args ...any) *failure {
	return fail(agentproto.FactUnavailable, agentproto.ReasonProtocolNotRead, format, args...)
}

func ioError(format string, args ...any) *failure {
	return fail(agentproto.FactUnknown, agentproto.ReasonIOError, format, args...)
}

func timedOut(format string, args ...any) *failure {
	return fail(agentproto.FactUnknown, agentproto.ReasonTimeout, format, args...)
}

func accessDenied(format string, args ...any) *failure {
	return fail(agentproto.FactUnavailable, agentproto.ReasonAccessDenied, format, args...)
}

func badAnswer(format string, args ...any) *failure {
	return fail(agentproto.FactUnknown, agentproto.ReasonBadAnswer, format, args...)
}

func badChecksum(what string) *failure {
	return fail(agentproto.FactUnknown, agentproto.ReasonBadChecksum, "%s: the checksum is wrong", what)
}

// asFailure turns any error into a failure: a command refused by the list
// or a panic is the agent's own error.
func asFailure(err error) *failure {
	var f *failure
	if errors.As(err, &f) {
		return f
	}
	return fail(agentproto.FactUnknown, agentproto.ReasonAgentError, "%v", err)
}

// is reports whether err is a failure for reason.
func is(err error, reason string) bool {
	var f *failure
	return errors.As(err, &f) && f.reason == reason
}

// refused reports whether err is a refusal by the device or by a driver,
// after which another protocol may be tried.
func refused(err error) bool {
	return is(err, agentproto.ReasonDeviceRefused) || is(err, agentproto.ReasonStorageDriver) || is(err, agentproto.ReasonProtocolNotRead)
}
