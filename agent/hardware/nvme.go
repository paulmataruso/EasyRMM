package hardware

import (
	"encoding/binary"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// maxCount caps a counter: the server holds counts within 2^62, and a
// 128-bit NVMe counter beyond it is not a real count.
const maxCount = 1 << 62

// healthLog is what the agent reads of the NVMe SMART / Health Information
// log (log page 02h, 512 bytes; NVM Express Base Specification 2.0c, figure
// 207).
type healthLog struct {
	criticalWarning uint8
	// temperature is the composite temperature in kelvins.
	temperature     uint16
	availableSpare  uint8
	spareThreshold  uint8
	percentageUsed  uint8
	dataWritten     int64
	powerOnHours    int64
	unsafeShutdowns int64
	mediaErrors     int64
	errorEntries    int64
}

// parseHealthLog reads the health log. Its counters are 128-bit little
// endian, capped at maxCount.
func parseHealthLog(b []byte) (healthLog, error) {
	if len(b) != 512 {
		return healthLog{}, badAnswer("NVMe health log: %d bytes, want 512", len(b))
	}
	return healthLog{
		criticalWarning: b[0],
		temperature:     binary.LittleEndian.Uint16(b[1:3]),
		availableSpare:  b[3],
		spareThreshold:  b[4],
		percentageUsed:  b[5],
		dataWritten:     u128(b[48:64]),
		powerOnHours:    u128(b[128:144]),
		unsafeShutdowns: u128(b[144:160]),
		mediaErrors:     u128(b[160:176]),
		errorEntries:    u128(b[176:192]),
	}, nil
}

// u128 reads a 128-bit little-endian counter, capped at maxCount.
func u128(b []byte) int64 {
	lo, hi := binary.LittleEndian.Uint64(b[:8]), binary.LittleEndian.Uint64(b[8:16])
	if hi != 0 || lo > maxCount {
		return maxCount
	}
	return int64(lo)
}

// parseIdentifyController reads Identify Controller (4,096 bytes; figure
// 275) for WCTEMP, the warning composite temperature threshold, in kelvins:
// 0 means the drive reports none. The drive's model and serial are not
// read here: a reading names the disk as the inventory does.
func parseIdentifyController(b []byte) (uint16, error) {
	if len(b) != 4096 {
		return 0, badAnswer("NVMe Identify Controller: %d bytes, want 4096", len(b))
	}
	return binary.LittleEndian.Uint16(b[266:268]), nil
}

// celsius converts a temperature in kelvins, as NVMe gives it, to whole
// degrees Celsius: 323 K is 49.85 °C, 50.
func celsius(kelvin uint16) int64 { return int64(kelvin) - 273 }

// readNVMe reads an NVMe controller: the health log, the verdict, and
// Identify Controller for the drive's warning temperature. A failure of the
// health log fails the reading; a timeout or a refused access fails it at
// any step.
func readNVMe(d nvmeDevice) (agentproto.DiskHealth, error) {
	h := agentproto.DiskHealth{State: agentproto.FactRead, Protocol: agentproto.ProtocolNVMe}
	data, err := d.nvme(nvmeHealthLog)
	if err != nil {
		return h, err
	}
	log, err := parseHealthLog(data)
	if err != nil {
		return h, err
	}
	h.CriticalWarning = agentproto.Read(int64(log.criticalWarning))
	h.Temperature = agentproto.Read(celsius(log.temperature))
	if log.temperature == 0 {
		h.Temperature = agentproto.NotRead(agentproto.FactUnknown, agentproto.ReasonNotValid)
	}
	h.Wear = agentproto.Read(int64(log.percentageUsed))
	h.AvailableSpare = agentproto.Read(int64(log.availableSpare))
	h.AvailableSpareThreshold = agentproto.Read(int64(log.spareThreshold))
	h.MediaErrors = agentproto.Read(log.mediaErrors)
	h.DriveErrors = agentproto.Read(log.errorEntries)
	h.PowerOnHours = agentproto.Read(log.powerOnHours)
	h.DataWritten = agentproto.Read(log.dataWritten)
	h.UnsafeShutdowns = agentproto.Read(log.unsafeShutdowns)
	notKept := agentproto.NotRead(agentproto.FactUnsupported, agentproto.ReasonNotKept)
	h.SMARTStatus, h.Thresholds, h.PowerMode = notKept, notKept, notKept
	h.ReallocatedSectors, h.PendingSectors, h.UncorrectableSectors = notKept, notKept, notKept

	data, err = d.nvme(nvmeIdentifyController)
	if fatal(err) {
		return h, err
	}
	var warning uint16
	if err == nil {
		warning, err = parseIdentifyController(data)
	}
	switch {
	case err != nil:
		h.TemperatureLimit = asFailure(err).fact()
	case warning == 0:
		// "No warning temperature threshold value is reported."
		h.TemperatureLimit = notKept
	default:
		h.TemperatureLimit = agentproto.Read(celsius(warning))
	}
	return h, nil
}

// fatal reports whether err fails a whole reading even after its first
// answer: a timeout (the disk is then left alone), a refused access, or the
// agent's own error.
func fatal(err error) bool {
	return is(err, agentproto.ReasonTimeout) || is(err, agentproto.ReasonAccessDenied) || (err != nil && asFailure(err).reason == agentproto.ReasonAgentError)
}
