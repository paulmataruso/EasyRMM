//go:build windows

package logcollect

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// jobCPURateControl is JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, which
// x/sys/windows does not define.
type jobCPURateControl struct {
	ControlFlags uint32
	CPURate      uint32 // the union's member for a hard cap: percent * 100
}

const (
	jobCPURateControlEnable  = 0x1
	jobCPURateControlHardCap = 0x4
	cpuRatePercent20         = 20 * 100
	collectorMemoryBytes     = 256 << 20
)

// confineOS puts the process in a job object of its own with a hard CPU rate
// cap of a fifth of one processor's worth of the machine, a 256 MiB memory
// limit and kill-on-close, and enters background processing mode, which
// lowers its I/O and memory priority (ADR-0060).
func confineOS() error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("creating the job object: %w", err)
	}
	var ext windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	ext.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
	ext.ProcessMemoryLimit = collectorMemoryBytes
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&ext)), uint32(unsafe.Sizeof(ext))); err != nil {
		return fmt.Errorf("limiting the job object: %w", err)
	}
	cpu := jobCPURateControl{ControlFlags: jobCPURateControlEnable | jobCPURateControlHardCap, CPURate: cpuRatePercent20}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectCpuRateControlInformation,
		uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu))); err != nil {
		return fmt.Errorf("capping the job object's CPU: %w", err)
	}
	if err := windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		return fmt.Errorf("entering the job object: %w", err)
	}
	if err := windows.SetPriorityClass(windows.CurrentProcess(), windows.PROCESS_MODE_BACKGROUND_BEGIN); err != nil {
		return fmt.Errorf("entering background mode: %w", err)
	}
	return nil
}

// defaultReaders are the channels of DefaultChannels.
func defaultReaders(Options) []Reader {
	rs := make([]Reader, 0, len(DefaultChannels))
	for _, c := range DefaultChannels {
		rs = append(rs, NewWindowsChannel(c))
	}
	return rs
}
