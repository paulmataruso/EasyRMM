package quickassist

import (
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// confiner is a Windows job object with KILL_ON_JOB_CLOSE: every child the
// runner starts is put in it, so the children die with the runner, however
// it ends, a crash or a kill included (ADR-0080).
type confiner struct{ job windows.Handle }

func newConfiner() (*confiner, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("creating the job object: %w", err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("setting the job object's limits: %w", err)
	}
	return &confiner{job: h}, nil
}

// Confine is called on a child before it starts.
func (*confiner) Confine(*exec.Cmd) {}

// Started puts the started child in the job.
func (c *confiner) Started(p *os.Process) {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid)) //nolint:gosec // a process id
	if err != nil {
		_ = p.Kill()
		return
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := windows.AssignProcessToJobObject(c.job, h); err != nil {
		// A child outside the job would outlive the runner: end it.
		_ = p.Kill()
	}
}

// Close closes the job, which ends everything in it.
func (c *confiner) Close() { _ = windows.CloseHandle(c.job) }
