//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// startUninstaller starts `exe uninstall --removal file` as a process of
// its own (ADR-0050): detached from the service, with no console, and
// outside any job the service runs in, so that stopping the service leaves
// it running. The service manager does not end a stopped service's other
// processes.
func (e *env) startUninstaller(_ context.Context, exe, file string) error {
	start := func(flags uint32) error {
		// The uninstaller outlives this process: nothing may cancel it.
		cmd := exec.CommandContext(context.Background(), exe, "uninstall", "--removal", file) //nolint:gosec // the agent's own executable
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags, HideWindow: true}
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}
	flags := uint32(windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP)
	err := start(flags | windows.CREATE_BREAKAWAY_FROM_JOB)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		// A job that forbids breaking away: the uninstaller stays in it,
		// and runs on unless that job ends its processes with the service.
		err = start(flags)
	}
	if err != nil {
		return fmt.Errorf("starting the uninstaller: %w", err)
	}
	return nil
}
