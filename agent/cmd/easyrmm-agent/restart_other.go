//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// restart replaces the agent's process with the build at exe, after an
// update. The process keeps its id, so it stays the service manager's (or
// the container's) process.
func (e *env) restart(exe string) error {
	e.log.Info("restarting the agent", "path", exe)
	err := syscall.Exec(exe, os.Args, os.Environ()) //nolint:gosec // the agent's own, checked build
	return fmt.Errorf("restarting into %s: %w", exe, err)
}
