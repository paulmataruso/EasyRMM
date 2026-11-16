//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// errServiceRestart ends the service with an error code after an update, so
// that the service manager starts it again with the new build
// (host.WindowsServices sets the recovery): a Windows process cannot replace
// itself in place.
var errServiceRestart = errors.New("restarting the agent after an update")

// restart starts the build at exe after an update: the service manager
// does it for the service; an agent run from a console starts it itself.
func (e *env) restart(exe string) error {
	if e.service {
		return errServiceRestart
	}
	// The new process outlives this one: nothing may cancel it.
	cmd := exec.CommandContext(context.Background(), exe, os.Args[1:]...) //nolint:gosec // the agent's own, checked build
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("restarting into %s: %w", exe, err)
	}
	e.log.Info("started the agent again", "path", exe, "pid", cmd.Process.Pid)
	return nil
}
