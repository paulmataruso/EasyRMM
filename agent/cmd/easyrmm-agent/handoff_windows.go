package main

import (
	"errors"
	"os"
	"os/exec"
)

// handoffExec runs the installed agent with the same arguments and streams,
// and ends this process with its exit code.
func handoffExec(path string, args []string) error {
	cmd := exec.Command(path, args...) //nolint:gosec,noctx // the installed agent, which answered capabilities
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return exitError{ee.ExitCode()}
	}
	if err != nil {
		return err
	}
	return exitError{0}
}
