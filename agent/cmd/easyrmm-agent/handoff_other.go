//go:build !windows

package main

import (
	"os"
	"syscall"
)

// handoffExec replaces this process with the installed agent, with the same
// arguments, environment and streams.
func handoffExec(path string, args []string) error {
	return syscall.Exec(path, append([]string{path}, args...), os.Environ()) //nolint:gosec // the installed agent, which answered capabilities
}
