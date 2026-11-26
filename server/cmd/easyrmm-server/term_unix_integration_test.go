//go:build integration && !windows

package main

import (
	"os"
	"syscall"
)

// sendTerm sends this process SIGTERM, as `docker stop` does.
func sendTerm() error { return syscall.Kill(os.Getpid(), syscall.SIGTERM) }
