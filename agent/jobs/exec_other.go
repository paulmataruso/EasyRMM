//go:build !unix

package jobs

import "os/exec"

// Scripts run on Linux in this phase (ADR-0017); elsewhere a stop ends the
// script's own process.
func isolate(*exec.Cmd) {}

func terminate(cmd *exec.Cmd) { _ = cmd.Process.Kill() }

func kill(cmd *exec.Cmd) { _ = cmd.Process.Kill() }
