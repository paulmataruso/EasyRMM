//go:build !windows

package easypatch

import (
	"os/exec"
	"syscall"
	"time"
)

func hide(*exec.Cmd) {}

// stopGrace is how long a program past its deadline has to stop after it is
// asked to, before it is killed.
var stopGrace = 30 * time.Second

// stopGently has a program past its deadline asked to stop (SIGTERM) and
// killed only if it is still running stopGrace later. apt-get, dpkg, dnf and
// rpm stop cleanly when asked; killed outright, they can leave their database
// locked or needing repair.
func stopGently(cmd *exec.Cmd) {
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopGrace
}
