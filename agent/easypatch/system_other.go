//go:build !windows

package easypatch

import "os/exec"

func hide(*exec.Cmd) {}
