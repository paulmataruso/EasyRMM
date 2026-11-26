//go:build !windows

package defender

import "os/exec"

func hideWindow(*exec.Cmd) {}
