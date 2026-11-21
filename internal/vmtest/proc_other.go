//go:build !linux

package vmtest

import "os/exec"

// killWithParent does nothing: only Linux kills a child with its parent.
func killWithParent(*exec.Cmd) {}
