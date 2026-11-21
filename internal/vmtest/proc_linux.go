package vmtest

import (
	"os/exec"
	"syscall"
)

// killWithParent has the kernel kill QEMU when the test process dies, for
// instance at go test's -timeout, which skips the tests' clean-up.
func killWithParent(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
