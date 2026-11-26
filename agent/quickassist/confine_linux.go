package quickassist

import (
	"os"
	"os/exec"
	"syscall"
)

// confiner keeps a runner's children from outliving it: on Linux each child
// has its own process group and is killed when the runner dies.
type confiner struct{}

func newConfiner() (*confiner, error) { return &confiner{}, nil }

// Confine is called on a child before it starts.
func (*confiner) Confine(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// Started is called with the started child.
func (*confiner) Started(*os.Process) {}

// Close ends what the confiner holds.
func (*confiner) Close() {}
