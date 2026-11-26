//go:build !linux && !windows

package quickassist

import (
	"os"
	"os/exec"
)

// confiner has nothing to hold on this platform; the runner stops its
// children itself.
type confiner struct{}

func newConfiner() (*confiner, error) { return &confiner{}, nil }

func (*confiner) Confine(*exec.Cmd)   {}
func (*confiner) Started(*os.Process) {}
func (*confiner) Close()              {}
