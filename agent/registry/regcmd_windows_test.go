//go:build windows

package registry

import (
	"os/exec"
)

// regCommand runs reg.exe, as the tests that make or compare files do.
func regCommand(args ...string) (string, error) {
	out, err := exec.Command("reg.exe", args...).CombinedOutput() //nolint:gosec // the test's own arguments
	return string(out), err
}
