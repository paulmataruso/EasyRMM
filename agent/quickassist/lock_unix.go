//go:build unix

package quickassist

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive lock that ends with the process, however it
// ends.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // a file descriptor
}
