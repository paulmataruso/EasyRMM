//go:build windows

package quickassist

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive lock on the whole file that ends with the
// handle, so with the process, however it ends. It fails at once when another
// process holds it.
func lockFile(f *os.File) error {
	var ol windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
}
