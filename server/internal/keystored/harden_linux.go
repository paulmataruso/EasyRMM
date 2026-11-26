//go:build linux

package keystored

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Harden makes the process dump-free and swap-free: no core file, not
// dumpable (so no ptrace or /proc/pid/mem by a same-user process), and all
// current and future memory locked. The container's ulimits and its
// memswap_limit back this up. An error means the process must not hold a key.
func Harden() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("keystore: disabling core files: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("keystore: making the process undumpable: %w", err)
	}
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return fmt.Errorf("keystore: locking memory (raise the container's memlock limit): %w", err)
	}
	return nil
}
