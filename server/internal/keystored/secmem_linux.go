//go:build linux

package keystored

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// alloc maps n bytes, locks them in RAM and excludes them from core dumps.
// A failure to lock is an error: a KEK that could reach swap is not held.
func alloc(n int) ([]byte, func([]byte), error) {
	if n == 0 {
		return nil, nil, nil
	}
	b, err := unix.Mmap(-1, 0, n, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, nil, fmt.Errorf("keystore: mapping memory for a key: %w", err)
	}
	if err := unix.Mlock(b); err != nil {
		_ = unix.Munmap(b)
		return nil, nil, fmt.Errorf("keystore: locking memory for a key (raise the container's memlock limit): %w", err)
	}
	if err := unix.Madvise(b, unix.MADV_DONTDUMP); err != nil {
		_ = unix.Munlock(b)
		_ = unix.Munmap(b)
		return nil, nil, fmt.Errorf("keystore: excluding a key's memory from core dumps: %w", err)
	}
	return b, func(b []byte) { _ = unix.Munlock(b); _ = unix.Munmap(b) }, nil
}
