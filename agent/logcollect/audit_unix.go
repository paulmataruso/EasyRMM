//go:build !windows

package logcollect

import (
	"errors"
	"os"
	"syscall"
)

func inodeSize(f *os.File) (uint64, int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("logcollect: no inode")
	}
	return uint64(st.Ino), fi.Size(), nil //nolint:unconvert // Ino is 32-bit on some platforms
}
