//go:build windows

package logcollect

import (
	"errors"
	"os"
)

// There is no auditd on Windows; the reader is never built there.
func inodeSize(*os.File) (uint64, int64, error) {
	return 0, 0, errors.New("logcollect: auditd's log is Linux only")
}
