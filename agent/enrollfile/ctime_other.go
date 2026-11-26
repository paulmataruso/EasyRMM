//go:build !linux && !windows

package enrollfile

import (
	"syscall"
	"time"
)

// statCtime is the modification time where the change time is not read.
func statCtime(st *syscall.Stat_t) time.Time { return time.Unix(0, 0) }
