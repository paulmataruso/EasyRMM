//go:build linux

package enrollfile

import (
	"syscall"
	"time"
)

//nolint:unconvert // the fields' types differ by architecture
func statCtime(st *syscall.Stat_t) time.Time {
	return time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec))
}
