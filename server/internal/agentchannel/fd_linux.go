//go:build linux

package agentchannel

import (
	"os"
	"syscall"
)

// processDescriptors reads the process's open descriptors and its soft
// RLIMIT_NOFILE.
func processDescriptors() (open, limit uint64, ok bool) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0, 0, false
	}
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, 0, false
	}
	return uint64(len(ents)), rl.Cur, true
}
