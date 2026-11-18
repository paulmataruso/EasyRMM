//go:build linux

package metrics

import "syscall"

// kernelStatfs reads a filesystem's space as df does.
func kernelStatfs(path string) (Space, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Space{}, err
	}
	bs := uint64(st.Bsize) //nolint:gosec // block sizes are positive
	used := (st.Blocks - st.Bfree) * bs
	return Space{Total: used + st.Bavail*bs, Used: used}, nil
}
