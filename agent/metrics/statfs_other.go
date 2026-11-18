//go:build !linux && !windows

package metrics

import "errors"

// kernelStatfs is only implemented for Linux so far.
func kernelStatfs(string) (Space, error) {
	return Space{}, errors.New("metrics: filesystem space is only read on Linux")
}
