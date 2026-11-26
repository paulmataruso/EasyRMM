//go:build !windows

package escrow

import "context"

// SystemReader is the reader of this platform: none off Windows.
type SystemReader struct{}

// Volumes reports that BitLocker is not available.
func (SystemReader) Volumes(context.Context) ([]Volume, error) { return nil, ErrUnsupported }

// RecoveryPassword reports that BitLocker is not available.
func (SystemReader) RecoveryPassword(context.Context, string, string) ([]byte, error) {
	return nil, ErrUnsupported
}
