//go:build !windows

package escrow

import "context"

// SystemManager is the manager of this platform: none off Windows, so a
// build here never changes BitLocker.
type SystemManager struct{}

var _ Manager = SystemManager{}

// Preconditions reports that BitLocker is not available.
func (SystemManager) Preconditions(context.Context) (Preconditions, error) {
	return Preconditions{}, ErrUnsupported
}

// Volume reports that BitLocker is not available.
func (SystemManager) Volume(context.Context, string) (*VolumeInfo, error) {
	return nil, ErrUnsupported
}

// AddRecoveryPassword reports that BitLocker is not available.
func (SystemManager) AddRecoveryPassword(context.Context, string) (string, error) {
	return "", ErrUnsupported
}

// DeleteProtector reports that BitLocker is not available.
func (SystemManager) DeleteProtector(context.Context, string, string) error { return ErrUnsupported }

// AddTPMProtector reports that BitLocker is not available.
func (SystemManager) AddTPMProtector(context.Context, string) error { return ErrUnsupported }

// StartEncryption reports that BitLocker is not available.
func (SystemManager) StartEncryption(context.Context, string, bool) error { return ErrUnsupported }
