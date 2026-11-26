//go:build !windows

package defender

import "errors"

type otherSystem struct{}

// NewSystem is a system that locks and verifies nothing: Defender exists on
// Windows only, and no Manager is built elsewhere.
func NewSystem() System { return otherSystem{} }

func (otherSystem) Lock(string) error   { return errors.New("not Windows") }
func (otherSystem) Verify(string) error { return errors.New("not Windows") }
