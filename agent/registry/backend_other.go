//go:build !windows

package registry

import "errors"

// NewBackend is the registry of this machine; there is none to read here.
func NewBackend() (Backend, error) {
	return nil, errors.New("the registry builtin runs on Windows only")
}
