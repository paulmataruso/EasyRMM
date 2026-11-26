//go:build !windows

package winevent

import "errors"

// NewBackend has no event logs to open here: the viewer is for Windows.
func NewBackend() (Backend, error) {
	return nil, errors.New("the event viewer reads Windows event logs, and this is not a Windows computer")
}
