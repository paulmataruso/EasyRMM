//go:build !windows

package host

// StopImage terminates the processes that run a program. It does nothing
// here: systemd stops a unit's processes itself, and a locked program is a
// Windows matter.
func StopImage(string) ([]string, error) { return nil, nil }
