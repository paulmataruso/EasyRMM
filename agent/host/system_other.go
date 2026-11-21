//go:build !windows

package host

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
)

func systemDescription() string {
	if runtime.GOOS == "linux" {
		return linuxDescription("/")
	}
	return ""
}

// IsAdmin reports whether the agent runs as root.
func IsAdmin() bool { return os.Geteuid() == 0 }

// ServicesAvailable reports whether the agent can install itself as a
// service: systemd manages this machine.
func ServicesAvailable() bool { return runtime.GOOS == "linux" && Available() }

// SystemServices returns the machine's service manager.
func SystemServices(p Paths) Services { return Systemd{Dir: p.Units(), Run: Exec} }

// Protect creates dir if needed and makes it reachable by its owner only.
func Protect(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700) //nolint:gosec // a directory, owner only
}

// checkState does nothing: only root reaches the state folder, and Load
// checks the key's mode.
func checkState(string, string, [][]string) (StateCheck, error) { return StateCheck{}, nil }

// RemoveExecutable deletes an installed program. later is true when it can
// only be deleted at the next restart, which happens on Windows only.
func RemoveExecutable(path string) (later bool, err error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return false, nil
}

// replaceFile moves src over dst, which may be a running program.
func replaceFile(src, dst string) error { return os.Rename(src, dst) }
