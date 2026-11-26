//go:build !unix && !windows

package quickassist

import (
	"errors"
	"os"
)

// lockFile is not built for this platform. The runner is built for Linux
// and Windows only (ADR-0080).
func lockFile(*os.File) error { return errors.New("quick assist is not built for this platform yet") }
