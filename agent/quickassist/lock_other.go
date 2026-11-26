//go:build !unix

package quickassist

import (
	"errors"
	"os"
)

// lockFile is not built for this platform: the Windows runner is a later
// slice (ADR-0080 QA3).
func lockFile(*os.File) error { return errors.New("quick assist is not built for this platform yet") }
