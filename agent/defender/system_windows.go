//go:build windows

package defender

import (
	"fmt"

	"github.com/paulmataruso/easyrmm/agent/host"
)

type windowsSystem struct{}

// NewSystem is this machine's folder handling: host.Protect to lock a
// folder down, and the folder-trust check of ADR-0064 to verify it: the
// folders above it, the folder, and its whole subtree.
func NewSystem() System { return windowsSystem{} }

func (windowsSystem) Lock(dir string) error { return host.Protect(dir) }

func (windowsSystem) Verify(dir string) error {
	if err := host.CheckAbove(dir); err != nil {
		return fmt.Errorf("%w", err)
	}
	return host.CheckSubtree(dir)
}
