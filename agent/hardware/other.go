//go:build !linux && !windows

package hardware

import (
	"runtime"

	"github.com/paulmataruso/easyrmm/agent/inventory"
)

// Disks are read on Linux and Windows only; elsewhere none is opened.
var system = platform{plan: func(string, inventory.ListedDisk) (*failure, target) {
	return notThisProtocol("disks are not read on %s", runtime.GOOS), target{}
}}
