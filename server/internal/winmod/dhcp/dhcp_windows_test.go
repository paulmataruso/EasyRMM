//go:build windows

package dhcp

import (
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/winmod/rolekit/rolekittest"
)

// TestScriptsOnWindows runs every DHCP script in Windows PowerShell on stdin
// params. The runner has no DHCP role, so each must say module_missing; a
// server with the role runs the reads only. Real role tests (a domain
// controller with every role) are a later manual step (ADR-0076, T1 and T2).
func TestScriptsOnWindows(t *testing.T) {
	rolekittest.RoleAbsentPath(t, "DhcpServer", Actions())
}
