//go:build windows

package printsrv

import (
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/winmod/rolekit/rolekittest"
)

// TestScriptsOnWindows runs the scripts in Windows PowerShell on stdin
// params. A runner has the SmbShare cmdlets, so the reads run (a change is not
// run with empty parameters) and each must answer in the result format. Real
// role tests (a server with shares and open files) are a later manual step
// (ADR-0076, T1).
func TestScriptsOnWindows(t *testing.T) {
	rolekittest.RoleAbsentPath(t, "PrintManagement", Actions())
}
