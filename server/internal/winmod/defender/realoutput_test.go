package defender

import (
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/winmod/realtest"
)

// TestRealOutputs: every output of a real Windows Server 2025 domain
// controller kept in testdata/real is still read by the action that printed it.
func TestRealOutputs(t *testing.T) {
	realtest.Parse(t, "defender", Actions())
}
