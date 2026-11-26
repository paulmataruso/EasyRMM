//go:build windows

package roles

import (
	"testing"

	"golang.org/x/sys/windows/svc/mgr"
)

// TestServiceStateProtectedService: WinDefend refuses a request for all
// access, which once made it look as if it were not installed, so Defender
// was never reported as a role (found on a real server).
func TestServiceStateProtectedService(t *testing.T) {
	m, err := mgr.Connect()
	if err != nil {
		t.Skipf("the service manager cannot be opened: %v", err)
	}
	defer func() { _ = m.Disconnect() }()
	if got := serviceState(m, "EasyRMMNoSuchService"); got != Missing {
		t.Errorf("a service that does not exist: got %v, want Missing", got)
	}
	if got := serviceState(m, "RpcSs"); got != Running {
		t.Errorf("RpcSs: got %v, want Running", got)
	}
	if !regKeyExists(`SYSTEM\CurrentControlSet\Services\WinDefend`) {
		t.Skip("this computer has no Windows Defender service")
	}
	if got := serviceState(m, "WinDefend"); !got.Installed() {
		t.Errorf("WinDefend is installed but reads as %v", got)
	}
}
