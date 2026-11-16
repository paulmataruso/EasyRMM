//go:build windows

package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestProtectWindows checks the agent's folders: an access list of their
// own, not inherited, for SYSTEM and administrators only.
func TestProtectWindows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := Protect(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	s := sd.String()
	if !strings.HasPrefix(s, "D:P") || !strings.Contains(s, ";;;SY)") || !strings.Contains(s, ";;;BA)") || strings.Contains(s, ";;;BU)") || strings.Contains(s, ";;;WD)") {
		t.Errorf("access list = %s", s)
	}
	// Protecting again is harmless.
	if err := Protect(dir); err != nil {
		t.Error(err)
	}
}

func TestWindowsVersion(t *testing.T) {
	v, err := WindowsVersion()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v.Name, "Windows") || !strings.HasPrefix(v.Version, "10.0.") || v.Build == "" {
		t.Errorf("version = %+v", v)
	}
	if !IsAdmin() {
		t.Log("not elevated: services are not installed by this test")
	}
}
