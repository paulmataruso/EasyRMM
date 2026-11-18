package host

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// InstallExecutable copies the program at src to dst, its installed
// location, and reports whether dst changed: a service needs a restart only
// for a new build. A program that is running can be replaced.
func InstallExecutable(src, dst string) (changed bool, err error) {
	if src == dst {
		return false, nil
	}
	b, err := os.ReadFile(src) //nolint:gosec // the agent's own executable
	if err != nil {
		return false, err
	}
	if cur, err := os.ReadFile(dst); err == nil && bytes.Equal(cur, b) { //nolint:gosec // the installed agent
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // a program directory
		return false, err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, b, 0o755); err != nil { //nolint:gosec // an executable
		return false, err
	}
	if err := replaceFile(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// WindowsName names a Windows release from its registry values: the
// product name, which still says Windows 10 on Windows 11, the display
// version (23H2) and the build number.
func WindowsName(product, displayVersion string, build int) string {
	name := strings.TrimSpace(product)
	if name == "" {
		name = "Windows"
	}
	if build >= 22000 && strings.HasPrefix(name, "Windows 10") {
		name = "Windows 11" + strings.TrimPrefix(name, "Windows 10")
	}
	if dv := strings.TrimSpace(displayVersion); dv != "" && !strings.Contains(name, dv) {
		name += " " + dv
	}
	return name
}
