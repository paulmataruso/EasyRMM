//go:build !windows

package host

// msiInstalled: there is no Windows Installer here.
func msiInstalled(string) bool { return false }
