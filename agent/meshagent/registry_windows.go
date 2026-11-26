//go:build windows

package meshagent

import "golang.org/x/sys/windows/registry"

// removeRegistry deletes the keys Windows MeshAgent keeps under its service
// name: HKLM\SOFTWARE\Open Source\<service name>, its node id and options,
// and the Uninstall entry that meshcore.js keeps correct (EstimatedSize and
// DisplayVersion), which it creates when no installer made one (ADR-0071).
// The names are exact: another MeshAgent's keys, "Mesh Agent" or a custom
// name, are never listed or matched.
func removeRegistry(service string) {
	for _, base := range []string{
		`SOFTWARE\Open Source\`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`,
	} {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, base+service)
	}
}
