//go:build windows

package meshagent

import "golang.org/x/sys/windows/registry"

// removeRegistry deletes the key Windows MeshAgent keeps its node id and
// options in, HKLM\SOFTWARE\Open Source\<service name>.
func removeRegistry(service string) {
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\Open Source\`+service)
}
