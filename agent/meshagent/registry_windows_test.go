//go:build windows

package meshagent

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

// ADR-0071: removing our MeshAgent deletes the key of our service name and no
// other key under Open Source (a client's "Mesh Agent", or its prefix).
func TestRemoveRegistryTouchesOnlyItsKey(t *testing.T) {
	const base = `SOFTWARE\Open Source\`
	ours, theirs := "EasyRMMTestMeshOurs", "EasyRMMTestMeshOurs Other"
	for _, n := range []string{ours, theirs} {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, base+n, registry.SET_VALUE)
		if err != nil {
			t.Skipf("cannot write HKLM here: %v", err)
		}
		_ = k.SetStringValue("NodeId", "x")
		_ = k.Close()
	}
	defer func() { _ = registry.DeleteKey(registry.LOCAL_MACHINE, base+theirs) }()
	un, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`+ours, registry.SET_VALUE)
	if err != nil {
		t.Skipf("cannot write HKLM here: %v", err)
	}
	_ = un.Close()
	removeRegistry(ours)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`+ours, registry.QUERY_VALUE); err == nil {
		_ = k.Close()
		t.Error("our Uninstall key is still there")
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, base+ours, registry.QUERY_VALUE); err == nil {
		_ = k.Close()
		t.Error("our key is still there")
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base+theirs, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("another key was deleted: %v", err)
	}
	_ = k.Close()
}
