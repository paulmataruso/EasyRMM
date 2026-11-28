package quickassist

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// existingEasyPatch names what shows a real EasyPatch install: its service,
// its data directory or its registry key. The agent refuses to start beside
// one as well; the runner looks first so it can say so.
func existingEasyPatch() string {
	if root := os.Getenv("ProgramData"); root != "" {
		d := filepath.Join(root, "EasyPatch")
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return d
		}
	}
	for _, p := range []string{`SYSTEM\CurrentControlSet\Services\EasyPatchAgent`, `SOFTWARE\EasyPatch`} {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ|registry.WOW64_64KEY); err == nil {
			_ = k.Close()
			return `HKLM\` + p
		}
	}
	return ""
}

// removeEPKey deletes the registry key the ad-hoc agent made for this
// session, by that exact name only.
func removeEPKey(key string) []string {
	path := `SOFTWARE\EasyPatchAdHoc\` + key
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	_ = k.Close()
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, path); err != nil {
		return []string{`HKLM\` + path}
	}
	return nil
}
