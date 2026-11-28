//go:build !windows

package quickassist

// existingEasyPatch names what shows an EasyPatch install of the computer's
// own. EasyPatch's installed agent is Windows' (its service, ProgramData
// folder and registry key); elsewhere there is none to collide with.
func existingEasyPatch() string { return "" }

func removeEPKey(string) []string { return nil }
