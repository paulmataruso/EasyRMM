//go:build !windows

package quickassist

// BaseFor is where a session's folder goes: the user's runtime folder, else
// the temp folder.
func BaseFor(bool) string { return DefaultBase() }

// askWindow has no window on this platform: the terminal asks.
func askWindow(string, string) (yes, handled bool) { return false, false }

// Relaunch is for Windows' UAC; elsewhere the user runs the program as the
// account they want.
func Relaunch(string, []string) bool { return false }

func removeNodeKeys(string) []string { return nil }

func askWindowAvailable() (bool, bool) { return false, false }
