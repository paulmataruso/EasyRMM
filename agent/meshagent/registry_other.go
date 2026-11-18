//go:build !windows

package meshagent

// removeRegistry is a no-op: only Windows MeshAgent keeps registry keys.
func removeRegistry(string) {}
