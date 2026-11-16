//go:build !windows

package main

// asService reports whether the Windows service manager started the agent;
// elsewhere a service manager runs "easyrmm-agent run" like a command.
func asService() (started bool, code int) { return false, 0 }
