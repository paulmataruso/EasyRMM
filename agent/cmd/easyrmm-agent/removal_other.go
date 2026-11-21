//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// startUninstaller runs `exe uninstall --removal file` as a transient
// systemd unit of its own (ADR-0050): stopping the agent's unit, which
// ends every process in it, leaves the uninstaller running. Each removal
// gets its own unit name, so a unit left from another cannot block it.
func (e *env) startUninstaller(ctx context.Context, exe, file string) error {
	args := []string{"--unit=easyrmm-agent-removal-" + unitSuffix(file), "--collect", "--quiet",
		"--description=EasyRMM agent removal"}
	if root := os.Getenv("EASYRMM_AGENT_ROOT"); root != "" {
		args = append(args, "--setenv=EASYRMM_AGENT_ROOT="+root)
	}
	args = append(args, "--", exe, "uninstall", "--removal", file)
	if out, err := e.command(ctx, "systemd-run", args...); err != nil {
		return fmt.Errorf("systemd-run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// unitSuffix names the removal's unit after the time the instruction was
// saved, which differs for each start.
func unitSuffix(file string) string {
	st, err := os.Stat(filepath.Clean(file))
	if err != nil {
		return "0"
	}
	return fmt.Sprintf("%x", st.ModTime().UnixNano())
}
