//go:build windows

package inventory

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// easyPatch reports the EasyPatch agent, nil when it is not installed. Its
// MSI installs it in Program Files\\EasyPatch Agent.
func (c Collector) easyPatch(ctx context.Context) *agentproto.EasyPatchAgent {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return nil
	}
	bin := filepath.Join(dir, "EasyPatch Agent", "EasyPatch.Agent.exe")
	if st, err := os.Stat(bin); err != nil || st.IsDir() {
		return nil
	}
	return c.easyPatchStatus(ctx, bin)
}

func output(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // a fixed program in Program Files
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Output()
}
