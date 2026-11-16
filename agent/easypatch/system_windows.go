package easypatch

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func platform() System { return windowsSystem{} }

type windowsSystem struct{}

func hide(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }

func (windowsSystem) Formats() ([]string, error) { return []string{agentproto.EasyPatchMSI}, nil }

func (windowsSystem) Install(ctx context.Context, p *agentproto.EasyPatchInstallPayload, _ agentproto.EasyPatchPackage, file string) error {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return fmt.Errorf("finding msiexec: %w", err)
	}
	args := []string{"/i", file, "/qn", "/norestart", "SERVERURL=" + p.ServerURL}
	if p.CACert != "" {
		// The agent's own trust for EasyPatch, as base64 DER.
		b, _ := pem.Decode([]byte(p.CACert))
		if b == nil {
			return errors.New("the certificate authority in the instruction cannot be read")
		}
		args = append(args, "SERVERCACERT="+base64.StdEncoding.EncodeToString(b.Bytes))
	}
	log := file + ".log"
	args = append(args, "/l*v", log)
	code, _, err := run(ctx, "", nil, filepath.Join(sys, "msiexec.exe"), args...)
	if err != nil {
		return err
	}
	switch code {
	case 0, 3010, 1641: // 3010 and 1641: done, a restart completes it
		_ = os.Remove(log)
		return nil
	case 1618:
		return errors.New("another installation is running on this device (msiexec exit code 1618); install again later")
	case 1603:
		return fmt.Errorf("the EasyPatch agent's installer failed (msiexec exit code 1603); its log is %s", log)
	case 1925, 1730:
		return fmt.Errorf("the EasyPatch agent's installer needs administrator rights (msiexec exit code %d)", code)
	}
	return fmt.Errorf("the EasyPatch agent's installer failed (msiexec exit code %d); its log is %s", code, log)
}

func (windowsSystem) Enroll(ctx context.Context, p *agentproto.EasyPatchInstallPayload) error {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return fmt.Errorf("finding Program Files: %w", err)
	}
	exe := filepath.Join(dir, "EasyPatch Agent", "EasyPatch.Agent.exe")
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("the EasyPatch agent is not at %s after its installer ran", exe)
	}
	code, out, err := run(ctx, "", []string{"EASYPATCH_ENROLLMENT_TOKEN=" + p.Token}, exe, "enroll", "--server", p.ServerURL)
	if err != nil {
		return err
	}
	return enrollError(code, []byte(redact(string(out), p.Token)), p, false)
}
