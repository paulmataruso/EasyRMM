package host

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// The updater's files in a deployment bundle, under deploy/updater/: the
// program for each architecture, and its systemd units.
var unitFiles = []string{"easyrmm-updater.service", "easyrmm-updater.timer"}

func bundledBinary(deployDir string) string {
	return filepath.Join(deployDir, "updater", "easyrmm-updater-linux-"+runtime.GOARCH)
}

// Install is where the updater is installed: setup.sh puts it there, and
// a confirmed upgrade replaces it with the new bundle's.
type Install struct {
	Binary  string // /usr/local/sbin/easyrmm-updater
	UnitDir string // /etc/systemd/system
	// Systemctl runs systemctl; nil runs the real one.
	Systemctl func(ctx context.Context, args ...string) error
}

// DefaultInstall is where setup.sh installs the updater.
var DefaultInstall = Install{Binary: "/usr/local/sbin/easyrmm-updater", UnitDir: "/etc/systemd/system"}

func systemctl(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "systemctl", args...) //nolint:gosec // arguments the updater builds
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	cmd.SysProcAttr = ownGroup()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %v: %w: %s", args, err, lastLines(string(out), 3))
	}
	return nil
}

// replaceFrom installs the updater and its units from a deploy/ directory
// the updater unpacked from a verified bundle, each renamed into place,
// and has systemd read the units again. The running updater carries on:
// the next run is the new one.
func (in Install) replaceFrom(ctx context.Context, deployDir string) error {
	files := map[string]string{bundledBinary(deployDir): in.Binary}
	for _, u := range unitFiles {
		files[filepath.Join(deployDir, "updater", u)] = filepath.Join(in.UnitDir, u)
	}
	for src, dst := range files {
		data, err := os.ReadFile(src) //nolint:gosec // from the verified bundle the updater unpacked, root's
		if err != nil {
			return fmt.Errorf("the bundle's updater: %w", err)
		}
		perm := os.FileMode(0o644)
		if dst == in.Binary {
			perm = 0o755
		}
		if err := writeFileAtomic(dst, data, perm); err != nil {
			return err
		}
	}
	run := in.Systemctl
	if run == nil {
		run = systemctl
	}
	return run(ctx, "daemon-reload")
}
