package easypatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Repairing the EasyPatch agent in place (ADR-0069, Part R). A repair keeps
// the agent's enrollment: it restarts the agent's service, or puts its
// program and service back by reinstalling the package of the version that
// is installed. It never runs the install path (Installer.install, Enroll),
// which refuses an enrolled agent and would make a new endpoint.

// Service names of the EasyPatch agent.
const (
	// WindowsService is the EasyPatch agent's Windows service.
	WindowsService = "EasyPatchAgent"
	// LinuxUnit is its systemd unit.
	LinuxUnit = "easypatch-agent.service"
)

// Services restarts the EasyPatch agent's service.
type Services interface {
	// Restart restarts a service, or starts it when it is stopped.
	Restart(ctx context.Context, name string) error
}

// Reinstaller is the platform's side of a repair; tests replace it, as they
// do System. A System that is also a Reinstaller is used for repairs.
type Reinstaller interface {
	// Service names the EasyPatch agent's service or unit.
	Service() string
	// Reinstall puts the downloaded package of the installed version back:
	// msiexec /fa, apt-get install --reinstall or dnf reinstall.
	Reinstall(ctx context.Context, pkg agentproto.EasyPatchPackage, file string) error
}

func (i *Installer) reinstaller() (System, Reinstaller, error) {
	sys := i.System
	if sys == nil {
		sys = platform()
	}
	r, ok := sys.(Reinstaller)
	if !ok {
		return nil, nil, errors.New("this device cannot repair the EasyPatch agent")
	}
	return sys, r, nil
}

// claimRepair takes the right to repair, which an install or another repair
// holds while it runs.
func (i *Installer) claimRepair() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.busy != "" || i.repairing {
		return errors.New("the EasyRMM agent is installing or repairing the EasyPatch agent already")
	}
	i.repairing = true
	return nil
}

func (i *Installer) releaseRepair() {
	i.mu.Lock()
	i.repairing = false
	i.mu.Unlock()
}

// Restart restarts the EasyPatch agent's service.
func (i *Installer) Restart(ctx context.Context) error {
	_, r, err := i.reinstaller()
	if err != nil {
		return err
	}
	if i.Services == nil {
		return errors.New("this device has no service manager the EasyRMM agent can use")
	}
	if i.Present != nil && i.Present(ctx) == nil {
		return errors.New("the EasyPatch agent is not installed on this device: it needs a repair, not a restart")
	}
	if err := i.Services.Restart(ctx, r.Service()); err != nil {
		return fmt.Errorf("restarting the EasyPatch agent's service: %w", err)
	}
	return nil
}

// Repair reinstalls the package of the version installed, which the signed
// instruction offers, over the installed agent. within bounds the download
// and the reinstall.
func (i *Installer) Repair(ctx, within context.Context, r *agentproto.RepairEasyPatch) error {
	if r == nil {
		return errors.New("the instruction carries no package")
	}
	sys, re, err := i.reinstaller()
	if err != nil {
		return err
	}
	formats, err := sys.Formats()
	if err != nil {
		return err
	}
	if err := i.claimRepair(); err != nil {
		return err
	}
	defer i.releaseRepair()
	// An agent that is not enrolled is not this repair's to touch, and a
	// version other than the one offered would be an update or a downgrade.
	var have string
	if i.Present != nil {
		if st := i.Present(ctx); st != nil {
			if st.Status == notEnrolled {
				return errors.New("the EasyPatch agent here is not enrolled; a repair keeps an enrollment and makes none")
			}
			have = st.Version
		}
	}
	var pkgs []agentproto.EasyPatchPackage
	for _, p := range r.Packages {
		if have == "" || agentproto.SameVersion(p.Version, have) {
			pkgs = append(pkgs, p)
		}
	}
	pkg, ok := choose(pkgs, formats)
	if !ok {
		if have != "" {
			return fmt.Errorf("the patching engine offered no package of version %s, the one installed (it installs %s)", have, strings.Join(formats, " or "))
		}
		return fmt.Errorf("the patching engine offered no package this device installs (it installs %s)", strings.Join(formats, " or "))
	}
	dir := filepath.Join(i.Dir, "easypatch")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating the download directory: %w", err)
	}
	file := filepath.Join(dir, pkg.FileName)
	defer os.Remove(file)
	if err := i.fetch(within, &agentproto.EasyPatchInstallPayload{CACert: r.CACert}, pkg, file); err != nil {
		return err
	}
	if within.Err() != nil {
		return errors.New("the EasyRMM agent stopped before the EasyPatch agent was repaired")
	}
	// As an install, the package manager is not interrupted when the agent
	// stops, only when it runs too long.
	until, _ := within.Deadline()
	work, cancel := context.WithDeadline(context.WithoutCancel(within), until)
	defer cancel()
	if err := re.Reinstall(work, pkg, file); err != nil {
		return err
	}
	if i.Finished != nil {
		defer i.Finished()
	}
	// The package starts the service; a restart makes sure of it.
	if i.Services != nil {
		if err := i.Services.Restart(work, re.Service()); err != nil {
			return fmt.Errorf("the package is back in place, but restarting the EasyPatch agent's service failed: %w", err)
		}
	}
	return nil
}
