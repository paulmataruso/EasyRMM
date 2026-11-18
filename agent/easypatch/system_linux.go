package easypatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// linuxAgent is where the EasyPatch agent's .deb and .rpm install it.
const linuxAgent = "/opt/easypatch/easypatch-agent"

func platform() System {
	return linuxSystem{euid: os.Geteuid, systemd: "/run/systemd/system", agent: linuxAgent}
}

// linuxSystem installs with apt-get or dnf; its fields are what tests
// replace.
type linuxSystem struct {
	euid func() int
	// systemd exists when systemd is the init system (sd_booted(3)).
	systemd string
	// agent is the installed EasyPatch agent.
	agent string
}

func (l linuxSystem) Formats() ([]string, error) {
	if l.euid() != 0 {
		return nil, errors.New("the EasyRMM agent does not run as root here, so it cannot install the EasyPatch agent")
	}
	if st, err := os.Stat(l.systemd); err != nil || !st.IsDir() {
		return nil, errors.New("this device does not run systemd, which the EasyPatch agent needs")
	}
	var out []string
	if _, err := exec.LookPath("apt-get"); err == nil {
		out = append(out, agentproto.EasyPatchDeb)
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		out = append(out, agentproto.EasyPatchRPM)
	}
	if len(out) == 0 {
		return nil, errors.New("EasyRMM installs the EasyPatch agent with apt-get or dnf, and this device has neither")
	}
	return out, nil
}

func (linuxSystem) Install(ctx context.Context, _ *agentproto.EasyPatchInstallPayload, pkg agentproto.EasyPatchPackage, file string) error {
	if pkg.Format == agentproto.EasyPatchRPM {
		code, out, err := run(ctx, "", nil, "dnf", "install", "-y", file)
		return packageError("dnf", code, out, err)
	}
	env := []string{"DEBIAN_FRONTEND=noninteractive"}
	install := func() (int, []byte, error) {
		return run(ctx, "", env, "apt-get", "install", "-y", "--no-install-recommends", "-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold", file)
	}
	code, out, err := install()
	if err == nil && code != 0 {
		// The package lists may be missing or stale for its dependencies.
		if c, _, e := run(ctx, "", env, "apt-get", "update"); e == nil && c == 0 {
			code, out, err = install()
		}
	}
	return packageError("apt-get", code, out, err)
}

func packageError(tool string, code int, out []byte, err error) error {
	switch {
	case err != nil:
		return err
	case code != 0:
		msg := fmt.Sprintf("%s could not install the EasyPatch agent (exit code %d)", tool, code)
		if t := tail(out); t != "" {
			msg += ": " + t
		}
		return errors.New(msg)
	}
	return nil
}

func (l linuxSystem) Enroll(ctx context.Context, p *agentproto.EasyPatchInstallPayload) error {
	if _, err := os.Stat(l.agent); err != nil {
		return fmt.Errorf("the EasyPatch agent is not at %s after its package installed", l.agent)
	}
	code, out, err := run(ctx, p.Token, nil, l.agent, "enroll", "--server", p.ServerURL, "--token-file", "-")
	if err != nil {
		return err
	}
	return enrollError(code, []byte(redact(string(out), p.Token)), p, true)
}
