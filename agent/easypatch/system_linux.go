package easypatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

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

// Enroll enrolls the EasyPatch agent with the token on standard input. With
// a certificate authority in the instruction (EasyRMM addressed by IP, with
// its own authority), the agent is told to trust it for EasyPatch only
// (--server-ca), as the MSI's SERVERCACERT does on Windows. An agent from
// before that option refuses it as a usage error (exit code 2) before it
// uses the token, and is enrolled again without it.
func (l linuxSystem) Enroll(ctx context.Context, p *agentproto.EasyPatchInstallPayload) error {
	if _, err := os.Stat(l.agent); err != nil {
		return fmt.Errorf("the EasyPatch agent is not at %s after its package installed", l.agent)
	}
	args := []string{"enroll", "--server", p.ServerURL, "--token-file", "-"}
	if p.CACert != "" {
		dir, err := os.MkdirTemp("", "easyrmm-easypatch-ca-")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(dir) }()
		ca := filepath.Join(dir, "server-ca.pem")
		if err := os.WriteFile(ca, []byte(p.CACert), 0o600); err != nil {
			return err
		}
		code, out, err := run(ctx, p.Token, nil, l.agent, append(args, "--server-ca", ca)...)
		if err != nil {
			return err
		}
		if code != 2 {
			return enrollError(code, []byte(redact(string(out), p.Token)), p, false)
		}
	}
	code, out, err := run(ctx, p.Token, nil, l.agent, args...)
	if err != nil {
		return err
	}
	return enrollError(code, []byte(redact(string(out), p.Token)), p, true)
}
