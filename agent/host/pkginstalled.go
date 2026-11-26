package host

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
)

// PackageName is the DEB's and the RPM's name (ADR-0056).
const PackageName = "easyrmm-agent"

// MSIUpgradeCode is the MSI's upgrade code, which finds the product however
// its version or ProductCode changed (ADR-0056). It never changes.
const MSIUpgradeCode = "{DA28A5EF-C528-4A43-9375-59DF190A02E2}"

// PackageKinds are the packages that install the agent.
var PackageKinds = []string{"deb", "rpm", "msi"}

// PackageInstalled reports whether the package manager lists the package of
// kind as installed: dpkg-query showing it installed, rpm -q, or
// MsiEnumRelatedProducts for a product of the MSI's upgrade code.
func PackageInstalled(ctx context.Context, run Runner, kind string) bool {
	switch kind {
	case "deb":
		out, err := run(ctx, "dpkg-query", "-W", "-f=${db:Status-Status}", PackageName)
		return err == nil && strings.TrimSpace(string(out)) == "installed"
	case "rpm":
		_, err := run(ctx, "rpm", "-q", PackageName)
		return err == nil
	case "msi":
		return msiInstalled(MSIUpgradeCode)
	}
	return false
}

// PackageRemoveCommand names the command that removes the package.
func PackageRemoveCommand(kind string) string {
	switch kind {
	case "deb":
		return "apt-get purge " + PackageName
	case "rpm":
		return "dnf remove " + PackageName + " (or rpm -e " + PackageName + ")"
	case "msi":
		return "remove EasyRMM Agent in Programs and Features, or run msiexec /x on its product"
	}
	return ""
}

// SystemdInstalled reports whether systemd is installed, running or not: an
// image built offline has its unit directory and systemctl.
func SystemdInstalled(p Paths) bool {
	for _, d := range []string{"usr/lib/systemd/system", "lib/systemd/system"} {
		if st, err := os.Stat(p.unix(d)); err == nil && st.IsDir() {
			_, err := exec.LookPath("systemctl")
			return err == nil
		}
	}
	return false
}

// StartForbidden reports whether Debian's policy-rc.d forbids starting
// services (it answers 101, as during image builds). `systemctl enable
// --now` does not ask it, so the agent does.
func StartForbidden(ctx context.Context, p Paths, run Runner) bool {
	path := p.unix("usr/sbin/policy-rc.d")
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Mode().Perm()&0o111 == 0 {
		return false
	}
	_, err = run(ctx, path, PackageName, "start")
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() == 101
}
