package jobs

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

func TestSoftwareInputChecks(t *testing.T) {
	ok := []SoftwareInput{
		{Software: Software{Action: ActionInstall, Manager: ManagerWinget, Package: "Mozilla.Firefox", Version: "128.0.3"}},
		{Software: Software{Action: ActionUpgrade, Manager: ManagerWinget, Package: "Microsoft.VCRedist.2015+.x64"}},
		{Software: Software{Action: ActionUninstall, Manager: ManagerChocolatey, Package: "7zip.install"}},
		{Software: Software{Action: ActionInstall, Manager: ManagerSystem, Package: "libc6:i386", Version: "2.36-9+deb12u4"}},
		{Software: Software{Action: ActionInstall, Manager: ManagerSystem, Package: "libstdc++", Version: "1:13.2~rc1"}},
	}
	for _, in := range ok {
		f := apperr.Fields{}
		in.check(f)
		if err := f.Err(); err != nil {
			t.Errorf("%+v refused: %v", in.Software, err)
		}
	}
	type bad struct {
		field string
		in    Software
	}
	bads := []bad{
		{"manager", Software{Action: ActionInstall, Manager: "brew", Package: "jq"}},
		{"action", Software{Action: "reinstall", Manager: ManagerSystem, Package: "jq"}},
		{"package", Software{Action: ActionInstall, Manager: ManagerSystem, Package: "-o APT::Get::foo"}},
		{"package", Software{Action: ActionInstall, Manager: ManagerChocolatey, Package: "notepad++"}},
		{"version", Software{Action: ActionUpgrade, Manager: ManagerSystem, Package: "jq", Version: "1.7"}},
		{"version", Software{Action: ActionInstall, Manager: ManagerWinget, Package: "Git.Git", Version: "--force"}},
	}
	for _, p := range []string{"", "jq; rm -rf /", "$(id)", "two words", "a\nb", strings.Repeat("a", 129), "Choco/../x", "pkg`id`"} {
		bads = append(bads, bad{"package", Software{Action: ActionInstall, Manager: ManagerSystem, Package: p}})
	}
	for _, b := range bads {
		f := apperr.Fields{}
		SoftwareInput{Software: b.in}.check(f)
		if _, refused := f[b.field]; !refused {
			t.Errorf("%+v not refused on %s (%v)", b.in, b.field, f)
		}
	}
}

func TestSoftwareLabelsAndArgs(t *testing.T) {
	cases := []struct {
		sw    Software
		label string
		args  []string
		shell string
	}{
		{Software{ActionInstall, ManagerSystem, "jq", ""}, "Install jq", []string{"install", "jq"}, agentproto.ShellSh},
		{Software{ActionInstall, ManagerSystem, "jq", "1.7.1-3"}, "Install jq 1.7.1-3", []string{"install", "jq", "1.7.1-3"}, agentproto.ShellSh},
		{Software{ActionUpgrade, ManagerWinget, "Git.Git", ""}, "Update Git.Git (winget)", []string{"upgrade", "Git.Git"}, agentproto.ShellPowerShell},
		{Software{ActionUninstall, ManagerChocolatey, "7zip", ""}, "Uninstall 7zip (Chocolatey)", []string{"uninstall", "7zip"}, agentproto.ShellPowerShell},
	}
	for _, c := range cases {
		if got := c.sw.label(); got != c.label {
			t.Errorf("label = %q, want %q", got, c.label)
		}
		if got := c.sw.args(); !slices.Equal(got, c.args) {
			t.Errorf("args = %q, want %q", got, c.args)
		}
		m := managers[c.sw.Manager]
		if m.shell != c.shell || len(m.script) == 0 || len(m.script) > MaxBody || !slices.Contains(agentproto.ShellPlatforms(m.shell), m.platform) {
			t.Errorf("%s: shell %s, %d-byte script, platform %s", c.sw.Manager, m.shell, len(m.script), m.platform)
		}
	}
}

// fakeTools puts stand-ins for the package managers on an otherwise empty
// PATH. Each writes its name and arguments to $LOG, one per line, and fails
// with $FAIL_RC when one of its arguments is $FAIL_MATCH. dpkg-query and
// rpm answer from $INSTALLED.
func fakeTools(t *testing.T, names ...string) (dir, log string) {
	t.Helper()
	dir = t.TempDir()
	log = filepath.Join(dir, "log")
	fake := `#!/bin/sh
printf '%s' "${0##*/}" >>"$LOG"
for a in "$@"; do printf ' [%s]' "$a" >>"$LOG"; done
printf '\n' >>"$LOG"
case "${0##*/}" in
dpkg-query) [ "$INSTALLED" = 1 ] && { printf 'install ok installed'; exit 0; }; exit 1 ;;
rpm) [ "$INSTALLED" = 1 ]; exit ;;
esac
case " $* " in *" $FAIL_MATCH "*) [ -n "$FAIL_MATCH" ] && exit "$FAIL_RC" ;; esac
exit 0
`
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(fake), 0o755); err != nil { //nolint:gosec // a test's fake tool
			t.Fatal(err)
		}
	}
	grep, err := exec.LookPath("grep")
	if err != nil {
		t.Skip("no grep")
	}
	if err := os.Symlink(grep, filepath.Join(dir, "grep")); err != nil {
		t.Fatal(err)
	}
	return dir, log
}

// runLinux runs the Linux software script with the fake tools and returns
// its exit code, its output and the tools' calls.
func runLinux(t *testing.T, dir, log string, env []string, args ...string) (int, string, []string) {
	t.Helper()
	_ = os.Remove(log)
	script := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(script, []byte(linuxScript), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", append([]string{script}, args...)...) //nolint:gosec,noctx // the script under test
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=" + dir, "LOG=" + log}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(log) //nolint:gosec // the test's own file
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(calls) == 0 {
		lines = nil
	}
	return code, string(out), lines
}

func TestLinuxSoftwareScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a POSIX shell script")
	}
	const aptOpts = "[-y] [-q] [-o] [DPkg::Lock::Timeout=600] [-o] [Dpkg::Options::=--force-confdef] [-o] [Dpkg::Options::=--force-confold]"
	type want struct {
		code  int
		calls []string
		out   string
	}
	cases := []struct {
		name  string
		tools []string
		env   []string
		args  []string
		want  want
	}{
		{"apt install", []string{"apt-get", "dpkg-query", "rpm"}, nil, []string{"install", "jq"},
			want{0, []string{"apt-get " + aptOpts + " [update]", "apt-get " + aptOpts + " [install] [jq]"}, "+ apt-get"}},
		{"apt install a version", []string{"apt-get", "dpkg-query"}, nil, []string{"install", "jq", "1.7.1-3"},
			want{0, []string{"apt-get " + aptOpts + " [update]", "apt-get " + aptOpts + " [install] [jq=1.7.1-3]"}, ""}},
		{"apt goes on when the lists cannot be refreshed", []string{"apt-get", "dpkg-query"}, []string{"FAIL_MATCH=update", "FAIL_RC=100"}, []string{"install", "jq"},
			want{0, []string{"apt-get " + aptOpts + " [update]", "apt-get " + aptOpts + " [install] [jq]"}, "Refreshing the package lists failed"}},
		{"apt install fails", []string{"apt-get", "dpkg-query"}, []string{"FAIL_MATCH=install", "FAIL_RC=100"}, []string{"install", "nosuch"},
			want{100, []string{"apt-get " + aptOpts + " [update]", "apt-get " + aptOpts + " [install] [nosuch]"}, ""}},
		{"apt update of a missing package", []string{"apt-get", "dpkg-query"}, nil, []string{"upgrade", "jq"},
			want{3, []string{"dpkg-query [-W] [-f=${Status}] [jq]"}, "jq is not installed."}},
		{"apt update", []string{"apt-get", "dpkg-query"}, []string{"INSTALLED=1"}, []string{"upgrade", "jq"},
			want{0, []string{"dpkg-query [-W] [-f=${Status}] [jq]", "apt-get " + aptOpts + " [update]", "apt-get " + aptOpts + " [install] [--only-upgrade] [jq]"}, ""}},
		{"apt uninstall of a missing package", []string{"apt-get", "dpkg-query"}, nil, []string{"uninstall", "jq"},
			want{0, []string{"dpkg-query [-W] [-f=${Status}] [jq]"}, "jq is not installed."}},
		{"apt uninstall", []string{"apt-get", "dpkg-query"}, []string{"INSTALLED=1"}, []string{"uninstall", "jq"},
			want{0, []string{"dpkg-query [-W] [-f=${Status}] [jq]", "apt-get " + aptOpts + " [remove] [jq]"}, ""}},
		{"dnf install a version", []string{"dnf", "yum", "rpm"}, nil, []string{"install", "jq", "1.7.1"},
			want{0, []string{"dnf [-y] [install] [jq-1.7.1]"}, ""}},
		{"yum update", []string{"yum", "rpm"}, []string{"INSTALLED=1"}, []string{"upgrade", "jq"},
			want{0, []string{"rpm [-q] [jq]", "yum [-y] [upgrade] [jq]"}, ""}},
		{"dnf update of a missing package", []string{"dnf", "rpm"}, nil, []string{"upgrade", "jq"},
			want{3, []string{"rpm [-q] [jq]"}, "jq is not installed."}},
		{"dnf uninstall", []string{"dnf", "rpm"}, []string{"INSTALLED=1"}, []string{"uninstall", "jq"},
			want{0, []string{"rpm [-q] [jq]", "dnf [-y] [remove] [jq]"}, ""}},
		{"zypper install, restart needed", []string{"zypper", "rpm"}, []string{"FAIL_MATCH=install", "FAIL_RC=102"}, []string{"install", "jq", "1.7"},
			want{0, []string{"zypper [--non-interactive] [--no-color] [install] [jq=1.7]"}, "Restart the computer to finish."}},
		{"zypper install fails", []string{"zypper", "rpm"}, []string{"FAIL_MATCH=install", "FAIL_RC=104"}, []string{"install", "nosuch"},
			want{104, []string{"zypper [--non-interactive] [--no-color] [install] [nosuch]"}, ""}},
		{"zypper uninstall", []string{"zypper", "rpm"}, []string{"INSTALLED=1"}, []string{"uninstall", "jq"},
			want{0, []string{"rpm [-q] [jq]", "zypper [--non-interactive] [--no-color] [remove] [jq]"}, ""}},
		{"zypper update", []string{"zypper", "rpm"}, []string{"INSTALLED=1"}, []string{"upgrade", "jq"},
			want{0, []string{"rpm [-q] [jq]", "zypper [--non-interactive] [--no-color] [update] [jq]"}, ""}},
		{"no package manager", nil, nil, []string{"install", "jq"},
			want{2, nil, "none of the package managers"}},
		{"unknown action", []string{"apt-get"}, nil, []string{"purge", "jq"},
			want{2, nil, "Unknown action: purge"}},
		// The server refuses such names; the script would still not run them.
		{"arguments stay arguments", []string{"apt-get", "dpkg-query"}, nil, []string{"install", "$(touch pwned)", "x;touch pwned"},
			want{0, []string{"apt-get " + aptOpts + " [update]", "apt-get " + aptOpts + " [install] [$(touch pwned)=x;touch pwned]"}, ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, log := fakeTools(t, c.tools...)
			code, out, calls := runLinux(t, dir, log, c.env, c.args...)
			if code != c.want.code || !slices.Equal(calls, c.want.calls) || !strings.Contains(out, c.want.out) {
				t.Errorf("exit %d, calls:\n%s\noutput:\n%s\nwant exit %d, calls:\n%s\noutput containing %q",
					code, strings.Join(calls, "\n"), out, c.want.code, strings.Join(c.want.calls, "\n"), c.want.out)
			}
			if _, err := os.Stat(filepath.Join(dir, "pwned")); err == nil {
				t.Error("an argument was run as a command")
			}
		})
	}
}
