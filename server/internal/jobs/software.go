package jobs

import (
	"context"
	_ "embed" // the software action scripts
	"fmt"
	"regexp"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Software actions (ADR-0028).
const (
	ActionInstall   = "install"
	ActionUpgrade   = "upgrade"
	ActionUninstall = "uninstall"
)

// Package managers. ManagerSystem is the Linux distribution's own: apt-get,
// dnf, yum or zypper, whichever the device has.
const (
	ManagerWinget     = "winget"
	ManagerChocolatey = "chocolatey"
	ManagerSystem     = "system"
)

// Kinds of job.
const (
	KindScript   = "script"
	KindSoftware = "software"
)

// DefaultSoftwareTimeout is how long a software action may run unless the
// request says otherwise: large installers take a while.
const DefaultSoftwareTimeout = 3600

var (
	//go:embed software/linux.sh
	linuxScript string
	//go:embed software/winget.ps1
	wingetScript string
	//go:embed software/chocolatey.ps1
	chocolateyScript string
)

// manager is what EasyRMM knows of a package manager.
type manager struct {
	name     string // how people write it
	platform string
	shell    string
	script   string
	// pkg is what a package name may look like. Names never start with a
	// dash, so that one cannot be read as an option.
	pkg *regexp.Regexp
}

var managers = map[string]manager{
	ManagerWinget: {"winget", "windows", agentproto.ShellPowerShell, wingetScript,
		regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)},
	ManagerChocolatey: {"Chocolatey", "windows", agentproto.ShellPowerShell, chocolateyScript,
		regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)},
	ManagerSystem: {"the system's package manager", "linux", agentproto.ShellSh, linuxScript,
		regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$`)},
}

var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,63}$`)

// Software is the action a software job carries.
type Software struct {
	Action  string `json:"action"`
	Manager string `json:"manager"`
	Package string `json:"package"`
	// Version is for installs only; empty takes the newest.
	Version string `json:"version,omitempty"`
}

// label names the action for job lists: "Install jq",
// "Uninstall Mozilla.Firefox (winget)".
func (sw Software) label() string {
	verb := map[string]string{ActionInstall: "Install", ActionUpgrade: "Update", ActionUninstall: "Uninstall"}[sw.Action]
	s := verb + " " + sw.Package
	if sw.Version != "" {
		s += " " + sw.Version
	}
	if m := managers[sw.Manager]; m.platform == "windows" {
		s += " (" + m.name + ")"
	}
	return s
}

// args are the script's arguments.
func (sw Software) args() []string {
	a := []string{sw.Action, sw.Package}
	if sw.Version != "" {
		a = append(a, sw.Version)
	}
	return a
}

// SoftwareInput asks for a software action on devices.
type SoftwareInput struct {
	DeviceIDs []uuid.UUID `json:"deviceIds"`
	Software
	// TimeoutSeconds overrides DefaultSoftwareTimeout when not zero.
	TimeoutSeconds int `json:"timeoutSeconds"`
	// WaitHours is how long to wait for an offline device; zero is the
	// default.
	WaitHours int `json:"waitHours"`
}

func (in SoftwareInput) check(f apperr.Fields) manager {
	m, known := managers[in.Manager]
	f.Check(known, "manager", "Choose winget, Chocolatey or the system's package manager.")
	f.Check(slices.Contains([]string{ActionInstall, ActionUpgrade, ActionUninstall}, in.Action), "action", "Choose install, update or uninstall.")
	switch {
	case in.Package == "":
		f.Add("package", "Enter the package's name.")
	case known && !m.pkg.MatchString(in.Package):
		f.Add("package", fmt.Sprintf("Enter the package name as %s writes it: letters, digits and punctuation such as . _ -, with no spaces.", m.name))
	}
	switch {
	case in.Version == "":
	case in.Action != ActionInstall:
		f.Add("version", "A version applies to installs only.")
	case !versionPattern.MatchString(in.Version):
		f.Add("version", "Enter a version without spaces, such as 1.2.3.")
	}
	return m
}

// CreateSoftwareJob installs, updates or removes a package on devices
// through their package manager (ADR-0028). It runs as a job of one of
// EasyRMM's own scripts with the package as an argument, and needs
// software.manage on every device. Every device must pass every check, or
// nothing runs.
func (s *Service) CreateSoftwareJob(ctx context.Context, c access.Caller, in SoftwareInput) (*Job, error) {
	f := apperr.Fields{}
	ids := checkDevices(f, in.DeviceIDs)
	m := in.check(f)
	timeout := DefaultSoftwareTimeout
	if in.TimeoutSeconds != 0 {
		timeout = in.TimeoutSeconds
		checkTimeout(f, timeout)
	}
	wait := checkWait(f, in.WaitHours)
	if err := f.Err(); err != nil {
		return nil, err
	}
	sw := in.Software
	sp := &spec{
		kind: KindSoftware, software: &sw, name: sw.label(), shell: m.shell, body: m.script, args: sw.args(), timeout: timeout,
		auditAction: "device.software_action",
		details: map[string]any{
			"action": sw.Action, "manager": sw.Manager, "package": sw.Package, "version": sw.Version,
		},
	}
	r := rule{perm: rbac.PermSoftwareManage, verb: "manage software", platforms: []string{m.platform}, runsOn: m.name + " runs on"}
	if sw.Manager == ManagerSystem {
		r.runsOn = "Linux package managers run on"
	}
	return s.create(ctx, c, ids, wait, sp, func(ctx context.Context, tx pgx.Tx) ([]target, error) {
		return s.targets(ctx, tx, c, ids, r)
	})
}
