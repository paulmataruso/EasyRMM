package jobs

import (
	"context"
	_ "embed" // the maintenance action scripts
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// KindMaintenance is the kind of a restart, shutdown or service action
// (feature 11, slice 3): one of EasyRMM's own scripts with the action as an
// argument.
const KindMaintenance = "maintenance"

// Maintenance actions.
const (
	MaintRestart        = "restart"
	MaintShutdown       = "shutdown"
	MaintServiceStart   = "service_start"
	MaintServiceStop    = "service_stop"
	MaintServiceRestart = "service_restart"
)

// DefaultMaintenanceTimeout is how long a maintenance action may run.
const DefaultMaintenanceTimeout = 300

// How long a device that was told to restart or shut down is expected to be
// offline: monitoring raises no offline alert for it in that time.
const (
	ExpectedRestartOffline  = 20 * time.Minute
	ExpectedShutdownOffline = 12 * time.Hour
)

var (
	//go:embed maintenance/linux.sh
	maintLinuxScript string
	//go:embed maintenance/windows.ps1
	maintWindowsScript string
)

// serviceName is what a service's or unit's name may look like. Names never
// start with a dash, so that one cannot be read as an option.
var serviceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}$`)

// Maintenance is the action a maintenance job carries.
type Maintenance struct {
	Action string `json:"action"`
	// Service is the service's (Windows) or unit's (Linux) name, for the
	// service actions.
	Service string `json:"service,omitempty"`
}

// ValidMaintenanceAction says whether the action is one of the known ones.
func ValidMaintenanceAction(a string) bool {
	return slices.Contains([]string{MaintRestart, MaintShutdown, MaintServiceStart, MaintServiceStop, MaintServiceRestart}, a)
}

// Check reports what is wrong with the action.
func (m Maintenance) Check(f apperr.Fields) {
	if !ValidMaintenanceAction(m.Action) {
		f.Add("action", "Choose restart, shutdown, or start, stop or restart a service.")
		return
	}
	switch m.Action {
	case MaintRestart, MaintShutdown:
		f.Check(m.Service == "", "service", "A restart or shutdown takes no service name.")
	default:
		f.Check(serviceName.MatchString(m.Service), "service", "Enter the service's name: letters, digits and . _ @ : -, with no spaces.")
	}
}

func (m Maintenance) label() string {
	switch m.Action {
	case MaintRestart:
		return "Restart"
	case MaintShutdown:
		return "Shut down"
	case MaintServiceStart:
		return "Start service " + m.Service
	case MaintServiceStop:
		return "Stop service " + m.Service
	}
	return "Restart service " + m.Service
}

func (m Maintenance) args() []string {
	if m.Service == "" {
		return []string{m.Action}
	}
	return []string{m.Action, m.Service}
}

// ExpectedOffline is how long the device is expected to be offline once the
// action has succeeded: zero for the actions that keep it up.
func (m Maintenance) ExpectedOffline() time.Duration {
	switch m.Action {
	case MaintRestart:
		return ExpectedRestartOffline
	case MaintShutdown:
		return ExpectedShutdownOffline
	}
	return 0
}

// MaintenanceInput asks for a maintenance action on devices of one platform
// ("windows" or "linux").
type MaintenanceInput struct {
	DeviceIDs []uuid.UUID `json:"deviceIds"`
	Platform  string      `json:"platform"`
	Maintenance
	// WaitHours is how long to wait for an offline device; zero is the
	// default.
	WaitHours int `json:"waitHours"`
}

// CreateMaintenanceJob restarts or shuts down devices, or starts, stops or
// restarts a service on them. It runs as a job of one of EasyRMM's own
// scripts and needs script.run on every device: what it does a script run
// could do. Every device must pass every check, or nothing runs.
func (s *Service) CreateMaintenanceJob(ctx context.Context, c access.Caller, in MaintenanceInput) (*Job, error) {
	f := apperr.Fields{}
	ids := checkDevices(f, in.DeviceIDs)
	in.Check(f)
	shell, body := agentproto.ShellSh, maintLinuxScript
	switch in.Platform {
	case "linux":
	case "windows":
		shell, body = agentproto.ShellPowerShell, maintWindowsScript
	default:
		f.Add("platform", "Choose windows or linux.")
	}
	wait := checkWait(f, in.WaitHours)
	if err := f.Err(); err != nil {
		return nil, err
	}
	m := in.Maintenance
	sp := &spec{
		kind: KindMaintenance, maintenance: &m, name: m.label(), shell: shell, body: body, args: m.args(),
		timeout: DefaultMaintenanceTimeout, auditAction: "device.maintenance_action",
		details: map[string]any{"action": m.Action, "service": m.Service},
	}
	r := rule{perm: rbac.PermScriptRun, verb: "run maintenance actions", platforms: []string{in.Platform}, runsOn: "This action runs on",
		requires: agentproto.ShellRequires(shell), what: "maintenance actions"}
	return s.create(ctx, c, ids, wait, sp, func(ctx context.Context, tx pgx.Tx) ([]target, error) {
		return s.targets(ctx, tx, c, ids, r)
	})
}

// expectOffline records, for the device of a succeeded run, that it is
// expected to be offline for a while: the run was a restart or shutdown. It
// never shortens a longer expectation.
func (s *Service) expectOffline(ctx context.Context, tx pgx.Tx, device, job uuid.UUID) error {
	var action *string
	if err := tx.QueryRow(ctx, `SELECT maintenance->>'action' FROM jobs WHERE id = $1`, job).Scan(&action); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if action == nil {
		return nil
	}
	m := Maintenance{Action: *action}
	d := m.ExpectedOffline()
	if d == 0 {
		return nil
	}
	reason := "Scheduled restart."
	if m.Action == MaintShutdown {
		reason = "Scheduled shutdown."
	}
	_, err := tx.Exec(ctx, `INSERT INTO device_expected_offline (device_id, until_at, reason, job_id) VALUES ($1, $2, $3, $4)
		ON CONFLICT (device_id) DO UPDATE SET until_at = greatest(device_expected_offline.until_at, EXCLUDED.until_at),
		reason = EXCLUDED.reason, job_id = EXCLUDED.job_id`, device, s.now().Add(d), reason, job)
	return err
}
