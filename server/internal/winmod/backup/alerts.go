package backup

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
)

// The alert kinds of ADR-0077 section 6 that backup.status can serve. Kinds
// that need Windows' backup event log (failures seen between two reads, a
// target not found at backup time, File History) and the workstation rules
// wait for the events slice and the real-run confirmation R1, so none of them
// is built here. backup_not_installed needs the role state, which the hourly
// read does not run for, so it waits too.
const (
	KindFailed        = "backup_failed"
	KindOverdue       = "backup_overdue"
	KindTargetMissing = "backup_target_missing"
	KindTargetLow     = "backup_target_low_space"
	KindNotConfigured = "backup_not_configured"
	KindStuck         = "backup_stuck"
)

// now is the clock of the stuck rule; tests replace it.
var now = time.Now

// snapshot reads the stored backup.status result. A computer without the
// feature has no backup to judge.
func snapshot(data json.RawMessage) (st Status, applicable bool, err error) {
	if err := json.Unmarshal(data, &st); err != nil {
		return st, false, monitoring.ErrUnknown
	}
	return st, st.Installed, nil
}

// hr writes an HRESULT the way Windows does.
func hr(v *int64) string {
	if v == nil {
		return "unknown"
	}
	return fmt.Sprintf("0x%08X", *v&0xFFFFFFFF)
}

// judge wraps a rule so that a computer without the feature, or without a
// policy, is not applicable, and a snapshot that cannot be read is unknown.
func judge(needPolicy bool, rule func(Status, *int) (monitoring.Verdict, error)) func(json.RawMessage, *int) (monitoring.Verdict, error) {
	return func(data json.RawMessage, threshold *int) (monitoring.Verdict, error) {
		st, ok, err := snapshot(data)
		switch {
		case err != nil:
			return monitoring.Verdict{}, err
		case !ok || (needPolicy && !st.Configured):
			return monitoring.Verdict{NotApplicable: true}, nil
		}
		return rule(st, threshold)
	}
}

// AlertKinds are the Windows Backup alerts monitoring registers.
func AlertKinds() monitoring.ModuleAlerts {
	const action = "windows_backup.status"
	return monitoring.ModuleAlerts{
		Module: modules.WindowsBackup,
		Kinds: []monitoring.ModuleKind{{
			Name: KindFailed, Label: "Last backup failed", Module: modules.WindowsBackup, Action: action,
			Eval: judge(true, func(st Status, _ *int) (monitoring.Verdict, error) {
				failed := st.LastFailure != nil && (st.LastSuccess == nil || st.LastFailure.After(*st.LastSuccess))
				return monitoring.Verdict{Holds: failed, Value: 1,
					Detail: "The last backup failed with " + hr(st.LastResultHR) + "."}, nil
			}),
		}, {
			Name: KindOverdue, Label: "No recent successful backup", Module: modules.WindowsBackup, Action: action,
			Threshold: monitoring.ThresholdSpec{Used: true, Min: 1, Max: 100, Unit: "days"},
			Eval: judge(true, func(st Status, threshold *int) (monitoring.Verdict, error) {
				switch {
				case threshold == nil:
					return monitoring.Verdict{}, monitoring.ErrUnknown
				case st.LastSuccessAgeDays == nil:
					return monitoring.Verdict{Holds: true, Value: float64(*threshold), Detail: "No successful backup is on record."}, nil
				}
				age := *st.LastSuccessAgeDays
				return monitoring.Verdict{Holds: age >= *threshold, Value: float64(age),
					Detail: fmt.Sprintf("The last successful backup was %d days ago.", age)}, nil
			}),
		}, {
			Name: KindTargetMissing, Label: "Backup target not found", Module: modules.WindowsBackup, Action: action, Grace: true,
			Eval: judge(true, func(st Status, _ *int) (monitoring.Verdict, error) {
				missing := 0
				for _, t := range st.Targets {
					if !t.Online {
						missing++
					}
				}
				return monitoring.Verdict{Holds: missing > 0, Value: float64(missing), Detail: "A backup target cannot be reached."}, nil
			}),
		}, {
			Name: KindTargetLow, Label: "Backup target nearly full", Module: modules.WindowsBackup, Action: action,
			Threshold: monitoring.ThresholdSpec{Used: true, Min: 1, Max: 90, Unit: "% free"},
			Eval: judge(true, func(st Status, threshold *int) (monitoring.Verdict, error) {
				if threshold == nil {
					return monitoring.Verdict{}, monitoring.ErrUnknown
				}
				lowest, known := 100.0, false
				for _, t := range st.Targets {
					if t.FreeBytes != nil && t.TotalBytes != nil && *t.TotalBytes > 0 {
						known = true
						lowest = min(lowest, 100*float64(*t.FreeBytes)/float64(*t.TotalBytes))
					}
				}
				if !known {
					return monitoring.Verdict{}, monitoring.ErrUnknown
				}
				return monitoring.Verdict{Holds: lowest < float64(*threshold), Value: lowest,
					Detail: fmt.Sprintf("A backup target has %.0f%% free.", lowest)}, nil
			}),
		}, {
			Name: KindNotConfigured, Label: "Backup not configured", Module: modules.WindowsBackup, Action: action, Grace: true,
			Eval: judge(false, func(st Status, _ *int) (monitoring.Verdict, error) {
				return monitoring.Verdict{Holds: !st.Configured, Value: 1, Detail: "Windows Server Backup is installed but has no policy."}, nil
			}),
		}, {
			Name: KindStuck, Label: "Backup running too long", Module: modules.WindowsBackup, Action: action,
			Threshold: monitoring.ThresholdSpec{Used: true, Min: 1, Max: 100, Unit: "hours"},
			Eval: judge(false, func(st Status, threshold *int) (monitoring.Verdict, error) {
				if threshold == nil {
					return monitoring.Verdict{}, monitoring.ErrUnknown
				}
				if !st.Running || st.Job == nil || st.Job.StartTime == nil {
					return monitoring.Verdict{Value: 0}, nil
				}
				hours := now().Sub(*st.Job.StartTime).Hours()
				return monitoring.Verdict{Holds: hours >= float64(*threshold), Value: hours,
					Detail: fmt.Sprintf("A backup job has been running for %.0f hours.", hours)}, nil
			}),
		}},
		// ADR-0077's server rules that backup.status serves. "Not
		// configured" starts off: many customers back servers up with
		// another product.
		Defaults: []monitoring.DefaultPolicy{
			{Key: "failed", Name: "Backup: last backup failed", Kind: KindFailed, Severity: monitoring.SeverityCritical, Enabled: true,
				Description: "The last Windows Server Backup run failed and no success has followed."},
			{Key: "target_missing", Name: "Backup: target not found", Kind: KindTargetMissing, Minutes: 60, Severity: monitoring.SeverityCritical, Enabled: true,
				Description: "A backup target has been offline or missing for an hour."},
			{Key: "overdue_2", Name: "Backup: no successful backup in 2 days", Kind: KindOverdue, Threshold: intp(2), Severity: monitoring.SeverityWarning, Enabled: true,
				Description: "No Windows Server Backup run has succeeded for 2 days."},
			{Key: "low_space_10", Name: "Backup: target nearly full (under 10% free)", Kind: KindTargetLow, Threshold: intp(10), Severity: monitoring.SeverityWarning, Enabled: true,
				Description: "A backup target has under 10% free space."},
			{Key: "stuck_12h", Name: "Backup: running too long", Kind: KindStuck, Threshold: intp(12), Severity: monitoring.SeverityWarning, Enabled: true,
				Description: "A backup job has been running for more than 12 hours."},
			{Key: "not_configured", Name: "Backup: not configured on a server", Kind: KindNotConfigured, Minutes: 1440, Severity: monitoring.SeverityWarning,
				Description: "Windows Server Backup is installed with no policy for a day. Off by default: servers backed up by another product would alert."},
		},
	}
}

func intp(n int) *int { return &n }
