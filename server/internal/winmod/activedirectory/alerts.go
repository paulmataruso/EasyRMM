package activedirectory

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
)

// KindReplicationFailed is ADR-0075 section 7's alert for a controller whose
// directory reports replication failures. It reads the hourly health_read
// snapshot. The lockout and privileged-group kinds come from the Security
// log events (ADR-0060's collector) and are not here yet.
const KindReplicationFailed = "ad_replication_failed"

// KindAccountsLockedOut is "accounts are locked out now" and
// KindPrivilegedGroupChanged "a privileged group changed lately". Both read
// the controller's snapshots (health_read, privileged_members) instead of the
// Security log events of ADR-0075 section 7, so they need no log collection
// and no audit policy; they say the same thing a moment later.
const (
	KindAccountsLockedOut      = "ad_account_locked_out"
	KindPrivilegedGroupChanged = "ad_privileged_group_changed"
)

// AlertKinds are the Active Directory alerts monitoring registers.
func AlertKinds() monitoring.ModuleAlerts {
	count := monitoring.ThresholdSpec{Used: true, Min: 1, Max: 100, Unit: "accounts"}
	hours := monitoring.ThresholdSpec{Used: true, Min: 1, Max: 100, Unit: "hours"}
	return monitoring.ModuleAlerts{
		Module: modules.ActiveDirectory,
		Kinds: []monitoring.ModuleKind{{
			Name: KindAccountsLockedOut, Label: "Directory accounts locked out", Module: modules.ActiveDirectory,
			Action: "active_directory.health_read", Threshold: count, Grace: true, Eval: evalLockedOut,
		}, {
			Name: KindPrivilegedGroupChanged, Label: "Directory privileged group changed", Module: modules.ActiveDirectory,
			Action: "active_directory.privileged_members", Threshold: hours, Eval: evalPrivileged,
		}, {
			Name: KindReplicationFailed, Label: "Directory replication failing", Module: modules.ActiveDirectory,
			Action: "active_directory.health_read",
			// The policy's minutes are how long the failure must have lasted,
			// on readings: a blip during a reboot does not alert.
			Grace: true,
			Eval:  evalReplication,
		}},
		Defaults: []monitoring.DefaultPolicy{{
			Key: "many_locked_out", Name: "Directory: many accounts locked out", Kind: KindAccountsLockedOut, Threshold: intp(10), Minutes: 15,
			Severity: monitoring.SeverityWarning, Enabled: true,
			Description: "Ten or more accounts have been locked out for 15 minutes: a password spray or a service with a stale password.",
		}, {
			Key: "one_locked_out", Name: "Directory: an account locked out", Kind: KindAccountsLockedOut, Threshold: intp(1), Minutes: 60,
			Severity: monitoring.SeverityWarning, Enabled: false,
			Description: "Off by default: one lockout is a mistyped password, the commonest event in a directory.",
		}, {
			Key: "privileged_changed", Name: "Directory: Domain, Enterprise, Schema or built-in Administrators changed", Kind: KindPrivilegedGroupChanged,
			Threshold: intp(24), Severity: monitoring.SeverityCritical, Enabled: true,
			Description: "One of the four groups that hold the domain changed in the last 24 hours. The alert names the group, never the member.",
		}, {
			Key: "replication_failing", Name: "Directory: replication failing", Kind: KindReplicationFailed, Minutes: 120,
			Severity: monitoring.SeverityWarning, Enabled: true,
			Description: "The directory reports replication failures that have lasted the grace period. A single controller has no partners and never fails.",
		}},
	}
}

// evalReplication judges a health_read snapshot. A check that could not run
// is unknown, never healthy (ADR-0075 section 8).
func evalReplication(data json.RawMessage, _ *int) (monitoring.Verdict, error) {
	var h Health
	if err := json.Unmarshal(data, &h); err != nil {
		return monitoring.Verdict{}, monitoring.ErrUnknown
	}
	for _, c := range h.Checks {
		if c.Name != "replication" {
			continue
		}
		switch c.State {
		case "not_applicable":
			return monitoring.Verdict{NotApplicable: true}, nil
		case "ok", "warning", "critical":
			n := h.Replication.FailureCount
			return monitoring.Verdict{Holds: n > 0, Value: float64(n), Detail: fmt.Sprintf("The directory reports %d replication failure(s).", n)}, nil
		}
		return monitoring.Verdict{}, monitoring.ErrUnknown
	}
	return monitoring.Verdict{}, monitoring.ErrUnknown
}

func intp(n int) *int { return &n }

// evalLockedOut judges the count of locked-out accounts in a health_read
// snapshot; a count the controller could not give is unknown.
func evalLockedOut(data json.RawMessage, threshold *int) (monitoring.Verdict, error) {
	var h Health
	if err := json.Unmarshal(data, &h); err != nil || threshold == nil || h.LockedOutCount == nil {
		return monitoring.Verdict{}, monitoring.ErrUnknown
	}
	n := *h.LockedOutCount
	return monitoring.Verdict{Holds: n >= *threshold, Value: float64(n), Detail: fmt.Sprintf("%d accounts are locked out.", n)}, nil
}

// evalPrivileged holds while a tier 1 group (Domain, Enterprise and Schema
// Administrators, built-in Administrators) was changed within the threshold's
// hours: a group's change time moves when a member is added or removed. It
// names the group, not the member.
func evalPrivileged(data json.RawMessage, threshold *int) (monitoring.Verdict, error) {
	var p Privileged
	if err := json.Unmarshal(data, &p); err != nil || threshold == nil {
		return monitoring.Verdict{}, monitoring.ErrUnknown
	}
	limit := time.Now().Add(-time.Duration(*threshold) * time.Hour)
	var names []string
	for _, g := range p.Groups {
		if g.Tier == 1 && g.ChangedAt != nil && g.ChangedAt.After(limit) {
			names = append(names, g.Name)
		}
	}
	if len(names) == 0 {
		return monitoring.Verdict{Value: 0}, nil
	}
	return monitoring.Verdict{Holds: true, Value: float64(len(names)), Detail: fmt.Sprintf("Changed in the last %d hours: %s.", *threshold, strings.Join(names, ", "))}, nil
}
