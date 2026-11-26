package defender

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
)

// EventsAction is the name of the derived snapshot the event-driven alert
// kinds read (ADR-0074 section 7). It is not a job: the server recomputes it
// from defender_events when a batch arrives, and at least every half hour
// while the module is on, so the alert evaluator sees it like any snapshot.
const EventsAction = "defender.events"

// Event-driven alert kinds.
const (
	KindThreat            = "defender_threat"
	KindRemediationFailed = "defender_remediation_failed"
	KindUpdateFailed      = "defender_update_failed"
	KindConfigChanged     = "defender_config_changed"
	KindExclusionChanged  = "defender_exclusion_changed"
	KindTamperBlocked     = "defender_tamper_blocked"
	KindUnhealthy         = "defender_unhealthy"
	KindOutOfSupport      = "defender_out_of_support"
)

// How long a change, a block or a health event keeps its alert open when
// nothing resolves it (ADR-0074: manually, or after 7 days).
const (
	ChangeAlertFor    = 7 * 24 * time.Hour
	UnhealthyFor      = 24 * time.Hour
	OutOfSupportFor   = 3 * 24 * time.Hour
	EventsRefreshEach = 30 * time.Minute
)

// OpenThreat is a detection nothing has acted on yet.
type OpenThreat struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity int       `json:"severity"`
	At       time.Time `json:"at"`
}

// EventsState is what the event kinds judge: the unresolved facts of the
// Defender event log of one computer. EasyRMM's own changes (marked ours)
// and backfilled events older than an hour are left out when it is built.
type EventsState struct {
	AsOf time.Time `json:"asOf"`
	// Gap is when events may have been missed (a cleared or wrapped log).
	Gap                *time.Time   `json:"gap"`
	OpenThreats        []OpenThreat `json:"openThreats"`
	FailedRemediations []OpenThreat `json:"failedRemediations"`
	UpdateFailingSince *time.Time   `json:"updateFailingSince"`
	UnhealthyAt        *time.Time   `json:"unhealthyAt"`
	OutOfSupportAt     *time.Time   `json:"outOfSupportAt"`
	ConfigChangedAt    *time.Time   `json:"configChangedAt"`
	ExclusionChangedAt *time.Time   `json:"exclusionChangedAt"`
	TamperBlockedAt    *time.Time   `json:"tamperBlockedAt"`
}

func eventsState(data json.RawMessage) (EventsState, error) {
	var st EventsState
	if err := json.Unmarshal(data, &st); err != nil {
		return st, monitoring.ErrUnknown
	}
	return st, nil
}

func within(t *time.Time, d time.Duration) bool { return t != nil && time.Since(*t) < d }

func maxSeverity(ts []OpenThreat) (int, string) {
	best, name := 0, ""
	for _, t := range ts {
		if t.Severity >= best {
			best, name = t.Severity, t.Name
		}
	}
	return best, name
}

func names(ts []OpenThreat) string {
	out := ""
	for i, t := range ts {
		if i == 3 {
			out += fmt.Sprintf(" and %d more", len(ts)-3)
			break
		}
		if i > 0 {
			out += ", "
		}
		out += t.Name
	}
	return out
}

// EventKinds are the alert kinds read from the event log (ADR-0074 section 7).
// An alert is per policy and device, not per threat: the detail names the
// threats (amended 2026-11-26, decided in review).
func EventKinds() []monitoring.ModuleKind {
	severity := monitoring.ThresholdSpec{Used: true, Min: 1, Max: 5, Unit: "severity (1 Low, 2 Moderate, 4 High, 5 Severe)"}
	// An event-driven judgement does not depend on how fresh the derived snapshot is (the server refreshes it every half hour).
	kind := func(name, label string, eval func(EventsState, *int) (monitoring.Verdict, error)) monitoring.ModuleKind {
		k := monitoring.ModuleKind{Name: name, Label: label, Module: modules.Defender, Action: EventsAction}
		k.Eval = func(data json.RawMessage, threshold *int) (monitoring.Verdict, error) {
			st, err := eventsState(data)
			if err != nil {
				return monitoring.Verdict{}, err
			}
			return eval(st, threshold)
		}
		return k
	}
	timed := func(at *time.Time, d time.Duration, detail string) monitoring.Verdict {
		return monitoring.Verdict{Holds: within(at, d), Value: 1, Detail: detail}
	}
	threat := kind(KindThreat, "Defender found a threat", func(st EventsState, th *int) (monitoring.Verdict, error) {
		if th == nil {
			return monitoring.Verdict{}, monitoring.ErrUnknown
		}
		var hit []OpenThreat
		for _, t := range st.OpenThreats {
			if t.Severity >= *th {
				hit = append(hit, t)
			}
		}
		top, _ := maxSeverity(hit)
		return monitoring.Verdict{Holds: len(hit) > 0, Value: float64(top), Detail: "Defender found " + names(hit) + " and has not removed it."}, nil
	})
	threat.Threshold = severity
	failed := kind(KindRemediationFailed, "Defender could not remove a threat", func(st EventsState, _ *int) (monitoring.Verdict, error) {
		return monitoring.Verdict{Holds: len(st.FailedRemediations) > 0, Value: float64(len(st.FailedRemediations)),
			Detail: "Defender could not remove " + names(st.FailedRemediations) + "."}, nil
	})
	update := kind(KindUpdateFailed, "Defender signature update failing", func(st EventsState, _ *int) (monitoring.Verdict, error) {
		return monitoring.Verdict{Holds: st.UpdateFailingSince != nil, Value: 1, Detail: "Defender's signature update has failed and not succeeded since."}, nil
	})
	update.Grace = true
	return []monitoring.ModuleKind{
		threat, failed, update,
		kind(KindConfigChanged, "Defender protection settings changed", func(st EventsState, _ *int) (monitoring.Verdict, error) {
			return timed(st.ConfigChangedAt, ChangeAlertFor, "A Defender protection setting was changed, not by EasyRMM."), nil
		}),
		kind(KindExclusionChanged, "Defender exclusions changed", func(st EventsState, _ *int) (monitoring.Verdict, error) {
			return timed(st.ExclusionChangedAt, ChangeAlertFor, "A Defender exclusion was added or removed, not by EasyRMM."), nil
		}),
		kind(KindTamperBlocked, "Tamper Protection blocked a change", func(st EventsState, _ *int) (monitoring.Verdict, error) {
			return timed(st.TamperBlockedAt, ChangeAlertFor, "Tamper Protection blocked a change to Defender that EasyRMM did not make."), nil
		}),
		kind(KindUnhealthy, "Defender is not healthy", func(st EventsState, _ *int) (monitoring.Verdict, error) {
			return timed(st.UnhealthyAt, UnhealthyFor, "Defender reported that its real-time protection or engine failed."), nil
		}),
		kind(KindOutOfSupport, "Defender engine or platform out of support", func(st EventsState, _ *int) (monitoring.Verdict, error) {
			return timed(st.OutOfSupportAt, OutOfSupportFor, "Defender's platform is expiring or expired and needs an update."), nil
		}),
	}
}

// EventDefaults are the default policies of the event kinds (ADR-0074
// "Default policies"); with the four of alerts.go they are the thirteen.
func EventDefaults() []monitoring.DefaultPolicy {
	return []monitoring.DefaultPolicy{
		{Key: "threat_high", Name: "Defender: high or severe threat", Kind: KindThreat, Threshold: intp(4), Severity: monitoring.SeverityCritical, Enabled: true,
			Description: "Defender found a high or severe threat and has not removed it."},
		{Key: "threat_low", Name: "Defender: low or moderate threat", Kind: KindThreat, Threshold: intp(1), Severity: monitoring.SeverityWarning, Enabled: true,
			Description: "Defender found a threat of any severity and has not removed it. A high or severe one raises the critical policy instead."},
		{Key: "remediation_failed", Name: "Defender: threat not removed", Kind: KindRemediationFailed, Severity: monitoring.SeverityCritical, Enabled: true,
			Description: "Defender tried to remove a threat and could not."},
		{Key: "update_failed", Name: "Defender: signature update failing", Kind: KindUpdateFailed, Minutes: 240, Severity: monitoring.SeverityWarning, Enabled: true,
			Description: "A signature, engine or platform update failed and no update has succeeded since, for four hours."},
		{Key: "out_of_support", Name: "Defender: engine or platform out of support", Kind: KindOutOfSupport, Severity: monitoring.SeverityCritical, Enabled: true,
			Description: "Defender's platform is expiring or expired."},
		{Key: "unhealthy", Name: "Defender: not healthy", Kind: KindUnhealthy, Severity: monitoring.SeverityCritical, Enabled: true,
			Description: "Defender's real-time protection or engine failed."},
		{Key: "exclusion_changed", Name: "Defender: exclusions changed", Kind: KindExclusionChanged, Severity: monitoring.SeverityWarning, Enabled: true,
			Description: "An exclusion was added or removed by anyone but EasyRMM."},
		{Key: "tamper_blocked", Name: "Defender: Tamper Protection blocked a change", Kind: KindTamperBlocked, Severity: monitoring.SeverityWarning, Enabled: true,
			Description: "Tamper Protection blocked a change to Defender that EasyRMM did not make."},
		{Key: "config_changed", Name: "Defender: protection settings changed", Kind: KindConfigChanged, Severity: monitoring.SeverityWarning,
			Description: "A security-relevant Defender setting was changed by anyone but EasyRMM. Off by default: Defender writes many changes on its own."},
	}
}
