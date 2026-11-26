package defender

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
)

// The alert kinds of ADR-0074 section 7 that need only defender.status's
// data. The kinds that come from the Defender event log (threats, failed
// remediation, update failures, configuration changes, tamper blocks,
// unhealthy, out of support) arrive with the events slice.
const (
	KindProtectionOff = "defender_protection_off"
	KindSignaturesOld = "defender_signatures_old"
	KindTamperOff     = "defender_tamper_off"
	KindScanOverdue   = "defender_scan_overdue"
)

// statusSnapshot reads the stored defender.status result. A Defender in
// passive mode is not the active antivirus, so the kinds that depend on an
// active Defender do not apply there (ADR-0074 "Not applicable").
func statusSnapshot(data json.RawMessage) (st Status, passive bool, err error) {
	if err := json.Unmarshal(data, &st); err != nil {
		return st, false, monitoring.ErrUnknown
	}
	return st, strings.Contains(strings.ToLower(st.RunningMode), "passive"), nil
}

// AlertKinds are the Defender alerts monitoring registers.
func AlertKinds() monitoring.ModuleAlerts {
	days := monitoring.ThresholdSpec{Used: true, Min: 1, Max: 100, Unit: "days"}
	return monitoring.ModuleAlerts{
		Module: modules.Defender,
		Kinds: []monitoring.ModuleKind{{
			Name: KindProtectionOff, Label: "Defender real-time protection off", Module: modules.Defender, Action: "defender.status",
			Grace: true,
			Eval: func(data json.RawMessage, _ *int) (monitoring.Verdict, error) {
				st, passive, err := statusSnapshot(data)
				switch {
				case err != nil:
					return monitoring.Verdict{}, err
				case passive:
					return monitoring.Verdict{NotApplicable: true}, nil
				case st.RealTimeProtectionEnabled == nil:
					return monitoring.Verdict{}, monitoring.ErrUnknown
				}
				return monitoring.Verdict{Holds: !*st.RealTimeProtectionEnabled, Value: 1, Detail: "Real-time protection is off."}, nil
			},
		}, {
			Name: KindSignaturesOld, Label: "Defender signatures out of date", Module: modules.Defender, Action: "defender.status",
			Threshold: days,
			Eval: func(data json.RawMessage, threshold *int) (monitoring.Verdict, error) {
				st, passive, err := statusSnapshot(data)
				switch {
				case err != nil || threshold == nil:
					return monitoring.Verdict{}, monitoring.ErrUnknown
				case passive:
					return monitoring.Verdict{NotApplicable: true}, nil
				case st.SignatureAgeDays == nil:
					return monitoring.Verdict{}, monitoring.ErrUnknown
				}
				age := *st.SignatureAgeDays
				return monitoring.Verdict{Holds: age >= *threshold, Value: float64(age), Detail: fmt.Sprintf("Signatures are %d days old.", age)}, nil
			},
		}, {
			Name: KindTamperOff, Label: "Defender Tamper Protection off", Module: modules.Defender, Action: "defender.status",
			Eval: func(data json.RawMessage, _ *int) (monitoring.Verdict, error) {
				st, passive, err := statusSnapshot(data)
				switch {
				case err != nil:
					return monitoring.Verdict{}, err
				case passive:
					return monitoring.Verdict{NotApplicable: true}, nil
				case st.TamperProtected == nil:
					return monitoring.Verdict{}, monitoring.ErrUnknown
				}
				return monitoring.Verdict{Holds: !*st.TamperProtected, Value: 1, Detail: "Tamper Protection is off."}, nil
			},
		}, {
			Name: KindScanOverdue, Label: "Defender no recent scan", Module: modules.Defender, Action: "defender.status",
			Threshold: days,
			Eval: func(data json.RawMessage, threshold *int) (monitoring.Verdict, error) {
				st, passive, err := statusSnapshot(data)
				switch {
				case err != nil || threshold == nil:
					return monitoring.Verdict{}, monitoring.ErrUnknown
				case passive:
					return monitoring.Verdict{NotApplicable: true}, nil
				case st.QuickScanAgeDays == nil:
					// Never run counts as overdue.
					return monitoring.Verdict{Holds: true, Value: float64(*threshold), Detail: "No quick scan has run."}, nil
				}
				age := *st.QuickScanAgeDays
				return monitoring.Verdict{Holds: age >= *threshold, Value: float64(age), Detail: fmt.Sprintf("The last quick scan was %d days ago.", age)}, nil
			},
		}},
		// Three of ADR-0074's defaults wait for their event kinds; these are
		// the ones defender.status serves. The age rules start off.
		Defaults: []monitoring.DefaultPolicy{
			{Key: "protection_off", Name: "Defender: real-time protection off", Kind: KindProtectionOff, Minutes: 5, Severity: monitoring.SeverityCritical, Enabled: true,
				Description: "Defender's real-time protection has been off for the grace period."},
			{Key: "tamper_off", Name: "Defender: Tamper Protection off", Kind: KindTamperOff, Severity: monitoring.SeverityWarning, Enabled: true,
				Description: "Tamper Protection reads off on a computer where Defender is the active antivirus."},
			{Key: "signatures_old_7", Name: "Defender: signatures out of date (7 days)", Kind: KindSignaturesOld, Threshold: intp(7), Severity: monitoring.SeverityWarning,
				Description: "Defender's signatures are at least 7 days old. Off by default: computers that are switched off for a week would alert."},
			{Key: "scan_overdue_7", Name: "Defender: no recent scan", Kind: KindScanOverdue, Threshold: intp(7), Severity: monitoring.SeverityWarning,
				Description: "No quick scan has run for 7 days. Off by default, like the signature age rule."},
		},
	}
}

func intp(n int) *int { return &n }
