package printsrv

import (
	"encoding/json"
	"fmt"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/rolekit"
)

// ADR-0076 section 7's alert kinds. The PrintService event kinds wait for the
// real-server confirmation of the events (slice P1).
const (
	KindQueueStuck       = "print_queue_stuck"
	KindPointAndPrint    = "print_point_and_print_weakened"
	KindServiceStopped   = "print_service_stopped"
	stuckAfterMinutes    = 15
	stuckKindDescription = "A print queue has held jobs that do not move for the grace period."
)

// stuck says whether a printer's queue is stuck: not paused on purpose, at
// least threshold jobs, and its oldest job in an error or offline state or
// older than stuckAfterMinutes. The policy's minutes then say for how long the
// condition must have held on readings.
func stuck(p Printer, threshold int) bool {
	if p.Paused || p.JobCount < threshold || p.JobCount == 0 {
		return false
	}
	old := p.OldestJobAgeMinutes != nil && *p.OldestJobAgeMinutes >= stuckAfterMinutes
	return p.JobsInError > 0 || (p.Offline && p.JobCount > 0) || old
}

// AlertKinds are the print alerts monitoring registers.
func AlertKinds() monitoring.ModuleAlerts {
	return monitoring.ModuleAlerts{
		Module: modules.Print,
		Kinds: []monitoring.ModuleKind{{
			Name: KindQueueStuck, Label: "Print queue stuck", Module: modules.Print, Action: "print.printer_list", Grace: true,
			Threshold: monitoring.ThresholdSpec{Used: true, Min: 1, Max: 100, Unit: "jobs"},
			Eval: func(data json.RawMessage, threshold *int) (monitoring.Verdict, error) {
				var ps Printers
				if err := json.Unmarshal(data, &ps); err != nil || threshold == nil {
					return monitoring.Verdict{}, monitoring.ErrUnknown
				}
				n := 0
				for _, p := range ps.Printers {
					if stuck(p, *threshold) {
						n++
					}
				}
				return monitoring.Verdict{Holds: n > 0, Value: float64(n), Detail: fmt.Sprintf("%d print queue(s) are stuck.", n)}, nil
			},
		}, {
			Name: KindPointAndPrint, Label: "Point and Print weakened", Module: modules.Print, Action: "print.hardening_status",
			Eval: func(data json.RawMessage, _ *int) (monitoring.Verdict, error) {
				var h Hardening
				if err := json.Unmarshal(data, &h); err != nil {
					return monitoring.Verdict{}, monitoring.ErrUnknown
				}
				return monitoring.Verdict{Holds: h.Weakened, Value: 1,
					Detail: "Point and Print lets drivers install without administrator rights or warnings."}, nil
			},
		},
			rolekit.ServiceStoppedKind(modules.Print, KindServiceStopped, "Print Spooler stopped", "print.status",
				func(data json.RawMessage) (string, error) {
					var st Status
					if err := json.Unmarshal(data, &st); err != nil {
						return "", monitoring.ErrUnknown
					}
					return st.ServiceState, nil
				}),
		},
		Defaults: []monitoring.DefaultPolicy{
			{Key: "queue_stuck", Name: "Print: queue stuck", Kind: KindQueueStuck, Threshold: intp(1), Minutes: 60, Severity: monitoring.SeverityWarning, Enabled: true,
				Description: stuckKindDescription},
			{Key: "point_and_print", Name: "Print: Point and Print weakened", Kind: KindPointAndPrint, Severity: monitoring.SeverityCritical, Enabled: true,
				Description: "Driver installation no longer needs an administrator (a known attack route)."},
			rolekit.ServiceStoppedDefault("service_stopped", "Print: service stopped", KindServiceStopped, 15, monitoring.SeverityWarning, false),
		},
	}
}

func intp(n int) *int { return &n }
