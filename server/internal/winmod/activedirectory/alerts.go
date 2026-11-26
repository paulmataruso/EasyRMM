package activedirectory

import (
	"encoding/json"
	"fmt"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
)

// KindReplicationFailed is ADR-0075 section 7's alert for a controller whose
// directory reports replication failures. It reads the hourly health_read
// snapshot. The lockout and privileged-group kinds come from the Security
// log events (ADR-0060's collector) and are not here yet.
const KindReplicationFailed = "ad_replication_failed"

// AlertKinds are the Active Directory alerts monitoring registers.
func AlertKinds() monitoring.ModuleAlerts {
	return monitoring.ModuleAlerts{
		Module: modules.ActiveDirectory,
		Kinds: []monitoring.ModuleKind{{
			Name: KindReplicationFailed, Label: "Directory replication failing", Module: modules.ActiveDirectory,
			Action: "active_directory.health_read",
			// The policy's minutes are how long the failure must have lasted,
			// on readings: a blip during a reboot does not alert.
			Grace: true,
			Eval:  evalReplication,
		}},
		Defaults: []monitoring.DefaultPolicy{{
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
