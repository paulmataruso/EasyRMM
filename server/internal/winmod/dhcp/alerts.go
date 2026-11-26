package dhcp

import (
	"encoding/json"
	"fmt"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/rolekit"
)

// The alert kinds of ADR-0076 section 5. All read the hourly snapshots of
// dhcp.status and dhcp.scope_list; no DHCP event is read (the event IDs are
// still to be confirmed on a test server, H1, and ADR-0076 allows no alert
// on them until then).
const (
	KindScopeExhausted = "dhcp_scope_exhausted"
	KindNotAuthorized  = "dhcp_not_authorized"
	KindServiceStopped = "dhcp_service_stopped"
)

// minScopeSize is the smallest scope a fullness alert applies to: a scope
// of a handful of addresses is always nearly full (ADR-0076).
const minScopeSize = 20

func statusOf(data json.RawMessage) (Status, error) {
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		return st, monitoring.ErrUnknown
	}
	return st, nil
}

// AlertKinds are the DHCP alerts monitoring registers.
func AlertKinds() monitoring.ModuleAlerts {
	return monitoring.ModuleAlerts{
		Module: modules.DHCP,
		Kinds: []monitoring.ModuleKind{{
			Name: KindScopeExhausted, Label: "DHCP scope nearly full", Module: modules.DHCP, Action: "dhcp.scope_list",
			Threshold: monitoring.ThresholdSpec{Used: true, Min: 50, Max: 100, Unit: "%"}, Grace: true,
			Eval: func(data json.RawMessage, threshold *int) (monitoring.Verdict, error) {
				var l ScopeList
				if err := json.Unmarshal(data, &l); err != nil || threshold == nil {
					return monitoring.Verdict{}, monitoring.ErrUnknown
				}
				worst, name := -1, ""
				for _, s := range l.Scopes {
					if s.State != "Active" || s.Free+s.InUse < minScopeSize {
						continue
					}
					if s.PercentageInUse > worst {
						worst, name = s.PercentageInUse, s.ScopeID
					}
				}
				if worst < 0 {
					return monitoring.Verdict{}, nil
				}
				return monitoring.Verdict{Holds: worst >= *threshold, Value: float64(worst),
					Detail: fmt.Sprintf("Scope %s is %d%% in use.", name, worst)}, nil
			},
		}, {
			Name: KindNotAuthorized, Label: "DHCP server not authorized", Module: modules.DHCP, Action: "dhcp.status",
			Eval: func(data json.RawMessage, _ *int) (monitoring.Verdict, error) {
				st, err := statusOf(data)
				switch {
				case err != nil:
					return monitoring.Verdict{}, err
				case st.DomainJoined != nil && !*st.DomainJoined:
					// A workgroup server needs no authorization.
					return monitoring.Verdict{NotApplicable: true}, nil
				case st.Authorized == nil:
					return monitoring.Verdict{}, monitoring.ErrUnknown
				}
				return monitoring.Verdict{Holds: !*st.Authorized, Value: 1,
					Detail: "This DHCP server is not authorized in Active Directory, so it does not serve clients."}, nil
			},
		},
			rolekit.ServiceStoppedKind(modules.DHCP, KindServiceStopped, "DHCP service stopped", "dhcp.status", func(data json.RawMessage) (string, error) {
				st, err := statusOf(data)
				return st.ServiceState, err
			}),
		},
		Defaults: []monitoring.DefaultPolicy{
			{Key: "scope_nearly_full", Name: "DHCP: scope nearly full", Kind: KindScopeExhausted, Threshold: intp(95), Minutes: 60, Severity: monitoring.SeverityWarning, Enabled: true,
				Description: "An active scope of at least 20 addresses has stayed at 95 percent or more in use for an hour."},
			{Key: "not_authorized", Name: "DHCP: not authorized", Kind: KindNotAuthorized, Severity: monitoring.SeverityWarning, Enabled: true,
				Description: "A DHCP server in a domain is not in the list authorized in Active Directory."},
			rolekit.ServiceStoppedDefault("service_stopped", "DHCP: service stopped", KindServiceStopped, 10, monitoring.SeverityCritical, true),
		},
	}
}

func intp(n int) *int { return &n }
