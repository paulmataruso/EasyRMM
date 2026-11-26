package dns

import (
	"encoding/json"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/rolekit"
)

// The alert kinds of ADR-0076 section 4 that dns.status's snapshot serves.
// dns_zone_deleted and dns_forwarders_changed read the DNS Server audit
// channel (events 513 and 537) through ADR-0068's reader and arrive with the
// events slice (D5); nothing here guesses them from a snapshot.
const KindServiceStopped = "dns_service_stopped"

func serviceState(data json.RawMessage) (string, error) {
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		return "", monitoring.ErrUnknown
	}
	return st.ServiceState, nil
}

// AlertKinds are the DNS alerts monitoring registers.
func AlertKinds() monitoring.ModuleAlerts {
	return monitoring.ModuleAlerts{
		Module: modules.DNS,
		Kinds: []monitoring.ModuleKind{
			rolekit.ServiceStoppedKind(modules.DNS, KindServiceStopped, "DNS service stopped", "dns.status", serviceState),
		},
		Defaults: []monitoring.DefaultPolicy{
			rolekit.ServiceStoppedDefault("service_stopped", "DNS: service stopped", KindServiceStopped, 10, monitoring.SeverityCritical, true),
		},
	}
}
