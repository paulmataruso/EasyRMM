package fileshares

import (
	"encoding/json"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/rolekit"
)

// KindServiceStopped is ADR-0076's file_server_service_stopped. The kinds that
// need events (share_changed) and FSRM quotas (fsrm_quota_high) wait for the
// events slice and for slice F5.
const KindServiceStopped = "file_server_service_stopped"

// AlertKinds are the file-sharing alerts monitoring registers.
func AlertKinds() monitoring.ModuleAlerts {
	return monitoring.ModuleAlerts{
		Module: modules.FileShares,
		Kinds: []monitoring.ModuleKind{
			rolekit.ServiceStoppedKind(modules.FileShares, KindServiceStopped, "File server service stopped", "file_shares.status",
				func(data json.RawMessage) (string, error) {
					var st Status
					if err := json.Unmarshal(data, &st); err != nil {
						return "", monitoring.ErrUnknown
					}
					return st.ServiceState, nil
				}),
		},
		// Off by default (ADR-0076 section 9): routine on a busy estate.
		Defaults: []monitoring.DefaultPolicy{
			rolekit.ServiceStoppedDefault("service_stopped", "Files: server service stopped", KindServiceStopped, 15, monitoring.SeverityWarning, false),
		},
	}
}
