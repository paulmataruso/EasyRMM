// Package roles gathers the server-role modules of ADR-0076 for app.go, so
// wiring a role is one line here and the wiring in app.go never changes.
package roles

import (
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/certauth"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/dhcp"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/dns"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/fileshares"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/printsrv"
)

// Actions are every role's catalog entries.
func Actions() []winmod.Action {
	var all []winmod.Action
	for _, a := range [][]winmod.Action{
		dns.Actions(),
		dhcp.Actions(),
		certauth.Actions(),
		fileshares.Actions(),
		printsrv.Actions(),
	} {
		all = append(all, a...)
	}
	return all
}

// Alerts are every role's alert kinds and default policies.
func Alerts() []monitoring.ModuleAlerts {
	return []monitoring.ModuleAlerts{
		dns.AlertKinds(),
		dhcp.AlertKinds(),
		certauth.AlertKinds(),
		fileshares.AlertKinds(),
		printsrv.AlertKinds(),
	}
}

// Register registers every role's alerts with monitoring.
func Register() error {
	for _, a := range Alerts() {
		if err := monitoring.RegisterModuleAlerts(a); err != nil {
			return err
		}
	}
	return nil
}
