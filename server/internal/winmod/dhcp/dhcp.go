// Package dhcp is the catalog of ADR-0076's DHCP Server module: scopes,
// exclusions, reservations, options and leases for IPv4. Authorization in
// Active Directory is read only, a new scope is created inactive, and the
// options every client acts on (the gateway and the DNS servers) are tier 3.
package dhcp

import (
	"embed"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

//go:embed scripts/*.ps1
var scripts embed.FS

func script(name string) string {
	b, err := scripts.ReadFile("scripts/" + name + ".ps1")
	if err != nil {
		panic("dhcp: no script " + name)
	}
	return string(b)
}

// Binding is an interface the server listens on.
type Binding struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
	Enabled   bool   `json:"enabled"`
}

// Status is dhcp.status's result. Authorized is null on a computer that is
// not in a domain (a workgroup server needs no authorization) and where the
// service is not running.
type Status struct {
	ServiceState              string    `json:"serviceState"`
	DomainJoined              *bool     `json:"domainJoined"`
	Authorized                *bool     `json:"authorized"`
	ConflictDetectionAttempts *int      `json:"conflictDetectionAttempts"`
	Bindings                  []Binding `json:"bindings"`
	ScopeCount                int       `json:"scopeCount"`
	ActiveScopeCount          int       `json:"activeScopeCount"`
}

// Scope is an IPv4 scope with its fill.
type Scope struct {
	ScopeID              string `json:"scopeId"`
	Name                 string `json:"name"`
	Description          string `json:"description"`
	State                string `json:"state"`
	StartRange           string `json:"startRange"`
	EndRange             string `json:"endRange"`
	SubnetMask           string `json:"subnetMask"`
	LeaseDurationSeconds int64  `json:"leaseDurationSeconds"`
	Free                 int64  `json:"free"`
	InUse                int64  `json:"inUse"`
	PercentageInUse      int    `json:"percentageInUse"`
}

// ScopeList is dhcp.scope_list's result.
type ScopeList struct {
	Scopes    []Scope `json:"scopes"`
	Truncated bool    `json:"truncated"`
}

// Exclusion is an excluded range.
type Exclusion struct {
	StartRange string `json:"startRange"`
	EndRange   string `json:"endRange"`
}

// Exclusions is dhcp.exclusion_list's result.
type Exclusions struct {
	Exclusions []Exclusion `json:"exclusions"`
}

// Reservation fixes an address for a client.
type Reservation struct {
	IPAddress   string `json:"ipAddress"`
	ClientID    string `json:"clientId"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Reservations is dhcp.reservation_list's result.
type Reservations struct {
	Reservations []Reservation `json:"reservations"`
}

// Option is one option value, at the server or in a scope.
type Option struct {
	OptionID int      `json:"optionId"`
	Name     string   `json:"name"`
	Value    []string `json:"value"`
}

// Options is dhcp.option_list's result.
type Options struct {
	Options []Option `json:"options"`
}

// Lease is one lease. It names a device and, through its host name, often a
// person, so the action is Sensitive.
type Lease struct {
	IPAddress string  `json:"ipAddress"`
	ClientID  string  `json:"clientId"`
	HostName  string  `json:"hostName"`
	State     string  `json:"state"`
	Expires   *string `json:"expires"`
}

// Leases is one page of dhcp.lease_list.
type Leases struct {
	Total  int     `json:"total"`
	Offset int     `json:"offset"`
	Next   *int    `json:"next"`
	Leases []Lease `json:"leases"`
}

// Done is what a change answers.
type Done struct {
	Count int `json:"count"`
}

// LeaseKeep is how long a lease page is kept (ADR-0076: 15 minutes).
const LeaseKeep = 15 * time.Minute

func scopeParam() winmod.Param {
	return winmod.Param{Name: "scopeId", Type: winmod.Text, Required: true, Min: 7, Max: 15}
}

func ipParam(name string) winmod.Param {
	return winmod.Param{Name: name, Type: winmod.Text, Required: true, Min: 7, Max: 15}
}

func read[T any](name, label string, timeout int, params ...winmod.Param) winmod.Action {
	return winmod.Action{
		Module: modules.DHCP, Name: "dhcp." + name, Label: label, Version: 1,
		Script: script(name), ScriptSHA256: pins[name], Permission: rbac.PermDHCPView,
		Timeout: timeout, Keep: time.Hour, Params: params, Decode: winmod.Typed[T](),
	}
}

func write(name, label string, timeout int, params ...winmod.Param) winmod.Action {
	return winmod.Action{
		Module: modules.DHCP, Name: "dhcp." + name, Label: label, Version: 1,
		Script: script(name), ScriptSHA256: pins[name], Permission: rbac.PermDHCPManage,
		Timeout: timeout, Keep: 7 * 24 * time.Hour, Params: params, Decode: winmod.Typed[Done](),
		Changes: true,
	}
}

func destructive(a winmod.Action, subject string) winmod.Action {
	a.Destructive, a.Subject = true, subject
	return a
}

func with(a winmod.Action, guard func(map[string]any) error) winmod.Action {
	a.Check = guard
	return a
}

func textParam(name string, max int) winmod.Param {
	return winmod.Param{Name: name, Type: winmod.Text, Max: max}
}

func leaseHours(required bool) winmod.Param {
	return winmod.Param{Name: "leaseHours", Type: winmod.Int, Required: required, Min: 1, Max: 8760}
}

// Actions are the DHCP actions the server can run: H1 to H4 of ADR-0076
// except failover. The tier-3 rule for options 3 and 6 is two actions, not a
// value test: option_set refuses those options and option_set_network takes
// only them, behind a step-up, at every level. (ADR-0076 made it tier 3
// only at server level and on a busy scope; the split is stricter.)
func Actions() []winmod.Action {
	status := read[Status]("status", "Read the DHCP server's state", 60)
	// The not-authorized and service-stopped alerts read this snapshot hourly.
	status.Freshness, status.Schedule = 5*time.Minute, time.Hour
	scopeList := read[ScopeList]("scope_list", "List the DHCP scopes", 60)
	// The scope-nearly-full alert reads the fill from this snapshot hourly.
	scopeList.Freshness, scopeList.Schedule = 5*time.Minute, time.Hour

	leaseList := with(read[Leases]("lease_list", "List the DHCP leases", 90, scopeParam(),
		winmod.Param{Name: "offset", Type: winmod.Int, Min: 0, Max: 1000000},
		winmod.Param{Name: "state", Type: winmod.Enum, Values: []string{"Active", "ActiveReservation", "InactiveReservation", "Declined", "Expired", "Offered"}}), guardScope)
	leaseList.Sensitive, leaseList.SensitivePermission, leaseList.Keep = true, rbac.PermDHCPManage, LeaseKeep

	optionList := with(read[Options]("option_list", "List the DHCP options", 30,
		winmod.Param{Name: "scopeId", Type: winmod.Text, Min: 6, Max: 15}), guardOptionScope(false))

	create := with(write("scope_create", "Create a DHCP scope", 60,
		winmod.Param{Name: "name", Type: winmod.Text, Required: true, Max: 100}, winmod.Param{Name: "startRange", Type: winmod.Text, Required: true, Min: 7, Max: 15},
		winmod.Param{Name: "endRange", Type: winmod.Text, Required: true, Min: 7, Max: 15},
		winmod.Param{Name: "subnetMask", Type: winmod.Text, Required: true, Min: 7, Max: 15}, leaseHours(true)), guardScopeCreate)

	set := with(write("scope_set", "Change a DHCP scope", 30, scopeParam(), textParam("name", 100), textParam("description", 200), leaseHours(false)), guardScopeSet)
	rng := func(name, label string) winmod.Action {
		return with(write(name, label, 30, scopeParam(), ipParam("startRange"), ipParam("endRange")), guardRange)
	}
	resv := func(name, label string) winmod.Action {
		return with(write(name, label, 30, scopeParam(), ipParam("ipAddress"),
			winmod.Param{Name: "clientId", Type: winmod.Text, Required: true, Min: 12, Max: 17}, textParam("name", 100), textParam("description", 200)), guardReservation)
	}
	optParams := []winmod.Param{
		{Name: "scopeId", Type: winmod.Text, Required: true, Min: 6, Max: 15},
		{Name: "optionId", Type: winmod.Int, Required: true, Min: 1, Max: 255},
		{Name: "value", Type: winmod.Text, Required: true, Max: 200},
	}
	optionSet := with(write("option_set", "Set a DHCP option", 30, optParams...), guardOption(false))
	optionNetwork := with(destructive(write("option_set_network", "Set the gateway or DNS servers clients receive", 30, optParams...), "scopeId"), guardOption(true))
	ipAct := func(name, label string) winmod.Action {
		return with(write(name, label, 30, scopeParam(), ipParam("ipAddress")), guardScopeAndIP)
	}

	return []winmod.Action{
		status, scopeList,
		with(read[Scope]("scope_get", "Read a DHCP scope", 60, scopeParam()), guardScope),
		with(read[Exclusions]("exclusion_list", "List the exclusion ranges", 30, scopeParam()), guardScope),
		with(read[Reservations]("reservation_list", "List the reservations", 30, scopeParam()), guardScope),
		optionList, leaseList,
		create, set,
		with(write("scope_activate", "Activate a DHCP scope", 30, scopeParam()), guardScope),
		with(destructive(write("scope_deactivate", "Deactivate a DHCP scope", 30, scopeParam()), "scopeId"), guardScope),
		with(destructive(write("scope_remove", "Remove a DHCP scope", 60, scopeParam()), "scopeId"), guardScope),
		rng("exclusion_add", "Exclude a range"), rng("exclusion_remove", "Remove an exclusion"),
		resv("reservation_add", "Add a reservation"), resv("reservation_set", "Change a reservation"),
		ipAct("reservation_remove", "Remove a reservation"),
		optionSet, optionNetwork,
		ipAct("lease_remove", "Remove a lease"), ipAct("lease_to_reservation", "Make a lease a reservation"),
	}
}
