// Package dns is the catalog of ADR-0076's DNS Server module: reading the
// server's zones and records and changing them, with the protected-record
// and protected-zone lists enforced twice (here before a job exists, and in
// every script on the computer, which also knows whether a zone is in
// Active Directory).
package dns

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
		panic("dns: no script " + name)
	}
	return string(b)
}

// Status is dns.status's result. Where the DNS service is not running only
// the state is filled in.
type Status struct {
	ServiceState      string   `json:"serviceState"`
	ZoneCount         int      `json:"zoneCount"`
	ADIntegratedCount int      `json:"adIntegratedCount"`
	RecursionEnabled  *bool    `json:"recursionEnabled"`
	Forwarders        []string `json:"forwarders"`
	ListenAddresses   []string `json:"listenAddresses"`
	ScavengingHours   *int     `json:"scavengingHours"`
	// TransferAnyZones are the zones found transferring to any server,
	// which gives anyone the whole zone (ADR-0076 shows a warning).
	TransferAnyZones []string `json:"transferAnyZones"`
}

// Zone is one zone in dns.zone_list.
type Zone struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	ADIntegrated     bool   `json:"adIntegrated"`
	ReplicationScope string `json:"replicationScope"`
	DynamicUpdate    string `json:"dynamicUpdate"`
	Reverse          bool   `json:"reverse"`
	Paused           bool   `json:"paused"`
	Shutdown         bool   `json:"shutdown"`
	Signed           bool   `json:"signed"`
	AgingEnabled     bool   `json:"agingEnabled"`
}

// ZoneList is dns.zone_list's result.
type ZoneList struct {
	Zones     []Zone `json:"zones"`
	Truncated bool   `json:"truncated"`
}

// ZoneDetail is dns.zone_get's result: the zone and its transfer settings.
type ZoneDetail struct {
	Zone
	SecondaryServers []string `json:"secondaryServers"`
	NotifyServers    []string `json:"notifyServers"`
	Transfer         string   `json:"transfer"`
	Notify           string   `json:"notify"`
	ZoneFile         string   `json:"zoneFile"`
}

// Record is one resource record. Data is the canonical text the write
// actions take back: an address, a host name, "preference host" for MX,
// "priority weight port host" for SRV, the text for TXT.
type Record struct {
	Name      string  `json:"name"`
	Type      string  `json:"type"`
	TTL       int     `json:"ttl"`
	Data      string  `json:"data"`
	Timestamp *string `json:"timestamp"`
	Static    bool    `json:"static"`
}

// RecordList is one page of dns.record_list.
type RecordList struct {
	Total   int      `json:"total"`
	Offset  int      `json:"offset"`
	Next    *int     `json:"next"`
	Records []Record `json:"records"`
}

// Done is what a change answers: how many records or zones it changed.
type Done struct {
	Count int `json:"count"`
}

const (
	maxName = 253
	maxData = 300
)

var recordTypes = []string{"A", "AAAA", "CNAME", "PTR", "MX", "TXT", "SRV", "NS"}

func zoneParam() winmod.Param {
	return winmod.Param{Name: "zone", Type: winmod.Text, Required: true, Max: maxName}
}

func nameParam(required bool) winmod.Param {
	return winmod.Param{Name: "name", Type: winmod.Text, Required: required, Max: maxName}
}

func recordParams() []winmod.Param {
	return []winmod.Param{
		zoneParam(), nameParam(true),
		{Name: "type", Type: winmod.Enum, Required: true, Values: recordTypes},
		{Name: "data", Type: winmod.Text, Required: true, Max: maxData},
	}
}

func ttlParam(name string) winmod.Param {
	return winmod.Param{Name: name, Type: winmod.Int, Min: 1, Max: 604800}
}

func read[T any](name, label string, timeout int, params ...winmod.Param) winmod.Action {
	return winmod.Action{
		Module: modules.DNS, Name: "dns." + name, Label: label, Version: 1,
		Script: script(name), ScriptSHA256: pins[name], Permission: rbac.PermDNSView,
		Timeout: timeout, Keep: time.Hour, Params: params, Decode: winmod.Typed[T](),
	}
}

func write(name, label string, timeout int, params ...winmod.Param) winmod.Action {
	return winmod.Action{
		Module: modules.DNS, Name: "dns." + name, Label: label, Version: 1,
		Script: script(name), ScriptSHA256: pins[name], Permission: rbac.PermDNSManage,
		Timeout: timeout, Keep: 7 * 24 * time.Hour, Params: params, Decode: winmod.Typed[Done](),
		Changes: true,
	}
}

func destructive(a winmod.Action, subject string) winmod.Action {
	a.Destructive, a.Subject = true, subject
	return a
}

// Actions are the DNS actions the server can run: D1 (reads), D2 (records)
// and the zone half of D3 of ADR-0076. Tier 3 actions (removing every record
// of a name, removing a zone, allowing unauthenticated updates) are
// destructive: confirmed by name and behind a step-up. Dynamic update to
// "none" or "secure" is tier 2, and unauthenticated updates a tier-3
// action of their own, so a tier never depends on a value.
func Actions() []winmod.Action {
	status := read[Status]("status", "Read the DNS server's state", 60)
	// The service-stopped alert reads this snapshot hourly.
	status.Freshness, status.Schedule = 5*time.Minute, time.Hour
	zoneList := read[ZoneList]("zone_list", "List the DNS zones", 60)
	zoneList.Freshness = 5 * time.Minute

	recordList := read[RecordList]("record_list", "List the records of a zone", 90,
		zoneParam(), nameParam(false),
		winmod.Param{Name: "type", Type: winmod.Enum, Values: append([]string{"SOA"}, recordTypes...)},
		winmod.Param{Name: "offset", Type: winmod.Int, Min: 0, Max: 1000000})
	recordList.Check = guardRecordList

	add := write("record_add", "Add a DNS record", 30, append(recordParams(), ttlParam("ttl"))...)
	add.Check = guardRecord(false)
	set := write("record_set", "Change a DNS record", 30, append(recordParams(),
		winmod.Param{Name: "newData", Type: winmod.Text, Required: true, Max: maxData}, ttlParam("newTtl"))...)
	set.Check = guardRecord(true)
	remove := write("record_remove", "Remove a DNS record", 30, recordParams()...)
	remove.Check = guardRecord(false)
	removeAll := destructive(write("record_remove_all", "Remove every record of a name", 60, zoneParam(), nameParam(true)), "name")
	removeAll.Check = guardRemoveAll

	create := write("zone_create", "Create a DNS zone", 60, zoneParam(),
		winmod.Param{Name: "storage", Type: winmod.Enum, Required: true, Values: []string{"file", "ad_domain", "ad_forest", "ad_legacy"}},
		winmod.Param{Name: "dynamicUpdate", Type: winmod.Enum, Required: true, Values: []string{"None", "Secure"}})
	create.Check = guardZoneCreate
	removeZone := destructive(write("zone_remove", "Remove a DNS zone", 60, zoneParam()), "zone")
	removeZone.Check = guardZoneRemove
	setUpdate := write("zone_set_update", "Set a zone's dynamic updates", 30, zoneParam(),
		winmod.Param{Name: "mode", Type: winmod.Enum, Required: true, Values: []string{"None", "Secure"}})
	setUpdate.Check = guardZoneOnly
	nonsecure := destructive(write("zone_allow_nonsecure", "Allow unauthenticated dynamic updates", 30, zoneParam()), "zone")
	nonsecure.Check = guardZoneOnly

	zoneGet := read[ZoneDetail]("zone_get", "Read a DNS zone", 30, zoneParam())
	zoneGet.Check = guardZoneOnly

	return []winmod.Action{status, zoneList, zoneGet, recordList, add, set, remove, removeAll, create, removeZone, setUpdate, nonsecure}
}
