// Package ntp is the catalog of the NTP/timezone configuration module:
// reading the time service and timezone state, changing the timezone, setting
// the NTP server, and forcing a time resync.
package ntp

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
		panic("ntp: no script " + name)
	}
	return string(b)
}

// Status is ntp.status's result.
type Status struct {
	Timezone  Timezone    `json:"timezone"`
	Service   ServiceInfo `json:"service"`
	Config    NTPConfig   `json:"config"`
	Peers     []Peer      `json:"peers"`
	SystemUTC string      `json:"systemTimeUtc"`
}

// Timezone describes the system's timezone.
type Timezone struct {
	ID           string `json:"id"`
	DisplayName  string `json:"displayName"`
	StandardName string `json:"standardName"`
	UTCOffset    string `json:"utcOffset"`
	DaylightName string `json:"daylightName"`
	SupportsDST  bool   `json:"supportsDst"`
	IsDST        bool   `json:"isDst"`
}

// ServiceInfo describes the Windows Time service.
type ServiceInfo struct {
	State         string  `json:"state"`
	Source        string  `json:"source"`
	LastSync      *string `json:"lastSync"`
	LastSyncError *string `json:"lastSyncError"`
}

// NTPConfig holds the registry-level NTP configuration.
type NTPConfig struct {
	NTPServer string `json:"ntpServer"`
	Type      string `json:"type"`
}

// Peer is one NTP peer.
type Peer struct {
	Name         string  `json:"name"`
	State        string  `json:"state"`
	LastSync     *string `json:"lastSync"`
	PollInterval int     `json:"pollInterval"`
}

// Changed is what a configuration change returns.
type Changed struct {
	Summary string `json:"summary"`
}

// SyncResult is what force_sync returns.
type SyncResult struct {
	Summary  string  `json:"summary"`
	Output   string  `json:"output"`
	Source   string  `json:"source"`
	LastSync *string `json:"lastSync"`
}

// Actions returns the NTP module's catalog entries.
func Actions() []winmod.Action {
	status := winmod.Action{
		Module: modules.NTP,
		Name:   "ntp.status", Label: "Read the time service and timezone", Version: 1,
		Script: script("status"), ScriptSHA256: pins["status"],
		Permission: rbac.PermDeviceView, Timeout: 60,
		Keep: time.Hour, Decode: winmod.Typed[Status](),
	}
	status.Freshness = 5 * time.Minute
	status.Schedule = time.Hour

	setTZ := winmod.Action{
		Module: modules.NTP,
		Name:   "ntp.set_timezone", Label: "Set the timezone", Version: 1,
		Script: script("set_timezone"), ScriptSHA256: pins["set_timezone"],
		Permission: rbac.PermDeviceConfigure, Timeout: 30, Changes: true,
		Keep: 7 * 24 * time.Hour, Decode: winmod.Typed[Changed](),
		Params: []winmod.Param{
			{Name: "timezoneId", Type: winmod.Text, Required: true, Min: 1, Max: 128},
		},
	}

	setNTP := winmod.Action{
		Module: modules.NTP,
		Name:   "ntp.set_ntp_server", Label: "Set the NTP server", Version: 1,
		Script: script("set_ntp_server"), ScriptSHA256: pins["set_ntp_server"],
		Permission: rbac.PermDeviceConfigure, Timeout: 30, Changes: true,
		Keep: 7 * 24 * time.Hour, Decode: winmod.Typed[Changed](),
		Params: []winmod.Param{
			{Name: "server", Type: winmod.Text, Required: true, Min: 1, Max: 253},
			{Name: "syncType", Type: winmod.Enum, Values: []string{"NTP", "NT5DS", "AllSync"}},
		},
	}

	forceSync := winmod.Action{
		Module: modules.NTP,
		Name:   "ntp.force_sync", Label: "Force a time resync", Version: 1,
		Script: script("force_sync"), ScriptSHA256: pins["force_sync"],
		Permission: rbac.PermDeviceConfigure, Timeout: 30, Changes: true,
		Keep: 7 * 24 * time.Hour, Decode: winmod.Typed[SyncResult](),
	}

	return []winmod.Action{status, setTZ, setNTP, forceSync}
}
