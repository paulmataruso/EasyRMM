// Package laps is the catalog of the LAPS (Local Administrator Password
// Solution) module: reading whether Windows LAPS or legacy LAPS is
// configured, the admin account state, the AD password expiry, and
// triggering a password rotation.
package laps

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
		panic("laps: no script " + name)
	}
	return string(b)
}

// Status is laps.status's result.
type Status struct {
	WindowsLAPS      bool          `json:"windowsLaps"`
	LegacyLAPS       bool          `json:"legacyLaps"`
	DomainJoined     bool          `json:"domainJoined"`
	Policy           any           `json:"policy"`
	AdminAccount     *AdminAccount `json:"adminAccount"`
	ADPasswordExpiry *string       `json:"adPasswordExpiry"`
}

// AdminAccount describes the local administrator account.
type AdminAccount struct {
	Name            string  `json:"name"`
	Enabled         bool    `json:"enabled"`
	LastLogon       *string `json:"lastLogon"`
	PasswordLastSet *string `json:"passwordLastSet"`
	PasswordExpires *string `json:"passwordExpires"`
}

// Changed is what a configuration change returns.
type Changed struct {
	Summary string `json:"summary"`
}

// Actions returns the LAPS module's catalog entries.
func Actions() []winmod.Action {
	status := winmod.Action{
		Module: modules.LAPS,
		Name: "laps.status", Label: "Read the LAPS configuration", Version: 1,
		Script: script("status"), ScriptSHA256: pins["status"],
		Permission: rbac.PermDeviceView, Timeout: 60,
		Keep: time.Hour, Decode: winmod.Typed[Status](),
	}
	status.Freshness = 5 * time.Minute
	status.Schedule = time.Hour

	configure := winmod.Action{
		Module: modules.LAPS,
		Name: "laps.configure", Label: "Configure Windows LAPS policy", Version: 1,
		Script: script("configure"), ScriptSHA256: pins["configure"],
		Permission: rbac.PermDeviceConfigure, Timeout: 60, Changes: true,
		Keep: 7 * 24 * time.Hour, Decode: winmod.Typed[Changed](),
		Params: []winmod.Param{
			{Name: "backupDirectory", Type: winmod.Enum, Required: true, Values: []string{"1", "2"}},
			{Name: "passwordAgeDays", Type: winmod.Int, Min: 1, Max: 365},
			{Name: "passwordLength", Type: winmod.Int, Min: 8, Max: 64},
			{Name: "passwordComplexity", Type: winmod.Enum, Values: []string{"1", "2", "3", "4"}},
			{Name: "administratorAccountName", Type: winmod.Text, Max: 64, AllowEmpty: true},
			{Name: "passwordExpirationProtectionEnabled", Type: winmod.Enum, Values: []string{"0", "1"}},
			{Name: "adPasswordEncryptionEnabled", Type: winmod.Enum, Values: []string{"0", "1"}},
			{Name: "adPasswordEncryptionPrincipal", Type: winmod.Text, Max: 256, AllowEmpty: true},
			{Name: "postAuthenticationResetDelay", Type: winmod.Int, Min: 0, Max: 720},
			{Name: "postAuthenticationActions", Type: winmod.Enum, Values: []string{"1", "3", "5"}},
		},
	}

	resetPw := winmod.Action{
		Module: modules.LAPS,
		Name: "laps.reset_password", Label: "Trigger a LAPS password rotation", Version: 1,
		Script: script("reset_password"), ScriptSHA256: pins["reset_password"],
		Permission: rbac.PermDeviceConfigure, Timeout: 120, Changes: true,
		Keep: 7 * 24 * time.Hour, Decode: winmod.Typed[Changed](),
	}

	return []winmod.Action{status, configure, resetPw}
}
