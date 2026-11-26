// Package defender is the catalog of ADR-0074's Microsoft Defender
// actions. This slice holds the framework's proof action, defender.status.
package defender

import (
	_ "embed"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

//go:embed status.ps1
var statusScript string

// StatusSHA256 is the pinned hash of status.ps1. Changing the script means
// changing this line in review; a test and the catalog's build check it.
const StatusSHA256 = "fcbc0fd4d138da91ab1604a2d018da09cf025486e362468bc19749a2b2653d6b"

// Status is defender.status's result, in the shapes Get-MpComputerStatus
// shows: switches are true, false or null where the computer does not say.
type Status struct {
	AntivirusEnabled          *bool      `json:"antivirusEnabled"`
	AntispywareEnabled        *bool      `json:"antispywareEnabled"`
	RealTimeProtectionEnabled *bool      `json:"realTimeProtectionEnabled"`
	BehaviorMonitorEnabled    *bool      `json:"behaviorMonitorEnabled"`
	IoavProtectionEnabled     *bool      `json:"ioavProtectionEnabled"`
	OnAccessProtectionEnabled *bool      `json:"onAccessProtectionEnabled"`
	NISEnabled                *bool      `json:"nisEnabled"`
	TamperProtected           *bool      `json:"tamperProtected"`
	RunningMode               string     `json:"runningMode"`
	ComputerState             *int       `json:"computerState"`
	EngineVersion             string     `json:"engineVersion"`
	ProductVersion            string     `json:"productVersion"`
	ServiceVersion            string     `json:"serviceVersion"`
	SignatureVersion          string     `json:"signatureVersion"`
	SignatureUpdatedAt        *time.Time `json:"signatureUpdatedAt"`
	SignatureAgeDays          *int       `json:"signatureAgeDays"`
	QuickScanAgeDays          *int       `json:"quickScanAgeDays"`
	FullScanAgeDays           *int       `json:"fullScanAgeDays"`
}

// Actions are the Defender actions the server can run.
func Actions() []winmod.Action {
	return []winmod.Action{{
		Module: modules.Defender, Name: "defender.status", Label: "Read Defender's state", Version: 1,
		Script: statusScript, ScriptSHA256: StatusSHA256,
		Permission: rbac.PermDefenderView, Timeout: 60, Keep: time.Hour,
		Decode: winmod.Typed[Status](),
	}}
}
