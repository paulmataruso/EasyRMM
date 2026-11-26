// Package defender is the catalog of ADR-0074's Microsoft Defender
// actions: the state reads, scans, signature updates, threats and
// quarantine, preferences, Attack Surface Reduction, Controlled Folder
// Access and exclusions, each a pinned script with typed parameters.
package defender

import (
	"embed"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

//go:embed status.ps1
var statusScript string

//go:embed *.ps1
var scriptFS embed.FS

// scriptText is the embedded script of an action ("scan_quick" is scan_quick.ps1).
func scriptText(name string) string {
	b, err := scriptFS.ReadFile(name + ".ps1")
	if err != nil {
		panic("defender: no script " + name)
	}
	return string(b)
}

// StatusSHA256 is the pinned hash of status.ps1. Changing the script means
// changing this line in review; a test and the catalog's build check it.
const StatusSHA256 = "ece7a930a128e323d61d1eb05b6ee75f5730931aaccdcfbccbf33eeb4169f9cc"

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

// The risk tiers of ADR-0074 section 3, as the framework expresses them:
//
//	tier 0 read:    Permission view (view_sensitive opens a sensitive result)
//	tier 1 routine: Permission manage
//	tier 2 change:  Permission manage, Confirm
//	tier 3 weaken:  Permission weaken, Destructive (confirmation and a step-up)
//
// Only Site Administrators and above hold weaken, and they also hold manage
// (a test checks it), so one permission on a tier 3 action means "manage and
// weaken". Each read result is kept for ten minutes when it is sensitive and
// an hour otherwise; a change is kept seven days.
const (
	keepRead      = time.Hour
	keepSensitive = 10 * time.Minute
	keepChange    = 7 * 24 * time.Hour
	freshFor      = 5 * time.Minute
)

func read(name, label string, timeout int, decode func(json.RawMessage) (json.RawMessage, error), sensitive bool) winmod.Action {
	a := winmod.Action{
		Module: modules.Defender, Name: "defender." + name, Label: label, Version: 1,
		Script: scriptText(name), ScriptSHA256: scriptPins[name],
		Permission: rbac.PermDefenderView, Timeout: timeout, Keep: keepRead, Freshness: freshFor, Decode: decode,
	}
	if sensitive {
		a.Sensitive, a.SensitivePermission, a.Keep = true, rbac.PermDefenderViewSensitive, keepSensitive
	}
	return a
}

// change is a write: tier 1 unless it is made a confirmed (tier 2) or
// weakening (tier 3) action by the helpers below.
func change(name, label string, timeout int, params []winmod.Param, decode func(json.RawMessage) (json.RawMessage, error)) winmod.Action {
	return winmod.Action{
		Module: modules.Defender, Name: "defender." + name, Label: label, Version: 1,
		Script: scriptText(name), ScriptSHA256: scriptPins[name],
		Permission: rbac.PermDefenderManage, Timeout: timeout, Keep: keepChange, Params: params, Decode: decode, Changes: true,
	}
}

func confirmed(a winmod.Action, subject string) winmod.Action {
	a.Confirm, a.Subject = true, subject
	return a
}

// deviceNamed makes the confirmation the computer's own name, which the server compares with the real one.
func deviceNamed(a winmod.Action) winmod.Action {
	a.SubjectIsDeviceName = true
	return a
}

func weakening(a winmod.Action, subject string) winmod.Action {
	a.Permission, a.Destructive, a.Subject = rbac.PermDefenderWeaken, true, subject
	return a
}

func checked(a winmod.Action, check func(map[string]any) error) winmod.Action {
	a.Check = check
	return a
}

func values(vs ...string) []string { return vs }

// Actions are the Defender actions the server can run.
func Actions() []winmod.Action {
	secs := func(d time.Duration) int { return int(d.Seconds()) }
	changeT := winmod.Typed[Change]()
	prefParams := []winmod.Param{
		{Name: "field", Type: winmod.Name, Required: true, Max: 64},
		{Name: "value", Type: winmod.Text, Required: true, Max: 32},
	}
	exclusionKind := winmod.Param{Name: "kind", Type: winmod.Enum, Required: true, Values: ExclusionKinds}
	exclusionValue := winmod.Param{Name: "value", Type: winmod.Text, Required: true, Max: 260, Sensitive: true}
	asrParams := func(modes ...string) []winmod.Param {
		return []winmod.Param{
			{Name: "id", Type: winmod.GUID, Required: true},
			{Name: "mode", Type: winmod.Enum, Required: true, Values: modes},
		}
	}
	cfaPath := []winmod.Param{{Name: "path", Type: winmod.Path, Required: true, Sensitive: true}}
	cfaAppPath := []winmod.Param{{Name: "path", Type: winmod.Text, Required: true, Max: 260, Sensitive: true}}

	status := winmod.Action{
		Module: modules.Defender, Name: "defender.status", Label: "Read Defender's state", Version: 1,
		Script: statusScript, ScriptSHA256: StatusSHA256,
		Permission: rbac.PermDefenderView, Timeout: 60, Keep: time.Hour,
		// The alerts of alerts.go read this snapshot, which the server
		// refreshes hourly on every computer where the module is on.
		Freshness: 5 * time.Minute, Schedule: time.Hour,
		Decode: winmod.Typed[Status](),
	}
	return []winmod.Action{
		status,
		read("preferences_read", "Read Defender's protection settings", 90, winmod.Typed[Preferences](), false),
		read("asr_read", "Read the Attack Surface Reduction rules", 60, decodeASR, false),
		read("cfa_read", "Read Controlled Folder Access", 60, winmod.Typed[CFARead](), true),
		read("exclusions_read", "Read Defender's exclusions", 60, winmod.Typed[ExclusionsRead](), true),
		read("threats_read", "Read the threats Defender knows", 90, winmod.Typed[ThreatsRead](), false),
		read("quarantine_read", "Read Defender's quarantine", 90, winmod.Typed[QuarantineRead](), true),

		// Scans. Design B of ADR-0074 until a real device shows design A: the job holds its slot until the scan ends.
		change("scan_quick", "Run a Defender quick scan", secs(2*time.Hour), nil, winmod.Typed[ScanDone]()),
		change("scan_full", "Run a Defender full scan", secs(24*time.Hour), nil, winmod.Typed[ScanDone]()),
		checked(change("scan_custom", "Run a Defender scan of one path", secs(6*time.Hour),
			[]winmod.Param{{Name: "path", Type: winmod.Text, Required: true, Max: 260}}, winmod.Typed[ScanDone]()), checkScanPath),
		change("scan_cancel", "Cancel the running Defender scan", 60, nil, winmod.Typed[Canceled]()),
		change("signatures_update", "Update Defender's signatures", secs(10*time.Minute), nil, winmod.Typed[SignaturesUpdated]()),
		deviceNamed(confirmed(change("threats_remove", "Remove Defender's active threats", secs(10*time.Minute),
			[]winmod.Param{{Name: "device", Type: winmod.Name, Required: true}}, winmod.Typed[ThreatsRemoved]()), "device")),
		weakening(checked(change("quarantine_restore", "Restore a quarantined item to its original place", secs(2*time.Minute),
			[]winmod.Param{{Name: "name", Type: winmod.Text, Required: true, Max: 200}}, winmod.Typed[Restored]()), checkQuarantineName), "name"),

		// Preferences: one field per call, in the action of the value's direction.
		checked(change("preferences_set", "Change a Defender setting", secs(2*time.Minute), prefParams, changeT), checkPreference(false)),
		weakening(checked(change("preferences_weaken", "Lower a Defender protection setting", secs(2*time.Minute), prefParams, changeT), checkPreference(true)), "field"),
		checked(change("asr_set", "Turn an Attack Surface Reduction rule on", secs(2*time.Minute), asrParams("Enabled", "Warn"), changeT), checkASR(false)),
		weakening(checked(change("asr_weaken", "Turn an Attack Surface Reduction rule off or to audit", secs(2*time.Minute), asrParams("AuditMode", "Disabled"), changeT), checkASR(true)), "id"),
		change("cfa_set", "Turn Controlled Folder Access on", secs(2*time.Minute),
			[]winmod.Param{{Name: "mode", Type: winmod.Enum, Required: true, Values: values("Enabled")}}, changeT),
		weakening(change("cfa_weaken", "Turn Controlled Folder Access off or to audit", secs(2*time.Minute),
			[]winmod.Param{{Name: "mode", Type: winmod.Enum, Required: true, Values: values("Disabled", "AuditMode")}}, changeT), "mode"),
		change("cfa_folder_add", "Protect a folder with Controlled Folder Access", secs(2*time.Minute), cfaPath, changeT),
		weakening(change("cfa_folder_remove", "Stop protecting a folder with Controlled Folder Access", secs(2*time.Minute), cfaPath, changeT), "path"),
		weakening(checked(change("cfa_app_add", "Allow a program through Controlled Folder Access", secs(2*time.Minute), cfaAppPath, changeT), checkCFAApp), "path"),
		weakening(checked(change("cfa_app_remove", "Stop allowing a program through Controlled Folder Access", secs(2*time.Minute), cfaAppPath, changeT), checkCFAApp), "path"),

		// Exclusions: Add- and Remove-MpPreference one value at a time, never Set- on a list (section 3).
		weakening(checked(change("exclusion_add", "Add a Defender exclusion", secs(2*time.Minute),
			[]winmod.Param{exclusionKind, exclusionValue, {Name: "reason", Type: winmod.Text, Required: true, Min: 3, Max: 200}}, changeT), checkExclusionAdd), "value"),
		confirmed(checked(change("exclusion_remove", "Remove a Defender exclusion", secs(2*time.Minute),
			[]winmod.Param{exclusionKind, exclusionValue}, changeT), checkExclusionRemove), "value"),
	}
}

var quarantineName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:/._!@#,()\[\] -]*$`)

// checkQuarantineName keeps a threat name from being read as an option by
// MpCmdRun; the script also checks the name is in the quarantine list.
func checkQuarantineName(p map[string]any) error {
	name, _ := p["name"].(string)
	if !quarantineName.MatchString(name) {
		return apperr.Invalid("params.name", "Use a threat name from the quarantine list.")
	}
	return nil
}

// checkScanPath is the custom scan path rule of ADR-0074: absolute (a drive
// or a UNC path), at most 260 characters, no .. part, no device path, no
// wildcard and none of the characters a shell would read.
func checkScanPath(p map[string]any) error {
	path, _ := p["path"].(string)
	bad := func(msg string) error { return apperr.Invalid("params.path", msg) }
	switch {
	case strings.HasPrefix(path, `\\.\`) || strings.HasPrefix(path, `\\?\`):
		return bad("A device path cannot be scanned this way.")
	case !scanPath.MatchString(path):
		return bad(`Use an absolute path such as C:\Folder or \\server\share\folder.`)
	case strings.ContainsAny(path, "*?\"';&|<>^%$`"):
		return bad("The path holds a character that is not allowed.")
	}
	for _, seg := range strings.FieldsFunc(path, func(r rune) bool { return r == '\\' || r == '/' }) {
		if seg == ".." || seg == "." {
			return bad("The path must not contain . or .. parts.")
		}
	}
	if strings.ContainsAny(path[2:], ":") && !strings.HasPrefix(path, `\\`) {
		return bad("The path holds a character that is not allowed.")
	}
	return nil
}

var scanPath = regexp.MustCompile(`^([A-Za-z]:\\|\\\\[^\\]+\\[^\\]+)`)

// checkASR is the Check of asr_set and asr_weaken: the rule is in the
// catalog, and the mode is that action's direction.
func checkASR(weaken bool) func(map[string]any) error {
	return func(p map[string]any) error {
		id, _ := p["id"].(string)
		mode, _ := p["mode"].(string)
		if ASRRuleName(id) == "" {
			return &apperr.Error{Kind: apperr.KindInvalid, Code: "not_allowed", Message: "This is not an Attack Surface Reduction rule the module knows.",
				Fields: map[string]string{"params.id": "This is not an Attack Surface Reduction rule the module knows."}}
		}
		if asrWeakens(mode) != weaken {
			return apperr.Invalid("params.mode", "This mode is set with the other action (asr_weaken for AuditMode and Disabled).")
		}
		return nil
	}
}
