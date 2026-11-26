package defender

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

// Field kinds of Set-MpPreference parameters the module may set (ADR-0074
// section 3, "Preferences the module may set").
const (
	kindBool    = "bool"
	kindInt     = "int"
	kindEnum    = "enum"
	kindMinutes = "minutes" // a time of day, as minutes after midnight
)

// Field is one preference the module may set: its type, range and which way
// each value points. Anything not listed is `not_allowed`.
type Field struct {
	Name   string
	Group  string
	Kind   string
	Min    int
	Max    int
	Values []string
	// Weakens lists the values that lower protection or widen what is not
	// scanned. A bool field with WeakensTrue weakens when it is true.
	WeakensTrue bool
	Weakening   []string
	// Tamper says Tamper Protection guards this field (ADR-0074 section 4).
	Tamper bool
}

var (
	enableModes   = []string{"Disabled", "Enabled", "AuditMode"}
	threatActions = []string{"Clean", "Quarantine", "Remove", "Allow", "UserDefined", "NoAction"}
	blockLevels   = []string{"Default", "Moderate", "High", "HighPlus", "ZeroTolerance"}
)

func switches(group string, names ...string) []Field {
	out := make([]Field, 0, len(names))
	for _, n := range names {
		out = append(out, Field{Name: n, Group: group, Kind: kindBool, WeakensTrue: true, Tamper: true})
	}
	return out
}

func plainBools(group string, names ...string) []Field {
	out := make([]Field, 0, len(names))
	for _, n := range names {
		out = append(out, Field{Name: n, Group: group, Kind: kindBool})
	}
	return out
}

// Fields is the table of settable preferences. A test compares it with the
// pinned Set-MpPreference parameter list and with the table inside
// preferences_set.ps1.
var Fields = func() []Field {
	var f []Field
	f = append(f, switches("protection",
		"DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableScriptScanning",
		"DisableBlockAtFirstSeen", "DisableArchiveScanning", "DisableEmailScanning", "DisableRemovableDriveScanning",
		"DisableScanningNetworkFiles", "DisableScanningMappedNetworkDrivesForFullScan")...)
	f = append(f,
		Field{Name: "MAPSReporting", Group: "cloud", Kind: kindInt, Min: 0, Max: 2, Weakening: []string{"0"}, Tamper: true},
		Field{Name: "SubmitSamplesConsent", Group: "cloud", Kind: kindInt, Min: 0, Max: 3, Tamper: true},
		Field{Name: "CloudBlockLevel", Group: "cloud", Kind: kindEnum, Values: blockLevels, Weakening: []string{"Default"}, Tamper: true},
		Field{Name: "CloudExtendedTimeout", Group: "cloud", Kind: kindInt, Min: 0, Max: 50, Tamper: true},
		Field{Name: "PUAProtection", Group: "features", Kind: kindEnum, Values: enableModes, Weakening: []string{"Disabled", "AuditMode"}, Tamper: true},
		Field{Name: "EnableNetworkProtection", Group: "features", Kind: kindEnum, Values: enableModes, Weakening: []string{"Disabled", "AuditMode"}, Tamper: true},
	)
	for _, n := range []string{"LowThreatDefaultAction", "ModerateThreatDefaultAction", "HighThreatDefaultAction", "SevereThreatDefaultAction"} {
		f = append(f, Field{Name: n, Group: "threats", Kind: kindEnum, Values: threatActions, Weakening: []string{"Allow", "NoAction", "UserDefined"}, Tamper: true})
	}
	f = append(f,
		Field{Name: "QuarantinePurgeItemsAfterDelay", Group: "retention", Kind: kindInt, Min: 0, Max: 365},
		Field{Name: "ScanPurgeItemsAfterDelay", Group: "retention", Kind: kindInt, Min: 0, Max: 365},
		Field{Name: "ScanScheduleDay", Group: "schedule", Kind: kindInt, Min: 0, Max: 8},
		Field{Name: "ScanScheduleTime", Group: "schedule", Kind: kindMinutes, Min: 0, Max: 1439},
		Field{Name: "ScanScheduleQuickScanTime", Group: "schedule", Kind: kindMinutes, Min: 0, Max: 1439},
		Field{Name: "ScanParameters", Group: "schedule", Kind: kindInt, Min: 1, Max: 2},
		Field{Name: "RemediationScheduleDay", Group: "schedule", Kind: kindInt, Min: 0, Max: 8},
		Field{Name: "RemediationScheduleTime", Group: "schedule", Kind: kindMinutes, Min: 0, Max: 1439},
		Field{Name: "DisableCatchupFullScan", Group: "schedule", Kind: kindBool, WeakensTrue: true},
		Field{Name: "DisableCatchupQuickScan", Group: "schedule", Kind: kindBool, WeakensTrue: true},
		Field{Name: "SignatureScheduleDay", Group: "schedule", Kind: kindInt, Min: 0, Max: 8},
		Field{Name: "SignatureScheduleTime", Group: "schedule", Kind: kindMinutes, Min: 0, Max: 1439},
		Field{Name: "SignatureUpdateInterval", Group: "schedule", Kind: kindInt, Min: 1, Max: 24},
		Field{Name: "SignatureUpdateCatchupInterval", Group: "schedule", Kind: kindInt, Min: 1, Max: 30},
		Field{Name: "ScanAvgCPULoadFactor", Group: "performance", Kind: kindInt, Min: 0, Max: 100},
	)
	f = append(f, plainBools("schedule", "RandomizeScheduleTaskTimes", "CheckForSignaturesBeforeRunningScan", "MeteredConnectionUpdates")...)
	f = append(f, plainBools("performance", "ScanOnlyIfIdleEnabled", "EnableLowCpuPriority", "DisableCpuThrottleOnIdleScans",
		"EnableFullScanOnBatteryPower", "DisableRestorePoint")...)
	f = append(f, Field{Name: "DisableAutoExclusions", Group: "servers", Kind: kindBool, WeakensTrue: true})
	return f
}()

// LookupField finds a settable preference by name.
func LookupField(name string) (Field, bool) {
	for _, f := range Fields {
		if f.Name == name {
			return f, true
		}
	}
	return Field{}, false
}

// Canonical checks a value against the field's type and range and returns
// it in the form the script reads: "true" or "false", digits, or the enum's
// own name. ok is false with the reason otherwise.
func (f Field) Canonical(raw string) (string, string) {
	v := strings.TrimSpace(raw)
	switch f.Kind {
	case kindBool:
		switch strings.ToLower(v) {
		case "true":
			return "true", ""
		case "false":
			return "false", ""
		}
		return "", "Use true or false."
	case kindInt, kindMinutes:
		n, err := strconv.Atoi(v)
		if err != nil || strconv.Itoa(n) != v {
			return "", "Use a whole number."
		}
		if n < f.Min || n > f.Max || (f.Name == "ScanAvgCPULoadFactor" && n != 0 && n < 5) {
			return "", fmt.Sprintf("This is out of range (%d to %d).", f.Min, f.Max)
		}
		return v, ""
	case kindEnum:
		for _, e := range f.Values {
			if strings.EqualFold(e, v) {
				return e, ""
			}
		}
		return "", "Use one of: " + strings.Join(f.Values, ", ") + "."
	}
	return "", "This field cannot be set."
}

// Weakens reports whether setting the canonical value lowers protection or
// widens what is not scanned (a tier 3 change).
func (f Field) Weakens(canonical string) bool {
	if f.Kind == kindBool {
		return f.WeakensTrue && canonical == "true"
	}
	return slices.Contains(f.Weakening, canonical)
}

// checkPreference is the Check of preferences_set and preferences_weaken:
// the field is settable, the value is of its type, and the action is the one
// of the value's direction, so a weakening value can never ride a tier 1
// request. ADR-0074 allows 8 fields per call; the catalog's parameters are
// single values, so one field is set per call.
func checkPreference(weaken bool) func(map[string]any) error {
	return func(p map[string]any) error {
		name, _ := p["field"].(string)
		raw, _ := p["value"].(string)
		f, ok := LookupField(name)
		if !ok {
			return &apperr.Error{Kind: apperr.KindInvalid, Code: "not_allowed", Message: "This preference cannot be set from the module.",
				Fields: map[string]string{"params.field": "This preference cannot be set from the module."}}
		}
		canon, msg := f.Canonical(raw)
		if msg != "" {
			return apperr.Invalid("params.value", msg)
		}
		p["value"] = canon
		if f.Weakens(canon) != weaken {
			if weaken {
				return apperr.Invalid("params.value", "This value does not lower protection; use preferences_set.")
			}
			return apperr.Invalid("params.value", "This value lowers protection; use preferences_weaken, which needs the weaken permission and a step-up.")
		}
		return nil
	}
}
