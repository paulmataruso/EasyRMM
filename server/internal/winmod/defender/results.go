package defender

import (
	"bytes"
	"encoding/json"
	"errors"
)

// PrefField is one preference as defender.preferences_read reports it.
// Value is what Get-MpPreference says (the effective one); Supported is
// false when the cmdlet did not return the property (older Windows Server),
// and ManagedBy names who owns it: group_policy, mdm, tamper_protection,
// defender_for_endpoint, configmgr, unknown_owner or null (ADR-0074 section 4).
type PrefField struct {
	Name      string  `json:"name"`
	Group     string  `json:"group"`
	Value     any     `json:"value"`
	Supported bool    `json:"supported"`
	ManagedBy *string `json:"managedBy"`
	// Unavailable carries Defender's own reason when it will not show the
	// value ("N/A: Must be an administrator..."); the value is then null.
	Unavailable string `json:"unavailable,omitempty"`
}

// Preferences is defender.preferences_read's result.
type Preferences struct {
	Fields          []PrefField `json:"fields"`
	TamperProtected *bool       `json:"tamperProtected"`
}

// ASRState is one Attack Surface Reduction rule as the script reports it.
type ASRState struct {
	ID        string  `json:"id"`
	Mode      string  `json:"mode"`
	ManagedBy *string `json:"managedBy"`
}

type asrWire struct {
	Supported bool       `json:"supported"`
	Rules     []ASRState `json:"rules"`
}

// ASRRead is defender.asr_read's result, joined to the catalogue's names.
type ASRRead struct {
	Supported bool           `json:"supported"`
	Rules     []ASRRuleState `json:"rules"`
}

// ASRRuleState is a rule with its name; Known is false for a GUID the
// catalogue does not list ("unrecognised rule").
type ASRRuleState struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Known     bool    `json:"known"`
	Mode      string  `json:"mode"`
	ManagedBy *string `json:"managedBy"`
}

func decodeASR(data json.RawMessage) (json.RawMessage, error) {
	var w asrWire
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil || dec.More() {
		return nil, errors.New("the data does not match the action's result schema")
	}
	out := ASRRead{Supported: w.Supported, Rules: make([]ASRRuleState, 0, len(w.Rules))}
	for _, r := range w.Rules {
		name := ASRRuleName(r.ID)
		out.Rules = append(out.Rules, ASRRuleState{ID: r.ID, Name: name, Known: name != "", Mode: r.Mode, ManagedBy: r.ManagedBy})
	}
	return json.Marshal(out)
}

// PathItem is a folder or program in a list; Ours marks what EasyRMM added.
type PathItem struct {
	Path string `json:"path"`
	Ours bool   `json:"ours"`
}

// CFARead is defender.cfa_read's result.
type CFARead struct {
	Supported           bool       `json:"supported"`
	Mode                string     `json:"mode"`
	ManagedBy           *string    `json:"managedBy"`
	ProtectedFolders    []PathItem `json:"protectedFolders"`
	AllowedApplications []PathItem `json:"allowedApplications"`
}

// Exclusion is one entry of an exclusion list. Ours entries are locked in
// the console; ManagedBy names a policy that owns the entry.
type Exclusion struct {
	Value     string  `json:"value"`
	Ours      bool    `json:"ours"`
	ManagedBy *string `json:"managedBy"`
}

// ExclusionsRead is defender.exclusions_read's result. Unavailable names the
// kinds Defender would not show (never an empty list in their place).
type ExclusionsRead struct {
	Path               []Exclusion `json:"path"`
	Process            []Exclusion `json:"process"`
	Extension          []Exclusion `json:"extension"`
	ASROnly            []Exclusion `json:"asrOnly"`
	Unavailable        []string    `json:"unavailable"`
	LocalMergeDisabled *bool       `json:"localMergeDisabled"`
	TamperProtected    *bool       `json:"tamperProtected"`
}

// Threat is one threat Defender knows (Get-MpThreat), without file paths.
type Threat struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	Severity   *int    `json:"severity"`
	Category   *int    `json:"category"`
	Active     bool    `json:"active"`
	Executed   *bool   `json:"executed"`
	DetectedAt *string `json:"detectedAt"`
	ChangedAt  *string `json:"changedAt"`
}

// ThreatsRead is defender.threats_read's result.
type ThreatsRead struct {
	Threats []Threat `json:"threats"`
}

// QuarantineItem is a quarantined item; Path is where it was found, which
// is why the read is sensitive.
type QuarantineItem struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// QuarantineRead is defender.quarantine_read's result.
type QuarantineRead struct {
	Items []QuarantineItem `json:"items"`
}

// ScanDone is what a finished scan reports.
type ScanDone struct {
	ScanType   string `json:"scanType"`
	FinishedAt string `json:"finishedAt"`
}

// SignaturesUpdated is signatures_update's result.
type SignaturesUpdated struct {
	Before  string `json:"before"`
	After   string `json:"after"`
	Updated bool   `json:"updated"`
}

// ThreatsRemoved is threats_remove's result.
type ThreatsRemoved struct {
	ActiveBefore int `json:"activeBefore"`
	ActiveAfter  int `json:"activeAfter"`
}

// Restored is quarantine_restore's result.
type Restored struct {
	Name     string `json:"name"`
	Restored bool   `json:"restored"`
}

// Change is what every write reports after it read the value back: Applied
// is false (with a Reason) when the value did not change, and nothing is
// then reported as changed (ADR-0074 section 4, "Read-back").
type Change struct {
	Applied bool   `json:"applied"`
	Reason  string `json:"reason"`
	Before  any    `json:"before"`
	After   any    `json:"after"`
}

// Cancelled is scan_cancel's result.
type Cancelled struct {
	Cancelled bool `json:"cancelled"`
}
