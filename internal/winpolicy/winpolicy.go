// Package winpolicy is the one reader of who owns a Windows setting
// (ADR-0054, "Policy ownership: one reader, built here"), and the Windows
// audit policy table of ADR-0060 beside it as data.
//
// The reader is a PowerShell script (reader.ps1) that defines functions
// only. Windows hardening's script includes it (the server puts it in place
// of its include line), and the agent is to carry the same file for log
// collection's Configure logging and for the registry editor's prepare
// (ADR-0060, ADR-0067), so that no feature builds a reader of its own. For
// each registry value, security setting and audit subcategory it gives
// exactly one of three results: an owner and its policy, none, or cannot
// tell with fixed reasons.
//
// It is shared by the server and the agent, as internal/agentproto is.
package winpolicy

import (
	"bytes"
	_ "embed" // the reader and the audit table
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
)

//go:embed reader.ps1
var reader string

//go:embed audit-policy.json
var auditPolicyJSON []byte

//go:embed query.ps1
var query string

// Reader returns the reader's PowerShell. It defines functions and sets
// nothing else; the script that includes it calls them.
func Reader() string { return reader }

// QueryResultPrefix starts the line Query's script prints its answers on.
const QueryResultPrefix = "EASYRMM-WINPOLICY-V1 "

// Query returns the reader as a script of its own (reader.ps1, then
// query.ps1), which the agent is to start as a child process with a
// request file for the registry editor and the event viewer (ADR-0054,
// "Policy ownership"; ADR-0067, ADR-0068). query.ps1 documents the request,
// the answer and the exit codes.
func Query() string { return reader + query }

// The reader's three results for a value.
const (
	ResultOwner      = "owner"
	ResultNone       = "none"
	ResultCannotTell = "cannot_tell"
)

// Owners the reader names, with ADR-0054's words in the comments.
const (
	// OwnerGroupPolicy: set by Group Policy, from the domain or the local
	// Group Policy object, with the policy's name.
	OwnerGroupPolicy = "group_policy"
	// OwnerTamperProtection: protected by Tamper Protection.
	OwnerTamperProtection = "tamper_protection"
	// OwnerSecurityProduct: another antivirus or firewall, named as the
	// policy (ADR-0054, "Another antivirus or firewall").
	OwnerSecurityProduct = "security_product"
)

// Owners are the owners a result may name.
var Owners = []string{OwnerGroupPolicy, OwnerTamperProtection, OwnerSecurityProduct}

// Reasons the reader cannot tell who owns a value: an owner may hold it
// whose settings the reader cannot read yet. The list grows only by
// amending ADR-0054; each is a fixed code both features show.
const (
	// ReasonGroupPolicyRecordOff: Group Policy's "Turn off Resultant Set of
	// Policy logging" stops Windows recording what Group Policy applied.
	ReasonGroupPolicyRecordOff = "group_policy_record_off"
	// ReasonGroupPolicyPreferences: Group Policy carries registry preference
	// items, which can set any registry value.
	ReasonGroupPolicyPreferences = "group_policy_preferences"
	// ReasonMDM: the computer is enrolled in an MDM, whose reader is not
	// proven on a real enrolled computer yet.
	ReasonMDM = "mdm"
	// ReasonDefenderForEndpoint: Defender for Endpoint's security settings
	// management may apply Intune's policies (Defender, attack surface
	// reduction, firewall).
	ReasonDefenderForEndpoint = "defender_for_endpoint"
	// ReasonConfigMgr: a Configuration Manager client, whose baselines may
	// remediate values.
	ReasonConfigMgr = "configmgr"
	// ReasonDSC: PowerShell DSC in ApplyAndAutoCorrect with a configuration.
	ReasonDSC = "dsc"
	// ReasonAzureMachineConfiguration: Azure's machine configuration.
	ReasonAzureMachineConfiguration = "azure_machine_configuration"
	// ReasonOSConfig: an OSConfig scenario is active (Windows Server 2025).
	// OSConfig names its settings and gives no registry value for them, so
	// the reader cannot name it as one value's owner (ADR-0054, amended in
	// W1).
	ReasonOSConfig = "osconfig"
	// ReasonUnexplainedPolicy: a value under a Policies key that none of
	// the readers explains (a tool the reader does not know).
	ReasonUnexplainedPolicy = "unexplained_policy"
)

// Reasons are the reasons a result may give.
var Reasons = []string{
	ReasonGroupPolicyRecordOff, ReasonGroupPolicyPreferences, ReasonMDM, ReasonDefenderForEndpoint,
	ReasonConfigMgr, ReasonDSC, ReasonAzureMachineConfiguration, ReasonOSConfig, ReasonUnexplainedPolicy,
}

// How a subcategory of the audit table is set.
const (
	SetSuccess        = "success"
	SetFailure        = "failure"
	SetSuccessFailure = "success_failure"
	// SetLeft is a subcategory the table leaves as it is (Logoff).
	SetLeft = "left"
)

// AuditSubcategory is a row of ADR-0060's Windows audit policy table.
type AuditSubcategory struct {
	// GUID is the subcategory's GUID, in braces and lower case, as auditpol
	// writes it: the script reads subcategories by GUID, never by their
	// translated names.
	GUID     string `json:"guid"`
	Category string `json:"category"`
	Name     string `json:"name"`
	Set      string `json:"set"`
	// DomainControllersOnly: set on domain controllers only, and only
	// when log collection is told to configure them.
	DomainControllersOnly bool `json:"domainControllersOnly,omitempty"`
}

// AuditValue is one of the table's registry values.
type AuditValue struct {
	ID   string `json:"id"`
	Path string `json:"path"`
	Name string `json:"name"`
	Data int    `json:"data"`
	// OnlyWith "pwsh": only where PowerShell 7 is installed.
	OnlyWith string `json:"onlyWith,omitempty"`
}

// AuditLog is an event log's smallest size.
type AuditLog struct {
	Channel  string `json:"channel"`
	MinKB    int    `json:"minKB"`
	OnlyWith string `json:"onlyWith,omitempty"`
}

// AuditTable is ADR-0060's Windows audit policy table and its other
// settings.
type AuditTable struct {
	Source        string             `json:"source"`
	Subcategories []AuditSubcategory `json:"subcategories"`
	Values        []AuditValue       `json:"values"`
	Logs          []AuditLog         `json:"logs"`
}

var guidForm = regexp.MustCompile(`^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`)

// Audit returns the audit table. It is checked when the package loads.
func Audit() AuditTable { return audit }

var audit = mustParseAudit(auditPolicyJSON)

// AuditJSON returns the table as compact JSON, for scripts to read.
func AuditJSON() string {
	var b bytes.Buffer
	if err := json.Compact(&b, auditPolicyJSON); err != nil {
		panic(err) // checked when the package loaded
	}
	return b.String()
}

func mustParseAudit(b []byte) AuditTable {
	t, err := parseAudit(b)
	if err != nil {
		panic("winpolicy: audit-policy.json: " + err.Error())
	}
	return t
}

// parseAudit reads the table and checks its form: GUIDs in auditpol's form
// and each once, a known way of setting each, positive sizes.
func parseAudit(b []byte) (AuditTable, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var t AuditTable
	if err := dec.Decode(&t); err != nil {
		return t, err
	}
	seen := map[string]bool{}
	for _, s := range t.Subcategories {
		switch {
		case !guidForm.MatchString(s.GUID):
			return t, fmt.Errorf("%q is not a subcategory GUID in braces and lower case", s.GUID)
		case seen[s.GUID]:
			return t, fmt.Errorf("%s is listed twice", s.GUID)
		case !slices.Contains([]string{SetSuccess, SetFailure, SetSuccessFailure, SetLeft}, s.Set):
			return t, fmt.Errorf("%s: unknown setting %q", s.GUID, s.Set)
		case s.Name == "" || s.Category == "":
			return t, fmt.Errorf("%s has no name", s.GUID)
		}
		seen[s.GUID] = true
	}
	for _, v := range t.Values {
		if v.ID == "" || v.Path == "" || v.Name == "" || (v.OnlyWith != "" && v.OnlyWith != "pwsh") {
			return t, fmt.Errorf("value %q is incomplete", v.ID)
		}
	}
	for _, l := range t.Logs {
		if l.Channel == "" || l.MinKB <= 0 || (l.OnlyWith != "" && l.OnlyWith != "pwsh") {
			return t, fmt.Errorf("log %q is incomplete", l.Channel)
		}
	}
	if len(t.Subcategories) == 0 || len(t.Logs) == 0 {
		return t, fmt.Errorf("the table is empty")
	}
	return t, nil
}
