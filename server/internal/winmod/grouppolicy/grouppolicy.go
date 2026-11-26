// Package grouppolicy is the catalog of ADR-0083's Group Policy module, slice 1: reading the GPOs, their links,
// delegation, WMI filters and every setting of a GPO (parsed from Get-GPOReport's XML), and the management actions
// (create, copy, rename, delete, links, status, security filtering, WMI filter, backup and restore). EasyRMM never
// writes SYSVOL or a GPO's directory attributes: every script calls only Microsoft's GroupPolicy cmdlets and the GPMC
// COM object model, on a domain controller. Every script is fixed, pinned by SHA-256 and gets its parameters on
// standard input. The scripts are built from src/ by gen.sh.
package grouppolicy

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

//go:embed scripts/*.ps1
var scriptFS embed.FS

func script(name string) string {
	b, err := scriptFS.ReadFile("scripts/" + name + ".ps1")
	if err != nil {
		panic(fmt.Sprintf("grouppolicy: no script %q", name))
	}
	return string(b)
}

const (
	readKeep   = time.Hour
	changeKeep = 7 * 24 * time.Hour
	// PageMax is the most rows a page of a list holds.
	PageMax = 60
	// MaxBackupZip is the largest zip of a GPO backup the module keeps. A result line is at most 64 KiB and a job's
	// parameters 16 KiB, so a backup travels in base64 inside one result and back in chunks (ADR-0083, amended).
	MaxBackupZip = 36000
	// ChunkChars is the base64 characters of one chunk of a restore; MaxChunks is how many a backup can need.
	ChunkChars = 12000
	MaxChunks  = 6
)

// The two Default policies. Their identifiers are fixed by Microsoft (ADR-0083, section 7).
const (
	DefaultDomainPolicyID      = "31b2f340-016d-11d2-945f-00c04fb984f9"
	DefaultControllersPolicyID = "6ac1786c-016f-11d2-945f-00c04fb984f9"
)

// DefaultPolicies maps a Default policy's identifier to its name.
var DefaultPolicies = map[string]string{
	DefaultDomainPolicyID:      "Default Domain Policy",
	DefaultControllersPolicyID: "Default Domain Controllers Policy",
}

var (
	gpoStatuses = []string{"AllSettingsEnabled", "UserSettingsDisabled", "ComputerSettingsDisabled", "AllSettingsDisabled"}
	// gpoName is a GPO's display name: letters and digits first, then those and the usual punctuation.
	gpoName   = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._()&'@#%+=,;~!\[\]{}-]{0,127}$`)
	b64Chunk  = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// modifies are the actions that change a GPO's settings, links or access, as opposed to reading it, copying it or backing it
// up: the Default policies need the extra confirmation and two people for these.
var modifies = map[string]bool{
	"gpo_rename": true, "gpo_delete": true, "gpo_status": true, "sec_filter_add": true, "sec_filter_remove": true,
	"wmi_set": true, "gpo_restore": true, "link_add": true, "link_remove": true, "link_order": true,
	"link_enabled": true, "link_enforced": true,
}

var (
	pID      = winmod.Param{Name: "id", Type: winmod.GUID, Required: true}
	pTarget  = winmod.Param{Name: "target", Type: winmod.DN, Required: true}
	pReason  = winmod.Param{Name: "reason", Type: winmod.Text, Required: true, Min: 10, Max: 500}
	pOffset  = winmod.Param{Name: "offset", Type: winmod.Int, Min: 0, Max: 100000}
	pSize    = winmod.Param{Name: "pageSize", Type: winmod.Int, Min: 1, Max: PageMax}
	pExpectC = winmod.Param{Name: "expectComputerVersion", Type: winmod.Int, Min: 0, Max: 65535}
	pExpectU = winmod.Param{Name: "expectUserVersion", Type: winmod.Int, Min: 0, Max: 65535}
	// confirmName is the extra confirmation of the Default policies: the policy's name, typed in full.
	pConfirmName = winmod.Param{Name: "confirmName", Type: winmod.Text, Max: 256}
	// approvalId names the approved request a change that needs two people runs under. The server checks it before the
	// job exists and uses it once.
	pApproval = winmod.Param{Name: "approvalId", Type: winmod.GUID}
	pOrder    = winmod.Param{Name: "order", Type: winmod.Int, Min: 1, Max: 999}
)

func pName(name string) winmod.Param {
	return winmod.Param{Name: name, Type: winmod.Text, Required: true, Min: 1, Max: 128, Pattern: gpoName}
}

// pNameConfirm is the typed confirmation of a destructive action: the GPO's name as it is now.
func pNameConfirm() winmod.Param {
	return winmod.Param{Name: "name", Type: winmod.Text, Required: true, Min: 1, Max: 256}
}

// A change's common parameters: the typed reason, the versions the page read the GPO at, the Default policies'
// confirmation and the approval.
func change(ps ...winmod.Param) []winmod.Param {
	return append(ps, pReason, pExpectC, pExpectU, pConfirmName, pApproval)
}

func read(name, label string, timeout int, params ...winmod.Param) winmod.Action {
	return winmod.Action{
		Module: modules.GroupPolicy, Name: "group_policy." + name, Label: label, Version: 1,
		Script: script(name), ScriptSHA256: pin(name), Params: params,
		Permission: rbac.PermGPOView, Timeout: timeout, Keep: readKeep, Freshness: 5 * time.Minute,
	}
}

// write is a change. Every change asks for a step-up and a typed reason (ADR-0083, section 7); Credential is how the
// framework says "step-up", the per-request credential of ADR-0075 being impossible here (the GroupPolicy cmdlets take
// no -Credential).
func write(name, label string, timeout int, perm rbac.Permission, params []winmod.Param) winmod.Action {
	a := winmod.Action{
		Module: modules.GroupPolicy, Name: "group_policy." + name, Label: label, Version: 1,
		Script: script(name), ScriptSHA256: pin(name), Params: params,
		Permission: perm, Timeout: timeout, Keep: changeKeep, Changes: true, Credential: true,
		Decode: decodeChanged,
	}
	a.Check = guard(name)
	return a
}

func destructive(a winmod.Action) winmod.Action {
	a.Destructive, a.Subject = true, "name"
	return a
}

// Actions are the Group Policy actions the server can run.
func Actions() []winmod.Action {
	status := read("status", "Read the domain's Group Policy", 300)
	status.Decode = winmod.Typed[Status]()

	list := read("gpo_list", "List the GPOs", 300, pOffset, pSize, winmod.Param{Name: "match", Type: winmod.Text, Max: 64})
	list.Decode, list.CountField = winmod.Typed[GPOPage](), "items"

	get := read("gpo_get", "Read a GPO", 120, pID)
	get.Decode = winmod.Typed[GPODetail]()

	tree := read("link_tree", "Read the link tree", 300, pOffset, pSize)
	tree.Decode, tree.CountField = winmod.Typed[LinkTree](), "targets"

	wmi := read("wmi_filters", "List the WMI filters", 120)
	wmi.Decode, wmi.CountField = winmod.Typed[WMIFilters](), "filters"

	report := read("gpo_report", "Read every setting of a GPO", 300, pID)
	report.Decode = decodeReport

	create := write("gpo_create", "Create a GPO", 120, rbac.PermGPOManage,
		append(change(pName("newName")), winmod.Param{Name: "comment", Type: winmod.Text, Max: 256}))
	create.Decode = decodeCreated
	create.Check = guardNewName("gpo_create", "newName")

	cp := write("gpo_copy", "Copy a GPO", 300, rbac.PermGPOManage, change(pID, pName("newName")))
	cp.Decode = decodeCreated
	cp.Check = guardNewName("gpo_copy", "newName")

	rename := write("gpo_rename", "Rename a GPO", 120, rbac.PermGPOManage, change(pID, pName("newName")))
	rename.Check = guardNewName("gpo_rename", "newName")

	del := destructive(write("gpo_delete", "Delete a GPO", 300, rbac.PermGPOManage, change(pID, pNameConfirm())))

	statusSet := write("gpo_status", "Change which parts of a GPO apply", 120, rbac.PermGPOManage,
		change(pID, winmod.Param{Name: "status", Type: winmod.Enum, Required: true, Values: gpoStatuses}))

	add := write("sec_filter_add", "Add a security filtering principal", 120, rbac.PermGPOManage,
		change(pID, winmod.Param{Name: "trustee", Type: winmod.SID, Required: true}))
	remove := destructive(write("sec_filter_remove", "Remove a security filtering principal", 120, rbac.PermGPOManage,
		change(pID, pNameConfirm(), winmod.Param{Name: "trustee", Type: winmod.SID, Required: true},
			winmod.Param{Name: "keepRead", Type: winmod.Bool})))

	wmiSet := write("wmi_set", "Set a GPO's WMI filter", 120, rbac.PermGPOManage,
		change(pID, winmod.Param{Name: "filter", Type: winmod.Text, Required: true, Max: 256, AllowEmpty: true}))

	backup := write("gpo_backup", "Back up a GPO", 300, rbac.PermGPOManage, []winmod.Param{pID, pReason, pApproval})
	backup.Changes = false

	stage := write("gpo_restore_stage", "Send a backup to the controller", 60, rbac.PermGPOManage, []winmod.Param{
		{Name: "backupId", Type: winmod.GUID, Required: true},
		{Name: "index", Type: winmod.Int, Required: true, Min: 0, Max: MaxChunks - 1},
		{Name: "count", Type: winmod.Int, Required: true, Min: 1, Max: MaxChunks},
		{Name: "chunk", Type: winmod.Text, Required: true, Min: 4, Max: ChunkChars, Pattern: b64Chunk},
	})
	stage.Changes, stage.Decode, stage.Check = false, winmod.Typed[Staged](), nil

	restore := destructive(write("gpo_restore", "Restore a GPO from a backup", 300, rbac.PermGPOManage, change(pID, pNameConfirm(),
		winmod.Param{Name: "backupId", Type: winmod.GUID, Required: true},
		winmod.Param{Name: "zipSha256", Type: winmod.Text, Required: true, Pattern: sha256Hex, Max: 64},
		winmod.Param{Name: "parts", Type: winmod.Int, Required: true, Min: 1, Max: MaxChunks})))

	linkAdd := write("link_add", "Link a GPO", 120, rbac.PermGPOLink, change(pID, pTarget,
		winmod.Param{Name: "enabled", Type: winmod.Bool}, winmod.Param{Name: "enforced", Type: winmod.Bool}, pOrder))
	linkRemove := destructive(write("link_remove", "Remove a link", 120, rbac.PermGPOLink, change(pID, pTarget, pNameConfirm())))
	linkOrder := write("link_order", "Change a link's order", 120, rbac.PermGPOLink, change(pID, pTarget,
		winmod.Param{Name: "order", Type: winmod.Int, Required: true, Min: 1, Max: 999}))
	linkEnabled := write("link_enabled", "Enable or disable a link", 120, rbac.PermGPOLink, change(pID, pTarget,
		winmod.Param{Name: "enabled", Type: winmod.Bool, Required: true}))
	linkEnforced := write("link_enforced", "Enforce or release a link", 120, rbac.PermGPOLink, change(pID, pTarget,
		winmod.Param{Name: "enforced", Type: winmod.Bool, Required: true}))
	block := write("inheritance_block", "Block or allow inheritance", 120, rbac.PermGPOLink, []winmod.Param{
		pTarget, {Name: "blocked", Type: winmod.Bool, Required: true}, pReason, pExpectC, pExpectU, pConfirmName, pApproval})

	return []winmod.Action{status, list, get, tree, wmi, report, create, cp, rename, del, statusSet, add, remove, wmiSet, backup, stage,
		restore, linkAdd, linkRemove, linkOrder, linkEnabled, linkEnforced, block}
}

// ClassifyTarget says what a link target's distinguished name is: "domain" (the domain root, all DC= parts),
// "dc_ou" (OU=Domain Controllers directly under it), "site" (CN=<site>,CN=Sites,CN=Configuration,...), "ou" (any
// other OU) or "other" (a container a GPO cannot be linked to).
func ClassifyTarget(dn string) string {
	parts := strings.Split(dn, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	allDC := func(ps []string) bool {
		for _, p := range ps {
			if len(p) < 4 || !strings.EqualFold(p[:3], "DC=") {
				return false
			}
		}
		return len(ps) > 0
	}
	switch {
	case allDC(parts):
		return "domain"
	case len(parts) > 1 && strings.EqualFold(parts[0], "OU=Domain Controllers") && allDC(parts[1:]):
		return "dc_ou"
	case len(parts) > 3 && strings.EqualFold(parts[0][:min(3, len(parts[0]))], "CN=") && strings.EqualFold(parts[1], "CN=Sites") &&
		strings.EqualFold(parts[2], "CN=Configuration") && allDC(parts[3:]):
		return "site"
	case strings.EqualFold(parts[0][:min(3, len(parts[0]))], "OU="):
		return "ou"
	}
	return "other"
}

// Sensitivity says why a change needs two people (ADR-0083, section 7), judged from what the request names:
// "default_policy" for a change to one of the two Default policies, "sensitive_link" for a link, unlink or
// inheritance block at the domain root, the Domain Controllers OU or a site. Empty when neither. A GPO already linked
// at such a place is known only from what the console last read; the service adds it.
func Sensitivity(action string, p map[string]any) string {
	short := strings.TrimPrefix(action, "group_policy.")
	if id, _ := p["id"].(string); id != "" {
		if _, ok := DefaultPolicies[id]; ok && modifies[short] {
			return "default_policy"
		}
	}
	if t, _ := p["target"].(string); t != "" && (strings.HasPrefix(short, "link_") || short == "inheritance_block") {
		switch ClassifyTarget(t) {
		case "domain", "dc_ou", "site":
			return "sensitive_link"
		}
	}
	return ""
}

// NeedsApprovalCheck says whether the action is one the approval gate looks at: a change to a GPO or a link, except a
// backup, a copy and the sending of a backup, which change nothing in the directory.
func NeedsApprovalCheck(action string) bool {
	short := strings.TrimPrefix(action, "group_policy.")
	switch short {
	case "gpo_create", "inheritance_block":
		return true
	}
	return modifies[short]
}

func guard(action string) func(map[string]any) error {
	return func(p map[string]any) error {
		id, _ := p["id"].(string)
		if name, ok := DefaultPolicies[id]; ok {
			switch action {
			case "gpo_delete", "gpo_rename":
				return apperr.Conflict("protected_policy", name+" is never deleted or renamed here.")
			case "link_remove":
				return apperr.Conflict("protected_policy", name+" is never unlinked here.")
			case "gpo_status":
				if s, _ := p["status"].(string); s != "AllSettingsEnabled" {
					return apperr.Conflict("protected_policy", name+" is never disabled, in whole or in part, here.")
				}
			}
			if modifies[action] {
				if c, _ := p["confirmName"].(string); c != name {
					return apperr.Invalid("params.confirmName", "Type the policy's name in full, \""+name+"\", to confirm a change to it.")
				}
			}
		}
		if t, ok := p["target"].(string); ok {
			switch kind := ClassifyTarget(t); {
			case kind == "other":
				return apperr.Invalid("params.target", "A GPO links to the domain, an organizational unit or a site.")
			case action == "inheritance_block" && kind == "site":
				return apperr.Invalid("params.target", "Inheritance is blocked on the domain or an organizational unit, not on a site.")
			}
		}
		return nil
	}
}

// guardNewName refuses a name that is one of the Default policies', which would make two look alike.
func guardNewName(action, field string) func(map[string]any) error {
	base := guard(action)
	return func(p map[string]any) error {
		if err := base(p); err != nil {
			return err
		}
		n, _ := p[field].(string)
		for _, d := range DefaultPolicies {
			if strings.EqualFold(strings.TrimSpace(n), d) {
				return apperr.Invalid("params."+field, "That is the name of a Default policy.")
			}
		}
		return nil
	}
}

// decodeChanged reads a change's data strictly and keeps it without the backup's zip, which the server moves to
// its own table (the hook reads it from the run's output).
func decodeChanged(data json.RawMessage) (json.RawMessage, error) {
	v, err := strict[Changed](data)
	if err != nil {
		return nil, err
	}
	if v.Backup != nil {
		v.Backup.Zip = ""
	}
	return json.Marshal(v)
}

func decodeCreated(data json.RawMessage) (json.RawMessage, error) {
	v, err := strict[Created](data)
	if err != nil {
		return nil, err
	}
	if v.Backup != nil {
		v.Backup.Zip = ""
	}
	return json.Marshal(v)
}

func strict[T any](data json.RawMessage) (*T, error) {
	var v T
	if err := winmod.DecodeStrict(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}
