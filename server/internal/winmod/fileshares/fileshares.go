// Package fileshares is the catalog of ADR-0076's file-sharing module: the
// shares of a Windows file server, their share permissions, and the open
// sessions and files. NTFS permission edits and FSRM quotas (slices F4 and
// F5) are not built: see docs/notes/roles2.md.
//
// Every action is a script in scripts/, pinned by the SHA-256 of the text the
// agent receives (the action's file with _common.ps1 put in where it says
// "#@library"). A change to a script or the library changes a pin in pins.go,
// in review.
//
// The protected shares (SYSVOL, NETLOGON, print$, IPC$, ADMIN$ and every share
// whose name ends in $) are refused by name here, before any job exists, and
// again in the script (ProtectedShare).
package fileshares

import (
	"embed"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/rolekit"
)

//go:embed scripts/*.ps1
var scriptFS embed.FS

// Tiers (ADR-0076, section 2).
const (
	tier0 = iota
	tier1
	tier2
	tier3
)

// Status is file_shares.status's result. The SMB settings are read only.
type Status struct {
	ServiceState       string `json:"serviceState"`
	ShareCount         int    `json:"shareCount"`
	UserShareCount     int    `json:"userShareCount"`
	SessionCount       int    `json:"sessionCount"`
	OpenFileCount      int    `json:"openFileCount"`
	SMB1Enabled        *bool  `json:"smb1Enabled"`
	SigningRequired    *bool  `json:"signingRequired"`
	EncryptionRequired *bool  `json:"encryptionRequired"`
}

// Share is one share as share_list shows it.
type Share struct {
	Name                  string `json:"name"`
	Path                  string `json:"path"`
	Description           string `json:"description"`
	Special               bool   `json:"special"`
	Protected             bool   `json:"protected"`
	Scoped                bool   `json:"scoped"`
	ContinuouslyAvailable bool   `json:"continuouslyAvailable"`
	Encrypted             bool   `json:"encrypted"`
	Caching               string `json:"caching"`
	FolderEnumeration     string `json:"folderEnumeration"`
	ConcurrentUserLimit   int64  `json:"concurrentUserLimit"`
}

// Shares is share_list's result.
type Shares struct {
	Shares    []Share `json:"shares"`
	Truncated bool    `json:"truncated"`
}

// AccessEntry is one share-permission entry.
type AccessEntry struct {
	Account string `json:"account"`
	Right   string `json:"right"`
	Type    string `json:"type"`
}

// Access is share_access_get's result.
type Access struct {
	Name    string        `json:"name"`
	Entries []AccessEntry `json:"entries"`
}

// Session is one open SMB session. The id is text: Windows' ids exceed what
// a JSON number holds safely.
type Session struct {
	ID            string `json:"id"`
	User          string `json:"user"`
	Client        string `json:"client"`
	OpenFiles     int64  `json:"openFiles"`
	SecondsActive int64  `json:"secondsActive"`
	SecondsIdle   int64  `json:"secondsIdle"`
}

// Sessions is session_list's result.
type Sessions struct {
	Sessions []Session `json:"sessions"`
	Total    int       `json:"total"`
}

// OpenFile is one file open over SMB.
type OpenFile struct {
	ID        string `json:"id"`
	SessionID string `json:"sessionId"`
	Path      string `json:"path"`
	User      string `json:"user"`
	Client    string `json:"client"`
	Locks     int64  `json:"locks"`
}

// OpenFiles is openfile_list's result.
type OpenFiles struct {
	Files []OpenFile `json:"files"`
	Total int        `json:"total"`
}

// Done is the result of an action with nothing to report.
type Done struct {
	Done bool `json:"done"`
}

// Parameter forms.

var (
	// accountPattern is a SID, or an account or group name, optionally
	// qualified by a domain (the script resolves it to a SID).
	accountPattern = regexp.MustCompile(`^(S-1-\d{1,10}(-\d{1,10}){1,15}|([A-Za-z0-9._ -]{1,64}\\)?[A-Za-z0-9._@$ -]{1,104})$`)
	idPattern      = regexp.MustCompile(`^\d{1,20}$`)
	driveRoot      = regexp.MustCompile(`^[A-Za-z]:\\?$`)
)

// ProtectedShare says whether a share is one the console shows and never
// changes: SYSVOL, NETLOGON, and every share whose name ends in $ (which
// takes in print$, IPC$, ADMIN$ and the drive shares). Case does not matter.
func ProtectedShare(name string) bool {
	n := strings.ToUpper(strings.TrimSpace(name))
	return strings.HasSuffix(n, "$") || n == "SYSVOL" || n == "NETLOGON"
}

// account splits an account into its lower-case name and domain.
func account(a string) (name, domain string) {
	a = strings.ToLower(strings.TrimSpace(a))
	if i := strings.LastIndex(a, `\`); i >= 0 {
		return a[i+1:], a[:i]
	}
	return a, ""
}

// weakSIDs open a share to everyone: Everyone, Anonymous Logon,
// Authenticated Users.
var weakSIDs = map[string]bool{"S-1-1-0": true, "S-1-5-7": true, "S-1-5-11": true}

// WeakensAccess says whether granting right (Read, Change or Full) to the
// account would open the share too far: Change or Full to Everyone, Anonymous
// Logon or Authenticated Users, or Full to Users (ADR-0076). Reading is
// allowed. The script checks again on the resolved SID.
func WeakensAccess(acct, right string) bool {
	if right != "Full" && right != "Change" {
		return false
	}
	name, domain := account(acct)
	up := strings.ToUpper(strings.TrimSpace(acct))
	switch {
	case weakSIDs[up]:
		return true
	case up == "S-1-5-32-545":
		return right == "Full"
	case name == "everyone" || name == "anonymous logon" || name == "authenticated users":
		return domain == "" || domain == "nt authority" || name == "everyone"
	case name == "users":
		return right == "Full" && (domain == "" || domain == "builtin")
	}
	return false
}

// LockOut says whether blocking the account could lock everybody, or the
// administrators, out of a share.
func LockOut(acct string) bool {
	name, domain := account(acct)
	switch strings.ToUpper(strings.TrimSpace(acct)) {
	case "S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-544", "S-1-5-18":
		return true
	}
	switch name {
	case "everyone":
		return true
	case "authenticated users", "system":
		return domain == "" || domain == "nt authority"
	case "users", "administrators":
		return domain == "" || domain == "builtin"
	}
	return false
}

// unsafePath says whether a path must not be shared: a drive root, the Windows
// folder or anything below it, or SYSVOL (the script, which knows the real
// system folder, checks again).
func unsafePath(p string) bool {
	if driveRoot.MatchString(p) {
		return true
	}
	segs := strings.FieldsFunc(strings.ToLower(p[min(len(p), 3):]), func(r rune) bool { return r == '\\' })
	for i, s := range segs {
		if s == "sysvol" || (i == 0 && s == "windows") {
			return true
		}
	}
	return false
}

func protectedGuard(param string) func(map[string]any) error {
	return func(p map[string]any) error {
		if ProtectedShare(rolekit.Str(p, param)) {
			return rolekit.Refuse("protected_share", "This share is protected: the console shows it and does not change it.")
		}
		return nil
	}
}

func createGuard(p map[string]any) error {
	if err := protectedGuard("name")(p); err != nil {
		return err
	}
	if unsafePath(rolekit.Str(p, "path")) {
		return rolekit.Refuse("protected_path", "A drive root, the Windows folder and SYSVOL cannot be shared.")
	}
	return nil
}

func grantGuard(p map[string]any) error {
	if err := protectedGuard("name")(p); err != nil {
		return err
	}
	if WeakensAccess(rolekit.Str(p, "account"), rolekit.Str(p, "right")) {
		return rolekit.Refuse("weakens_access", "This would open the share to everyone. Reading may be granted; changing or full control may not.")
	}
	return nil
}

func blockGuard(p map[string]any) error {
	if err := protectedGuard("name")(p); err != nil {
		return err
	}
	if LockOut(rolekit.Str(p, "account")) {
		return rolekit.Refuse("would_lock_out", "Blocking this account could lock everyone, or the administrators, out of the share.")
	}
	return nil
}

func device() winmod.Param {
	return winmod.Param{Name: "device", Type: winmod.Name, Required: true, Max: 64}
}

func shareName(required bool) winmod.Param {
	return winmod.Param{Name: "name", Type: winmod.Name, Required: required, Max: 80}
}

func acct() winmod.Param {
	return winmod.Param{Name: "account", Type: winmod.Text, Required: true, Max: 170, Pattern: accountPattern}
}

func optional(p winmod.Param) winmod.Param { p.Required = false; return p }

func library(file string) string {
	b, err := scriptFS.ReadFile("scripts/" + file)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Script is the text of an action's script as the agent receives it.
func Script(file string) string {
	return strings.Replace(library(file+".ps1"), "#@library common\n", library("_common.ps1"), 1)
}

func entry(tier int, file, label string, timeout int, decode func(json.RawMessage) (json.RawMessage, error), params ...winmod.Param) winmod.Action {
	a := winmod.Action{
		Module: modules.FileShares, Name: "file_shares." + file, Label: label, Version: 1,
		Script: Script(file), ScriptSHA256: pins[file], Params: params, Timeout: timeout, Decode: decode,
	}
	switch tier {
	case tier0:
		a.Permission, a.Keep = rbac.PermSharesView, time.Hour
	case tier1:
		a.Permission, a.Keep, a.Changes = rbac.PermSharesManage, 7*24*time.Hour, true
	case tier2:
		a.Permission, a.Keep, a.Changes = rbac.PermSharesManage, 7*24*time.Hour, true
		a.Confirm, a.Subject, a.SubjectIsDeviceName = true, "device", true
	case tier3:
		a.Permission, a.Keep, a.Changes = rbac.PermSharesManage, 7*24*time.Hour, true
		a.Destructive, a.Subject, a.SubjectIsDeviceName = true, "device", true
	}
	return a
}

func sensitive(a winmod.Action) winmod.Action {
	// There is no shares.view_sensitive: a Technician holds no shares.view at
	// all (ADR-0073), so shares.view opens who is connected and what they have
	// open. The result is kept for minutes, and audited as a count.
	a.Sensitive, a.SensitivePermission, a.Keep = true, rbac.PermSharesView, 15*time.Minute
	return a
}

// Actions are the file-sharing actions the server can run.
func Actions() []winmod.Action {
	status := entry(tier0, "status", "Read the file server state", 60, winmod.Typed[Status]())
	status.Freshness, status.Schedule = 5*time.Minute, time.Hour

	sessions := sensitive(entry(tier0, "session_list", "List the open sessions", 60, winmod.Typed[Sessions]()))
	sessions.CountField = "sessions"
	files := sensitive(entry(tier0, "openfile_list", "List the open files", 60, winmod.Typed[OpenFiles](), optional(shareName(false))))
	files.CountField = "files"
	list := entry(tier0, "share_list", "List the shares", 60, winmod.Typed[Shares]())
	list.Freshness = 5 * time.Minute
	list.CountField = "shares"

	create := entry(tier2, "share_create", "Create a share", 60, winmod.Typed[Done](), device(), shareName(true),
		winmod.Param{Name: "path", Type: winmod.Path, Required: true, Max: 260},
		winmod.Param{Name: "description", Type: winmod.Text, Max: 256},
		winmod.Param{Name: "enumeration", Type: winmod.Enum, Values: []string{"AccessBased", "Unrestricted"}},
		winmod.Param{Name: "caching", Type: winmod.Enum, Values: []string{"Manual", "Documents", "Programs", "BranchCache", "None"}})
	create.Guard = createGuard
	set := entry(tier2, "share_set", "Change a share", 30, winmod.Typed[Done](), device(), shareName(true),
		winmod.Param{Name: "description", Type: winmod.Text, Max: 256},
		winmod.Param{Name: "enumeration", Type: winmod.Enum, Values: []string{"AccessBased", "Unrestricted"}},
		winmod.Param{Name: "caching", Type: winmod.Enum, Values: []string{"Manual", "Documents", "Programs", "BranchCache", "None"}},
		winmod.Param{Name: "concurrentLimit", Type: winmod.Int, Min: 0, Max: 1000000},
		winmod.Param{Name: "encrypt", Type: winmod.Bool})
	set.Guard = protectedGuard("name")
	grant := entry(tier2, "share_access_grant", "Grant share access", 30, winmod.Typed[Done](), device(), shareName(true), acct(),
		winmod.Param{Name: "right", Type: winmod.Enum, Required: true, Values: []string{"Read", "Change", "Full"}})
	grant.Guard = grantGuard
	revoke := entry(tier2, "share_access_revoke", "Revoke share access", 30, winmod.Typed[Done](), device(), shareName(true), acct())
	revoke.Guard = protectedGuard("name")
	block := entry(tier2, "share_access_block", "Block an account from a share", 30, winmod.Typed[Done](), device(), shareName(true), acct())
	block.Guard = blockGuard
	unblock := entry(tier2, "share_access_unblock", "Unblock an account", 30, winmod.Typed[Done](), device(), shareName(true), acct())
	unblock.Guard = protectedGuard("name")
	remove := entry(tier3, "share_remove", "Remove a share (not its files)", 60, winmod.Typed[Done](), device(), shareName(true))
	remove.Guard = protectedGuard("name")

	return []winmod.Action{
		status, list,
		entry(tier0, "share_access_get", "Read a share's permissions", 30, winmod.Typed[Access](), shareName(true)),
		sessions, files,
		create, set, grant, revoke, block, unblock, remove,
		entry(tier2, "session_close", "Close a session", 30, winmod.Typed[Done](), device(),
			winmod.Param{Name: "id", Type: winmod.Text, Required: true, Max: 20, Pattern: idPattern}),
		entry(tier2, "openfile_close", "Close an open file", 30, winmod.Typed[Done](), device(),
			winmod.Param{Name: "id", Type: winmod.Text, Required: true, Max: 20, Pattern: idPattern}),
	}
}
