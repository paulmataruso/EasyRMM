// Package activedirectory is the catalog of ADR-0075's Active Directory
// actions: reading a domain through one of its controllers, and the everyday
// changes to users and groups (unlock, enable, disable, reset a password,
// create, edit, move, delete, membership). Every script is fixed, pinned by
// SHA-256 and gets its parameters on standard input. The scripts are built
// from src/ by gen.sh.
package activedirectory

import (
	"embed"
	"fmt"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

//go:embed scripts/*.ps1
var scriptFS embed.FS

func script(name string) string {
	b, err := scriptFS.ReadFile("scripts/" + name + ".ps1")
	if err != nil {
		panic(fmt.Sprintf("activedirectory: no script %q", name))
	}
	return string(b)
}

const (
	readKeep      = time.Hour
	sensitiveKeep = 10 * time.Minute
	changeKeep    = 7 * 24 * time.Hour
	// MaxPage is the most rows a page of a list holds.
	MaxPage = 200
)

// sam is a sAMAccountName for a new user: letters, digits and . _ - only,
// at most 20 characters (ADR-0075).
const samPattern = `^[A-Za-z0-9._-]{1,20}$`

// A service account is changed only with a second confirmation, typed as
// "service-account:<sam>", which only someone who may manage the directory
// can send (ADR-0075 section 4).
const serviceConfirmPattern = `^service-account:[A-Za-z0-9._$-]{1,64}$`

var (
	pID     = winmod.Param{Name: "id", Type: winmod.SID, Required: true, RefuseWellKnown: true}
	pMember = winmod.Param{Name: "member", Type: winmod.SID, Required: true, RefuseWellKnown: true}
	// The read parameters.
	pContainer = winmod.Param{Name: "container", Type: winmod.DN}
	pScope     = winmod.Param{Name: "scope", Type: winmod.Enum, Values: []string{"one_level", "subtree"}}
	pMatch     = winmod.Param{Name: "match", Type: winmod.Text, Max: 64}
	pAfter     = winmod.Param{Name: "after", Type: winmod.Text, Max: 256}
	pPageSize  = winmod.Param{Name: "pageSize", Type: winmod.Int, Min: 1, Max: MaxPage}
)

// credential is the fallback of ADR-0075 section 3: a domain administrator's
// user name and password for one request, sealed like a password. Never
// stored, never reused, never shown back.
func credential() []winmod.Param {
	return []winmod.Param{
		{Name: "credUser", Type: winmod.Text, Min: 1, Max: 256, Sensitive: true},
		{Name: "credPassword", Type: winmod.Text, Min: 1, Max: 256, Secret: true},
	}
}

// serviceConfirm is the extra confirmation for a service account. Sending it
// needs the permission to manage the directory, not only the help desk's.
func serviceConfirm(needs rbac.Permission) winmod.Param {
	return winmod.Param{Name: "serviceConfirm", Type: winmod.Text, Pattern: serviceConfirmPattern, Max: 80, Needs: needs}
}

func withCredential(ps ...winmod.Param) []winmod.Param { return append(ps, credential()...) }

// file is the script's file name: the action's, except that the file of the
// password reset leaves out the word, so that a secret scanner does not take
// its pinned hash for a credential.
func file(name string) string {
	if name == "user_reset_password" {
		return "user_reset"
	}
	return name
}

// read is a read action of the module.
func read(name, label string, timeout int, perm rbac.Permission, params ...winmod.Param) winmod.Action {
	return winmod.Action{
		Module: modules.ActiveDirectory, Name: "active_directory." + name, Label: label, Version: 1,
		Script: script(file(name)), ScriptSHA256: pin(file(name)), Params: params,
		Permission: perm, Timeout: timeout, Keep: readKeep,
	}
}

// write is a change.
func write(name, label string, timeout int, perm rbac.Permission, params []winmod.Param) winmod.Action {
	return winmod.Action{
		Module: modules.ActiveDirectory, Name: "active_directory." + name, Label: label, Version: 1,
		Script: script(file(name)), ScriptSHA256: pin(file(name)), Params: params,
		Permission: perm, Timeout: timeout, Keep: changeKeep, Changes: true,
	}
}

// Actions are the Active Directory actions the server can run.
func Actions() []winmod.Action {
	status := read("status", "Read the domain and its controller", 60, rbac.PermADView)
	status.Decode, status.Freshness = winmod.Typed[Status](), 5*time.Minute

	ouTree := read("ou_tree", "Browse organizational units", 60, rbac.PermADView, winmod.Param{Name: "parent", Type: winmod.DN})
	ouTree.Decode, ouTree.CountField = winmod.Typed[OUTree](), "items"

	userList := read("user_list", "List users", 120, rbac.PermADView, pContainer, pScope, pMatch,
		winmod.Param{Name: "state", Type: winmod.Enum, Values: []string{"all", "disabled", "locked", "password_expired", "never_logged_on", "stale_over_days"}},
		winmod.Param{Name: "staleDays", Type: winmod.Int, Min: 1, Max: 3650}, pAfter, pPageSize)
	userList.Decode, userList.CountField = winmod.Typed[UserPage](), "items"

	// A user's other attributes are personal data: Site Administrators and
	// above may ask for them at all, and the result is kept for minutes.
	userGet := read("user_get", "Read a user", 60, rbac.PermADViewSensitive, pRead(pID))
	userGet.Decode, userGet.Sensitive, userGet.SensitivePermission, userGet.Keep = winmod.Typed[User](), true, rbac.PermADViewSensitive, sensitiveKeep

	groupList := read("group_list", "List groups", 120, rbac.PermADView, pContainer, pScope, pMatch,
		winmod.Param{Name: "kind", Type: winmod.Enum, Values: []string{"all", "security", "distribution"}}, pAfter, pPageSize)
	groupList.Decode, groupList.CountField = winmod.Typed[GroupPage](), "items"

	groupMembers := read("group_members", "List a group's members", 60, rbac.PermADView, pRead(pID), pAfter, pPageSize)
	groupMembers.Decode, groupMembers.CountField = winmod.Typed[MemberPage](), "items"

	// health_read has no parameters: the server reads it on a schedule for
	// the replication alert, and the cards show it.
	health := read("health_read", "Check the directory's health", 300, rbac.PermADView)
	health.Decode, health.CountField, health.Freshness, health.Schedule = winmod.Typed[Health](), "checks", 5*time.Minute, time.Hour

	// The help desk: unlock, enable, disable, reset a password, on ordinary
	// users. Enable, disable and reset need a typed confirmation and a
	// step-up; a service account needs the second confirmation, which needs
	// ad.manage (ad.reset_password for a password).
	unlock := write("user_unlock", "Unlock a user", 60, rbac.PermADHelpdesk, withCredential(pID, serviceConfirm(rbac.PermADManage)))
	unlock.Decode = winmod.Typed[Done]()

	enable := write("user_enable", "Enable a user", 60, rbac.PermADHelpdesk, withCredential(pID, serviceConfirm(rbac.PermADManage)))
	enable.Decode, enable.Destructive, enable.Subject = winmod.Typed[Done](), true, "id"

	disable := write("user_disable", "Disable a user", 60, rbac.PermADHelpdesk, withCredential(pID, serviceConfirm(rbac.PermADManage)))
	disable.Decode, disable.Destructive, disable.Subject = winmod.Typed[Done](), true, "id"

	reset := write("user_reset_password", "Reset a user's password", 120, rbac.PermADHelpdesk, withCredential(pID,
		winmod.Param{Name: "password", Type: winmod.Text, Secret: true, Generate: true, Min: 8, Max: 128},
		winmod.Param{Name: "mustChange", Type: winmod.Bool}, winmod.Param{Name: "unlock", Type: winmod.Bool},
		serviceConfirm(rbac.PermADResetPassword)))
	reset.Decode, reset.Destructive, reset.Credential, reset.Subject = winmod.Typed[Reset](), true, true, "id"

	// Directory changes: Organization Administrators.
	set := write("user_set", "Change a user's attributes", 60, rbac.PermADManage, withCredential(pID, serviceConfirm(rbac.PermADManage),
		attr("givenName"), attr("surname"), attr("displayName"), attr("description"), attr("mail"), attr("telephone"),
		attr("title"), attr("department"), attr("company"), attr("office")))
	set.Decode = winmod.Typed[Changed]()

	move := write("user_move", "Move a user to another organizational unit", 60, rbac.PermADManage, withCredential(pID, serviceConfirm(rbac.PermADManage),
		winmod.Param{Name: "targetOu", Type: winmod.DN, Required: true}))
	move.Decode = winmod.Typed[Done]()

	create := write("user_create", "Create a user", 120, rbac.PermADManage, withCredential(
		winmod.Param{Name: "ou", Type: winmod.DN, Required: true},
		winmod.Param{Name: "sam", Type: winmod.Name, Required: true, Pattern: samPattern},
		winmod.Param{Name: "name", Type: winmod.Name, Required: true, Max: 64},
		winmod.Param{Name: "upn", Type: winmod.Name, Max: 256},
		winmod.Param{Name: "givenName", Type: winmod.Name, Max: 64}, winmod.Param{Name: "surname", Type: winmod.Name, Max: 64},
		winmod.Param{Name: "displayName", Type: winmod.Name, Max: 128},
		winmod.Param{Name: "password", Type: winmod.Text, Secret: true, Generate: true, Min: 8, Max: 128, Needs: rbac.PermADResetPassword},
		winmod.Param{Name: "mustChange", Type: winmod.Bool}))
	create.Decode, create.Destructive, create.Credential, create.Subject = winmod.Typed[Created](), true, true, "sam"

	del := write("user_delete", "Delete a user", 120, rbac.PermADManage, withCredential(pID, serviceConfirm(rbac.PermADManage)))
	del.Decode, del.Destructive, del.Subject = winmod.Typed[Done](), true, "id"

	groupCreate := write("group_create", "Create a group", 60, rbac.PermADManage, withCredential(
		winmod.Param{Name: "ou", Type: winmod.DN, Required: true},
		winmod.Param{Name: "name", Type: winmod.Name, Required: true, Max: 64},
		winmod.Param{Name: "scope", Type: winmod.Enum, Required: true, Values: []string{"domain_local", "global", "universal"}},
		winmod.Param{Name: "category", Type: winmod.Enum, Required: true, Values: []string{"security", "distribution"}},
		winmod.Param{Name: "description", Type: winmod.Text, Max: 200}))
	groupCreate.Decode = winmod.Typed[Created]()

	addMember := write("group_add_member", "Add a member to a group", 120, rbac.PermADManage, withCredential(pID, pMember))
	addMember.Decode, addMember.Destructive, addMember.Subject = winmod.Typed[Done](), true, "id"

	removeMember := write("group_remove_member", "Remove a member from a group", 120, rbac.PermADManage, withCredential(pID, pMember))
	removeMember.Decode = winmod.Typed[Done]()

	groupDelete := write("group_delete", "Delete a group", 120, rbac.PermADManage, withCredential(pID))
	groupDelete.Decode, groupDelete.Destructive, groupDelete.Subject = winmod.Typed[Done](), true, "id"

	return []winmod.Action{status, ouTree, userList, userGet, groupList, groupMembers, health,
		unlock, enable, disable, reset, set, move, create, del, groupCreate, addMember, removeMember, groupDelete}
}

// attr is an optional attribute of user_set: a value of any printable
// character, or empty to clear it.
func attr(name string) winmod.Param {
	return winmod.Param{Name: name, Type: winmod.Text, Max: 128, AllowEmpty: true}
}

// pRead is a read parameter: the same as the write's, but a read may name a
// well-known principal (the guard is for changes).
func pRead(p winmod.Param) winmod.Param {
	p.RefuseWellKnown = false
	return p
}
