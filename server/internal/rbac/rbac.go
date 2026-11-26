// Package rbac implements EasyRMM's role-based access control.
//
// A user holds one or more role assignments. Each assignment grants the
// permissions of a built-in role at a scope: the whole platform (super
// administrators only), one organization, or one site. Authorization
// decisions are always made on the server against the scope of the resource
// being touched; the frontend only uses the same data to hide controls.
package rbac

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/google/uuid"
)

// Permission is a single capability.
type Permission string

// Permissions. Keep this list in sync with docs/security/rbac.md.
const (
	PermOrgView       Permission = "org.view"
	PermOrgManage     Permission = "org.manage"    // edit an organization, create sites in it
	PermOrgCreate     Permission = "org.create"    // create and delete organizations (platform-wide)
	PermSiteView      Permission = "site.view"     //
	PermSiteManage    Permission = "site.manage"   // edit a site and its device groups
	PermDeviceView    Permission = "device.view"   //
	PermDeviceEdit    Permission = "device.edit"   // rename, move between groups, tags, custom fields
	PermDeviceRetire  Permission = "device.retire" // revoke credentials, uninstall, delete
	PermDeviceHarden  Permission = "device.harden" // apply and undo hardening (ADR-0051)
	PermRemoteDesktop Permission = "device.remote_desktop"
	PermTerminal      Permission = "device.terminal"
	PermFiles         Permission = "device.files"
	PermScriptView    Permission = "script.view"
	PermScriptManage  Permission = "script.manage"
	PermScriptRun     Permission = "script.run"
	PermJobView       Permission = "job.view"
	PermJobManage     Permission = "job.manage" // cancel, reschedule
	// PermJobViewSensitive opens what a run printed and a job's argument
	// values, each read audited (ADR-0063). job.view shows the rest.
	PermJobViewSensitive Permission = "job.view_sensitive"
	PermSoftwareView     Permission = "software.view"
	PermSoftwareManage   Permission = "software.manage"
	PermPatchView        Permission = "patch.view"
	PermPatchManage      Permission = "patch.manage"
	// PermPatchConfigure marks who may change EasyPatch's standing rules
	// (policies, exclusions, windows): it makes someone an Admin in
	// EasyPatch rather than ReadOnly. Only organization-wide grants count.
	PermPatchConfigure Permission = "patch.configure"
	PermMonitorView    Permission = "monitoring.view"
	PermMonitorManage  Permission = "monitoring.manage"
	PermAlertView      Permission = "alert.view"
	PermAlertManage    Permission = "alert.manage"      // acknowledge, resolve
	PermEnrollManage   Permission = "enrollment.manage" // deployment tokens
	PermUserView       Permission = "user.view"
	PermUserManage     Permission = "user.manage"
	PermAuditView      Permission = "audit.view"
	PermReportView     Permission = "report.view"
	PermSettingsManage Permission = "settings.manage" // platform settings (platform-wide)
	// PermDocView reads customer documentation: contact information,
	// contacts, addresses, places and business hours (ADR-0066).
	PermDocView Permission = "doc.view"
	// PermDocManage creates, changes and deletes it. Checked at the row's
	// organization, or its site for a site's rows.
	PermDocManage Permission = "doc.manage"
	// PermLogView reads a device's agent logs (ADR-0069). It is not a view
	// permission: logs can hold user names, paths and host names, so
	// Technicians and above hold it, Read-Only does not.
	PermLogView Permission = "log.view"

	// The Windows management modules (ADR-0073). Each module has a view and
	// a manage permission; Active Directory adds two more. None is a
	// view permission: module state is more than a status light, so
	// Read-Only holds none of them.
	PermDefenderView    Permission = "defender.view"
	PermDefenderManage  Permission = "defender.manage"
	PermADView          Permission = "ad.view"
	PermADManage        Permission = "ad.manage"
	PermADResetPassword Permission = "ad.reset_password"
	PermADViewSensitive Permission = "ad.view_sensitive"
	PermADHelpdesk      Permission = "ad.helpdesk" // unlock, reset, enable, disable an ordinary user (ADR-0075)
	PermCAView          Permission = "ca.view"
	PermCAManage        Permission = "ca.manage"
	PermDNSView         Permission = "dns.view"
	PermDNSManage       Permission = "dns.manage"
	PermDHCPView        Permission = "dhcp.view"
	PermDHCPManage      Permission = "dhcp.manage"
	PermSharesView      Permission = "shares.view"
	PermSharesManage    Permission = "shares.manage"
	PermPrintView       Permission = "print.view"
	PermPrintManage     Permission = "print.manage"
	PermBackupView      Permission = "backup.view"
	PermBackupManage    Permission = "backup.manage"
	// Windows Backup adds two (ADR-0077): target paths, shares and accounts
	// name customers, and tier 3 actions erase, format or stop protecting.
	PermBackupViewSensitive Permission = "backup.view_sensitive"
	PermBackupDestroy       Permission = "backup.destroy"
	// The print server adds two (ADR-0076): job documents, owners and client
	// computers name people and files; tier 3 print actions clear a queue or
	// touch a driver.
	PermPrintViewSensitive Permission = "print.view_sensitive"
	PermPrintDestroy       Permission = "print.destroy"

	// PermRDPCredentialsSave lets a person save, replace and delete their own
	// saved RDP credential on a device they may open remote desktop on
	// (ADR-0079). It is never a way to read one.
	PermRDPCredentialsSave Permission = "device.rdp_credentials.save" //nolint:gosec // a permission name, not a credential
)

// Quick Assist (ADR-0080), all at the organization. Permanent links, taking a
// session over and installing permanently start at Organization
// Administrator.
const (
	PermQAView          Permission = "quickassist.view"
	PermQALinkCreate    Permission = "quickassist.link.create"
	PermQALinkPermanent Permission = "quickassist.link.permanent"
	PermQASession       Permission = "quickassist.session"
	PermQATakeover      Permission = "quickassist.session.takeover"
	PermQAInstall       Permission = "quickassist.install"
)

// ADR-0074's two added Defender permissions: PermDefenderViewSensitive reads
// file paths, user names and the exclusions an administrator added;
// PermDefenderWeaken does what lowers protection or restores a threat. Both
// start at Site Administrator.
const (
	PermDefenderViewSensitive Permission = "defender.view_sensitive"
	PermDefenderWeaken        Permission = "defender.weaken"
)

// The compliance engine's permissions (ADR-0078, section 8). The ones that
// need step-up (fix_high, fix_approve, attest, approve, admin) exist, and
// their actions are refused until step-up ships.
const (
	PermComplianceView       Permission = "compliance.view"
	PermComplianceScan       Permission = "compliance.scan"
	PermComplianceFix        Permission = "compliance.fix"
	PermComplianceFixHigh    Permission = "compliance.fix_high"
	PermComplianceFixApprove Permission = "compliance.fix_approve"
	PermComplianceEdit       Permission = "compliance.edit"
	PermComplianceAttest     Permission = "compliance.attest"
	PermComplianceApprove    Permission = "compliance.approve"
	PermComplianceExport     Permission = "compliance.export"
	PermComplianceAdmin      Permission = "compliance.admin"
)

// The registry editor's permissions (ADR-0067): PermRegistryView browses,
// reads, searches and exports a Windows computer's registry, and reads
// changes; PermRegistryEdit changes it. Reading a result needs
// job.view_sensitive as well.
const (
	PermRegistryView Permission = "registry.view"
	PermRegistryEdit Permission = "registry.edit"
)

// The disk-recovery-key permissions (ADR-0081, section 6). They are held only
// through the add-on roles below and are implied by no other role: a super
// administrator can already run anything on every computer, but reading a key
// must still be an explicit, recorded act of someone who holds the permission.
const (
	// PermNotificationManage changes, tests and reveals an organization's
	// notification channels (ADR-0053): Organization Administrators, from
	// organization-wide grants only (the role is never assigned at a site),
	// and super administrators for the platform's own.
	PermNotificationManage Permission = "notification.manage"
	PermRecoveryKeyRead    Permission = "device.recovery_key.read"
	PermRecoveryKeyApprove Permission = "device.recovery_key.approve"
)

// AddOnPermissions are the permissions only an add-on role grants.
var AddOnPermissions = []Permission{PermRecoveryKeyRead, PermRecoveryKeyApprove}

// AllPermissions lists every permission a built-in role other than the
// add-on roles can hold.
var AllPermissions = []Permission{
	PermOrgView, PermOrgManage, PermOrgCreate, PermSiteView, PermSiteManage,
	PermDeviceView, PermDeviceEdit, PermDeviceRetire, PermDeviceHarden, PermRemoteDesktop, PermRDPCredentialsSave, PermTerminal, PermFiles,
	PermScriptView, PermScriptManage, PermScriptRun, PermJobView, PermJobManage, PermJobViewSensitive, PermRegistryView, PermRegistryEdit,
	PermSoftwareView, PermSoftwareManage, PermPatchView, PermPatchManage, PermPatchConfigure,
	PermMonitorView, PermMonitorManage, PermAlertView, PermAlertManage,
	PermEnrollManage, PermUserView, PermUserManage, PermAuditView, PermReportView, PermSettingsManage,
	PermDocView, PermDocManage, PermLogView,
	PermDefenderView, PermDefenderManage, PermADView, PermADManage, PermADResetPassword, PermADViewSensitive, PermADHelpdesk,
	PermDefenderViewSensitive, PermDefenderWeaken,
	PermCAView, PermCAManage, PermDNSView, PermDNSManage, PermDHCPView, PermDHCPManage,
	PermSharesView, PermSharesManage, PermPrintView, PermPrintManage, PermBackupView, PermBackupManage,
	PermBackupViewSensitive, PermBackupDestroy, PermPrintViewSensitive, PermPrintDestroy,
	PermComplianceView, PermComplianceScan, PermComplianceFix, PermComplianceFixHigh, PermComplianceFixApprove,
	PermComplianceEdit, PermComplianceAttest, PermComplianceApprove, PermComplianceExport, PermComplianceAdmin,
	PermQAView, PermQALinkCreate, PermQALinkPermanent, PermQASession, PermQATakeover, PermQAInstall,
	PermNotificationManage,
}

// globalOnly permissions are only meaningful platform-wide and are never
// granted by an organization- or site-scoped assignment.
var globalOnly = map[Permission]bool{PermOrgCreate: true, PermSettingsManage: true, PermComplianceAdmin: true}

// Role identifies a built-in role.
type Role string

const (
	RoleSuperAdmin Role = "super_admin"
	RoleOrgAdmin   Role = "org_admin"
	RoleSiteAdmin  Role = "site_admin"
	RoleTechnician Role = "technician"
	RoleReadOnly   Role = "read_only"
	// The add-on roles (ADR-0081): assigned beside a person's ordinary role,
	// at an organization or a site, they add one permission and nothing else.
	RoleKeyReader   Role = "key_reader"
	RoleKeyApprover Role = "key_approver"
)

// ScopeKind describes which scopes a role may be assigned at.
type ScopeKind int

const (
	ScopeGlobal ScopeKind = iota
	ScopeOrganization
	ScopeSite
)

// String returns the scope's name.
func (k ScopeKind) String() string {
	switch k {
	case ScopeGlobal:
		return "global"
	case ScopeOrganization:
		return "organization"
	case ScopeSite:
		return "site"
	}
	return "unknown"
}

// MarshalText encodes the scope by name for JSON.
func (k ScopeKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// RoleDef describes a built-in role.
type RoleDef struct {
	Role        Role
	Name        string
	Description string
	// Rank orders roles by privilege; a user can only grant roles of lower or
	// equal rank inside scopes they administer.
	Rank        int
	Permissions []Permission
	Scopes      []ScopeKind
}

var viewPerms = []Permission{
	PermOrgView, PermSiteView, PermDeviceView, PermScriptView, PermJobView,
	PermSoftwareView, PermPatchView, PermMonitorView, PermAlertView, PermReportView, PermDocView,
}

func union(sets ...[]Permission) []Permission {
	seen := map[Permission]bool{}
	var out []Permission
	for _, s := range sets {
		for _, p := range s {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

var technicianPerms = union(viewPerms, []Permission{
	PermDeviceEdit, PermRemoteDesktop, PermRDPCredentialsSave, PermTerminal, PermFiles,
	PermScriptRun, PermJobManage, PermJobViewSensitive, PermSoftwareManage, PermPatchManage, PermAlertManage,
	PermDocManage, PermLogView, PermRegistryView, PermRegistryEdit,
	// The Windows modules (ADR-0073): every view except ad.view_sensitive,
	// ca.view, dns.view and shares.view, which start at Site Administrator,
	// plus the reversible manage permissions. No Active Directory writes.
	PermDefenderView, PermADView, PermDHCPView, PermPrintView, PermBackupView,
	PermDefenderManage, PermBackupManage, PermPrintManage, PermADHelpdesk,
	// Compliance (ADR-0078): view, scan and the fixes that need no step-up.
	PermComplianceView, PermComplianceScan, PermComplianceFix,
	PermQAView, PermQALinkCreate, PermQASession,
})

var siteAdminPerms = union(technicianPerms, []Permission{
	PermSiteManage, PermDeviceRetire, PermDeviceHarden, PermScriptManage, PermMonitorManage,
	PermEnrollManage, PermUserView, PermAuditView,
	PermDefenderViewSensitive, PermDefenderWeaken,
	PermDNSManage, PermDHCPManage, PermSharesManage, PermCAView, PermDNSView, PermSharesView, PermADView, PermADViewSensitive,
	PermBackupViewSensitive, PermBackupDestroy, PermPrintViewSensitive, PermPrintDestroy,
})

var orgAdminPerms = union(siteAdminPerms, []Permission{PermOrgManage, PermUserManage, PermPatchConfigure,
	PermCAManage, PermADManage, PermADResetPassword,
	// Every compliance permission but compliance.admin, which is server-wide.
	PermComplianceFixHigh, PermComplianceFixApprove, PermComplianceEdit, PermComplianceAttest, PermComplianceApprove,
	PermComplianceExport,
	PermQALinkPermanent, PermQATakeover, PermQAInstall,
	PermNotificationManage})

// Roles is the catalog of built-in roles.
var Roles = map[Role]RoleDef{
	RoleSuperAdmin: {
		Role: RoleSuperAdmin, Name: "Super Administrator", Rank: 100,
		Description: "Full control of the platform, every organization and all settings.",
		Permissions: union(AllPermissions), Scopes: []ScopeKind{ScopeGlobal},
	},
	RoleOrgAdmin: {
		Role: RoleOrgAdmin, Name: "Organization Administrator", Rank: 80,
		Description: "Manages one organization: its sites, devices, users and automation.",
		Permissions: orgAdminPerms, Scopes: []ScopeKind{ScopeOrganization},
	},
	RoleSiteAdmin: {
		Role: RoleSiteAdmin, Name: "Site Administrator", Rank: 60,
		Description: "Manages devices, enrollment, monitoring and scripts for a site or organization.",
		Permissions: siteAdminPerms, Scopes: []ScopeKind{ScopeOrganization, ScopeSite},
	},
	RoleTechnician: {
		Role: RoleTechnician, Name: "Technician", Rank: 40,
		Description: "Supports assigned devices: remote access, scripts, software, patches and alerts.",
		Permissions: technicianPerms, Scopes: []ScopeKind{ScopeOrganization, ScopeSite},
	},
	RoleKeyReader: {
		Role: RoleKeyReader, Name: "Recovery Key Reader", Rank: 10,
		Description: "Add-on: may read a device's disk recovery key, with a reason and a second factor. Never part of another role.",
		Permissions: []Permission{PermRecoveryKeyRead}, Scopes: []ScopeKind{ScopeOrganization, ScopeSite},
	},
	RoleKeyApprover: {
		Role: RoleKeyApprover, Name: "Recovery Key Approver", Rank: 10,
		Description: "Add-on: may approve another person's request to read a disk recovery key, where the organization asks for two people.",
		Permissions: []Permission{PermRecoveryKeyApprove}, Scopes: []ScopeKind{ScopeOrganization, ScopeSite},
	},
	RoleReadOnly: {
		Role: RoleReadOnly, Name: "Read-Only", Rank: 20,
		Description: "Views devices, alerts and reports without making changes.",
		Permissions: union(viewPerms), Scopes: []ScopeKind{ScopeOrganization, ScopeSite},
	},
}

// Assignment grants a role at a scope. For a site assignment OrganizationID
// is the site's organization.
type Assignment struct {
	Role           Role
	OrganizationID uuid.UUID // uuid.Nil for global assignments
	SiteID         uuid.UUID // uuid.Nil unless the assignment is site-scoped
}

// Kind returns the scope kind of the assignment.
func (a Assignment) Kind() ScopeKind {
	switch {
	case a.SiteID != uuid.Nil:
		return ScopeSite
	case a.OrganizationID != uuid.Nil:
		return ScopeOrganization
	default:
		return ScopeGlobal
	}
}

// Placement is where a person with the assignments as belongs: the one
// organization all of them are in, and, with only one assignment, its
// site. It is uuid.Nil when they have none, one on the whole platform, or
// assignments in several organizations; the order of as does not matter.
// Audit records about the person go there, so that its administrators
// see them, and the person's account mail counts against its limits.
func Placement(as []Assignment) (org, site uuid.UUID) {
	if len(as) == 0 {
		return uuid.Nil, uuid.Nil
	}
	for _, a := range as {
		if a.OrganizationID == uuid.Nil || a.OrganizationID != as[0].OrganizationID {
			return uuid.Nil, uuid.Nil
		}
	}
	if len(as) == 1 {
		return as[0].OrganizationID, as[0].SiteID
	}
	return as[0].OrganizationID, uuid.Nil
}

// ErrInvalidAssignment reports an assignment whose scope does not suit its role.
var ErrInvalidAssignment = errors.New("rbac: invalid role assignment")

// Validate checks that the role exists and the scope is allowed for it.
func (a Assignment) Validate() error {
	def, ok := Roles[a.Role]
	if !ok {
		return fmt.Errorf("%w: unknown role %q", ErrInvalidAssignment, a.Role)
	}
	if a.SiteID != uuid.Nil && a.OrganizationID == uuid.Nil {
		return fmt.Errorf("%w: site assignment without organization", ErrInvalidAssignment)
	}
	if !slices.Contains(def.Scopes, a.Kind()) {
		return fmt.Errorf("%w: role %q cannot be assigned at this scope", ErrInvalidAssignment, a.Role)
	}
	return nil
}

// Resource locates the object being accessed. Platform-level objects have
// neither an organization nor a site.
type Resource struct {
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
}

// Org is a convenience constructor for an organization-level resource.
func Org(id uuid.UUID) Resource { return Resource{OrganizationID: id} }

// Site is a convenience constructor for a site-level resource.
func Site(orgID, siteID uuid.UUID) Resource { return Resource{OrganizationID: orgID, SiteID: siteID} }

// Scope is the set of organizations and sites in which a permission holds.
type Scope struct {
	All   bool
	Orgs  []uuid.UUID // full access to every site in these organizations
	Sites []uuid.UUID // access to these individual sites
}

// Empty reports whether the scope grants nothing.
func (s Scope) Empty() bool { return !s.All && len(s.Orgs) == 0 && len(s.Sites) == 0 }

// Principal is an authenticated user's resolved permissions.
type Principal struct {
	UserID      uuid.UUID
	Assignments []Assignment
	global      map[Permission]bool
	orgs        map[Permission]map[uuid.UUID]bool
	sites       map[Permission]map[uuid.UUID]bool
	siteOrg     map[uuid.UUID]uuid.UUID
}

// NewPrincipal resolves a user's assignments. Invalid assignments are
// rejected rather than ignored so data corruption cannot silently widen or
// narrow access.
func NewPrincipal(userID uuid.UUID, assignments []Assignment) (*Principal, error) {
	p := &Principal{
		UserID:      userID,
		Assignments: slices.Clone(assignments),
		global:      map[Permission]bool{},
		orgs:        map[Permission]map[uuid.UUID]bool{},
		sites:       map[Permission]map[uuid.UUID]bool{},
		siteOrg:     map[uuid.UUID]uuid.UUID{},
	}
	for _, a := range assignments {
		if err := a.Validate(); err != nil {
			return nil, err
		}
		for _, perm := range Roles[a.Role].Permissions {
			switch a.Kind() {
			case ScopeGlobal:
				p.global[perm] = true
			case ScopeOrganization:
				if globalOnly[perm] {
					continue
				}
				if p.orgs[perm] == nil {
					p.orgs[perm] = map[uuid.UUID]bool{}
				}
				p.orgs[perm][a.OrganizationID] = true
			case ScopeSite:
				if globalOnly[perm] || perm == PermOrgManage || perm == PermUserManage || perm == PermPatchConfigure {
					// A site-scoped role cannot manage its parent organization, its
					// users or its EasyPatch rules, whatever the role definition says.
					continue
				}
				if p.sites[perm] == nil {
					p.sites[perm] = map[uuid.UUID]bool{}
				}
				p.sites[perm][a.SiteID] = true
				p.siteOrg[a.SiteID] = a.OrganizationID
			}
		}
	}
	return p, nil
}

// IsSuperAdmin reports whether the principal holds the super administrator role.
func (p *Principal) IsSuperAdmin() bool {
	for _, a := range p.Assignments {
		if a.Role == RoleSuperAdmin {
			return true
		}
	}
	return false
}

// CanGlobal reports whether the permission is held platform-wide.
func (p *Principal) CanGlobal(perm Permission) bool { return p != nil && p.global[perm] }

// Can reports whether the permission holds for the resource.
//
// Organization-level resources (Resource.SiteID == uuid.Nil) require an
// organization-wide grant, except for read permissions on the organization
// itself which site-scoped users need in order to see where their sites live.
func (p *Principal) Can(perm Permission, r Resource) bool {
	if p == nil {
		return false
	}
	if p.global[perm] {
		return true
	}
	if r.OrganizationID == uuid.Nil {
		return false // platform resource without a global grant
	}
	if p.orgs[perm][r.OrganizationID] {
		return true
	}
	if r.SiteID != uuid.Nil {
		return p.sites[perm][r.SiteID] && p.siteOrg[r.SiteID] == r.OrganizationID
	}
	if perm == PermOrgView {
		for siteID := range p.sites[PermSiteView] {
			if p.siteOrg[siteID] == r.OrganizationID {
				return true
			}
		}
	}
	return false
}

// CanAnywhere reports whether the permission holds anywhere: platform-wide,
// in an organization or at a site. Shared, platform-level objects (the
// shared script library) are read with it.
func (p *Principal) CanAnywhere(perm Permission) bool {
	return p != nil && (p.global[perm] || len(p.orgs[perm]) > 0 || len(p.sites[perm]) > 0)
}

// CanInOrg reports whether the permission holds in the organization or at
// any of its sites. Organization-level objects that sites use (an
// organization's scripts) are read with it.
func (p *Principal) CanInOrg(perm Permission, orgID uuid.UUID) bool {
	if p == nil || orgID == uuid.Nil {
		return p != nil && p.global[perm]
	}
	if p.global[perm] || p.orgs[perm][orgID] {
		return true
	}
	for siteID := range p.sites[perm] {
		if p.siteOrg[siteID] == orgID {
			return true
		}
	}
	return false
}

// Scope returns where the permission holds, for building filtered queries.
func (p *Principal) Scope(perm Permission) Scope {
	if p == nil {
		return Scope{}
	}
	if p.global[perm] {
		return Scope{All: true}
	}
	var s Scope
	for id := range p.orgs[perm] {
		s.Orgs = append(s.Orgs, id)
	}
	for id := range p.sites[perm] {
		if !p.orgs[perm][p.siteOrg[id]] { // already covered by an org grant
			s.Sites = append(s.Sites, id)
		}
	}
	sortIDs(s.Orgs)
	sortIDs(s.Sites)
	return s
}

// OrgsWithSiteAccess returns organizations the principal can reach only
// through individual site assignments. Such users may read the organization
// record but nothing else at organization level.
func (p *Principal) OrgsWithSiteAccess() []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for siteID := range p.sites[PermSiteView] {
		org := p.siteOrg[siteID]
		if !seen[org] && !p.orgs[PermOrgView][org] {
			seen[org] = true
			out = append(out, org)
		}
	}
	sortIDs(out)
	return out
}

// Permissions returns every permission the principal holds anywhere, for the
// frontend to decide which navigation to show.
func (p *Principal) Permissions() []Permission {
	set := map[Permission]bool{}
	for perm := range p.global {
		set[perm] = true
	}
	for perm, m := range p.orgs {
		if len(m) > 0 {
			set[perm] = true
		}
	}
	for perm, m := range p.sites {
		if len(m) > 0 {
			set[perm] = true
		}
	}
	out := make([]Permission, 0, len(set))
	for perm := range set {
		out = append(out, perm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ScopedPermissions returns, for each permission held in some organizations or
// sites but not platform-wide, where it holds: the organizations with a grant
// over all their sites, and the individual sites outside those. The frontend
// checks a permission at the page's own scope with it.
func (p *Principal) ScopedPermissions() map[Permission]Scope {
	out := map[Permission]Scope{}
	for _, perm := range p.Permissions() {
		if p.global[perm] {
			continue
		}
		out[perm] = p.Scope(perm)
	}
	return out
}

// GlobalPermissions returns the permissions the principal holds
// platform-wide, for the frontend to show what only those may do: deciding
// on devices that wait for approval and belong to no organization yet.
func (p *Principal) GlobalPermissions() []Permission {
	out := make([]Permission, 0, len(p.global))
	for perm, ok := range p.global {
		if ok {
			out = append(out, perm)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// CanAssign reports whether the principal may grant (or revoke) the given
// assignment. It prevents privilege escalation:
//   - only super administrators grant super administrator;
//   - otherwise the actor needs user.manage over the target scope and may
//     only grant roles ranked at or below their best role in that scope.
func (p *Principal) CanAssign(a Assignment) bool {
	if p == nil || a.Validate() != nil {
		return false
	}
	if p.IsSuperAdmin() {
		return true
	}
	if a.Role == RoleSuperAdmin {
		return false
	}
	target := Resource{OrganizationID: a.OrganizationID, SiteID: a.SiteID}
	if !p.Can(PermUserManage, target) {
		return false
	}
	return Roles[a.Role].Rank <= p.bestRankFor(target)
}

func (p *Principal) bestRankFor(r Resource) int {
	best := 0
	for _, a := range p.Assignments {
		covers := false
		switch a.Kind() {
		case ScopeGlobal:
			covers = true
		case ScopeOrganization:
			covers = a.OrganizationID == r.OrganizationID
		case ScopeSite:
			covers = r.SiteID != uuid.Nil && a.SiteID == r.SiteID
		}
		if covers && Roles[a.Role].Rank > best {
			best = Roles[a.Role].Rank
		}
	}
	return best
}

func sortIDs(ids []uuid.UUID) {
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
}
