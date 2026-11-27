// Package modules is the framework the Windows management modules build on
// (ADR-0073): the roles a device's agent reports, the per-organization and
// per-site toggles, and the one gate every module's automatic behavior asks.
package modules

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Module names a Windows management module.
type Module string

// The modules.
const (
	Defender             Module = "defender"
	ActiveDirectory      Module = "active_directory"
	CertificateAuthority Module = "certificate_authority"
	DNS                  Module = "dns"
	DHCP                 Module = "dhcp"
	FileShares           Module = "file_shares"
	Print                Module = "print"
	WindowsBackup        Module = "windows_backup"
	GroupPolicy          Module = "group_policy"
)

// Non-role modules: available on any Windows device, not gated by a detected
// server role. They have no toggle and no entry in Catalog.
const (
	BitLocker Module = "bitlocker"
	NTP       Module = "ntp"
	LAPS      Module = "laps"
)

// nonRole lists the modules that run on any Windows device.
var nonRole = map[Module]bool{BitLocker: true, NTP: true, LAPS: true}

// Known says whether a module is one the framework can run actions of: the
// catalogue's, or any non-role module.
func Known(m Module) bool {
	if nonRole[m] {
		return true
	}
	_, ok := Lookup(m)
	return ok
}

// Def describes a module: the role whose presence offers it and the
// permission that reads it.
type Def struct {
	Module Module
	Label  string
	// Role is the agentproto role name that must be detected.
	Role string
	// View is the permission that opens the module's state.
	View rbac.Permission
}

// Catalog lists every module, in the order the console shows them.
var Catalog = []Def{
	{Defender, "Microsoft Defender", agentproto.RoleDefender, rbac.PermDefenderView},
	{ActiveDirectory, "Active Directory", agentproto.RoleADDS, rbac.PermADView},
	{CertificateAuthority, "Certificate Authority", agentproto.RoleADCS, rbac.PermCAView},
	{DNS, "DNS", agentproto.RoleDNS, rbac.PermDNSView},
	{DHCP, "DHCP", agentproto.RoleDHCP, rbac.PermDHCPView},
	{FileShares, "File shares", agentproto.RoleFileServer, rbac.PermSharesView},
	{Print, "Print server", agentproto.RolePrintServer, rbac.PermPrintView},
	{WindowsBackup, "Windows Backup", agentproto.RoleWindowsBackup, rbac.PermBackupView},
	{GroupPolicy, "Group Policy", agentproto.RoleGPMC, rbac.PermGPOView},
}

// Lookup returns a module's definition.
func Lookup(m Module) (Def, bool) {
	for _, d := range Catalog {
		if d.Module == m {
			return d, true
		}
	}
	return Def{}, false
}

// ForRole returns the module a role offers.
func ForRole(role string) (Def, bool) {
	for _, d := range Catalog {
		if d.Role == role {
			return d, true
		}
	}
	return Def{}, false
}

// RolesKnownFor is how long the last reported roles stand when an agent
// stops reporting them; after it they read as unknown (ADR-0073).
const RolesKnownFor = 7 * 24 * time.Hour

// RemovedHook is called, in the heartbeat's transaction, when a role that a
// device reported is no longer in its report. A module registers one to
// clear its snapshots for the device and resolve its open alerts with the
// reason "role removed".
type RemovedHook func(ctx context.Context, tx pgx.Tx, deviceID, orgID uuid.UUID, m Module) error

// EnabledHook is called, in the transaction of the change, when a toggle
// turns a module on for an organization or one of its sites. A module
// registers one to create its default alert policies for the organization
// (idempotently).
type EnabledHook func(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, m Module) error

// Service holds the framework's state.
type Service struct {
	db      *database.DB
	audit   *audit.Logger
	log     *slog.Logger
	now     func() time.Time
	removed []RemovedHook
	enabled []EnabledHook
}

// New returns a Service.
func New(db *database.DB, auditLog *audit.Logger, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, log: log, now: time.Now}
}

// OnEnabled registers a hook for a module turned on. Call it while wiring,
// before the server serves.
func (s *Service) OnEnabled(h EnabledHook) { s.enabled = append(s.enabled, h) }

// OnRoleRemoved registers a hook for a role that disappeared. Call it while
// wiring, before the server serves.
func (s *Service) OnRoleRemoved(h RemovedHook) { s.removed = append(s.removed, h) }
