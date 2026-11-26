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
)

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

// Service holds the framework's state.
type Service struct {
	db      *database.DB
	audit   *audit.Logger
	log     *slog.Logger
	now     func() time.Time
	removed []RemovedHook
}

// New returns a Service.
func New(db *database.DB, auditLog *audit.Logger, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, log: log, now: time.Now}
}

// OnRoleRemoved registers a hook for a role that disappeared. Call it while
// wiring, before the server serves.
func (s *Service) OnRoleRemoved(h RemovedHook) { s.removed = append(s.removed, h) }
