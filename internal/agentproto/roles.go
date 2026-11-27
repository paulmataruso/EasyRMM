package agentproto

// Role names a Windows role or feature the agent detects (ADR-0073). The
// set is fixed; the server drops names it does not know.
const (
	RoleADDS          = "ad_ds"
	RoleADCS          = "ad_cs"
	RoleDNS           = "dns"
	RoleDHCP          = "dhcp"
	RoleFileServer    = "file_server"
	RolePrintServer   = "print_server"
	RoleWindowsBackup = "windows_backup"
	RoleDefender      = "defender"
	// RoleGPMC is a domain controller with the Group Policy Management tools
	// (the GroupPolicy PowerShell module): ADR-0083 offers Group Policy there.
	RoleGPMC = "gpmc"
)

// RoleNames lists every role name in a fixed order.
var RoleNames = []string{
	RoleADDS, RoleADCS, RoleDNS, RoleDHCP, RoleFileServer, RolePrintServer, RoleWindowsBackup, RoleDefender,
	RoleGPMC,
}

// Role states. Present is a role that is installed and set up; the others
// say why a role that was found is not fully there.
const (
	RolePresent      = "present"
	RoleUnconfigured = "unconfigured" // installed, not set up (DHCP without its parameters)
	RoleUnknown      = "unknown"      // found, but the state could not be read in time
	RolePassive      = "passive"      // Defender installed, another product active
	// RoleNotInstalled is a server without the Windows Server Backup feature:
	// reported so the console can offer to install it (ADR-0077).
	RoleNotInstalled = "not_installed"
)

// Role is one entry of Facts.Roles.
type Role struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
}

// ValidRoleName reports whether name is one of RoleNames.
func ValidRoleName(name string) bool {
	for _, n := range RoleNames {
		if n == name {
			return true
		}
	}
	return false
}

// ValidRoleState reports whether state is one a role may carry.
func ValidRoleState(state string) bool {
	return state == RolePresent || state == RoleUnconfigured || state == RolePassive || state == RoleUnknown || state == RoleNotInstalled
}
