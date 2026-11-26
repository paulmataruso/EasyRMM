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
)

// RoleNames lists every role name in a fixed order.
var RoleNames = []string{
	RoleADDS, RoleADCS, RoleDNS, RoleDHCP, RoleFileServer, RolePrintServer, RoleWindowsBackup, RoleDefender,
}

// Role states. Present is a role that is installed and set up; the others
// say why a role that was found is not fully there.
const (
	RolePresent      = "present"
	RoleUnconfigured = "unconfigured" // installed, not set up (DHCP without its parameters)
	RoleUnknown      = "unknown"      // found, but the state could not be read in time
	RolePassive      = "passive"      // Defender installed, another product active
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
	return state == RolePresent || state == RoleUnconfigured || state == RolePassive || state == RoleUnknown
}
