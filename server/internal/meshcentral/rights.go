package meshcentral

// Device group rights (MeshCentral's MESHRIGHT_* flags). Only those EasyRMM
// uses are listed.
const (
	RightEditMesh       uint32 = 0x00000001
	RightManageUsers    uint32 = 0x00000002
	RightManageDevices  uint32 = 0x00000004
	RightRemoteControl  uint32 = 0x00000008
	RightAgentConsole   uint32 = 0x00000010
	RightNoTerminal     uint32 = 0x00000200
	RightNoFiles        uint32 = 0x00000400
	RightNoAMT          uint32 = 0x00000800
	RightLimitEvents    uint32 = 0x00002000
	RightNoDesktop      uint32 = 0x00010000
	RightNoRegistry     uint32 = 0x00400000
	RightNoSoftware     uint32 = 0x00800000
	RightFullAdmin      uint32 = 0xFFFFFFFF
	rightsRestrictedSet        = RightNoAMT | RightLimitEvents | RightNoRegistry | RightNoSoftware
)

// Site rights (MeshCentral's SITERIGHT_* flags).
const (
	SiteRightNoNewGroups  uint32 = 0x00000040
	SiteRightNoMeshCmd    uint32 = 0x00000080
	SiteRightLockSettings uint32 = 0x00000400
	SiteRightNoNewDevices uint32 = 0x00001000
)

// TechnicianSiteRights are the server-wide rights of the MeshCentral account
// behind an EasyRMM user: none, plus restrictions that stop the account
// creating device groups or devices, running MeshCentral's command tools or
// changing its own settings.
const TechnicianSiteRights = SiteRightNoNewGroups | SiteRightNoMeshCmd | SiteRightLockSettings | SiteRightNoNewDevices

// Access is what an EasyRMM user may do on the devices of one site.
type Access struct {
	Desktop  bool
	Terminal bool
	Files    bool
}

// Any reports whether any remote access is granted.
func (a Access) Any() bool { return a.Desktop || a.Terminal || a.Files }

// Rights converts access to device group rights. Remote control is the base
// right that the three session types share; the features not granted are
// switched off with MeshCentral's restriction flags. The agent console,
// device management, wake, power and sharing rights are never granted, and
// the registry, software, Intel AMT and event-history views are restricted.
// It returns 0 when nothing is granted, meaning "no link".
func (a Access) Rights() uint32 {
	if !a.Any() {
		return 0
	}
	r := RightRemoteControl | rightsRestrictedSet
	if !a.Desktop {
		r |= RightNoDesktop
	}
	if !a.Terminal {
		r |= RightNoTerminal
	}
	if !a.Files {
		r |= RightNoFiles
	}
	return r
}
