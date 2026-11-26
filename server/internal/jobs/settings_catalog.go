package jobs

import "slices"

// SettingInfo is what the compliance library (ADR-0078) needs to know of one
// setting the hardening scripts check. It is read from the same lists the
// scripts and the result parser use, so that a control can only name a
// setting that exists.
type SettingInfo struct {
	ID     string
	Module string
	// What is the setting's description, in EasyRMM's words.
	What string
	// Tier is the risk tier 0 (report only) to 3, Windows only; Linux
	// settings are tiered by the compliance library.
	Tier int
	// Option is the option a Windows setting needs before an apply changes
	// it, or empty.
	Option string
	// Cite is meets, differs or not_set against the STIG rules; Windows only.
	Cite string
	// Client is true for a Windows setting that applies to workstations
	// only; NotDomainController for one that does not apply to a domain
	// controller; MinBuild is the lowest Windows build it applies to.
	Client, NotDomainController bool
	MinBuild                    int
}

// WindowsSettingCatalog lists the settings of windows-settings.json.
func WindowsSettingCatalog() []SettingInfo {
	out := make([]SettingInfo, 0, len(windowsSettings))
	for _, s := range windowsSettings {
		i := SettingInfo{ID: s.ID, Module: s.Module, What: s.What, Tier: windowsSettingTier(s), Option: s.Option, Cite: s.Cite}
		if s.Only != nil {
			i.Client = s.Only.Client != nil && *s.Only.Client
			i.NotDomainController = slices.Contains(s.Only.NotRoles, "domain_controller")
			i.MinBuild = s.Only.MinBuild
		}
		out = append(out, i)
	}
	return out
}

// LinuxSettingCatalog lists the settings of linux-settings.json.
func LinuxSettingCatalog() []SettingInfo {
	out := make([]SettingInfo, 0, len(linuxSettings))
	for _, s := range linuxSettings {
		out = append(out, SettingInfo{ID: s.ID, Module: s.Module, What: s.What})
	}
	return out
}
